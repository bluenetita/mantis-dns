# Design: Customizable Block Page

Status: draft · Owner: TBD · Depends on: `proto/bundle.proto`, `services/filter`, `services/control`, `apps/ui`

## 1. Problem

When a query is blocked, the filter node returns `NXDOMAIN`
(`services/filter/mantis-filter/src/lib.rs`, `Decision::Block` arm). The client
sees a generic "server not found" browser error — no explanation, no branding,
no self-service path. Admins want a page that says *why* the domain was blocked
(category), shows tenant branding, and optionally lets the user request an
unblock.

`docs/design.md` §Request-path already reserves the concept: *"return sinkhole
answer (NXDOMAIN / 0.0.0.0 / custom) per policy"* — only NXDOMAIN is built.

## 2. Overview

Three parts:

1. **DNS redirect** — on block, return an A/AAAA record pointing at a
   block-page listener IP (a stable VIP) with a **low TTL**, instead of
   NXDOMAIN. Selected per policy via a new `block_response` mode.
2. **Block-page listener** — an HTTP(S) server on that VIP that renders the
   page. Resolves the requesting client IP → group (same mapping the filter
   uses), looks up that group's template, renders.
3. **Template config** — per-tenant (with optional per-group override) content
   stored in the control plane, edited in the UI.

```
client ── blocked query ──▶ filter node
                               │  Decision::Block + mode=REDIRECT
                               ▼
        A 10.x.x.x (TTL 30s) ──┘
client ── http://blocked.com/ ─▶ block-page listener (VIP 10.x.x.x)
                                    │ src IP → group → template
                                    ▼
                               rendered branded page
```

## 3. DNS side (hot path)

### 3.1 Proto additions (`proto/bundle.proto`)

```proto
message Bundle {
  // ... existing fields 1-8, 15-16
  BlockResponse block_response = 9;
}

message BlockResponse {
  BlockMode mode = 1;
  string redirect_ipv4 = 2;   // when mode = REDIRECT
  string redirect_ipv6 = 3;   // optional AAAA
  uint32 ttl_seconds = 4;     // low, e.g. 30; avoids stale block after unblock
}

enum BlockMode {
  BLOCK_MODE_UNSPECIFIED = 0; // treated as NXDOMAIN
  BLOCK_MODE_NXDOMAIN   = 1;  // current behavior, default
  BLOCK_MODE_ZERO_IP    = 2;  // 0.0.0.0 / ::
  BLOCK_MODE_REDIRECT   = 3;  // A/AAAA -> block-page VIP
}
```

Additive (proto3), backward compatible: old bundles decode with
`block_response = None` → filter falls back to NXDOMAIN.

### 3.2 Filter change

`Decision::Block` arm becomes a match on `bundle.block_response.mode`:

- `NXDOMAIN` / unspecified → current path (`set_response_code(NXDomain)`).
- `ZERO_IP` → NoError + A `0.0.0.0` (and AAAA `::` for AAAA queries).
- `REDIRECT` → NoError + A `redirect_ipv4` for A queries, AAAA
  `redirect_ipv6` for AAAA queries, `ttl_seconds` TTL. Other qtypes
  (MX/TXT/…) → NXDOMAIN so only web navigations land on the page.

Telemetry `decision:"block"` unchanged. Low TTL is load-bearing: after an
admin unblocks, the browser must re-resolve quickly rather than stay pinned to
the block VIP.

## 4. Block-page listener

### 4.1 Placement — two options

**Option A (recommended, phase 1): co-hosted in the filter node.** A second
tokio listener (ports 80/443 on the VIP), separate from the DNS task. The
filter already computes client-IP → group (`docs/design.md` §7) and holds the
current bundle in memory, so no new IP-mapping duplication and no extra
cross-plane call on render. Off the DNS hot path.

**Option B: standalone `services/blockpage`.** Own deployable behind the VIP.
Cleaner blast-radius separation, but must re-implement client→group mapping and
fetch templates itself. Defer unless the HTTP surface on DNS nodes is
unacceptable.

Either way the render path never blocks DNS resolution.

### 4.2 HTTPS caveat (must be explicit to users)

DNS-level redirection cannot present a valid TLS cert for the *blocked*
domain. Consequences:

- Plain `http://` navigations and captive-portal-style probes → page renders
  cleanly.
- `https://` / HSTS sites → browser shows a cert warning **before** our page.
  Unavoidable at the DNS layer without MITM.

Strategy: serve HTTP block page always; on 443 present our own cert and accept
the warning; document that fully-clean HTTPS block pages require installing an
org root CA on managed devices (MDM) — out of scope for phase 1.

## 5. Template config (control plane)

### 5.1 DB model (`services/control/mantis_control/db/models.py`)

```python
class BlockPageTemplate(Base):
    __tablename__ = "block_page_templates"
    # scope: exactly one of tenant-default or group-override
    id, tenant_id (FK), group_id (FK, nullable, unique when set)
    block_mode        # nxdomain | zero_ip | redirect   (drives §3 bundle field)
    redirect_ipv4, redirect_ipv6, ttl_seconds
    title, message            # message = sanitized HTML/markdown
    logo_url                  # or logo_blob for embedded
    brand_color
    show_domain: bool         # echo the blocked hostname
    show_category: bool       # echo matched category/reason
    contact_url
    allow_unblock_request: bool
    updated_at
```

Resolution order at render: group override → tenant default → built-in default.

### 5.2 Wiring

- `block_mode` + redirect IPs + ttl feed the compiler
  (`compiler/build_policy_bundle.py`) → new `BlockResponse` in the signed
  bundle. This is the only template field the hot path needs.
- All *presentation* fields (title, message, logo, colors, flags) are served to
  the listener via a control-plane REST endpoint
  (`GET /internal/block-template?group_id=`), cached with ETag. Kept **out** of
  the signed bundle to keep the hot-path artifact lean.

### 5.3 API + UI

- REST CRUD under the existing policy/group admin
  (`services/control/mantis_control/api`, `schemas.py`).
- UI: a "Block page" tab on the group/policy screen (`apps/ui/src`) — mode
  selector, branding fields, live preview, "send test" button.

## 6. Optional: request-unblock flow (phase 2)

Block page "Request access" button → `POST /public/unblock-request`
{group, domain, reason} → new `unblock_requests` table + `AuditLog` entry →
admin queue in UI. Rate-limited by source IP. Keep gated behind
`allow_unblock_request`.

## 7. Rollout / phasing

1. Proto + filter redirect modes + tenant-level template (mode + branding),
   co-hosted listener, HTTP only, built-in template rendering.
2. UI editor + live preview; per-group override; HTTPS listener with own cert.
3. Unblock-request flow; per-category block modes; MDM root-CA guidance.

## 8. Open questions

- Listener placement: co-host in filter (A) vs standalone service (B)?
- Customization granularity: tenant-only, or tenant + per-group override, or
  down to per-category?
- HTTPS: ship own cert + accept warning, or HTTP-only for phase 1?
- Block VIP: one global anycast VIP, or per-filter-node IP?
