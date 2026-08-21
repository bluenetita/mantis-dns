# Mantis-DNS — Sprint Plan

**Stack:** filter node = Rust · control plane = Python · UI = TypeScript
**Sprint length:** 2 weeks
**Source:** roadmap in [`design.md`](design.md) §16–§26

> **Checkbox status verified against the codebase on 2026-07-25.**
> `[x]` = built and in the repo · `[ ]` = not built · `[~]` = partially built,
> with the gap named on the line · ❌ = formally **cut**, removed from the plan
> rather than left as an unbuilt item. Sprints 1–18 were originally left
> unchecked long after they shipped; this pass corrects them in both
> directions — several items marked open in Sprints 20–21 had in fact shipped,
> and several assumed complete in Sprints 4–18 were never built. A same-day
> chief-architect review (design.md §26) then cut several items outright
> (OpenVPN AS integration, Kubernetes/Kafka/ClickHouse/Redis Cluster/etcd as
> targets) and inserted **Epic P** and **Epic Q** ahead of **Epic O**, which
> was re-sequenced as a result — see the Epic map below.

---

## Stack rationale (recorded decision)

| Component | Lang | Why |
|---|---|---|
| Filter node (data plane) | **Rust** | hot path — bloom filter lookups, async DNS I/O, predictable low-latency, no GC pause risk at p99. `hickory-dns` (trust-dns) as base, or custom on `tokio` + `hickory-proto`. |
| Control plane (policy compiler, ingester, API) | **Python** | feed parsing/normalization is I/O + string-heavy, fast iteration matters more than raw speed here. FastAPI for API, `httpx`/`asyncio` for fetchers, SQLAlchemy + Postgres. |
| Management UI | **TypeScript** | React SPA, talks to FastAPI via REST/OpenAPI client codegen. |
| Bundle format | language-agnostic | flatbuffers or protobuf so Rust and Python share schema without hand-sync. |

---

## Epic → Sprint map

```
Epic A: Bundle format & policy compiler        (Sprints 1-2)
Epic B: Filter node core (Rust)                (Sprints 2-4)
Epic C: Control plane API + DB (Python)        (Sprints 1-3)
Epic D: Category feed ingestion + auto-update  (Sprints 4-6)
Epic E: VPN DNS delivery + Proxmox profile     (Sprints 5-7) — OpenVPN AS scope cut, see design.md §7, §26.9
Epic F: Telemetry & observability              (Sprints 6-8)
Epic G: Management UI — prototype (TS)         (Sprints 3-6, parallel)
Epic H: HA / multi-node / Proxmox profile      (Sprints 8-9)
Epic J: Enterprise UI redesign (TS)            (Sprints 11-13) — see design.md §19
Epic K: SIEM integration                       (Sprints 14-16) — see design.md §20
Epic L: DNS upstream configuration             (Sprints 17-18) — see design.md §21
Epic M: Native DHCP engine (mantis-dhcp)       (Sprints 19-21+) — see design.md §22
Epic N: SIEM syslog export                     (Sprint 22) — see design.md §20.8
Epic P: Foundation hardening                   (Sprints 23-25) — see design.md §26, next
Epic Q: Enterprise entry ticket                (Sprints 26-28) — see design.md §26.10-26.11
Epic O: Fleet observability / per-node stats   (Sprint 29) — see design.md §23  ← blocked on P, Q
Epic R: DNS protocol conformance               (Sprints 30-33) — see design.md §27; Phases 1-2 land
                                                before Epic O Sprint 29 starts, same precedent as P/Q
                                                jumping ahead of O above — Sprint 29's per-rcode
                                                counters would otherwise baseline a pre-fix rcode mix
```

**2026-07-25 architecture review re-sequenced everything below this line.**
Epic O was going to be Sprint 23; it no longer is. A chief-architect review
(design.md §26) found three foundation risks — an unbenchmarked hot path that
Epic O was about to add more instrumentation to, a single fleet-wide shared
credential, and application-code-only tenant isolation — serious enough to
sequence ahead of it. Epic P and Epic Q are new; Epic O is unchanged in scope,
just moved to Sprint 29 and reframed as the control surface Epic Q's canary
rollout needs, not a page built for its own sake. See design.md §26.10.

### Shipped outside the sprint sequence

Two subsystems were built without an epic, between the SIEM and upstream work.
They are listed here so the plan accounts for everything in the repo:

| Feature | Where | Design |
|---|---|---|
| **DNS Zones** — authoritative local records, BIND-format export, DDNS target for mantis-dhcp | `zone_routers.py`, `zone_store.rs`, `ZonesPage.tsx` / `ZoneDetailPage.tsx`, `GET /api/v1/local-zones` | design.md **§24** |
| **Block page** — per-group/tenant templates, branding, filter-node HTTP listener | `block_page.py`, `blockpage.rs`, `BlockPageCard.tsx` | design.md **§25** + [`design-block-page.md`](design-block-page.md) |

> **UI status (logged gap):** Epic G delivered a *working prototype* (prompt/alert,
> hand-rolled fetch, raw tables — functional, not enterprise-grade). The full
> enterprise UI is **Epic J** below, broken out of the old single "UI polish"
> bullet so it can't be silently dropped. Plan: design.md §19.

Epics B and C start in parallel sprint 1 once the bundle schema (Epic A) is frozen — that's the contract between Rust and Python, so it's the critical-path blocker for everything else.

---

## Sprint 1 — Bundle schema + skeleton services

**Goal:** Rust and Python agree on the wire format. Both sides build empty shells against it.

- [x] Define bundle schema in protobuf (**protobuf** chosen; `proto/bundle.proto`, never revisited — (de)serialize cost never showed up).
  - fields: tenant_id, group_id, version, signature, category_sets[], bloom_filter bytes, override allow/deny lists, ttl/metadata
- [x] Python: FastAPI skeleton, Postgres schema (tenants, groups, policies, feeds), health endpoint.
- [x] Rust: cargo workspace skeleton — `mantis-filter` bin crate, `mantis-bundle` lib crate.
- [x] CI: both sides build + lint (`cargo clippy -D warnings`, `ruff`, `mypy`), shared `proto/` package (`.github/workflows/ci.yml`).
- [x] Signing scheme: ed25519 (`crypto.py` Python side, verified in `mantis-bundle` Rust side).

**Exit criteria:** Python can emit an empty signed bundle; Rust can load + verify it. No DNS logic yet.

---

## Sprint 2 — Policy compiler (Python) + bloom filter core (Rust)

- [x] Python: policy compiler — `compiler/bloom.py`, params shared with the Rust reader via the versioned schema.
- [x] Rust: bloom filter lookup module (`mantis-policy` crate) + cross-language fixture tests (`tests/cross_lang_fixture.rs`, `tests/test_bloom.py`).
- [x] Rust: in-memory bundle store with hot-swap (`arc-swap`, no lock on the read path).
- [x] Python: bundle versioning + content-addressed storage on local disk (`services/control/bundles/`; object store still 🚧 per design.md §6).

**Exit criteria:** Python-built bloom filter, Rust-verified lookups, fixture tests green both sides.

---

## Sprint 3 — DNS frontend (Rust) + Control API CRUD (Python)

- [x] Rust: DNS server on `tokio` + `hickory-proto` (hand-rolled UDP/TCP listeners, `lib.rs`).
- [x] Rust: policy lookup wired into the request path: query → tenant/group resolve → bloom check → block or forward.
- [x] Python: CRUD API for tenants, groups, policies (`api/routers.py`), recompile on policy change.
- [x] TypeScript: Vite + React + TS scaffold, OpenAPI client codegen (`npm run gen:api`), auth.

**Exit criteria:** end-to-end happy path — create tenant/policy in API → compiled bundle → Rust node blocks a test domain.

---

## Sprint 4 — Local cache + recursor forwarding (Rust)

- [x] Rust: in-process LRU cache honoring TTL (`cache.rs`).
- [x] Rust: upstream forwarding over DoT (later generalized to DoT/DoH/do53 pools in Epic L).
- [x] Rust: full hot-path assembled — tenant resolve → policy → cache → forward → respond.
- [x] Python: feed registry schema + ingester with conditional fetch (`feeds/`).
- [ ] **Load test harness** (`dnsperf` or custom Rust bench) — **not built.** No `benches/` anywhere in the workspace and no perf job in CI, so the p99 baseline this sprint was supposed to establish does not exist. Every later reference to "the regression gate" (Cross-cutting, below; Epic O's exit criteria) is therefore aspirational, not enforced.

**Exit criteria:** filter node resolves real domains end-to-end with cache + DoT upstream — met. First perf baseline recorded — **not met**.

---

## Sprint 5 — Category ingestion pipeline + VPN DNS delivery v1

- [x] Python: full ingestion pipeline — fetch → validate → normalize → dedupe/diff → sanity gates (`feeds/`, `test_feed_ingest.py`).
- [x] Python: APScheduler running feeds on configured intervals (`scheduler.py`).
- [x] Python: category → bundle compilation wired, multiple categories per tenant (`compiler/`).
- ❌ ~~OpenVPN AS client config push + per-group VIP~~ — **cut** (design.md §7, §26.9), not just unbuilt. Clients get the filter node's address via mantis-dhcp option 6 or a manually configured VPN DNS push instead, which delivers the same outcome without the AS dependency.
- [x] Rust: tenant/group resolution from source-IP subnet (`router.rs`, `/routing-table`).

**Exit criteria:** a client in a test group gets filtered DNS driven by an auto-updating category feed — met, via DHCP/manual DNS delivery.

---

## Sprint 6 — Telemetry pipeline v1 + UI policy editor

- [x] Rust: async fire-and-forget query event emission to the control plane's ingestion endpoint (`telemetry.rs`; a Kafka message bus was cut, not deferred — design.md §5.4, §26.9).
- [x] Python: query event consumer → Postgres (`telemetry_routers.py`) — the permanent store; ClickHouse was cut, not a stepping stone (§14, §26.9).
- [x] TypeScript: policy editor UI — category toggles, live domain counts, domain test box (`PolicyPage.tsx` + `POST /groups/{id}/policy/test`).

**Exit criteria:** ops can see live metrics; tenant-admin can toggle categories from UI and see it land in a new bundle within the propagation SLA.

---

## Sprint 7 — Multi-feed hardening + Proxmox profile v1

- [x] Python: priority feeds wired (adult, gambling, weapons, ads, malware/phishing, NRD) with per-feed license metadata.
- [~] Python: sanity gates reject bad feed refreshes and record the rejection — **but there is no alerting delivery** (no Slack/email) and no staged/canary recompile. Rejections are visible in the Feeds UI only. Ties to design.md §11 alerting 🚧.
- [~] Proxmox: shell installers exist (`infra/lxc/install.sh`, `install-rocky.sh`, `mantis-control.service`, `infra/cloud-init/`) — **no LXC CT templates and no Ansible playbook**. Matches design.md §16 phase 0c (🚧 partial).
- [ ] OpenVPN community server integration **validated** on the Proxmox profile — no validated integration or runbook in the repo.

**Exit criteria:** Proxmox single-host deployment installable via one Ansible run — **not met** (installable via shell script, not Ansible). Community OpenVPN clients get filtered DNS — unverified in-repo.

---

## Sprint 8 — Auth/RBAC + audit (backend)

- [~] Python: **RBAC middleware + scoped tenant access built** (`auth.py`: `require_role`, `check_tenant_access`, `user_tenant_filter`; roles viewer/operator/admin), plus local accounts, sessions, CSRF, token versioning, rate-limited login and self-service password change. **OIDC/SSO not built** — `auth.py` says so in its own module docstring. Keycloak was never introduced.
- [x] Python: append-only audit log on mutating endpoints + read API (`audit.py`, `audit_routers.py`).
- [~] Rust: fail-open/fail-closed on bundle-load failure exists but is **node-global, not per-tenant** — a single `bootstrap_fail_open()` env-var check in `lib.rs`, not a per-tenant policy field. A deployment cannot currently fail one tenant closed and another open.

> UI for RBAC nav and the audit-log viewer moved to **Epic J / Sprint 12** — they
> belong on the enterprise UI foundation (design.md §19), not bolted onto the
> prototype. This sprint delivers the backend they consume.

**Exit criteria:** RBAC enforced at the API — met. Audit trail queryable via API for every policy change — met. Federated SSO — not met.

---

## Sprint 9 — HA hardening

- [~] Rust: the node serves the last-good bundle when the control plane is unreachable, and falls back to `UPSTREAM_FALLBACK_ADDRESS` when no bundle is present (design.md §21.3) — **but there is no staleness threshold and no alert.** A node serving a month-old bundle is indistinguishable from a healthy one. This is the exact gap design.md §23 exists to close, and it is still open.
- [ ] Python: Postgres HA (Patroni or managed) — **not built.** Single instance (design.md §6 🚧).
- ❌ ~~Cloud: filter node autoscaling (k8s HPA)~~ — **cut**, not unbuilt: Kubernetes itself is cut as a target (§14, §26.9). `charts/mantis-dns` is kept only in case a customer's platform team requires it, not pursued further.
- [ ] DR drill — **not run/documented.**

**Exit criteria:** **not met.** The §17.3 failure modes are described in the design doc but not tested, and the staleness-alerting half of the first item is unbuilt.

---

## Epic J — Enterprise UI redesign (Sprints 11–13)

The prototype UI (Epic G) proved the API contract but is not enterprise-grade. This epic rebuilds it on a real foundation. Full plan and stack rationale: **design.md §19**. Backend dependencies (OIDC/RBAC, audit API, PostgreSQL-backed query logs) land in Sprints 8–9, so this epic follows them.

### Sprint 11 — UI foundation (UI-0)

- [x] **Mantine 9** component library, theme tokens (`theme.ts`), light/dark.
- [x] TanStack Query server-state layer (`src/api/hooks.ts`); `openapi-typescript` client generated into `src/api/schema.ts`, with `gen:api:check` gating CI on drift. Hand-written `api.ts` retired.
- [x] App shell (`src/app/Shell.tsx`): left nav, tenant context, error boundary, React Router.
- [x] Prototype views ported onto the foundation with empty/loading/error states.

**Exit criteria:** met — prototype parity, zero native `prompt`/`alert`/`confirm` remain, all server state flows through the query client.

### Sprint 12 — Auth, RBAC, data grids, audit (UI-1, UI-2 partial)

- [~] **Login + session + role-gated nav and actions built** (`src/auth/`, `Shell.tsx`'s per-entry `minRole`), against the roles that actually exist (viewer / operator / admin), plus a Users management page. **OIDC PKCE not built** — local credentials instead (see Sprint 8).
- [~] Server-side pagination/sort/filter built for the feed manager and query-log explorer (including client-IP, qtype and category filters). **Row virtualization not built** — no virtualization library in `apps/ui`. Server-side paging covers the stated failure mode, so this is a gap in the plan's letter, not in its intent.
- [x] Audit log viewer (`AuditPage.tsx`, consumes the Sprint 8 audit API).

**Exit criteria:** a non-admin role sees only what it may touch — met (enforced both in nav and server-side). Large feed / query log render without client-side load — met via pagination rather than virtualization.

### Sprint 13 — Forms/UX, analytics, hardening (UI-3, UI-4, UI-5)

- [x] All native dialogs replaced with validated forms, modals, toasts and destructive-action confirmations — via **`@mantine/form` + `@mantine/modals` + `@mantine/notifications`**, not React Hook Form + Zod. Same outcome, one fewer dependency pair; the plan's stack choice was not followed and does not need to be.
- [x] Analytics dashboard (`AnalyticsPage.tsx`, `DashboardPage.tsx`) + domain-test explainability box (§18.5) on `PolicyPage.tsx`.
- [~] Hardening: **built** — Vitest + Testing Library component tests, i18n scaffolding (`react-i18next`, `en` only), `size-limit` bundle budget enforced in CI (400 kB JS / 40 kB CSS gzip), `tsc -b` + `oxlint`. **Not built** — WCAG 2.1 AA audit (never run, no a11y assertion in CI), Playwright E2E, visual-regression (no Storybook/Chromatic).

**Exit criteria:** performance budget enforced — met. WCAG AA pass and E2E green — **not met**; both remain open against design.md §19.2 U10/U14.

---

## Epic K — SIEM integration (Sprints 14–16)

Full architecture and data model: **design.md §20**.

The DNS query stream is the most complete network telemetry source in the stack. This epic exposes it to any SIEM via a cursor-based pull API and HMAC-signed webhook push, in JSON and CEF formats, with enriched event fields (client IP, matched category, feed, latency) that make the data actionable without post-processing.

### Sprint 14 — Event enrichment + pull API

- [x] **QueryEvent schema enrichment** — all fields shipped, plus `matched_rule` and a monotonic `seq` cursor column. `matched_feed_id` was later widened to `String(512)` (migration `a1b2c3d4e5f6`) because a category's bloom joins several source feed ids.
- [x] **Pull API** `GET /api/v1/siem/events` (`siem_routers.py`), cursor-based, JSON + CEF, operator+.
- [x] **CEF serialization** per design.md §20.5 (`siem_common.py`).
- [x] **Analytics page refresh** with the new fields.

**Exit criteria:** `curl /api/v1/siem/events?format=cef` returns valid CEF lines with all enriched fields populated from a live DNS query; cursor advances correctly across pages; format verified against CEF spec.

### Sprint 15 — Webhook push + Settings UI (removed 2026-07-26, see design.md §20.4)

- [x] **`SiemWebhook` model** (`siem_webhook_routers.py`, `db/models.py`).
- [x] **Delivery engine** (`siem_delivery.py`, APScheduler): batching, HMAC-SHA256 `X-Mantis-Signature`, exponential backoff, auto-disable after 6 consecutive failures. Shares its delivery/backoff core with the Sprint 22 syslog path after a later dedupe pass.
- [x] **Settings UI — SIEM section** (`SettingsPage.tsx`), including the test-event button and last-delivery/last-error display.
- [x] **Webhook audit trail** in `AuditLog`.
- [x] **SSRF hardening** (not in the original plan): `ssrf_guard.py` + `resolve_pinned_webhook_url` close a DNS-rebinding gap on the webhook target.

**Exit criteria:** configure a webhook in UI → test-event button triggers a delivery → Splunk/Elastic/webhook.site receives valid signed JSON batch; disable after failure threshold verified by test.

### Sprint 16 — Client registry

- [x] **`ClientEntry` model** — plus `registered_at`/`registered_by`, unique on `(tenant_id, ip)`.
- [x] **Auto-discovery** on query-event ingest; mantis-dhcp additionally upserts registry entries in-process from `/internal/dhcp-event` (Sprint 20), so DHCP-known clients arrive named rather than as stubs.
- [~] **Client registry API** CRUD built (`client_routers.py`). **Bulk CSV import endpoint not built** — no CSV handling anywhere in the router.
- [x] **UI**: `ClientsPage.tsx`.
- [x] **Event enrichment** in SIEM exports for registered clients.

**Exit criteria:** met, except bulk CSV import (clients must be registered one at a time or arrive via DHCP auto-discovery).

---

## Epic L — DNS Upstream Configuration (Sprints 17–18)

Full architecture and data model: **design.md §21**.

Replace the single static upstream resolver with an enterprise-grade upstream management system: named resolver profiles (DoT/DoH/do53), HA pools with health monitoring and automatic failover, split-horizon routing rules, per-tenant policies, DNSSEC enforcement, and a management UI. All upstream config is delivered inside a signed bundle — the filter node resolves with zero control-plane dependency at query time.

### Sprint 17 — Data model, API, bundle delivery

- [x] **DB models**: `UpstreamResolver`, `UpstreamPool`, `UpstreamPoolMember`, `UpstreamRoute`, `UpstreamTenantPolicy`. **Correction:** these are managed by **Alembic** (`services/control/migrations/`, baseline `a7263be2ad89`), not the `ADD COLUMN IF NOT EXISTS` startup pattern this line originally specified — Alembic is the project-wide migration mechanism (design.md §12).
- [x] **CRUD API** (`upstream_routers.py`).
- [x] **Upstream bundle compiler** — signed JSON, fetched on the policy-bundle poll interval.
- [x] **"Test resolver" endpoint** (`POST .../probe`), SSRF-guarded (`test_upstream_probe_ssrf.py`).
- [x] **Rust: bundle loader** (`upstream_bundle.rs`) — signature verify, atomic hot-swap, `UPSTREAM_FALLBACK_ADDRESS` fallback, TLS pinning (`tls_pin.rs`).

**Exit criteria:** create a DoT resolver + failover pool via API → compile bundle → Rust node loads it and forwards queries through the DoT pool; old flat `UPSTREAM_FALLBACK_ADDRESS` still works as fallback.

### Sprint 18 — Health monitor, failover, routing, observability, UI

- [~] **Rust: health monitor** — probe loop, healthy/unhealthy state machine and latency EMA all built (`health_monitor.rs`, `HealthStore`, consumed by `UpstreamBundleForwarder`). **`UpstreamFailedEvent` / `UpstreamRecoveredEvent` are not emitted** — neither symbol exists in the codebase, so no health transition ever reaches the telemetry pipeline.
- [x] **Rust: route evaluation** — priority-ordered matching (domain_suffix / domain_exact / qtype / category / default), pool selection, fallback pool, SERVFAIL on pool collapse.
- [~] **Rust: DNSSEC enforcement** — `strict` built, via hickory's `ResolverOpts::validate` + the `dnssec-ring` feature (a stronger mechanism than the planned AD-bit inspection). **The `dnssec-failed.org` resolver-behaviour assertion during health probes is not built.**
- [ ] **Telemetry metrics** `upstream_latency_us` / `upstream_errors_total` / `upstream_health_state` / `upstream_pool_healthy_members` / `upstream_dnssec_failures_total` — **none exist.** This is the single largest gap left in Epic L.
- [x] **Settings UI — Resolvers section** (`pages/upstream/`: `ResolversTab`, `PoolsTab`, `RoutesTab`, `PolicyTab`).
- [ ] **Upstream Health dashboard tab** — **`HealthTab.tsx` is a placeholder** whose body says the data will appear "once the Sprint 18 health monitor is active in the filter node." That framing is misleading and worth correcting: the monitor *is* active; what is missing is the telemetry path that would carry its state to the control plane. §23's per-node heartbeat (which ships `HealthStore::snapshot` per member) is the intended supply route, so this tab is effectively blocked on Epic O.

**Exit criteria:** failover and re-admission behaviour — met in the node. **Verification "via UI and telemetry dashboard" — not met**; health state is observable only in the node's own logs.

---

## Epic M — Native DHCP engine, mantis-dhcp (Sprints 19–21+)

Full architecture and status: **design.md §22**.

Sprints 19–21 originally planned a co-located ISC Kea sidecar. That integration shipped, then was torn out and replaced by a native engine (`services/dhcp/mantis-dhcp`, Rust) once the Kea integration's maintenance cost — a broken `config-set` push path, state that didn't survive a Kea restart, HA that needed a daemon reload Mantis couldn't trigger, fragile hook-path packaging, DDNS through a shell script — turned out to exceed the cost of owning the protocol. design.md §22.1 has the full case for the rewrite. This epic's items below reflect what actually shipped, not the original Kea-shaped plan.

### Sprint 19 (shipped as: native DHCPv4 core)

- [x] **`services/dhcp/mantis-dhcp`** (new Rust workspace crate): `dhcproto` for wire codec, `sqlx` for Postgres, `arc-swap` for hot-reloading scope config every 10s — no config push, no separate daemon state to drift from the DB.
- [x] **DB models**: `DhcpScope`, `DhcpStaticLease`, `DhcpOption`, `DhcpRelayConfig` (existing, `kea_subnet_id`/`last_pushed_at` dropped — nothing to push to anymore) + new `DhcpLease`/`DhcpLease6` tables, Mantis-owned and authoritative for lease state (migration `f4a9c1d3e8b2`).
- [x] **Allocation**: DISCOVER is a non-committing pool peek; REQUEST commits inside a `pg_advisory_xact_lock(hashtextextended(scope_id, 0))` transaction — this is also the entire HA story (§22.6), no peer protocol needed. RELEASE deletes the lease row; DECLINE marks it `state=1`; a 30s sweep deletes expired rows.
- [x] **Reservations**: fixed-IP-for-MAC honored on both DISCOVER (offer) and REQUEST (claim, NAK on requested-IP mismatch).
- [x] **Auto-injected options**: subnet mask, router, DNS servers (falls back to the Mantis filter node IP), domain name, lease/T1/T2 timers, server identifier.
- [x] **Scope/reservation/option CRUD API** (`dhcp_routers.py`): unchanged externally, simplified internally — every mutating endpoint used to end in `await try_push(db)`; now a plain commit, since there's nothing to push.
- [x] **Lease read API**: `GET /api/v1/dhcp/leases` reads `dhcp_leases` directly (was a raw `SELECT` against Kea's `lease4` table).

**Exit criteria (met):** `cargo check --workspace` and `cargo clippy` clean; full Python test suite (219 tests) and UI test suite (72 tests) pass against the new schema/routers; DORA cycle (relayed + direct-broadcast) verified against `dhcproto`'s documented API surface.

---

### Sprint 20 (shipped in full — the four items below were open at the time of writing and have since landed)

- [x] **Relay**: scope selection by `DhcpRelayConfig.relay_ip` match, falling back to subnet-containment of `giaddr` when no explicit relay row exists (`Snapshot::find_scope_for_relay`).
- [x] **DDNS**: mantis-dhcp POSTs directly to `/internal/dhcp-event` on ACK/RELEASE — same ownership-guard logic in `dhcp_internal_routers.py` that used to sit behind Kea's `run_script` hook + `mantis-ddns-bridge.sh`, just called in-process. That endpoint's own lookup switched from Kea's integer `kea_subnet_id` to the scope's own UUID, since there's no other system's id to translate anymore.
- [x] **Client registry**: no separate sync loop — `/internal/dhcp-event`'s handler upserts `ClientEntry` as part of the same call, rather than a second process polling a lease table (`lease_sync.py`/`DhcpLeaseSyncLoop` deleted outright).
- [x] **PXE**: `scope.pxe_next_server`/`pxe_boot_filename` and per-reservation `next_server`/`boot_filename` overrides, wired into every OFFER/ACK's `siaddr`/boot-filename.
- [x] **Option 82 scope matching** (`circuit_id_hex`/`remote_id_hex`): now consumed — `Snapshot::find_scope_for_relay` matches a relay row's configured circuit-id/remote-id against the packet's, and a row that specifies them only accepts relayed traffic carrying them (design.md §22.7, §22.12). Delivered as *relay authentication / scope selection* rather than a general client-class concept; mantis-dhcp still has no client classes.
- [x] **PXE arch-classing**: option 93 is parsed and a UEFI client gets the UEFI boot filename (`is_uefi_client` in `server.rs`, `pxe_uefi_boot_filename` via migration `b6e2a814f9c3`). Implemented as a BIOS/UEFI split, deliberately not one class per RFC 4578 architecture code.
- [x] **Custom per-scope/per-reservation `DhcpOption` rows**: `options::apply_custom` layers arbitrary option-code rows over the well-known set (last write wins if a custom row reuses a well-known code). v4 only — v6 passthrough remains unbuilt (design.md §22.9).
- [x] **Per-interface socket dispatch**: built for v4 — `recv_interface` threads through dispatch, `find_scope_for_direct` selects by receiving interface, and `interface_server_ips` resolves each interface's own address so option 6/server-id never hand out an off-subnet address on a secondary interface. **v6 still has no per-interface dispatch** (§22.9).

**Exit criteria: met.** Relay → scope selection → ACK → DDNS within one request/response cycle; option 82, PXE arch-classing and multi-interface direct-attach all land for v4.

---

### Sprint 21 (shipped in full — the DHCPv6 daemon and observability items have since landed)

- [x] **HA**: no `DhcpHaConfig` table anymore — running a second `mantis-dhcp` against the same Postgres is active/active HA, coordinated entirely by the advisory lock in Sprint 19's allocation transaction. The real constraint is operational, not configuration: `network_mode: host` means one process per host can bind `:67`, so "a second instance" means a second host, not a second container.
- [x] **UI**: HA tab and "push to Kea" button removed (`HaTab.tsx`/`KeaStatusCard.tsx` deleted) — neither concept exists anymore. Scopes/Reservations/Leases/Status tabs updated to the native schema. The interface field is **no longer a plain text input**: `GET /api/v1/dhcp/interfaces` enumerates the host's interfaces and the scope form offers them as an autocomplete picker, restoring the affordance Kea's interface list used to provide.
- [x] **DHCPv6 daemon**: built — a separate `mantis-dhcp6` binary on `[::]:547` (`config6.rs`/`db6.rs`/`options6.rs`/`server6.rs`/`metrics6.rs`, shared library crate `src/lib.rs`). SOLICIT/ADVERTISE, REQUEST/RENEW/REBIND/REPLY, RELEASE, DECLINE, INFORMATION-REQUEST, CONFIRM; IA_NA by DUID with random-candidate allocation (a /64 is too large to scan), single-prefix IA_PD, relay unwrapping, AAAA DDNS. Documented limits in design.md §22.9: one IA_NA + one IA_PD per message, no v6 custom-option passthrough, no v6 relay allow-list, no per-interface dispatch.
- [x] **Observability**: built — opt-in `/metrics` on both daemons (`MANTIS_DHCP_METRICS_BIND_ADDR` / `MANTIS_DHCP6_METRICS_BIND_ADDR`, blank = disabled) exposing in-process DORA counters plus pool-utilisation and DDNS-retry-depth gauges computed at scrape time; per-request `tracing::debug!` logging; and `dhcp_daemon_heartbeats` liveness keyed on `(hostname, family)`, surfaced by `GET /api/v1/dhcp/health` (operator+) and as a per-instance badge on the Status tab. Design: §22.11. No pool-exhaustion alert rule — deliberately left to a Prometheus alerting rule.

**Exit criteria: met.** Kill one `mantis-dhcp` instance and a second on a different host keeps issuing leases with zero configuration (advisory-lock coordination, not a peer protocol); a DHCPv6 client receives IA_NA and its AAAA record; Prometheus metrics are exposed by both daemons.

---

## Epic N — SIEM syslog export (Sprint 22)

Full architecture and data model: **design.md §20.8**.

A third export path alongside the pull API (Sprint 14) and webhook push (Sprint 15) — RFC 5424 syslog over TCP/TLS/UDP, for SIEMs and log collectors (Wazuh, rsyslog-fed ArcSight/QRadar, etc.) whose native ingestion path is a syslog listener rather than an HTTP endpoint. Same enriched event model and CEF/JSON serialization as the webhook path; only the transport and framing are new.

### Sprint 22 — Syslog delivery engine + Settings UI

- [x] **`SiemSyslog` model** (Postgres): host, port, transport (tcp/tls/udp), format, facility, app_name, filter_decision, batch_size, flush_interval_s, enabled, delivery state — same cursor/backoff/auto-disable shape as `SiemWebhook`, no secret column (syslog has no HMAC signing concept).
- [x] **Delivery engine** (Python APScheduler job, own 10 s tick, independent of webhook delivery): RFC 5424 framing (RFC 6587 octet-counting for TCP/TLS, one message per datagram for UDP), CEF or JSON in the MSG field, retry with the same exponential backoff as webhook delivery, disable after 6 consecutive failures + audit log entry.
- [x] **TOCTOU-safe connect**: host resolved once and connected to the resolved IP literal (TLS SNI/cert verification still targets the original hostname) — closes the same DNS-rebinding gap `resolve_pinned_webhook_url` closes for the webhook path.
- [x] **Settings UI — SIEM syslog section**: add/edit/delete sink configs, enable/disable, "send test event" button, last-delivery timestamp + last-error display, alongside the existing webhook section.
- [x] **Retention safety bound extended**: `prune_query_events` now takes the minimum enabled cursor across *both* `SiemWebhook` and `SiemSyslog`, not just webhooks — a backlogged syslog sink can no longer have its undelivered rows pruned out from under it.

**Exit criteria:** configure a syslog sink in UI → test-event button sends one RFC 5424 line to the configured host → collector receives valid CEF/JSON; auto-disable after failure threshold verified by test; retention never deletes a row an enabled syslog sink hasn't delivered yet.

**Deliberately out of scope:** application-layer delivery acknowledgment (syslog has none — "delivered" means "written to an open socket," same as any fire-and-forget syslog client); TLS certificate pinning (webhook-style HMAC secret doesn't apply here, and the trust tier matches `check_probe_target_safe`'s existing private-network allowance).

---

## Epic P — Foundation hardening (Sprints 23–25)

Full reasoning for every item below: **design.md §26** (R1–R7). Not a feature
epic — nothing here is user-visible. It exists because the 2026-07-25
architecture review found risks that any feature built on top of them would
inherit, foremost among them: no benchmark exists for the DNS hot path, so
Epic O's own exit criteria (below) had nothing to check against.

### R8 hardening (mantis-dhcp) — done, out of sequence (**completed 2026-07-25**)

R8 (owning a DHCP implementation from scratch means inheriting none of Kea's
accumulated hardening) was reasoned about in the review but never given its
own sprint slot below — Sprints 23–25 are scoped to the DNS filter node, a
different subsystem. This work happened anyway, ahead of and independent of
the sequence below. Full detail, and the real Kea CVE history / config
defaults it's checked against: **design.md §22.14**.

- [x] **Option 82 echoed in every reply** (`server.rs::base_reply`) — RFC 3046 §2.2; previously consumed on the way in but never echoed back, which real relay hardware can silently drop the reply for.
- [x] **Panic isolation + bounded concurrency**: every packet handled in its own spawned task, gated by a `MANTIS_DHCP_MAX_INFLIGHT`/`MANTIS_DHCP6_MAX_INFLIGHT` semaphore (default 512) and drained via a `JoinSet`, with a `dhcp_handler_panics_total`/`dhcp_packet_queue_drops_total` counter pair. Decoding itself moved *inside* the spawned task after cargo-fuzz found a real crash in the recv loop's own decode call — see next item.
- [x] **cargo-fuzz harness** (`services/dhcp/mantis-dhcp/fuzz/`, two targets: v4 `Message::decode`, v6 `unwrap_relay` + `Message::decode`) — found **3 real crash sites in `dhcproto` in under a minute of combined fuzzing** (two `debug_assert!` failures in v4's option parser, one integer-underflow in v6's; the first two are masked by this project's release profile, the third's downstream consequence plausibly isn't). Not fixed upstream (third-party crate); contained here by the panic-isolation item above. 🚧 **Not wired into CI** — needs a nightly toolchain + clang this project's CI doesn't currently provision; tracked as still open.
- [x] **Bounded, two-stage lease reclaim** (`sweep_expired`/`sweep_expired6`): an expired lease moves to a hold state (schema value 2, "expired-reclaimed" — already named in `models.py`'s docstring, never wired up before now) for `MANTIS_DHCP_EXPIRED_HOLD_S` (default 300s) before physical deletion, protecting a lost-renewal retry from losing its address to a different client; both the mark and the delete steps are batch-limited (`MANTIS_DHCP_RECLAIM_BATCH_LIMIT`, default 1000) instead of one unbounded `DELETE`. 🚧 **No wall-clock cap per pass** (Kea's `max-reclaim-time`) — only row-count is bounded; flagged, not built.
- [x] **Client identity verified safe**: traced every use of `client_id` in `db.rs`/`server.rs` — it's stored but never used in a `WHERE` clause or identity comparison anywhere; `mac_address` is the sole key. Rules out the classic PXE dual-identity bug by construction. No code change; this was already correct.
- [x] **Option 57/52 investigated**: neither was handled; added a log-only warning (`warn_if_reply_oversized`) when a reply exceeds the client's declared option-57 max (or the 576-byte legacy floor) — visibility for an operator's own oversized custom `dhcp_options`, not enforcement/truncation. v6 has no equivalent option to honor (RFC 8415 defines none, relying on IPv6's 1280-byte MTU floor instead).

### Sprint 23 — Perf floor (**done**)

- [x] **Bench harness + recorded p99 baseline**, on cache-hit, cache-miss and zone-blocked lookup (`services/filter/mantis-filter/benches/hot_path.rs`). No criterion: `[[bench]] harness = false` + `std::time::Instant`, no new dependency. `cargo bench -p mantis-filter --bench hot_path --record` writes `benches/baseline.txt` (plain `name p50_ns p99_ns` lines, not actually JSON despite the filename this line originally used); without `--record` it compares against the committed baseline and exits non-zero past the gate. Upstream-forward path not benched — it's a network call, not a pure function, so it's out of scope for an allocation-focused micro-bench; cache hit/miss and zone lookup are what the review's R7 finding was actually about.
- [x] **Fixed `ZoneStore::lookup`'s hot-path allocation** (`zone_store.rs`): the per-zone `format!(".{z}")` allocation is gone, replaced by `is_subdomain_of` — a byte-slice suffix compare with a dot-boundary guard, no allocation. `normalize(qname)` still allocates once per query (needed as the owned `HashMap` lookup key); only the O(zones) allocation was in scope per the review finding. New unit test `is_subdomain_of_requires_dot_boundary` covers the boundary case directly.
- [x] CI wired: `cargo bench -p mantis-filter --bench hot_path` runs after `cargo test` in the `rust` job and fails the job on a >10% p99 regression against the committed baseline.

**Exit criteria:** a committed baseline exists (`benches/baseline.txt`) — met. The zone-lookup fix lands — met (existing `suffix_match_does_not_false_positive_on_label_boundary` test still passes, plus the new boundary test). CI fails a deliberately-introduced regression — wired via the bench's own exit code, not separately re-verified against a real CI run in this pass.

### Sprint 24 — Credential and correctness hardening (**done**)

- [x] **Bloom exact-match confirmation tier** (design.md §26 R1): on a bloom hit, `decide()` (`services/filter/mantis-filter/src/lib.rs`) now binary-searches a sorted per-category `exact_hashes` list before blocking, via `category_confirms_domain`. Not literally the "sorted/`fst`" suggestion — an `fst` crate has no usable Python-side binding, so this reuses the bloom's own h1 hash (`mantis_policy::exact_hash` / `compiler/bloom.py::exact_hash`, cross-language-tested in `cross_lang_fixture.rs`) as a sorted `repeated fixed64` in the bundle proto instead: 8 bytes/domain, no new dependency on either side. An empty `exact_hashes` (bundle predates this field) falls back to trusting the bloom hit rather than silently unblocking everything. New Rust tests prove both directions (`decide_bloom_hit_without_exact_match_does_not_block`, `decide_bloom_hit_confirmed_by_exact_match_blocks`); new Python test `test_compile_bloom_emits_sorted_exact_hashes_for_the_real_domain_set`.
- [x] **Per-node credentials** (design.md §9, §26 R3): `MANTIS_SERVICE_TOKEN` (one shared secret, checked with `hmac.compare_digest` against every node) is gone. Each filter node now sends `X-Mantis-Node` (its name, env `MANTIS_NODE_NAME` / hostname fallback) + `Authorization: Bearer` (its own token, env `MANTIS_NODE_TOKEN`) — `auth.require_node_token` looks up a `NodeCredential` row by name and checks a sha256 hash + `revoked_at`. Credentials are explicitly scoped with `allowed_tenant_ids` and/or `allowed_group_ids`; only the compatibility-migrated credentials and the local `dev` seed use `allow_all`. Routing tables are filtered to that scope, and group bundles, local zones, block templates, upstream bundles, and telemetry ingestion enforce it. Admin CRUD lives in `node_credentials_routers.py` (`POST /api/v1/nodes/credentials`, `.../rotate`, `.../revoke`) — the raw token is returned once, like any API key. Local/dev `docker compose up` still works out of the box: `main.py`'s lifespan seeds a single `node_name="dev"` credential from `MANTIS_DEV_NODE_TOKEN` when not `is_production`, mirroring the existing `ADMIN_EMAIL`/`ADMIN_PASSWORD` seed. mTLS was not pursued — design.md §9 names a per-node token as sufficient on its own, and it's the smaller change.

**Exit criteria:** a bloom-hit domain confirmed absent from the exact set resolves normally, not blocked — met (Rust tests above). Revoking one node's credential doesn't affect any other node — met (`test_revoking_one_node_does_not_affect_another`). A leaked node credential can no longer forge another node's heartbeat, bundle pull, or query events — met for bundle pull/routing-table/public-key/query-events/local-zones/upstream-bundle (every route that was on `MANTIS_SERVICE_TOKEN`); Epic O's heartbeat endpoint doesn't exist yet (still Sprint 29) so there's nothing to forge there yet — it will use the same `require_node_token` dependency when built.

### Sprint 25 — Contract and isolation hardening (**not started**)

- [ ] **Bundle schema version + protobuf compat gate**: a version field in the bundle format, and a CI check that fails on a breaking protobuf change without a version bump (design.md §26 R7) — closes the one contract in this system (`gen:api:check` covers UI↔API) that currently has no check at all.
- [ ] **Tenant-isolation coverage test**: enumerate every tenant-scoped route and fail CI if any lacks `user_tenant_filter`/`check_tenant_access` (design.md §26 R4).
- [ ] **Postgres RLS** on tenant-scoped tables, as defense in depth behind the application-code filter above.

**Exit criteria:** a route added without a tenant filter fails CI, not just code review; a query issued with the wrong tenant's session cannot read another tenant's rows even if the application-layer filter is bypassed.

---

## Epic Q — Enterprise entry ticket (Sprints 26–28)

Full reasoning: **design.md §26.10–§26.11**. These three items gate real
enterprise procurement and were on no roadmap before this review — not because
they were forgotten, but because nothing before Epic P made them safe to build
(canary rollout needs the per-node identity Epic P Sprint 24 establishes;
retention/erasure needs the tenant-isolation guarantees Epic P Sprint 25
establishes).

### Sprint 26 — SSO + SCIM (**not started**)

- [ ] **OIDC/SAML SSO** against the roles that already exist (viewer/operator/admin) — retires the local username/password store `auth.py` currently maintains (design.md §19.1 U1, §26.11).
- [ ] **SCIM provisioning** so an IdP can manage user lifecycle instead of the Users page doing it by hand.
- [ ] MFA, if the chosen IdP doesn't already enforce it upstream.

**Exit criteria:** a user provisioned in the IdP can log in and land in the correct role with no manual account creation in Mantis; local password login is gated off (or removed) once SSO is configured.

### Sprint 27 — Canary bundle rollout + automatic rollback (**not started**)

- [ ] **Staged bundle rollout**: push a new policy bundle to a configurable subset of nodes first, using the per-node identity Epic P Sprint 24 established.
- [ ] **Automatic rollback** on an error-rate/SERVFAIL spike among the canary set, before the bundle reaches the full fleet.
- [ ] UI surface for both — this is also the first real consumer of Epic O's per-node identity, which is why Epic O is sequenced after this, not before it.

**Exit criteria:** a deliberately bad bundle (e.g. a policy that blocks everything) pushed to a canary subset triggers automatic rollback before reaching the rest of the fleet; a good bundle promotes to 100% within the configured window.

### Sprint 28 — Retention, erasure, residency (**not started**)

- [ ] **Per-tenant retention override** on top of today's single global `QUERY_EVENT_RETENTION_DAYS` (design.md §26 R6).
- [ ] **Right-to-erasure path**: delete/anonymize a `ClientEntry` and its associated `query_events` on request.
- [ ] **Data-residency documentation** per deployment profile (design.md §15, §26.11) — not a code deliverable, but a gate some customers require before signing.

**Exit criteria:** a tenant's retention window can be set independently of the global default; an erasure request against one client's IP removes/anonymizes its `ClientEntry` and associated query events without touching any other tenant's data.

---

## Epic O — Fleet observability, per-node statistics (Sprint 29)

Full architecture and data model: **design.md §23**. Sequencing: design.md
§26.10 — this epic is unchanged in scope from its original design, only moved
later and reframed. It was going to be Sprint 23; Epic P and Epic Q now come
first, for two concrete reasons: this epic adds per-query instrumentation to
a hot path Epic P Sprint 23 is what first benchmarks, and its heartbeat is one
more thing forgeable with the shared fleet token Epic P Sprint 24 replaces.

The filter fleet is the only component on the DNS hot path and the only one with no operator-facing surface: a filter node has no identity anywhere in the control plane, so bundle skew, version skew, per-node SERVFAIL spikes and dropped telemetry are all invisible. mantis-dhcp already established both halves of the pattern in Sprint 21 (`dhcp_daemon_heartbeats` for identity, in-process relaxed atomics for counters, §22.11); this epic applies them to mantis-filter and adds the fleet view neither has.

This epic also unblocks the one item Epic L could not finish: `HealthTab.tsx` (Sprint 18) is empty because per-node upstream health has no route to the control plane, and the heartbeat defined here is that route. It additionally becomes the control surface Epic Q Sprint 27's canary rollout needs to target a subset of the fleet by identity — the reason this epic is worth building now, beyond a table in a UI.

### Sprint 29 — Node stats + Nodes page (**not started** — no `node.rs`, no `FilterNodeHeartbeat`, no `node_routers.py`, no `NodesPage.tsx` in the repo)

- [ ] **`NodeStats`** (`services/filter/mantis-filter/src/node.rs`): relaxed `AtomicU64` counters (queries/blocked/allowed/stub-zone, cache hit-miss-evict, rcode mix, telemetry drops, no-bundle ServFail) + a dep-free 16-bucket log2 latency histogram. Instrumented at *one* point — the top of `TelemetryEmitter::emit`, before `try_send`, so the whole of `lib.rs`'s hot path is untouched and counters stay accurate while the telemetry channel is dropping. Two explicit one-line bumps for the paths that never reach `emit`: the `bootstrap_fail_open()` ServFail early return, and `DnsCache::insert`'s eviction branch.
- [ ] **Node identity**: `MANTIS_NODE_NAME` → `/proc/sys/kernel/hostname` fallback. The env var is a hard deployment requirement for any non-host-networked install — a container hostname changes per restart and would turn the fleet table into a graveyard of dead one-shot rows.
- [ ] **Heartbeat task** (10 s, `with_service_token`): counter snapshot as absolute values (never deltas — a lost heartbeat then costs resolution, not correctness), plus sampled gauges: `DnsCache::len()`, RSS/FDs from `/proc/self/*`, policy + upstream bundle versions per store, key-pin boolean, and the per-member `HealthStore::snapshot` matrix that makes §21.4's deliberately-uncoordinated upstream health *diagnosable* across nodes.
- [ ] **`FilterNodeHeartbeat` model** + migration: keyed on `node_name` (restart takes over the row, same reasoning as `(hostname, family)`), `stats`/`prev_stats` JSONB pair so rates come from a stored sample pair rather than a time-series table. Plus `query_events.node_id` (`String(64)`, nullable, batch-level on the wire, **no index yet** — deferred until a per-node analytics query actually reads it).
- [ ] **`node_routers.py`**: `POST /nodes/heartbeat` (`require_service_token`), `GET /nodes` (`require_role("operator")` — hostnames and topology are infrastructure data, not tenant data, so a tenant-scoped user gets 403, not a filtered list). `GET /nodes` folds in `dhcp_daemon_heartbeats` behind a `role` discriminator so the UI has one shape to render. Rates return `null`, never zero, across an `instance_id` change; latency percentiles are bucket-interpolated and labelled `~p95`.
- [ ] **`NodesPage.tsx`** + nav entry (`minRole: "operator"`): one table, filter and DHCP rows together — splitting them into tabs would hide the correlation that matters (both processes on one host went stale at the same second). Skew and telemetry-drop conditions are banners, not columns; per-row expansion carries the rcode breakdown, latency histogram and upstream health matrix.
- [ ] **Opt-in `/metrics`** on the filter node (`MANTIS_FILTER_METRICS_BIND_ADDR`), same axum text-exposition shape and default-disabled posture as mantis-dhcp's. A second *reader* of the one `Arc<NodeStats>`, not a second counter set — restores what `metrics_init.rs` removed without the split-brain that motivated removing it.

**Exit criteria:** kill one filter node → its row goes stale in the Nodes page within 30 s and stays (never auto-pruned); pin a node to an old bundle → skew banner names it and its version lag; saturate the telemetry channel → drop count is visible in the UI, not just in `journalctl`; a node whose egress to one upstream is blackholed shows that resolver unhealthy *for that node alone*; hot-path benchmark (Epic P Sprint 23, now a real, running check rather than an aspirational reference) shows no p99 regression beyond 10%.

**Deliberately out of scope:** in-flight query gauge (the one metric that can't be derived at the `emit` choke point — needs guards in all four server loops, and QPS + p99 covers saturation for now); alerting delivery (every input a rule wants is now exposed, but the channel decision belongs to §11's open alerting work); per-tenant counter labels on node stats (cardinality the hot path would pay for, already free from `query_events`); node control actions — drain, restart, force refresh — which are a write path to the fleet and a separate security surface; a control-plane fleet-aggregate Prometheus endpoint.

---

## Epic R — DNS protocol conformance (Sprints 30–33)

Full audit and rationale: [`design.md` §27](design.md#27-dns-protocol-conformance)
and [`docs/rfc-compliance.md`](rfc-compliance.md). Nothing in mantis-filter's
hand-rolled UDP/TCP listeners had been checked against RFC 1035/6891/2308/7766
end to end before this epic; the audit found 9 findings that are wrong on the
wire today (answering QR=1 messages, no SOA on negative answers, empty
non-terminals returning NXDOMAIN instead of NODATA, among others).

**Sequencing:** Phases 1–2 (Sprints 30–31) must land *before* Epic O Sprint 29
begins collecting its per-rcode baseline — the same reordering precedent
Epic P/Q already set against Epic O above. Phases 3–4 (Sprints 32–33) have no
such constraint and can slip without blocking anything else in this plan.

### Sprint 30 — Phase 1: query sanity + EDNS (**built**, shipped ahead of formal sequencing)

- [x] `services/filter/mantis-filter/src/protocol.rs`: `validate_query`
  (opcode/class/QDCOUNT/qtype dispatch), `should_process` (QR=1 → drop, no
  reply), `negotiate_edns` (OPT echo on both UDP and TCP, BADVERS on an
  unsupported EDNS version), `formerr_for_unparseable` (best-effort FORMERR
  when a packet's 12-byte header parses but the body doesn't).
- [x] `build_response` (`lib.rs`) returns `Option<Message>`; all four
  listener loops (`run_udp_server`, `run_tcp_server`, `run_router_udp_server`,
  `run_router_tcp_server`) route through the shared module so none of the
  four can drift from another the way they previously did.
- [x] RD=0 honored on a cache miss (REFUSED, no outbound lookup); RA cleared
  on the closed-bootstrap/unmatched-route ServFail path.
- [x] `enforce_udp_size_limit` truncation reworked: sheds the additional
  section first, then empties the answer section entirely (TC=1) rather than
  popping records one at a time — closer to what RFC 6891 §7 and common
  resolver practice expect from a truncated response.

**Exit criteria (partial — see Not built):** unit + integration test coverage
for every Phase 1 finding in `protocol.rs` and `lib.rs`'s test module;
`cargo clippy -D warnings` and the full workspace test suite pass.

**Not built this sprint:** the `ednscomp`/`dig`-based `scripts/conformance.sh`
gate described in rfc-compliance.md §4 — needs a running compose stack, which
this pass didn't stand up. Until that script exists and runs in CI, Phase 1's
correctness rests on the unit/integration suite alone, not a wire-level tool.

### Sprint 31 — Phase 2: negative answers + local zone correctness (**built**)

- [x] Apex SOA/NS synthesis for local zones — control-plane-authored
  (`get_local_zone_records` in `routers.py`, serial from `DnsZone.updated_at`,
  see rfc-compliance.md B9 for why control-plane over filter-node-synthesized),
  with a filter-node-side fallback (`zone_store::synthesize_soa`) so the
  authority section is never silently empty either way.
- [x] SOA in the authority section of every NXDOMAIN/NODATA, all three
  answer paths (stub zone, upstream). **The predicted `Forwarder`
  trait-signature change didn't happen**: `hickory_resolver::ResolveError`
  already carries the upstream's SOA on the exact error path both forwarders
  return through (`into_soa()`) — `resolve_records` just needed to ask.
  (Block-path SOA stays out of scope — see D3, no real zone backs a blocked
  name; EDE in Phase 4 is the right mitigation there instead.)
- [x] Empty non-terminals → NODATA, CNAME returned instead of NODATA at a
  different qtype, single-label wildcard support in local zones (deliberate
  simplification — not the full RFC 4592 closest-encloser algorithm).
  ANY's local half needed no change (already NODATA, never forwarded); ANY
  forwarding stays Phase 4 (B5).
- [x] TXT record chunking past the 255-byte character-string limit.
- [x] Built-in special-use/RFC 6303 empty zones (`.onion`, `.local`,
  `10.in-addr.arpa`, etc.) as an always-present `ZoneStore` layer, overridden
  by a same-apex tenant zone if one exists.
- [x] SERVFAIL caching (`NegativeKind::ServFail`, fixed 30s TTL per RFC 9520).

**Exit criteria (verified):** a non-existent name under a local zone returns
NXDOMAIN *with* SOA; an empty non-terminal returns NOERROR/NODATA; `.onion`
and `10.in-addr.arpa` never appear in an upstream packet capture (unit-tested
against `ZoneStore::empty()`); a blackholed upstream produces exactly one
attempt per SERVFAIL TTL (`resolve_records_caches_servfail_...` test). SOA
extraction from a real `hickory_resolver::ResolveError` (not a mock) is
pinned by `resolve_records_attaches_the_upstreams_own_soa_on_nxdomain`.
`cargo clippy -D warnings`, the full Rust workspace test suite (mantis-filter,
mantis-bundle, mantis-policy), `ruff`, and `mypy` all pass. `scripts/conformance.sh`
(live `dig`/`ednscomp` gate) remains unbuilt, same gap Sprint 30 left open.

### Sprint 32 — Phase 3: DNSSEC transparency (**partially built**)

- [x] AD propagated to the client — but honestly, from *this resolver's own*
  validation, not a pass-through of upstream's raw AD bit (hickory's
  `Resolver::lookup()` doesn't expose that). `Forwarder::lookup` now returns
  `LookupOutcome { records, authenticated }`; `authenticated` reflects
  `dnssec_record_iter()`'s per-record `Proof`, only ever `true` when
  `dnssec_strict` (§21.5) is on and every record proved `Secure`. Cached
  alongside the record set so a cache hit still asserts AD. Filtering stays
  a synthesized unsigned answer + Extended DNS Error (Phase 4), not a fake
  signature — see design.md §27.2.
- [x] DO echoed back on our own response (`protocol::negotiate_edns`).
- [ ] **Not built, and re-scoped as separate future work, not a Sprint 32
  remainder:** RRSIG/NSEC/NSEC3 pass-through and per-query CD-driven bypass
  of `dnssec_strict`. Both need a lower-level DNS client
  (`hickory-client`'s `AsyncClient`/raw `DnsHandle`) as a second resolution
  path alongside the existing `hickory-resolver`-based one — `Resolver::lookup()`
  filters every answer down to the single requested record type by design,
  so DO on the wire can't make RRSIG data appear through it regardless of
  anything this sprint could add. See design.md §27.2 for the full
  explanation; **neither of the two options this sprint originally listed
  (transparent pass-through vs. local validation) had this right** — track
  the real fix as its own item if a customer needs a validating stub
  resolver downstream of a Mantis node.

**Exit criteria (for the shipped half):** a query with `dnssec_strict` on
against a domain with a valid chain gets AD=1; the same query against a
domain with a broken chain (or with `dnssec_strict` off) gets AD=0; a cache
hit preserves whichever of those the original lookup produced — all pinned
by `dnssec_outcome_authenticated_only_when_every_record_is_secure` and
`resolve_records_sets_authentic_data_and_caches_it`. No regression in
`dnssec_strict` health-probe behavior (§21.5) — unaffected, since no new
validation was added. The originally-planned `dnsviz` exit criterion doesn't
apply to what shipped; it's relevant again once RRSIG pass-through exists.

### Sprint 33 — Phase 4: hardening (**partially built**)

- [x] Extended DNS Errors (RFC 8914) on blocked answers — info-code 17
  (Filtered), the client-visible signal that a filtering deviation, not a
  lookup failure, produced this answer. `protocol::attach_extended_error`,
  called from `build_response`'s block path.
- [x] `edns-tcp-keepalive` (RFC 7828) on TCP responses.
- [x] TCP out-of-order pipelining (RFC 7766 §6.2.1.1, §7) — both TCP
  listener loops split into a reader that spawns each query onto its own
  task (bounded, `MAX_PIPELINED_TCP_QUERIES_PER_CONN` = 16) and a writer
  task draining an mpsc channel in completion order. Proved with a real
  client in `tests/tcp_pipelining.rs`: pipelines a slow query then a fast
  one with no read in between, asserts the fast answer comes off the wire
  first.
- [x] DNS Cookies (RFC 7873) — compute/verify only, no enforcement. **Scope
  correction found while implementing**: the plan assumed
  BADCOOKIE-on-mismatch was the point; RFC 7873 §5.2 actually makes that an
  optional under-load policy, and enforcing it unconditionally would reject
  legitimate clients on every one of this process's own restarts (which
  rotate the cookie secret by design). See design.md §27.3.
- [ ] **Not started, re-scoped as its own future item, not a Sprint 33
  remainder:** `IP_PKTINFO`/`IPV6_RECVPKTINFO` source-address selection on
  multi-homed nodes — real bug, but needs `sendmsg`/`recvmsg` ancillary-data
  support tokio's `UdpSocket` doesn't expose, unsafe platform-specific code,
  and real multi-homed hardware to verify against, none of which this
  sprint had. See design.md §27.3.
- [ ] **Not started, paired with the item above as its own future epic:**
  response rate limiting (BCP 140) — a full feature (memory-bounded
  per-source tracking under real attack load), not a hardening-pass line
  item; also the load signal the cookie foundation above needs before
  BADCOOKIE enforcement means anything. See design.md §27.3.

**Exit criteria (for the shipped half):** a blocked domain's response
carries an EDE record a client resolver can surface to a user
(`build_response_attaches_an_extended_error_to_a_blocked_answer`); a TCP
client pipelining a slow query behind a fast one gets the fast answer first
(`tests/tcp_pipelining.rs`); a client sending a COOKIE option gets one back,
correctly bound to its own address
(`negotiate_cookie_echoes_client_cookie_and_attaches_a_server_cookie`,
`negotiate_cookie_server_cookie_differs_by_client_ip`). The originally
planned `dig`-from-a-second-address exit criterion doesn't apply to what
shipped; it's relevant again once C5 exists.

---

## Cross-cutting (every sprint)

- [x] Cross-language fixture tests (Python-built bundle → Rust-verified) run in CI (`cross_lang_fixture.rs`, `test_bloom.py`).
- [x] **Perf regression gate** (Epic P Sprint 23): `services/filter/mantis-filter/benches/hot_path.rs` + committed `benches/baseline.txt`, run via `cargo bench -p mantis-filter --bench hot_path` in the `rust` CI job. Covers cache hit/miss and zone-blocked lookup, not the upstream-forward path (network I/O, not a pure function).
- [x] `cargo clippy -D warnings`, `ruff` + `mypy`, `oxlint` + `tsc -b` gate merges. Also enforced: `size-limit` bundle budget and `gen:api:check` (UI schema drift vs FastAPI's OpenAPI spec). Linter note: `mypy` runs in its default mode, not `--strict`.

---

## Risks tied to language split

| Risk | Mitigation |
|---|---|
| Bloom filter param drift between Python compiler and Rust reader | Shared fixture tests (Sprint 2), params in versioned schema, not hardcoded both sides |
| Protobuf schema evolution breaking either side | Schema in shared `proto/` package, semver, CI fails on incompatible change without version bump |
| Python ingestion slow under many feeds | Feeds fetched concurrently (`asyncio.gather`), diff-only recompilation limits blast radius |
| Rust async DNS edge cases (UDP truncation, TCP fallback) | Mitigation partly diverged: message parsing/serialization uses `hickory-proto`, but the UDP/TCP listeners are hand-rolled on `tokio` rather than using `hickory-server`. Truncation and TCP-fallback handling are therefore ours, and covered by `tests/dns_server.rs` and `tests/tcp_idle_timeout.rs` instead of by the crate |
| Building enterprise UI features on the throwaway prototype foundation | Epic J Sprint 11 (UI-0) lands the real foundation *first*; no enterprise UI feature is built on the prototype's hand-rolled fetch/tables |

---

*End of document.*
