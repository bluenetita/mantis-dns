# Mantis-DNS — Sprint Plan

**Stack:** filter node = Rust · control plane = Python · UI = TypeScript
**Sprint length:** 2 weeks
**Source:** roadmap in [`design.md`](design.md) §16–§25

> **Checkbox status verified against the codebase on 2026-07-25.**
> `[x]` = built and in the repo · `[ ]` = not built · `[~]` = partially built,
> with the gap named on the line. Sprints 1–18 were originally left unchecked
> long after they shipped; this pass corrects them in both directions — several
> items marked open in Sprints 20–21 had in fact shipped, and several assumed
> complete in Sprints 4–18 were never built.

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
Epic E: OpenVPN integration (AS + Proxmox)     (Sprints 5-7)
Epic F: Telemetry & observability              (Sprints 6-8)
Epic G: Management UI — prototype (TS)         (Sprints 3-6, parallel)
Epic H: HA / multi-node / Proxmox profile      (Sprints 8-9)
Epic J: Enterprise UI redesign (TS)            (Sprints 11-13) — see design.md §19
Epic K: SIEM integration                       (Sprints 14-16) — see design.md §20
Epic L: DNS upstream configuration             (Sprints 17-18) — see design.md §21
Epic M: Native DHCP engine (mantis-dhcp)       (Sprints 19-21+) — see design.md §22
Epic N: SIEM syslog export                     (Sprint 22) — see design.md §20.8
Epic O: Fleet observability / per-node stats   (Sprint 23) — see design.md §23  ← not started
```

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

## Sprint 5 — Category ingestion pipeline + OpenVPN AS integration v1

- [x] Python: full ingestion pipeline — fetch → validate → normalize → dedupe/diff → sanity gates (`feeds/`, `test_feed_ingest.py`).
- [x] Python: APScheduler running feeds on configured intervals (`scheduler.py`).
- [x] Python: category → bundle compilation wired, multiple categories per tenant (`compiler/`).
- [ ] **OpenVPN AS client config push + per-group VIP** — **not built.** No AS integration, no VIP automation, no OpenVPN artifacts anywhere in `infra/`, `scripts/` or `packaging/`. As built, clients get the filter node's address via mantis-dhcp option 6 or a manually configured VPN DNS push. Matches design.md §16 phase 2 (🚧).
- [x] Rust: tenant/group resolution from source-IP subnet (`router.rs`, `/routing-table`) — §7.3 option 2, not the per-group VIP of option 1.

**Exit criteria:** a client in a test group gets filtered DNS driven by an auto-updating category feed — met. Driven by *OpenVPN AS* — not met; the delivery mechanism is DHCP/manual, not AS.

---

## Sprint 6 — Telemetry pipeline v1 + UI policy editor

- [x] Rust: async fire-and-forget query event emission to the control plane's ingestion endpoint (`telemetry.rs`; Kafka deferred indefinitely — design.md §5.4 🚧).
- [x] Python: query event consumer → Postgres (`telemetry_routers.py`; ClickHouse not adopted — §14).
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
- [ ] Cloud: filter node autoscaling (k8s HPA) — **not built.** No Kubernetes in use; `charts/mantis-dns` is an early unverified chart (§14).
- [ ] DR drill — **not run/documented.**

**Exit criteria:** **not met.** The §7.5 / §17.3 failure modes are described in the design doc but not tested, and the staleness-alerting half of the first item is unbuilt.

---

## Epic J — Enterprise UI redesign (Sprints 11–13)

The prototype UI (Epic G) proved the API contract but is not enterprise-grade. This epic rebuilds it on a real foundation. Full plan and stack rationale: **design.md §19**. Backend dependencies (OIDC/RBAC, audit API, ClickHouse query logs) land in Sprints 8–9, so this epic follows them.

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

### Sprint 15 — Webhook push + Settings UI

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

## Epic O — Fleet observability, per-node statistics (Sprint 23)

Full architecture and data model: **design.md §23**.

The filter fleet is the only component on the DNS hot path and the only one with no operator-facing surface: a filter node has no identity anywhere in the control plane, so bundle skew, version skew, per-node SERVFAIL spikes and dropped telemetry are all invisible. mantis-dhcp already established both halves of the pattern in Sprint 21 (`dhcp_daemon_heartbeats` for identity, in-process relaxed atomics for counters, §22.11); this epic applies them to mantis-filter and adds the fleet view neither has.

This epic also unblocks the one item Epic L could not finish: `HealthTab.tsx` (Sprint 18) is empty because per-node upstream health has no route to the control plane, and the heartbeat defined here is that route.

### Sprint 23 — Node stats + Nodes page (**not started** — no `node.rs`, no `FilterNodeHeartbeat`, no `node_routers.py`, no `NodesPage.tsx` in the repo)

- [ ] **`NodeStats`** (`services/filter/mantis-filter/src/node.rs`): relaxed `AtomicU64` counters (queries/blocked/allowed/stub-zone, cache hit-miss-evict, rcode mix, telemetry drops, no-bundle ServFail) + a dep-free 16-bucket log2 latency histogram. Instrumented at *one* point — the top of `TelemetryEmitter::emit`, before `try_send`, so the whole of `lib.rs`'s hot path is untouched and counters stay accurate while the telemetry channel is dropping. Two explicit one-line bumps for the paths that never reach `emit`: the `bootstrap_fail_open()` ServFail early return, and `DnsCache::insert`'s eviction branch.
- [ ] **Node identity**: `MANTIS_NODE_NAME` → `/proc/sys/kernel/hostname` fallback. The env var is a hard deployment requirement for any non-host-networked install — a container hostname changes per restart and would turn the fleet table into a graveyard of dead one-shot rows.
- [ ] **Heartbeat task** (10 s, `with_service_token`): counter snapshot as absolute values (never deltas — a lost heartbeat then costs resolution, not correctness), plus sampled gauges: `DnsCache::len()`, RSS/FDs from `/proc/self/*`, policy + upstream bundle versions per store, key-pin boolean, and the per-member `HealthStore::snapshot` matrix that makes §21.4's deliberately-uncoordinated upstream health *diagnosable* across nodes.
- [ ] **`FilterNodeHeartbeat` model** + migration: keyed on `node_name` (restart takes over the row, same reasoning as `(hostname, family)`), `stats`/`prev_stats` JSONB pair so rates come from a stored sample pair rather than a time-series table. Plus `query_events.node_id` (`String(64)`, nullable, batch-level on the wire, **no index yet** — deferred until a per-node analytics query actually reads it).
- [ ] **`node_routers.py`**: `POST /nodes/heartbeat` (`require_service_token`), `GET /nodes` (`require_role("operator")` — hostnames and topology are infrastructure data, not tenant data, so a tenant-scoped user gets 403, not a filtered list). `GET /nodes` folds in `dhcp_daemon_heartbeats` behind a `role` discriminator so the UI has one shape to render. Rates return `null`, never zero, across an `instance_id` change; latency percentiles are bucket-interpolated and labelled `~p95`.
- [ ] **`NodesPage.tsx`** + nav entry (`minRole: "operator"`): one table, filter and DHCP rows together — splitting them into tabs would hide the correlation that matters (both processes on one host went stale at the same second). Skew and telemetry-drop conditions are banners, not columns; per-row expansion carries the rcode breakdown, latency histogram and upstream health matrix.
- [ ] **Opt-in `/metrics`** on the filter node (`MANTIS_FILTER_METRICS_BIND_ADDR`), same axum text-exposition shape and default-disabled posture as mantis-dhcp's. A second *reader* of the one `Arc<NodeStats>`, not a second counter set — restores what `metrics_init.rs` removed without the split-brain that motivated removing it.

**Exit criteria:** kill one filter node → its row goes stale in the Nodes page within 30 s and stays (never auto-pruned); pin a node to an old bundle → skew banner names it and its version lag; saturate the telemetry channel → drop count is visible in the UI, not just in `journalctl`; a node whose egress to one upstream is blackholed shows that resolver unhealthy *for that node alone*; hot-path benchmark shows no p99 regression beyond 10%. **Note:** that last criterion currently has nothing to run against — the Sprint 4 bench and baseline were never built (see Cross-cutting). Either this epic stands up the bench first, or the criterion should be struck rather than left as an unverifiable exit gate.

**Deliberately out of scope:** in-flight query gauge (the one metric that can't be derived at the `emit` choke point — needs guards in all four server loops, and QPS + p99 covers saturation for now); alerting delivery (every input a rule wants is now exposed, but the channel decision belongs to §11's open alerting work); per-tenant counter labels on node stats (cardinality the hot path would pay for, already free from `query_events`); node control actions — drain, restart, force refresh — which are a write path to the fleet and a separate security surface; a control-plane fleet-aggregate Prometheus endpoint.

---

## Cross-cutting (every sprint)

- [x] Cross-language fixture tests (Python-built bundle → Rust-verified) run in CI (`cross_lang_fixture.rs`, `test_bloom.py`).
- [ ] **Perf regression gate — never built.** There is no hot-path bench, no `benches/` directory, and no perf job in `.github/workflows/ci.yml`; the Sprint 4 baseline it would compare against was never recorded either. Treat every "10% p99 gate" reference in this document as a stated intent, not an enforced check.
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
