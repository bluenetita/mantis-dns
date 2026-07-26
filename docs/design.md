# Enterprise DNS Filtering Platform — Design Document

**Codename:** Mantis-DNS
**Status:** Draft v1.3
**Date:** 2026-07-25 (status markers re-validated against the codebase on this date)
**Audience:** Platform engineering, network security, SRE

> **Deployment profile.** The platform runs as the **Proxmox VE single-host /
> small-cluster profile** (§17): systemd or Docker Compose, one PostgreSQL
> instance, filesystem-based bundle distribution — see
> [`ARCHITECTURE.md`](../ARCHITECTURE.md) for the as-built summary.
> Category-based content filtering with auto-updating feeds (porn, gambling,
> firearms, etc.) is a first-class feature (§18).

> **⚠️ Build status.** §4–§6, §8, §11–§12, and §15 describe a larger
> cloud/K8s design that predates this deployment profile. Most of it — a
> Kubernetes-orchestrated cluster, Kafka/NATS, Redis Cluster, ClickHouse,
> etcd/Consul, Vault, Patroni — is **formally cut, not deferred**, per the
> 2026-07-25 architecture review; the record of what was cut and why is
> **§26.9**, not scattered `🚧` markers through those sections. The one item
> kept as a live target from that list is mTLS between the control plane and
> the fleet (§26 R3) — everything else stays only where an as-built path
> already covers the same need (Postgres for query logs, filesystem pull for
> bundle distribution, an in-process LRU cache).
>
> Sections describing subsystems that are **fully built** and match this
> document: §18 (category filtering), §20 (SIEM export), §22 (DHCP), §24 (DNS
> zones), §25 (block page). §21 (upstream) is built except for the
> telemetry/dashboard items flagged inline. §19 (UI) and §23 (fleet
> observability) carry per-item status. **§26 is the current architecture
> review** — read it before treating §16's roadmap or the sprint plan's
> ordering as current: the delivery sequence was re-planned around it.
> Per-sprint delivery detail lives in [`sprint-plan.md`](sprint-plan.md).

---

## 1. Summary

Mantis-DNS is a DNS-based ad/tracker/malware blocking platform with per-client policy, query logging, and a management UI, built as a horizontally scalable, multi-tenant, highly available platform suitable for enterprise deployment, co-located with an **OpenVPN Access Server (AS) cluster** so that VPN clients receive filtered, policy-controlled DNS regardless of which gateway node they connect to.

The core architectural shift is the separation of the system into three planes:

- **Data plane** — stateless DNS resolvers/filters that answer queries at line rate.
- **Control plane** — policy, blocklist, and configuration distribution.
- **Management plane** — API, UI, multi-tenant administration, audit.

This separation — rather than one process and one SQLite file — is the core architectural bet behind the rest of this document.

---

## 2. Goals & Non-Goals

### 2.1 Goals

| # | Goal |
|---|------|
| G1 | Horizontal scalability of DNS query handling (stateless filter nodes). |
| G2 | High availability: no single point of failure; survive node and AZ loss. |
| G3 | ~~Co-residency / tight integration with an OpenVPN AS cluster~~ — withdrawn (§7, §26.9); superseded by G3': filtered DNS delivered to any client regardless of gateway, via DHCP or a manually configured VPN DNS push. |
| G4 | Multi-tenancy with per-tenant policy, blocklists, and isolated query logs. |
| G5 | Centralized, versioned, auditable policy & blocklist distribution. |
| G6 | Observability: metrics, structured query logs, tracing, alerting. |
| G7 | Sub-millisecond added latency at p99 for cache hits. |
| G8 | Secure-by-default: DNS-over-TLS/HTTPS upstream, mTLS internal, RBAC. |

### 2.2 Non-Goals

- Replacing the recursive resolver algorithm itself (we wrap Unbound/Knot, not reinvent).
- Being a general-purpose CDN or web proxy.
- Endpoint agent / DNS client software (we operate at the network/VPN resolver layer).
- Layer-7 content inspection beyond DNS.

---

## 3. Single-Node Baseline & Its Limits

| Concern | Single-node DNS sinkhole | Enterprise requirement |
|---------|---------------|------------------------|
| Storage | SQLite on local disk | Replicated, HA datastore |
| Scaling | Single host (manual sync tooling at best) | Stateless autoscaling fleet |
| HA | None native | Active-active, multi-AZ |
| Policy scope | Global + limited per-client groups | Multi-tenant, hierarchical groups |
| Config distribution | Local DB rebuild | Versioned, pushed to fleet |
| API/UI | Single-instance web admin | Stateless API, SSO, RBAC, audit |
| Logging | Local query log | Central pipeline, retention, search |
| Upstream privacy | Optional | DoT/DoH enforced |
| Secrets | Local config files | Vault / KMS |

---

## 4. High-Level Architecture

```
                         ┌──────────────────────────────────────────────┐
                         │              MANAGEMENT PLANE                  │
                         │  Admin API · Web UI (SPA) · SSO/OIDC 🚧 · RBAC │
                         │  Audit log · Tenant mgmt · Policy authoring    │
                         └───────────────┬──────────────────────────────┘
                                         │ REST (FastAPI), mTLS 🚧
                         ┌───────────────▼──────────────────────────────┐
                         │               CONTROL PLANE                    │
                         │  Policy compiler · Blocklist ingester          │
                         │  PostgreSQL (source of truth) + object store 🚧│
                         └───────────────┬──────────────────────────────┘
                                         │ push: signed policy bundles
            ┌────────────────────────────┼────────────────────────────┐
            │                            │                            │
   ┌────────▼────────┐         ┌─────────▼────────┐         ┌─────────▼────────┐
   │  FILTER NODE A  │         │  FILTER NODE B   │   ...   │  FILTER NODE N   │
   │  DNS frontend   │         │  DNS frontend    │         │  DNS frontend    │
   │  Policy engine  │         │  Policy engine   │         │  Policy engine   │
   │  Local cache    │         │  Local cache     │         │  Local cache     │
   │  Recursor/fwd   │         │  Recursor/fwd    │         │  Recursor/fwd    │
   └────────┬────────┘         └────────┬─────────┘         └────────┬────────┘
            │                            │                            │
            │  (no shared cache — each node's LRU is independent)     │
            │ query events (async, fire-and-forget)
            ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  QUERY EVENTS → PostgreSQL (§20) → pull API / syslog    │
   │  SIEM export. OpenTelemetry traces 🚧 · Loki/ELK operational logs 🚧│
   └─────────────────────────────────────────────────────────────────┘

   DNS delivered to clients via mantis-dhcp option 6 or manual VPN DNS push
```

### 4.1 Request path (cache miss)

See [`ARCHITECTURE.md`](../ARCHITECTURE.md#request-path-cache-miss) for the
as-built request path — it's kept there rather than duplicated here so the
two documents can't drift against each other. Target property that hasn't
changed: a cache hit is served entirely in-node, with no control-plane
dependency on the hot path.

---

## 5. Component Design

### 5.1 Filter node (data plane)

- **Stateless.** Holds only: cache + the latest signed policy bundle (in memory + local disk cache). Can be killed/replaced anytime.
- **DNS frontend.** CoreDNS or a custom Go/Rust server. CoreDNS chosen for plugin model; custom plugin chain: `tenant-resolve → policy → cache → forward`. *As built: a custom Rust server (`services/filter`), not CoreDNS — see ARCHITECTURE.md.*
- **Policy engine.** Evaluates against compiled bundle. Blocklists stored as **bloom filter + sorted hash set** for O(1) negative checks and bounded memory (millions of domains in tens of MB).
- **Resolver.** Forwards allowed misses to internal recursive resolver pool (Unbound/Knot) 🚧 over DoT, or directly to vetted upstreams.
- **Local cache.** In-process LRU with TTL honoring. No shared/cross-node cache — a shared Redis layer was evaluated and cut (§26.9); nothing observed at this deployment scale justified the added moving part.

Scaling: add nodes behind anycast/LB. No coordination needed — pure function of (query, policy bundle).

### 5.2 Control plane

- **Source of truth:** PostgreSQL (HA: Patroni/RDS Multi-AZ 🚧 — as built: single PostgreSQL instance, no HA). Stores tenants, policies, group definitions, blocklist subscriptions, allow/deny overrides.
- **Blocklist ingester:** scheduled jobs fetch external lists (StevenBlack, URLhaus, threat feeds), normalize, dedupe, diff. Produces canonical domain sets.
- **Policy compiler:** takes DB policy + ingested lists → emits a **signed, versioned policy bundle** per tenant/group (bloom filter blob + override tables + metadata). Bundles are immutable and content-addressed.
- **Distribution:** bundles published to object store (S3-compatible) 🚧, pointer/version published alongside. A distributed config store (etcd/Consul) was evaluated and cut (§26.9) — filesystem/HTTP pull (§17.2) already gives every node the current bundle on its next poll, and there's no fleet large enough for watch-based propagation to matter yet. Filter nodes pull on a fixed interval; no push-on-change.
- **Signing:** bundles signed (e.g. cosign/ed25519). Nodes verify before applying. Prevents poisoned policy.

### 5.3 Management plane

- **API:** gRPC 🚧 + REST gateway, stateless, behind LB. All writes go to PostgreSQL; triggers recompile. *As built: REST (FastAPI) only, no gRPC.*
- **UI:** SPA (React) talking to API. No PHP, no per-node state.
- **AuthN:** OIDC/SAML SSO (Okta/Entra/Keycloak) 🚧. Service-to-service mTLS 🚧.
- **AuthZ:** RBAC + tenant scoping. Roles: super-admin, tenant-admin, policy-author, read-only/auditor.
- **Audit:** every mutation appended to immutable audit log (separate store, WORM/retention 🚧).

### 5.4 Telemetry pipeline

✅ Built, and simpler than originally planned — a message bus (Kafka/NATS) and
a dedicated analytical store (ClickHouse) were both evaluated and cut
(§26.9); PostgreSQL carries the volume this product actually sees.

- Query events are **enriched at the filter node** before leaving the data plane: client IP, query type, response code, matched category, matched feed ID, and resolution latency are attached at source — not inferred later from partial data.
- Enriched events flush directly to the control plane's PostgreSQL `query_events` table (§20.2) — no intermediate bus.
- Dashboards (in-app, off the telemetry/metrics APIs): QPS, block ratio, cache hit ratio, p50/p99 latency, upstream health, per-tenant volume.
- **SIEM export layer** (§20): the same query-event stream exposed via pull API (cursor-based REST) and RFC 5424 syslog push, in JSON or CEF format, so any SIEM can consume without a custom connector.
- **Not built, and not cut** — genuinely open: **OpenTelemetry** 🚧 traces on the resolve path; **Loki/ELK** 🚧 for operational logs. Neither is blocked on anything above.

---

## 6. Data Stores

A distributed config store (etcd/Consul) and a shared cross-node cache
(Redis Cluster) were both evaluated and cut (§26.9) — neither row is listed
below because neither exists as a layer in this product, not just as an
unbuilt technology choice.

| Store | Tech | Role | HA strategy | Status |
|-------|------|------|-------------|--------|
| Source of truth | PostgreSQL | Tenants, policy, config | Patroni / Multi-AZ, sync replica | 🚧 single instance, no HA — see §26 R2, this is now a named risk, not just a someday item |
| Bundle storage | S3-compatible object store | Immutable signed bundles | Multi-AZ, versioned | 🚧 filesystem instead (§17.2) |
| Query logs | PostgreSQL | Analytics, search, retention | Single instance | ✅ built — the permanent answer, not a stepping stone to ClickHouse (§26.9) |
| Audit | Append-only (PostgreSQL) | Compliance | Single instance | 🚧 append-only by convention only, not DB-enforced — see §26.11 |
| SIEM config | PostgreSQL | Syslog sink endpoints, delivery state, cursor | Same as source of truth | ✅ built (§20) |
| Secrets | env vars / systemd `EnvironmentFile` (0600) | Keys, upstream creds | — | 🚧 no rotation, no KMS — kept as a real gap (§26.11), Vault itself not pursued at this scale |

**Key principle:** the hot DNS path depends on *none* of these synchronously. It reads only the in-memory policy bundle and local cache. Control/management stores being down degrades management, not resolution.

---

## 7. *(withdrawn)*

This section previously specified OpenVPN Access Server cluster integration
(topology, DNS hand-off, tenant identification via per-group VIP, sidecar
deployment options). Cut in the 2026-07-25 architecture review — see §26.9
for why — and removed rather than left as an unbuilt design nobody intends to
execute. mantis-dhcp option 6 and a manually configured VPN DNS push against
community OpenVPN already deliver this section's actual goal. Number kept as
a tombstone, same convention as §13.

---

## 8. Scalability & Performance

- **Stateless filter nodes** → linear horizontal scale; autoscale on QPS/CPU 🚧 (currently: manual scale-out, one node per host/CT — §17.3).
- **Bloom-filter blocklists** → millions of domains, tens of MB RAM, O(1) negative lookups, no DB on hot path.
- **Cache** — in-process LRU only. A second tier (shared Redis cluster for cross-node warm cache) was evaluated and cut (§26.9); no deployment running today has shown a cold-cache penalty large enough to justify it.
- **Recursor pool** scaled independently; only cache misses for allowed domains reach it.
- **Anycast** 🚧 spreads load to nearest node; LB health checks eject bad nodes in seconds.

Performance targets:

| Metric | Target |
|--------|--------|
| Added latency, cache hit | < 1 ms p99 |
| Added latency, policy eval | < 200 µs |
| Cache miss (allowed, DoT upstream) | < 50 ms p99 |
| Per-node throughput | ≥ 50k QPS (commodity node) |
| Policy bundle propagation | < 30 s fleet-wide |

---

## 9. Security

- **Upstream privacy:** all recursion via DoT/DoH to vetted resolvers or self-hosted recursors with QNAME minimization.
- **Internal:** mTLS between all planes 🚧 — kept as a live target (§26 R3): the whole fleet currently shares one static `MANTIS_SERVICE_TOKEN`, so this closes a real credential-compromise blast radius, not aspirational polish. Full SPIFFE/SPIRE workload-identity federation was evaluated and cut (§26.9) — per-node client certs or per-node tokens close R3 without it.
- **Bundle integrity:** signed, content-addressed bundles; nodes reject unsigned/invalid. *Built (ed25519 signing, `crypto.py`).*
- **DNS hardening:** rate limiting per source (built: login endpoint only, in-memory — `rate_limit.py`), response-rate-limiting (RRL) 🚧 to resist amplification, DNSSEC validation at recursor 🚧.
- **AuthN/Z:** SSO 🚧 (Epic Q) + RBAC + per-tenant isolation; least-privilege service accounts.
- **Secrets:** env vars / systemd `EnvironmentFile` (0600) — not plaintext-on-disk in the sense of an unprotected file, but no rotation and no KMS (§6, §26.11). Vault was evaluated and not pursued at this deployment scale.
- **Audit:** immutable, exportable for compliance (built: `audit.py`/`audit_routers.py` + UI; SOC2/ISO27001 certification scope itself 🚧).
- **Tenant isolation:** policy bundles, query logs, and UI scoped per tenant; no cross-tenant data leakage.

---

## 10. Multi-Tenancy Model

```
Organization (tenant)
 └── Policy sets (versioned)
      ├── Blocklist subscriptions (external + custom)
      ├── Allowlist / denylist overrides
      └── Groups
           ├── engineering   → policy set X
           ├── contractors   → policy set Y (stricter)
           └── guests        → policy set Z
```

- Hierarchical: org default policy, overridable per group.
- Each group maps to a subnet/source-IP identity resolved by the filter node (`router.rs`, `/routing-table`) — the mapping mechanism originally specified as an OpenVPN AS per-group VIP (§7, withdrawn); source-IP resolution is what's actually built.
- Query logs partitioned and access-controlled per tenant — enforced in application code today (`user_tenant_filter`/`check_tenant_access`, `auth.py`); §26 R4 flags this as a real risk and Postgres RLS as the fix.

---

## 11. Observability

- **Metrics:** QPS, block ratio, cache hit ratio, latency histograms — surfaced via the control plane telemetry API and the in-app Analytics dashboard, aggregated across the fleet. **Per-node** metrics (bundle version per node, per-node QPS/rcode mix, upstream errors) are 🚧 — nothing in `query_events` or the telemetry API identifies the emitting node today; that is exactly what §23 exists to fix. mantis-dhcp is the exception: it already exposes per-daemon liveness and Prometheus counters (§22.11).
- **Logs (Loki/ELK) 🚧:** operational; structured JSON.
- **Query analytics:** ✅ built on PostgreSQL — per-tenant top domains, blocked categories, client breakdown, retention by policy. This is the permanent store, not a placeholder for ClickHouse (§26.9).
- **Traces (OpenTelemetry) 🚧:** resolve path spans for latency debugging.
- **Alerting 🚧:** stale bundle, node down, upstream failure, block-ratio anomaly (possible misconfig or attack), PG health.
- **SLOs 🚧:** availability of resolution (e.g. 99.99%), p99 latency, bundle freshness.

---

## 12. Deployment & Operations

- **Packaging:** containers (OCI) — built (Docker Compose images). Filter node also ships as a native `.deb`. Control-plane/UI each independently deployable.
- **Orchestration:** ✅ built — systemd units (native install) or Docker Compose. Kubernetes was evaluated as the target orchestrator and cut (§26.9); `charts/mantis-dns` (an early, unverified Helm chart) is kept only in case a customer's platform team requires it, not as a direction being built toward.
- **IaC:** Terraform 🚧 for infra — kept as a real gap, independent of the Kubernetes decision. Helm and GitOps (Argo/Flux) are K8s-native tooling and are cut along with it. *As built: shell installers (`infra/lxc/*.sh`) + Ansible-shaped provisioning notes in §17.5, not yet an Ansible playbook.*
- **Rollout:** canary policy bundles to a subset of nodes 🚧; automatic rollback on error-rate spike 🚧. This is now **Epic Q** (§26.10, §26.11) — the highest blast-radius gap in the product, not a someday item. Blue/green for control-plane services 🚧. *As built: the update scripts (`scripts/update.sh`, `infra/lxc/install*.sh`) do backup → deploy → health-check → keep-previous-generation → manual rollback instructions on failure — no automatic traffic-based rollback.*
- **Backup/DR:** PostgreSQL PITR 🚧 (as built: `pg_dump` before upgrades), object-store versioning 🚧. Multi-AZ 🚧; documented RTO/RPO 🚧 — §26.11 flags this as untested, not just unbuilt.
- **Upgrades:** filter nodes are cattle — rolling replace 🚧 (as built: in-place restart per node, no rolling fleet orchestration). Schema migrations gated and reversible — built (Alembic, `services/control/migrations/`).

---

## 13. *(withdrawn)*

This section previously described a migration path from an existing Pi-hole
deployment. Mantis-DNS is not positioned as a Pi-hole migration target and no
import/shadow-mode/cutover tooling was ever built, so the section was removed
rather than left standing as a plan nobody intends to execute. The number is
kept as a tombstone so every `§14`–`§25` cross-reference in this document and in
the code stays valid.

---

## 14. Technology Choices (reference, not mandatory)

> **❌ 2026-07-25:** every row below marked cut is removed from the roadmap, not
> deferred — see §26.9. PostgreSQL-without-HA is the one exception: it stays
> 🚧 because it is now a named risk (§26 R2 — DHCP lease allocation has no
> fallback when Postgres is down) rather than a someday-nice-to-have, and it is
> sequenced explicitly in Epic P.

| Layer | Primary | Alternative | Status |
|-------|---------|-------------|--------|
| DNS frontend | CoreDNS (custom plugins) | Knot Resolver, custom Rust | ✅ built, but as *custom Rust* — CoreDNS was never adopted |
| Recursor | Unbound | Knot Resolver | 🚧 filter forwards to configured upstream pools directly (§21), no local recursor |
| Source DB | PostgreSQL + Patroni | CockroachDB | 🚧 PostgreSQL only, no Patroni/HA — kept as a live target, see §26 R2 |
| Query analytics | PostgreSQL | ClickHouse, Druid | ✅ built on PostgreSQL — the permanent answer, not a stepping stone (§26.9) |
| Metrics | In-app Analytics dashboard (telemetry API) | External APM (optional) | ✅ built (fleet-aggregate only). The filter node's Prometheus exporter was removed (`metrics_init.rs` deleted, was an unreferenced tombstone) and its `infra/prometheus.yml` job dropped with it. mantis-dhcp and mantis-dhcp6 do expose opt-in `/metrics` (§22.11) and are what `infra/prometheus.yml` scrapes now; restoring the filter's is §23.8. |
| Secrets | env vars / systemd `EnvironmentFile` | Vault, Cloud KMS | 🚧 no rotation, no KMS — kept as a real gap: secret rotation is part of the mTLS fix in §26 R3. Vault itself not pursued at this scale |
| Orchestration | systemd / Docker Compose | Kubernetes, Nomad | ✅ built. Kubernetes evaluated and cut (§26.9); `charts/mantis-dns` (early, unverified Helm chart) kept only in case a customer's platform team requires it |

Config store (etcd/Consul), shared cache (Redis Cluster/KeyDB), and a
message bus (Kafka/NATS) don't appear above — all three were evaluated and
cut as target layers, not just as unbuilt technology choices within a layer
that still exists. §26.9 has the reasoning.

---

## 15. Open Questions / Risks

- **DNS leak enforcement** on heterogeneous VPN clients (Windows `block-outside-dns`, macOS/Linux split-DNS behavior) — needs per-OS validation.
- **Anycast vs LB** in the specific cloud/on-prem network — depends on routing capability.
- **Bloom-filter false positives** — bounded by sizing; pair with exact-match confirmation tier for the (rare) FP on block-critical lists.
- **Per-query tenant resolution cost** — the current source-IP subnet mapping (§10, `/routing-table`) resolves tenant/group without a per-query lookup against an external system; revisit only if a deployment's subnet layout stops fitting that model.
- **Compliance scope** (data residency of query logs per tenant) — may force regional PostgreSQL instances. §26.11 covers the broader retention/erasure gap this sits inside of.

---

## 16. Phased Roadmap

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 0 | Control-plane schema, blocklist ingester, policy compiler, signed bundles | ✅ built |
| 0b | Category taxonomy + feed registry + auto-update pipeline with sanity gates (§18) | ✅ built |
| 0c | Proxmox VE appliance: CT templates + Ansible, collapsed control plane (§17) | 🚧 partial — shell installers exist (`infra/lxc/*.sh`), no Ansible/CT-template packaging yet |
| 1 | Stateless filter node (CoreDNS plugin chain), bundle pull + verify, local cache | ✅ built (custom Rust, not CoreDNS) |
| 3 | Telemetry pipeline, in-app analytics dashboards | ✅ built on PostgreSQL — the originally planned Kafka → ClickHouse pipeline was cut (§26.9), not left pending |
| 4 | Management API + UI, SSO/RBAC, audit | 🚧 API/UI/audit ✅ built; SSO not built |
| 5 | HA hardening, multi-AZ, DR drills, canary rollout, autoscaling | 🚧 not built |

*Phase 2 (OpenVPN AS integration) is withdrawn — see §7, §26.9 — and removed from this table rather than left as a numbered gap with a strikethrough; the number is simply not reused.*

Phases 6–10 were not in the original roadmap — they record work that shipped after it was written, so the table accounts for the whole product rather than stopping at phase 5:

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 6 | Enterprise UI rebuild on Mantine + TanStack Query + generated OpenAPI client (§19) | ✅ built — SSO, WCAG audit, E2E/visual tests still open (§19.1) |
| 7 | SIEM integration: enriched query events, cursor pull API, RFC 5424 syslog push, client registry (§20) | ✅ built |
| 8 | DNS upstream configuration: resolver profiles, HA pools with health monitoring and failover, split-horizon routes, DNSSEC policy (§21) | ✅ built — upstream telemetry metrics and the health dashboard still open (§21.4) |
| 9 | Native DHCP engine: DHCPv4 + DHCPv6, DB-coordinated HA, DDNS, relay, PXE, conflict detection, Prometheus metrics (§22) | ✅ built — replaced the ISC Kea integration entirely (§22.1) |
| 10 | DNS zones (§24) and block page (§25) | ✅ built |

**Phases 11–13 supersede the original "phase 11 = Epic O next" plan** — the
2026-07-25 architecture review (§26) found three foundation risks serious
enough to sequence ahead of fleet observability. Epic O still ships; it ships
third, with better justification (§26.10).

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 11 | Foundation hardening: perf bench + baseline, bloom exact-match tier, per-node credentials, bundle schema compat gate, tenant-isolation coverage + RLS (§26, Epic P) | 🚧 not started — **next** |
| 12 | Enterprise entry ticket: OIDC/SAML + SCIM, canary bundle rollout + automatic rollback, per-tenant retention/erasure/residency (§26, Epic Q) | 🚧 not started |
| 13 | Fleet observability: per-node identity, stats, and a Nodes page (§23, Epic O) — reframed as the canary-rollout control surface and §21.4's health-dashboard data source, not a page for its own sake | 🚧 not started — blocked on phases 11–12, not just unstarted (§26.10) |

---

## 17. Deployment Profile: Proxmox VE Hypervisor

This is the only deployment profile actually pursued — the cloud/Kubernetes
profile referenced below and in §4–§6, §8, §11–§12 was withdrawn in the
2026-07-25 architecture review (§26.9); this section is written as a
"collapse" of it for historical continuity, not because a cloud profile is
still on the roadmap. A **single Proxmox VE host (or small PVE cluster)**
that already runs an **OpenVPN server** (community `openvpn`, not AS — see
§7) is the real target: same containers described elsewhere in this
document, fewer of them, control plane co-resident.

### 17.1 Topology (single PVE host)

```
┌─────────────────────── Proxmox VE host ───────────────────────┐
│                                                                │
│  ┌────────────────┐   ┌────────────────┐  ┌────────────────┐  │
│  │ CT: openvpn     │   │ CT: mantis-      │  │ CT: mantis-     │  │
│  │ (server)        │   │ filter          │  │ control        │  │
│  │ pushes DNS =    │──▶│ CoreDNS chain   │◀─│ Postgres-lite  │  │
│  │ filter CT IP    │   │ + policy engine │  │ compiler +     │  │
│  │                 │   │ + local cache   │  │ ingester + UI  │  │
│  └────────────────┘   │ + recursor(fwd) │  │ + category     │  │
│                       └───────┬─────────┘  │ feeds          │  │
│                               │            └────────────────┘  │
│   vmbr0 / internal bridge ────┘  signed bundle via shared vol  │
└────────────────────────────────────────────────────────────────┘
```

- Run components as **LXC containers** (lightweight, recommended) or VMs. Minimum: 2 CTs — `mantis-filter` + `mantis-control` — plus the existing `openvpn` CT/host.
- OpenVPN pushes `dhcp-option DNS <mantis-filter IP>` on the tunnel bridge. Add `block-outside-dns` (Windows) and route DNS through the tunnel to stop leaks.
- No anycast, no external LB needed on a single host. The filter CT IP is the resolver.

### 17.2 Collapsed control plane

- Postgres runs as a small instance in the `mantis-control` CT. PostgreSQL 17 is the only supported database; it provides the ARRAY type, JSONB audit columns, and the pg_isready healthcheck used by all deployment configurations.
- Bundle distribution degenerates to a **shared volume / bind-mount** (or local HTTP) between control and filter CTs. The signed-bundle + version-pointer mechanism is unchanged; the "bus" is just the filesystem. Filter still verifies signature before applying.
- Object store remains a genuinely optional add-on at this scale — bundle distribution already works over a bind-mount. Kafka and ClickHouse are not optional-and-available, they're cut (§26.9); query logs land in Postgres, full stop.

### 17.3 HA on a PVE cluster (optional)

- For a **multi-node PVE cluster**, run `mantis-filter` as a CT on each node and use **PVE HA + a shared VIP** (keepalived/VRRP CT, or pfSense/CARP if present) so VPN clients hit a floating DNS IP.
- `mantis-control` runs as a single HA-managed CT (PVE HA restarts it on another node on failure); it is **not** on the DNS hot path, so brief downtime only delays policy updates.
- Postgres replication optional; for most PVE sites, PVE HA failover of one control CT + ZFS replication of its disk is sufficient.

### 17.4 Resourcing (rule of thumb, single host)

| CT | vCPU | RAM | Disk | Notes |
|----|------|-----|------|-------|
| mantis-filter | 2 | 1–2 GB | 4 GB | bloom filters + cache in RAM |
| mantis-control | 2 | 2–4 GB | 20 GB+ | Postgres (incl. query logs/analytics) + feeds + UI |

### 17.5 Provisioning

- Ship as a **Proxmox CT template / appliance** (or `pveam`-style image) plus an Ansible playbook that: creates the CTs, wires the bridge, configures OpenVPN's `dhcp-option DNS`, seeds the control DB, enables category feeds.
- Updates: `git`/registry-pulled container images; control CT self-updates feeds (§18). One-command upgrade script.

### 17.6 What this profile collapsed from

The withdrawn cloud profile (§26.9), for historical reference only — nothing
in the right column below is a live target:

| Concern | Withdrawn cloud profile | This profile (Proxmox, as built) |
|---------|--------------------------|-----------------------------------|
| Filter nodes | Autoscaled fleet, anycast | 1 CT/host, optional VIP |
| Control plane | k8s services, etcd, S3 | 1 CT, shared volume |
| Bundle distribution | object store + etcd watch | bind-mount + version file |
| Telemetry | Kafka → ClickHouse | Postgres |
| VPN | OpenVPN AS cluster | community OpenVPN on host |
| HA | Multi-AZ | PVE HA + VRRP VIP |

Same policy/category/bundle logic, signed bundles, RBAC, and UI regardless — only the scale-out plumbing was ever meant to differ, and the left column is not being built.

---

## 18. Category-Based Content Filtering (Auto-Updating)

A first-class requirement: block by **content category** (porn, gambling, firearms/weapons, malware, phishing, ads/trackers, social media, streaming, drugs, hate/violence, proxies/anonymizers, etc.) with feeds that **auto-update** on a schedule, with no manual blocklist curation.

### 18.1 Category model

```
Category (system-defined)
 ├── id: "adult", "gambling", "weapons", "malware", ...
 ├── severity / default action
 ├── one or more Feed subscriptions  (sources that populate it)
 └── per-tenant/group toggle: block | allow | log-only
```

- Categories are **system-defined taxonomy**; tenants/groups toggle them on/off (maps to the multi-tenancy model in §10).
- A policy = a set of enabled categories + custom allow/deny overrides. Compiles to the same signed bundle the filter node already consumes (§5.2).

### 18.2 Feed sources

| Category | Example feed types |
|----------|--------------------|
| Adult / porn | Shalla, UT1 (université Toulouse) "adult", StevenBlack porn variant, Hagezi |
| Gambling | UT1 "gambling", Hagezi gambling, OISD |
| Firearms / weapons | UT1 "weapons", curated category lists |
| Malware / phishing | URLhaus, OpenPhish, Spamhaus, Hagezi TIF, abuse.ch |
| Ads / trackers | StevenBlack, OISD, Hagezi, EasyList-derived |
| Social / streaming | Category lists (often "log-only" by default) |
| Proxies / anonymizers | UT1 "proxy", VPN/Tor exit lists |

> Several category corpora (e.g. UT1, Shalla) carry licensing terms — track license per feed in the feed registry and surface it in the UI. Ship only feeds whose license permits redistribution; otherwise fetch at the customer site.

### 18.3 Ingestion & auto-update pipeline

```
Scheduler (cron in control plane)
   │  per feed: interval (e.g. daily / 6h), source URL, format, category map
   ▼
Fetcher ──▶ Validator ──▶ Normalizer ──▶ Dedupe/Diff ──▶ Category sets
   │           │             │              │                 │
 ETag/        size &       domain         vs previous     per-category
 If-Modified  sanity       canonical      version         canonical
 -Since       checks       (lowercase,    (added/removed)  domain set
              (no empty/   strip www,                          │
              poisoned)    IDN→punycode)                       ▼
                                                    Policy compiler
                                                  (only recompiles
                                                   affected bundles)
                                                          │
                                                  Signed bundle vN+1
                                                          │
                                                  Distribution (§5.2 / §17.2)
```

Key safeguards:
- **Conditional fetch** (ETag / If-Modified-Since) — skip unchanged feeds, save bandwidth.
- **Sanity gates** — reject a feed update if it shrinks/grows beyond a threshold (e.g. ±40%) or contains high-value domains (allowlist of "must-never-block" like `microsoft.com`, `google.com`, banking, OS-update hosts). Prevents a poisoned/broken feed from nuking resolution.
- **Diffing** — store only deltas; recompile only the category sets and tenant bundles actually affected. Most daily updates touch a few thousand domains.
- **Staged rollout** — new category data canaries to a subset of filter nodes (cloud) or applies after sanity-gate pass (Proxmox), with automatic rollback on block-ratio anomaly (§11 alerting).
- **Provenance** — each category set records source feed, fetch time, version, license. Auditable in UI.

### 18.4 Runtime representation

- Per category → bloom filter + sorted hash set (same structure as §5.1). A bundle includes only the categories the tenant/group enabled.
- Lookup order on the hot path: tenant allow-override → tenant deny-override → enabled-category bloom filters → cache/forward. First match wins; allow-override always beats category block.
- Memory bounded: even ~10 categories × millions of domains = low hundreds of MB; fits the 1–2 GB filter CT in the Proxmox profile.

### 18.5 Admin UX

- UI shows category toggles per group with live counts ("Adult: 1.2M domains, source: UT1, updated 4h ago").
- Per-category action: **block / log-only / allow**. Log-only lets an org observe before enforcing.
- Custom categories: tenant can define its own category from an uploaded/URL list.
- Test box: enter a domain → see which category/feed would match and the resulting action (block-decision explainability).
- Scheduled-update status panel: last run, next run, feeds healthy/stale/failed, sanity-gate rejections.

### 18.6 Feed registry (config)

Feeds are declarative config in the control DB, e.g.:

```yaml
feeds:
  - id: ut1-adult
    category: adult
    url: https://dsi.ut-capitole.fr/blacklists/download/adult.tar.gz
    format: domains-tar
    interval: 24h
    license: "UT1 — research/educational; verify redistribution"
    sanity:
      min_domains: 100000
      max_delta_pct: 40
  - id: urlhaus
    category: malware
    url: https://urlhaus.abuse.ch/downloads/hostfile/
    format: hostfile
    interval: 1h
    sanity:
      max_delta_pct: 60
```

Adding a category = adding feed rows; no code change. The ingester, compiler, and bundle format are category-agnostic.

---

## 19. Management UI — Enterprise-Grade Plan

### 19.1 Current state

> **Historical note.** The paragraphs below originally described the Sprint 6
> prototype (browser-native `prompt`/`alert`/`confirm`, hand-rolled `fetch` +
> `useState`, raw HTML tables, no auth/routing/design-system/tests). That
> baseline no longer exists — Epic J (Sprints 11–13) replaced it. What follows
> is the state as verified against `apps/ui` on 2026-07-25.

The console is built on the foundation this section called for:

- **Design system:** Mantine 9 (`@mantine/core`, `form`, `modals`, `notifications`, `charts`), light/dark theme tokens in `theme.ts`. No native `prompt`/`alert`/`confirm` remain.
- **Server state:** TanStack Query throughout (`src/api/hooks.ts`); no hand-rolled `fetch`+`useState` views left.
- **Typed client:** `openapi-typescript` codegen from FastAPI's `/openapi.json` into `src/api/schema.ts`, with `npm run gen:api:check` gating CI on drift — the hand-written `api.ts` is gone.
- **Shell + routing:** React Router with an app shell (`src/app/Shell.tsx`), role-gated nav (`minRole` per entry), error boundary, tenant context.
- **Auth:** session-based login with server-side roles (`src/auth/`, `auth_routers.py`), RBAC-gated nav and actions, self-service password change, user management page.
- **Pages:** Dashboard, Tenants, Groups, Policy, Feeds, DNS Zones (+ detail), Analytics, Query Log, Audit, Users, Upstream, DHCP, Settings, Clients, Block Page.
- **Quality gates in CI:** `tsc -b`, `oxlint`, Vitest, and a `size-limit` bundle budget (400 kB JS / 40 kB CSS gzip).

**Still open against §19.2** (tracked in the sprint plan, not silently closed):

| Req | Gap |
|---|---|
| U1 | 🚧 **OIDC/SAML SSO** — as built is local username/password with server-side sessions. The RBAC model underneath (U2) is complete; only the federated-identity front end is missing. |
| U4 | 🚧 **Row virtualization** — feeds and query log use server-side pagination/filtering, which covers the stated failure mode, but no view virtualizes a large rendered result set. |
| U10 | 🚧 **WCAG 2.1 AA audit** — Mantine supplies most of the primitives; the audit itself has not been run and no a11y assertion exists in CI. |
| U12 | 🟡 **i18n** — `react-i18next` is wired and all user-facing strings are keyed, but `en` is the only locale shipped. Scaffolding done, localization not. |
| U14 | 🚧 **E2E + visual regression** — Vitest + Testing Library component tests exist; no Playwright, no Storybook/Chromatic. |

### 19.2 Enterprise requirements (what "enterprise-grade" actually means here)

| # | Requirement | Why it's non-negotiable |
|---|-------------|-------------------------|
| U1 | Authentication + session management (OIDC/SAML SSO) | No enterprise runs an unauthenticated admin console; ties to §9 RBAC. *As built: local accounts + server-side sessions; SSO 🚧.* |
| U2 | Role-aware UI (super-admin, tenant-admin, policy-author, auditor) | UI must hide/disable what the role can't do, not just rely on API 403s. |
| U3 | Multi-tenant navigation + tenant/org context switcher | MSPs manage dozens of tenants; the 3-column prototype doesn't scale past ~5. |
| U4 | Data-grid views: server-side pagination, sorting, filtering, virtualization | Feeds (100k–1M domains) and query logs (millions of rows) cannot be client-loaded. |
| U5 | Real forms with validation (no prompt/alert) | CIDR, domain, URL, interval inputs need inline validation + good error UX. |
| U6 | Async server-state layer (cache, refetch, optimistic, error/loading states) | Every view currently reimplements fetch+loading+error by hand. |
| U7 | Toast notifications + confirmation dialogs for destructive actions | Deleting a feed or tenant via `confirm()` is not acceptable. |
| U8 | In-app observability: dashboards, query-log explorer, propagation status | All observability surfaced natively in the console (§11). |
| U9 | Audit log viewer (who changed which policy when) | Compliance (SOC2/ISO27001) requires it; ties to §5.3 audit log. |
| U10 | Accessibility (WCAG 2.1 AA, keyboard nav, screen-reader) | Public-sector / large-enterprise procurement mandates it (Section 508, VPAT). |
| U11 | Theming (light/dark) + optional per-tenant white-label | MSP resale scenarios brand the console per customer. |
| U12 | i18n scaffolding | Multi-region enterprises require localization readiness. |
| U13 | Performance budget (code-split routes, bundle-size ceiling) | Admin consoles bloat fast; enforce a budget in CI. |
| U14 | Test coverage: component, E2E, visual regression | A console driving security policy needs regression protection. |

### 19.3 Target front-end architecture

```
apps/ui/
 ├── api/                 generated OpenAPI client (typed, from FastAPI /openapi.json)
 ├── auth/                session context, role guards (OIDC PKCE flow 🚧 — as built:
 │                        local login against auth_routers.py)
 ├── routes/             file/route-based code splitting (lazy)
 │    ├── tenants/        list, detail, create
 │    ├── groups/         per-tenant, subnet wiring, policy editor
 │    ├── feeds/          catalog browser + custom feeds + ingest status
 │    ├── analytics/      query-log explorer, top domains, block ratio
 │    ├── audit/          audit log viewer
 │    └── settings/       SSO, RBAC, API keys, white-label
 ├── components/         design-system wrappers (Button, DataGrid, Form, Modal, Toast)
 └── lib/                query client, validation schemas (Zod), formatters
```

**Stack decisions (recommended, not mandatory):**

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Component library | **Mantine** (or Ant Design) | Batteries-included enterprise admin kit: data grids, forms, modals, notifications, dark mode, a11y out of the box. Ant Design is the other strong fit (literally built for admin consoles); Mantine is lighter and more themeable. |
| Server state | **TanStack Query** | Caching, background refetch, optimistic updates, request dedup — deletes most of the hand-rolled fetch/useState code. |
| Data grids | **TanStack Table** + virtualization | Headless, handles server-side pagination/sort/filter and 100k-row virtualization. |
| Forms + validation | **React Hook Form + Zod** | Typed schemas shared with the API client; inline validation; no `prompt()`. |
| Routing | **TanStack Router** or React Router | Type-safe params, lazy route code-splitting. |
| API client | **openapi-typescript** codegen | FastAPI already emits `/openapi.json`; generate the typed client instead of hand-writing `api.ts` (eliminates a whole class of drift, same philosophy as the proto contract on the backend). |
| Auth | **oidc-client-ts** 🚧 | Standard OIDC PKCE against Keycloak/Okta/Entra (§9). *Not adopted — the console authenticates against the control plane's own user table.* |
| Toasts/modals | Mantine notifications + modals | Replaces every `alert()`/`confirm()`. |
| Testing | **Vitest + Testing Library** ✅, **Playwright** (E2E) 🚧, **Storybook** + Chromatic (visual regression) 🚧 | Component, end-to-end, and visual coverage. |
| Quality gates | ESLint, Prettier, `tsc --noEmit`, bundle-size check | Enforced in CI (§ Cross-cutting). |

### 19.4 Information architecture

- **App shell**: persistent left nav (Tenants, Feeds, Analytics, Audit, Settings), top bar with tenant/org switcher, global search, user menu, theme toggle.
- **Breadcrumbs** for deep navigation (Tenant → Group → Policy).
- **Tenant context** is global state: selecting a tenant scopes every subsequent view; super-admins get an "all tenants" overview.
- **Empty / loading / error states** are first-class for every data view (skeleton loaders, actionable empty states, error boundaries — not blank screens).

### 19.5 Key views to (re)build

1. **Policy editor** ✅ — category toggles with live domain counts and per-category action (block / log-only / allow), override management with validated domain input, a **domain test box** (the §18.5 explainability feature — built: `POST /api/v1/groups/{group_id}/policy/test` → `PolicyTestResult`, surfaced in `PolicyPage.tsx`), bundle compile + propagation status indicator. Policy can also be duplicated from another group (`DuplicatePolicyModal.tsx`).
2. **Feed manager** — catalog browser with search/filter, per-feed ingest status + last-run/next-run, sanity-gate rejection surfacing, license display, add/edit/delete with real forms.
3. **Query-log explorer** — server-side paginated, filterable by tenant/group/decision/time-range, backed by PostgreSQL — the permanent store, not a placeholder (§6, §26.9).
4. **Analytics dashboard** — block ratio, QPS, cache-hit ratio, top blocked domains, per-category volume; native charts backed by the telemetry/metrics APIs (already implemented).
5. **Audit log viewer** — immutable, filterable, exportable.
6. **Settings** — SSO config, RBAC role assignment, API keys, white-label branding.

### 19.6 Accessibility & i18n

- Target **WCAG 2.1 AA**: keyboard-operable everything, visible focus, ARIA on custom widgets, contrast-checked theme tokens. Mantine/AntD give most of this; the audit is on us.
- Wrap user-facing strings in an i18n layer (e.g. `react-i18next`) from the start — retrofitting localization is far more expensive than scaffolding it early, even if only `en` ships initially.

### 19.7 Phased delivery (folds into the sprint plan)

| Phase | Deliverable | Status |
|-------|-------------|--------|
| UI-0 | Foundation: component library, TanStack Query, OpenAPI-generated client, app shell + routing, theme. Port existing prototype views onto it (no new features, just the platform). | ✅ built |
| UI-1 | Auth + RBAC: OIDC login, session, role-gated nav/actions (depends on backend §9 / Sprint 8). | 🟡 session + RBAC ✅; OIDC 🚧 |
| UI-2 | Data grids: feed manager + query-log explorer with server-side pagination/sort/filter/virtualization. | 🟡 server-side pagination/filter ✅; virtualization 🚧 |
| UI-3 | Forms + UX: replace all prompt/alert/confirm with validated forms, modals, toasts, confirmation dialogs. | ✅ built (Mantine form/modals/notifications; no native dialogs remain) |
| UI-4 | Analytics + audit: dashboards, domain-test explainability box, audit log viewer. | ✅ built |
| UI-5 | Hardening: a11y audit (WCAG AA), i18n scaffolding, E2E + visual-regression tests, performance budget in CI. | 🟡 i18n scaffolding ✅ (`en` only), size budget ✅ (`size-limit`), component tests ✅; WCAG audit 🚧, Playwright/visual regression 🚧 |

UI-0 was the unlock and landed first, as intended — no enterprise feature was built on the prototype foundation.

---

## 20. SIEM Integration

Enterprise DNS filtering produces the highest-fidelity network telemetry available: every DNS query from every device, timestamped to the microsecond, with a policy decision attached. That data belongs in the SIEM, not siloed in Mantis. This section defines the integration architecture.

---

### 20.1 Design principles

1. **Enrich at source, not at the SIEM.** The filter node has full context (client IP, matched category, matched feed, latency) that the SIEM cannot reconstruct from raw DNS traffic. Enrichment at the SIEM requires custom parsers and is fragile; enrichment at the filter node is authoritative.
2. **Both pull and push.** Pull (REST cursor API) works with any SIEM that has an HTTP poller — zero additional infrastructure. Push (RFC 5424 syslog) covers real-time requirements and SIEMs that only receive via a syslog listener. The same enriched event model feeds both.
3. **Standard formats.** JSON for API-native SIEMs (Elastic, Splunk HEC, Panther, Chronicle). CEF (Common Event Format) for legacy SIEMs (ArcSight, QRadar, many MSSPs). Format is a serialization choice, not a separate pipeline.
4. **Delivery guarantees.** At-least-once delivery with idempotency keys. Cursor-based pull is inherently resumable. Syslog push includes retry with exponential backoff and a dead-letter log visible in the UI.
5. **No performance impact on DNS path.** SIEM export is fully async and decoupled from query resolution. A SIEM outage or slow consumer cannot increase DNS latency.

---

### 20.2 Enriched query event schema

The filter node emits this event for every resolved query. All fields populated at the Rust layer before the event enters the async telemetry channel.

```
QueryEvent {
    // identity
    id              UUID            // globally unique, used as idempotency key
    occurred_at     timestamp(µs)   // UTC, microsecond precision
    tenant_id       UUID            // denormalized — no join needed at SIEM
    tenant_name     string
    group_id        UUID
    group_name      string

    // client
    client_ip       string          // actual VPN client IP (e.g. 10.8.1.47)
    client_name     string | null   // resolved from client registry if registered

    // query
    qname           string          // queried domain, lowercased, trailing dot stripped
    qtype           string          // "A" | "AAAA" | "MX" | "TXT" | "CNAME" | …
    query_id        uint16          // DNS wire protocol ID (for correlation with pcap)

    // decision
    decision        "allow" | "block"
    matched_rule    "category" | "override_allow" | "override_deny" | "default"
    matched_category string | null  // e.g. "malware", "adult", "gambling"
    matched_feed_id  string | null  // e.g. "urlhaus-malware"

    // response
    response_code   "NOERROR" | "NXDOMAIN" | "REFUSED" | "SERVFAIL"
    upstream_used   string | null   // DoT resolver hostname (if forwarded)
    cache_hit       bool
    latency_us      uint32          // total resolution latency in microseconds
}
```

**Current implementation state:** ✅ built. The Sprint 14 enrichment shipped — `QueryEvent` stores `tenant_id`, `client_ip`, `qtype`, `matched_rule`, `matched_category`, `matched_feed_id` (comma-joined feed ids, widened to `String(512)` by migration `a1b2c3d4e5f6`), `response_code`, `cache_hit` and `latency_us` alongside the original `group_id`/`qname`/`decision`/`occurred_at`, plus a monotonic `seq` identity column used solely as the pull API's pagination cursor. The one field §23 adds later is `node_id` (🚧 — see §23.5).

---

### 20.3 Pull API (cursor-based REST)

```
GET /api/v1/siem/events
    ?after_id=<uuid>          cursor (exclusive); omit for first page
    &limit=<int>              default 500, max 10 000
    &tenant_id=<uuid>         filter (admin sees all tenants; operator sees own)
    &group_id=<uuid>          filter
    &decision=block|allow     filter
    &since=<ISO8601>          lower-bound timestamp (alternative to cursor for initial backfill)
    &until=<ISO8601>          upper-bound timestamp
    &format=json|cef          default json
```

Response (JSON):
```json
{
  "events": [ ...QueryEvent... ],
  "next_cursor": "018f4a...",      // null if no more events
  "total_in_window": 3847          // informational, not guaranteed exact
}
```

Response (CEF, `format=cef`):
```
CEF:0|MantisDNS|mantis-filter|1.0|DNS_QUERY|DNS query event|3|
  start=1719830400000000 
  src=10.8.1.47 shost=fabio-laptop 
  dhost=casino.com
  cs1=gambling cs1Label=matchedCategory
  cs2=urlhaus-malware cs2Label=matchedFeed
  act=block
  cn1=1240 cn1Label=latencyMicros
  tenantId=9319a77d tenant=acme-corp
  groupId=3cdf4d87 grp=employees
  rt=1719830400000
```

**Pagination contract:**
- `after_id` is the `id` of the last event the caller processed. Exclusive — the next page starts *after* that event.
- Pages are ordered by `(occurred_at ASC, id ASC)` — stable across retries.
- The cursor survives server restarts; it is just a UUID, not a session token.
- SIEM pollers should store `next_cursor` durably between poll cycles to avoid re-processing on restart.

**Auth:** standard Bearer JWT (§9 / Sprint 8). Operators see only their own tenants. Admins see all.

---

### 20.4 *(withdrawn)*

This section previously specified `SiemWebhook`: an HMAC-signed HTTP push
sink (config model, per-event POST contract, receiver-side verification
snippet). Removed 2026-07-26 — the syslog sink (§20.8) and the pull API
(§20.3) cover SIEM export; number kept as a tombstone, same convention as §7.

---

### 20.5 Format details — CEF mapping

| CEF field | Mantis field | Notes |
|---|---|---|
| `start` | `occurred_at` | epoch milliseconds |
| `src` | `client_ip` | |
| `shost` | `client_name` | omitted if null |
| `dhost` | `qname` | |
| `act` | `decision` | "block" / "allow" |
| `cs1` / `cs1Label` | `matched_category` / "matchedCategory" | |
| `cs2` / `cs2Label` | `matched_feed_id` / "matchedFeed" | |
| `cs3` / `cs3Label` | `qtype` / "queryType" | |
| `cn1` / `cn1Label` | `latency_us` / "latencyMicros" | |
| `cn2` / `cn2Label` | `cache_hit` (0/1) / "cacheHit" | |
| `outcome` | `response_code` | |
| `deviceExternalId` | `id` | UUID, idempotency key |

CEF severity mapping: `block` → `7` (High), `allow` → `3` (Low).

---

### 20.6 Client registry

Client identity is the missing link between a raw IP in a query event and a meaningful SIEM alert. The client registry bridges them.

```
ClientEntry {
    id          UUID
    tenant_id   UUID
    group_id    UUID
    ip          string          // VPN-assigned IP (e.g. 10.8.1.47); unique within tenant
    hostname    string | null   // FQDN if known (e.g. fabio-laptop.corp.local)
    owner       string | null   // email or username
    device_type string | null   // "laptop" | "server" | "mobile" | "iot"
    tags        string[]        // freeform (e.g. ["contractor", "unmanaged"])
    last_seen   timestamp       // updated each time a query event is processed
    registered_at timestamp
    registered_by string        // actor (from audit)
}
```

**Auto-discovery:** filter nodes emit `client_ip` on every query. The control plane surfaces any IP not in the registry as an "unregistered client" in the UI and in query events (`client_name = null`). Operators register them on-demand or via bulk import.

**SIEM value:** `client_name`, `owner`, `device_type`, and `tags` are embedded in every exported query event once registered, enabling SIEM rules like:
- *"Block event from device tagged `unmanaged` targeting category `malware`"* → P1 alert.
- *"Any contractor device querying internal hostnames"* → anomaly flag.

---

### 20.7 SIEM connector compatibility

| SIEM | Integration method | Format | Notes |
|---|---|---|---|
| Splunk | Pull API → Splunk REST input | JSON | Splunk's scripted/REST modular input polls `/api/v1/siem/events` on a schedule |
| Elastic (SIEM/Security) | Pull API → Filebeat HTTP poller | JSON | Filebeat's `httpjson` input polls the cursor endpoint directly |
| Microsoft Sentinel | Syslog sink (§20.8) → Azure Monitor Agent, or Pull API via a polling connector/Logic App | CEF via syslog, or JSON | No native inbound webhook receiver; AMA's syslog collection is the lower-effort path |
| IBM QRadar | Pull API → Universal DSM, or syslog | CEF (`format=cef`) | Syslog sink (§20.8) feeds QRadar's native syslog listener directly |
| Palo Alto Cortex XSIAM | Pull API via a polling connector | JSON | No native inbound webhook receiver for arbitrary payloads without a custom collector |
| Chronicle (Google SecOps) | Pull API via a polling feed/connector | JSON (UDM mapping at ingestion) | |
| Panther | Pull API | JSON | Native REST poller |
| Wazuh | Syslog sink (§20.8), or Pull API → `<localfile>` JSON log tailing | CEF via syslog, or JSON | Wazuh has no inbound HTTP event receiver at all — its built-in `<remote>` syslog listener consumes the syslog sink directly, no polling script needed. The pull-script bridge (`integrations/wazuh/README.md`) predates syslog support and remains for stock configs that don't want an inbound listener open. |
| Any MSSP | Pull API | CEF | MSSP controls polling cadence |

---

### 20.8 Syslog export

**Built (Sprint 22).** RFC 5424 syslog is a thin adapter on top of the same enriched event model — iterate the event stream, serialize as CEF or JSON into the MSG field, and write to a TCP/TLS/UDP socket. The control-plane config is a `SiemSyslog` table with a cursor/backoff/auto-disable delivery shape; no signing secret, since syslog has no HMAC concept.

```
SiemSyslog {
    id                  UUID
    tenant_id           UUID | null     // null = org-wide (admin only)
    name                string
    host                string          // collector address (hostname or IP literal)
    port                int             // default 514
    transport           "tcp" | "tls" | "udp"   // default "tls"
    format              "cef" | "json"  // default "cef"
    facility            int             // RFC 5424 facility, default 16 (local0)
    app_name            string          // RFC 5424 APP-NAME header field, default "mantis-dns"
    batch_size          int             // events per delivery cycle, default 200, max 2000
    flush_interval_s    int             // max seconds between deliveries, default 30
    filter_decision     "all" | "block" | "allow"
    enabled             bool
    last_delivered_seq  int64           // this sink's own cursor into QueryEvent.seq
    last_delivered_at   timestamp | null
    last_error          string | null
    consecutive_failures int            // reset to 0 on success; auto-disables at 6
    next_retry_at       timestamp | null
    created_at          timestamp
}
```

**Message format.** One RFC 5424 line per event:

```
<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
```

`PRI = facility × 8 + severity`, where severity is `4` (Warning) for `decision=block` and `6` (Informational) for `decision=allow` — a block is a security-relevant decision worth flagging, not a system failure. `TIMESTAMP` is `occurred_at` in UTC with microsecond precision (`2026-07-23T14:32:01.123456Z`). `HOSTNAME`, `PROCID`, `MSGID`, and `STRUCTURED-DATA` are all NILVALUE (`-`) — the enriched event in `MSG` already carries tenant/group/client identity, which those fields would otherwise duplicate. `MSG` is the same CEF line (§20.5) or a single JSON object, per the sink's `format`.

**Framing.** TCP and TLS use RFC 6587 octet-counting (`"<byte-length> <message>"` per event) so a stream receiver can split messages without a trailer scan. UDP sends one message per datagram, no framing prefix.

**Transport.** TLS is the recommended default; verification uses the system CA trust store, with SNI/certificate checks against the configured hostname even though the connection itself dials a pre-resolved IP literal (closes the DNS-rebinding TOCTOU gap between validation and connect — see `resolve_pinned_syslog_host` in `ssrf_guard.py`). UDP is supported for collectors that only speak classic syslog, but is explicitly best-effort: no application-layer acknowledgment exists for any transport here (a TCP/TLS write success only means the collector's kernel accepted the bytes), and UDP is additionally lossy at the network layer with no delivery signal at all. The delivery cursor only advances on a successful send, so a refused/closed connection is retried like any other failure — a receiver that silently drops accepted bytes is outside what any of these transports can detect.

**Host validation.** `check_probe_target_safe` gates sink hosts: only loopback and link-local/cloud-metadata addresses are blocked, since self-hosted collectors are routinely on RFC-1918 addresses.

**Retention interaction.** `prune_query_events` (§6) takes the minimum `last_delivered_seq` across every *enabled* `SiemSyslog` sink as a safety bound — a row isn't pruned until every enabled sink has delivered it.

---

### 20.9 Sprint plan update (superseded — see sprint-plan.md Sprints 14–16)

| Sprint | Scope |
|---|---|
| **Sprint 14** | QueryEvent enrichment (client_ip, qtype, rcode, matched_category, matched_feed_id, latency_us) in Rust filter node + Postgres schema. Pull API `/api/v1/siem/events` with cursor pagination, tenant/decision filters, JSON + CEF format. Auth gated (operator+). |
| **Sprint 15** | `SiemWebhook` model + delivery engine (async, retry/backoff, HMAC signing). Webhook management UI in Settings. Delivery status + last-error surface. |
| **Sprint 16** | Client registry (CRUD API + UI, auto-discovery from query events, `client_name` embedded in events). |
| **Sprint 22** | `SiemSyslog` model + delivery engine (RFC 5424, TCP/TLS/UDP, retry/backoff, auto-disable). Syslog sink management UI in Settings, alongside webhook config. Retention safety bound extended to cover syslog cursors. See sprint-plan.md Epic N. |

---

## 21. DNS Upstream Configuration

Today the filter node forwards allowed queries to a single, statically configured resolver. That is adequate for a prototype but brittle in production: a single upstream is a single point of failure, offers no per-tenant privacy controls, cannot route internal domains to internal resolvers, and exposes no operational visibility into upstream health. This section defines the enterprise upstream model.

---

### 21.1 Design goals

| # | Goal |
|---|------|
| US1 | Zero-downtime upstream failover — a dead resolver must be ejected automatically and re-admitted after recovery. |
| US2 | Per-tenant resolver policy — tenant A uses its own corporate recursors; tenant B uses privacy-preserving public DoT. |
| US3 | Split-horizon routing — internal domain suffixes (e.g. `corp.local`) route to internal recursors; everything else routes to the external pool. |
| US4 | Protocol diversity — DoT (853), DoH (443), plain DNS (53 fallback) per resolver, not global. |
| US5 | Certificate pinning — DoT/DoH resolvers may have their public key pinned so a compromised CA cannot MitM upstream traffic. |
| US6 | QNAME minimization and no ECS by default — privacy-preserving default; opt-in per resolver for ECS. |
| US7 | DNSSEC validation — enforced per upstream / per tenant; `AD` bit propagated to clients. |
| US8 | Observability — per-resolver: latency histogram, error rate, health state, last-failure reason — surfaced in the Analytics UI. |
| US9 | No DNS hot-path dependency on the control plane — upstream routing config is delivered inside the signed policy bundle; the filter node resolves without ever calling home during query processing. |

---

### 21.2 Data model

#### UpstreamResolver

A single named upstream DNS server. Multiple resolvers are grouped into pools for load-balancing and failover.

```
UpstreamResolver {
    id                  UUID
    name                string          // human label, e.g. "Cloudflare DoT #1"
    protocol            "dot" | "doh" | "do53"
    address             string          // IPv4, IPv6, or hostname
    port                int             // 853 (DoT default), 443 (DoH), 53 (Do53)
    tls_hostname        string | null   // SNI for DoT/DoH; null → use address
    tls_pin_sha256      string[] | null // hex SHA-256 of SubjectPublicKeyInfo;
                                        // null = trust system CA bundle
    doh_path            string          // URL path for DoH; default "/dns-query"
    doh_method          "get" | "post"  // RFC 8484; default "post"
    dnssec_validation   "strict"        // reject unsigned / bad chains
                      | "opportunistic" // validate if AD bit set; pass through otherwise
                      | "disabled"      // pass through, do not validate
    qname_minimization  bool            // RFC 7816; default true
    edns_client_subnet  bool            // RFC 7871; default false (privacy)
    timeout_ms          int             // per-query timeout; default 5000
    max_retries         int             // attempts before marking failed; default 2
    connect_timeout_ms  int             // TCP/TLS handshake timeout; default 3000
    tags                string[]        // "public", "internal", "threat-intel", "doh"
    enabled             bool
    created_at          timestamp
    updated_at          timestamp
}
```

Key invariants:
- `do53` resolvers must not be used as the sole resolver for a tenant marked `require_encrypted_upstream = true`.
- `tls_pin_sha256` pins are evaluated against the **leaf certificate** SPKI, not the CA. Pinning against the CA is also supported if a single CA value is provided.
- `doh_path` supports query templates: `{?dns}` will be replaced with the base64url-encoded query for GET requests (RFC 8484 §4.1).

#### UpstreamPool

A pool groups one or more resolvers under a named load-balancing / failover policy.

```
UpstreamPool {
    id                          UUID
    name                        string   // e.g. "public-dot-ha", "corp-internal"
    strategy                    "round_robin"
                              | "weighted_round_robin"
                              | "failover"    // priority order; lowest priority first
                              | "latency"     // always route to lowest-latency healthy member
    health_check_interval_s     int      // probe each member this often; default 30
    health_check_timeout_ms     int      // probe timeout; default 2000
    health_check_query          string   // domain to probe; default "." (SOA query)
    health_check_type           "soa" | "a" | "txt"  // record type for probe
    unhealthy_threshold         int      // consecutive failures before ejecting; default 3
    healthy_threshold           int      // consecutive successes before re-admitting; default 2
    min_healthy_members         int      // alert + fallback pool if pool drops below; default 1
    fallback_pool_id            UUID | null  // pool to use if this one collapses entirely
    members                     [UpstreamPoolMember]
}

UpstreamPoolMember {
    pool_id         UUID
    resolver_id     UUID
    weight          int   // for weighted_round_robin; default 1
    priority        int   // for failover: lower value = preferred; default 0
}
```

The `latency` strategy maintains a running P50 latency estimate per member (exponentially weighted moving average over the last 100 probes) and routes each query to the member with the lowest estimated latency, unless it is unhealthy.

#### UpstreamRoute

Routes map a (tenant, domain pattern) tuple to a pool. Routes are evaluated per-query, in priority order, by the filter node.

```
UpstreamRoute {
    id              UUID
    name            string          // human label, e.g. "corp-internal-domains"
    tenant_id       UUID | null     // null = applies to all tenants (global route)
    group_id        UUID | null     // null = applies to all groups within the tenant
    match_type      "domain_suffix" // qname ends with match_value, e.g. ".corp.local"
                  | "domain_exact"  // qname == match_value exactly
                  | "qtype"         // match on record type (e.g. route PTR queries to internal)
                  | "category"      // match on the category the domain falls into
                  | "default"       // catch-all; must be the lowest-priority route
    match_value     string | null   // the suffix / fqdn / qtype / category; null for "default"
    pool_id         UUID            // target pool
    nxdomain_ttl_override int | null  // override NXDOMAIN TTL for this route; null = use reply
    require_dnssec  bool | null     // override tenant's dnssec_validation for this route
    priority        int             // lower value = evaluated first; default 100
    enabled         bool
}
```

Example routing table for a tenant with a corporate network:

| Priority | Match type | Match value | Pool |
|----------|-----------|------------|------|
| 10 | `domain_suffix` | `.corp.local` | corp-internal |
| 10 | `domain_suffix` | `.10.in-addr.arpa` | corp-internal |
| 20 | `domain_suffix` | `.ad.corp.local` | corp-ad-dc |
| 50 | `category` | `threat-intel` | threat-intel-resolvers |
| 100 | `default` | — | public-dot-ha |

#### UpstreamTenantPolicy

Per-tenant defaults that interact with the routing model.

```
UpstreamTenantPolicy {
    tenant_id               UUID
    require_encrypted       bool    // reject do53 resolvers in any pool used by this tenant
    dnssec_validation       "strict" | "opportunistic" | "disabled"  // tenant default
    qname_minimization      bool    // tenant default; overrides resolver setting
    blocked_response_type   "nxdomain" | "refused" | "zero_ip"  // how to answer blocked queries
    min_ttl_s               int     // clamp downstream TTL; default 0 (honour reply)
    max_ttl_s               int     // clamp downstream TTL; default 86400
    negative_ttl_s          int     // TTL for synthesized NXDOMAIN/REFUSED; default 300
}
```

---

### 21.3 Bundle integration

Upstream configuration is compiled into a **signed upstream config bundle** — separate from the policy bundle but using the same signing key and distribution channel. The filter node fetches both bundles on the same poll interval. Separating them limits blast radius: a policy change does not force a full upstream-config redistribute, and vice versa.

```
UpstreamBundle {
    version         uint64
    tenant_id       UUID | null   // null = global (applies to all tenants on this node)
    routes          [UpstreamRoute]   // ordered by priority
    pools           {pool_id → UpstreamPool}
    resolvers       {resolver_id → UpstreamResolver}
    tenant_policies {tenant_id → UpstreamTenantPolicy}
    issued_at       timestamp
    signature       bytes         // ed25519 over the serialized payload
}
```

The filter node loads the bundle atomically. If verification fails, it keeps the previous bundle and logs an alert. If this is the first startup and no bundle is present, it falls back to a single configurable `UPSTREAM_FALLBACK_ADDRESS` environment variable — this covers the Proxmox single-host profile where the control plane may not yet be reachable.

---

### 21.4 Health monitoring (filter node)

Each filter node runs an independent health monitor — there is no shared health state to avoid distributed coordination on the hot path.

```
HealthMonitor (per pool member, per filter node):
    state:      healthy | unhealthy | probe_pending
    last_probe: timestamp
    consec_failures: int
    consec_successes: int
    latency_ema_ms: float   // exponentially weighted moving average

Probe cycle (every health_check_interval_s):
    1. Send health_check_query (SOA "." or configured domain) to the resolver.
    2. If response within health_check_timeout_ms and response_code ∈ {NOERROR, NXDOMAIN}:
           consec_successes++; consec_failures = 0
           if state == unhealthy and consec_successes >= healthy_threshold:
               state = healthy; emit UpstreamRecoveredEvent
    3. Else:
           consec_failures++; consec_successes = 0
           if state == healthy and consec_failures >= unhealthy_threshold:
               state = unhealthy; emit UpstreamFailedEvent
    4. Update latency_ema_ms (regardless of state transition).
```

Health events (`UpstreamFailedEvent`, `UpstreamRecoveredEvent`) are forwarded to the telemetry pipeline (§5.4) and surfaced in the Analytics UI as resolver health timelines.

> 🚧 **As built:** the probe loop, state machine and latency EMA are implemented (`health_monitor.rs`, `MemberHealthSnapshot`) and `UpstreamBundleForwarder` consumes the resulting `HealthStore` at query time — failover works. What is *not* built is the observability half: no `UpstreamFailedEvent`/`UpstreamRecoveredEvent` is emitted to telemetry, none of `upstream_latency_us` / `upstream_errors_total` / `upstream_health_state` / `upstream_pool_healthy_members` / `upstream_dnssec_failures_total` exists, and no min-healthy alert is written to the audit log. Consequently `HealthTab.tsx` is a placeholder, and health state is visible only in the node's own logs. §23 is the section that fixes this: the per-node heartbeat ships `HealthStore::snapshot` per pool member to the control plane, which is what makes this data reachable by the UI at all.

If a pool's healthy member count drops below `min_healthy_members`:
- An alert is emitted to the audit log and (if configured) to the notification channel.
- If `fallback_pool_id` is set, queries for this pool are routed to the fallback pool.
- If no fallback is set and the pool is completely dead, the filter node returns `SERVFAIL` for affected queries (not `NXDOMAIN` — the distinction matters for client retry behavior).

---

### 21.5 DNSSEC validation

DNSSEC validation is performed by the upstream resolver, not by the filter node itself (that would require running a recursive validator — it is in scope for a future sprint, see §21.9). Instead, the filter node enforces the DNSSEC *policy*:

| Validation mode | Behavior |
|----------------|---------|
| `strict` | Resolver must set the `AD` (Authentic Data) bit. If the response is `SERVFAIL` with `AD=0` (DNSSEC validation failure at the resolver), the filter node returns `SERVFAIL` to the client and logs a `DnssecFailureEvent`. |
| `opportunistic` | Propagate `AD` bit from the upstream response. Do not escalate `SERVFAIL` with DNSSEC context. |
| `disabled` | Strip `AD` bit before forwarding to client. Never log DNSSEC events. |

For `strict` mode to work, the resolver must be configured to validate DNSSEC and return `SERVFAIL` on validation failures (e.g. Unbound `val-override-date: "20990101T0000"` turned off, `module-config: "validator iterator"`). The filter node validates that the configured resolver behaves correctly during health probes by sending a query to a known-broken DNSSEC domain (e.g. `dnssec-failed.org`) and asserting `SERVFAIL` is returned.

> **As built:** `strict` is implemented by setting hickory's `ResolverOpts::validate = true` (the `dnssec-ring` feature), so the filter node's own resolver stub rejects unvalidated answers rather than merely inspecting the upstream's `AD` bit — a stronger guarantee than the table describes, but a different mechanism. 🚧 The `dnssec-failed.org` resolver-behaviour assertion during health probes is **not** built (`health_monitor.rs` probes only the pool's configured `health_check_query`), and no `DnssecFailureEvent` is emitted.

---

### 21.6 Split-horizon and private DNS

The route table (§21.2) is the primary mechanism for split-horizon. Additionally:

**RPZ (Response Policy Zone) integration:** upstream resolvers that support RPZ (Unbound, BIND) can be configured with threat-intelligence zone feeds directly at the resolver layer. The Mantis filter node can optionally forward to an RPZ-capable resolver for categories that benefit from real-time threat data (e.g. `threat-intel` category) while using a faster public resolver for general queries.

**DNS64:** for IPv6-only client segments that need to reach IPv4-only destinations, a pool member can be a DNS64-capable resolver. The filter node routes `AAAA` queries from the tenant's IPv6 group to the DNS64 pool, where the resolver synthesizes `64:ff9b::/96` prefixes. Configuration:

```
Dns64Config {
    scope_id    UUID    // the DHCP scope (§22) or VPN group
    pool_id     UUID    // must point to a DNS64-capable resolver pool
    pref64      string  // prefix, default "64:ff9b::/96"
}
```

**Stub zones (authoritative answers):** for domains the tenant owns that should be answered from local data without forwarding (e.g. `corp.local` records managed by the DNS Zones feature, **§24**), the local zone database answers authoritatively and no upstream is consulted. This is a zero-latency path and is how DNS Zones integrates with the upstream model.

> **As built — mechanism differs from the original plan.** This was designed as an `UpstreamRoute` of type `stub_zone` that outranks pool routing. It is *not* implemented that way: `match_type` has no `stub_zone` value (`domain_suffix|domain_exact|qtype|category|default` only). Instead the zone lookup short-circuits *before* route evaluation — `ZoneStore::lookup` runs early in `build_response_inner`, and a hit returns `ZoneLookup::Answer` or an authoritative `ZoneLookup::NxDomain` without ever entering the routing or Bloom-filter path. Telemetry labels these `decision = "stub_zone"`. The observable behaviour matches the intent (local data wins, zero upstream latency); the configuration surface does not — there is no route row to inspect or reorder, because zone membership alone decides it. See §24.3.

---

### 21.7 Observability

The filter node exposes per-resolver metrics on the telemetry pipeline:

| Metric | Description |
|--------|-------------|
| `upstream_latency_us{resolver_id, quantile}` | P50/P95/P99 latency per resolver |
| `upstream_errors_total{resolver_id, error_type}` | timeout, tls_error, refused, servfail, etc. |
| `upstream_queries_total{resolver_id, dnssec_ad}` | query count, broken out by DNSSEC AD bit |
| `upstream_health_state{resolver_id}` | 1=healthy, 0=unhealthy |
| `upstream_pool_healthy_members{pool_id}` | count of healthy members |
| `upstream_dnssec_failures_total{tenant_id}` | DNSSEC validation failures per tenant |

These are surfaced in the Analytics UI on a new **Upstream Health** tab: per-resolver latency timeline, error breakdown, health state history, pool member utilization donut.

---

### 21.8 Management UI

A new **Resolvers** section under Settings:

- **Resolvers list** — name, protocol, address, health state badge (green/red/amber), P50 latency, error rate. Add / edit / delete.
- **Resolver editor** — form with protocol selector, address, port, TLS hostname, pin input with SHA-256 fingerprint helper (pastes a cert PEM, extracts SPKI hash), DNSSEC validation selector, QName minimization toggle, ECS toggle, timeout/retry fields. "Test resolver" button — sends a live SOA probe and shows the raw response.
- **Pools list** — name, strategy, member count, min-healthy, current health. Add / edit / delete.
- **Pool editor** — member list with drag-to-reorder (for failover priority), weight sliders for WRR, health check config, fallback pool selector.
- **Routes table** — per-tenant, ordered by priority; inline drag-to-reorder; add / edit / delete route.
- **Tenant policy editor** — encrypted upstream requirement, DNSSEC mode, TTL clamp, blocked response type.
- **Upstream health dashboard** — health state timeline per resolver, latency heatmap, DNSSEC failure rate.

---

### 21.9 Future work (not in scope for this epic)

- **In-node DNSSEC validation** (run `hickory-resolver` in validating mode, removing dependency on the upstream resolver for validation). This enables `strict` mode even with do53 resolvers.
- **DoQ (DNS-over-QUIC, RFC 9250)** as a protocol option.
- **Per-client upstream routing** — route VPN clients in the `engineering` group through a different upstream than `guests` based on DHCP scope (§22) correlation.
- **Upstream policy as code** — export/import resolver + pool + route config as YAML for GitOps workflows.
- **Threat-intel resolver integration** — forward queries for newly registered domains to a threat-intel resolver (Quad9, NextDNS) regardless of category match, then apply category block on top. Belt-and-suspenders for APT/zero-day coverage.

---

## 22. DHCP — Native Engine (mantis-dhcp)

Mantis-DNS serves DHCP with its own engine, **mantis-dhcp** (`services/dhcp`, Rust), rather than integrating ISC Kea as a sidecar. Kea was the original approach; it was replaced because every point of contact with it was itself a maintenance burden rather than a shortcut:

- **Config push was fundamentally broken.** Kea's `config-set` rebinds `control-sockets` as part of applying a new config, and that bind always collides with the listener currently serving the `config-set` request — a deterministic failure on every push, not an edge case. Working around it meant hand-rolling incremental `subnet_cmds`/`host_cmds` diffing against `subnet4-list`, plus a 28-bit hash-with-collision-probing scheme just to map a scope's UUID onto Kea's integer `subnet4.id`.
- **Runtime state didn't survive a Kea restart.** `subnet4`/`subnet6` lists live only in the daemon's memory; a crash or package upgrade silently emptied them, needing a periodic reconcile job just to notice and repair the drift.
- **HA required a live daemon reload Mantis couldn't trigger.** Toggling HA in the DB didn't make Kea load/unload `libdhcp_ha.so` — only a full restart with a rewritten static config did.
- **Packaging was fragile.** Locating `libdhcp_*.so` hook paths, a symlink-rejection quirk in Kea's own path validator, and manual `dhcpdb_create.pgsql` execution because `kea-admin` refuses to run against a DB that already has (Mantis's own) tables.
- **DDNS ran through a shell script.** Kea's `run_script` hook shelled out to `mantis-ddns-bridge.sh`, which built JSON via `jq` from fully client-controlled DHCP option data before POSTing to the control plane.
- **No tenancy, and two daemons/two control ports** for a protocol Mantis otherwise needed unified with its own scope/reservation model.

mantis-dhcp removes the translation layer entirely: it reads `dhcp_scopes` / `dhcp_static_leases` / `dhcp_options` / `dhcp_relay_configs` directly from the same Postgres tables the control-plane API and UI already edit — a scope change is live on mantis-dhcp's next config-refresh tick (10 s), no push/sync step, no "re-push after restart" job. It owns its own lease state (`dhcp_leases` / `dhcp_leases6`) instead of reading a separate daemon's schema, and reports lease/DDNS events directly to the control plane's existing `/internal/dhcp-event` endpoint (the same security-reviewed ownership-guard logic that used to sit behind Kea's `run_script` hook, just called in-process instead of via a shell script).

- A new device joins the network → mantis-dhcp assigns an IP → DDNS event → Mantis DNS Zones A/AAAA record → device appears in the client registry → visible in SIEM export — all without operator action.
- Scope/reservation/option changes made in the Mantis UI are read directly off Postgres on the next refresh tick; there is nothing to push and nothing that can fail to push.

---

### 22.1 Architecture

```
        Mantis Postgres (single source of truth)
   dhcp_scopes / dhcp_static_leases / dhcp_options / dhcp_relay_configs
   dhcp_scopes6 / dhcp_static_leases6      +      dhcp_leases / dhcp_leases6
        ▲ read config (10s refresh)     ▲ write leases (DB-locked alloc)
        │                                │
   ┌────┴────────────────────────────────┴────┐
   │            mantis-dhcp (Rust)             │   UDP :67 (DHCPv4)
   │  dhcproto codec · allocation FSM          │
   │  DDNS event → control /internal/dhcp-event│
   └────────────────────────────────────────────┘
```

**Why no raw sockets:** replies to a client with no address yet are sent as plain broadcast UDP (`SO_BROADCAST`, destination `255.255.255.255:68`) rather than a hand-crafted L2 frame over `AF_PACKET`. RFC 2131 §4.1 makes broadcasting always acceptable even when a unicast-before-configured optimization would also be legal — this is the same call dnsmasq and other minimal DHCP servers make, and it avoids the whole raw-socket/privilege-surface question. Relayed traffic (via `giaddr`) is plain unicast to the relay, which needs nothing special either. Dispatching *direct-attached* clients across *multiple* listening interfaces (§22.7) does need one more privilege — `SO_BINDTODEVICE`, Linux-only, one dedicated socket per configured scope `interface` alongside the wildcard socket — but that's still an ordinary `SOCK_DGRAM` socket, not `AF_PACKET`; the capability it needs (`CAP_NET_RAW`) is a Linux quirk of that specific setsockopt, not a sign of raw packet crafting.

**mantis-dhcp internals** (`services/dhcp/mantis-dhcp/src`):
- `db.rs` — loads scopes/reservations/relay configs into an in-memory `Snapshot` (via `arc-swap`, the same hot-reload idiom `mantis-filter` uses for policy bundles), refreshed every 10s; the packet-handling hot path never blocks on a config query, only on lease allocation itself.
- `server.rs` — the DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE/DECLINE/INFORM state machine.
- `options.rs` — builds the auto-injected DHCP option set for a scope.
- `ddns.rs` — posts lease add/expire events to the control plane's `/internal/dhcp-event`.

---

### 22.2 Mantis data model

Scopes, reservations, options, and relay configs are plain Mantis tables — not a shadow of another system's config format, since there's no other system to shadow. `kea_subnet_id` / `last_pushed_at` (bookkeeping for a push that no longer happens) are gone from `DhcpScope`/`DhcpScope6`.

**`dhcp_leases` / `dhcp_leases6` are Mantis-owned and authoritative for live lease state** — mantis-dhcp writes them directly as part of allocation; there is no separate daemon lease table to read from.

#### DhcpScope

```
DhcpScope {
    id                  UUID             PK
    tenant_id           UUID             FK → Tenant; indexed
    name                string(255)
    description         text | null
    // addressing
    subnet              cidr             // e.g. "10.8.1.0/24"
    range_start         inet             // start of dynamic pool
    range_end           inet             // end of dynamic pool
    // binding
    interface           string(64) | null   // bind to one interface; null = all
    vlan_id             int | null          // informational
    // lease timing
    lease_time_s        int              default 86400
    max_lease_time_s    int              default 604800
    renew_time_s        int | null       // T1; null → 50% of valid-lifetime
    rebind_time_s       int | null       // T2; null → 87.5% of valid-lifetime
    // DNS integration
    domain_name         string(255) | null  // option 15
    ddns_enabled        bool             default false
    ddns_zone_id        UUID | null      // FK → DnsZone; required if ddns_enabled
    ddns_ttl_s          int              default 300
    // PXE
    pxe_next_server     inet | null      // option 66 (siaddr), scope default
    pxe_boot_filename   string(255) | null  // option 67, scope default
    // meta
    enabled             bool             default true
    created_at          timestamp
    updated_at          timestamp
}
```

#### DhcpStaticLease

A fixed IP for a known MAC within a scope.

```
DhcpStaticLease {
    id              UUID             PK
    scope_id        UUID             FK → DhcpScope
    tenant_id       UUID             FK → Tenant
    mac_address     string(17)       // lowercase, colon-delimited
    ip_address      inet             // reserved IP
    hostname        string(255) | null
    description     text | null
    client_id       string(255) | null   // option 61 (not yet used for matching — see §22.7)
    next_server     inet | null          // option 66 TFTP for PXE (siaddr); overrides scope default
    boot_filename   string(255) | null   // option 67; overrides scope default
    enabled         bool             default true
    created_at      timestamp
}
```

#### DhcpOption

Per-scope or per-reservation DHCP options.

```
DhcpOption {
    id              UUID
    scope_id        UUID | null          // null = global; FK → DhcpScope
    static_lease_id UUID | null          // FK → DhcpStaticLease (reservation-level)
    option_code     int                  // 1–254 (DHCPv4) or 0–65535 (DHCPv6)
    option_space    string default "dhcp4"
    value           text                 // CSV or hex
    always_send     bool default false
}
```

Consumed by `options::apply_custom` (`db::CustomOption` → `Snapshot::custom_options_for`): scope-level rows apply to every client in that scope; a reservation-level row for the same `option_code` overrides the scope-level one. `value` is parsed by `options::parse_custom_value` — a `0x`-prefixed value decodes as hex bytes, anything else is sent as its literal ASCII/UTF-8 bytes via `dhcproto`'s `DhcpOption::Unknown`/`UnknownOption`. There is no per-code typed encoding (e.g. a comma-separated IP list) — that would need knowing each code's declared data type the way Kea's option definitions do, which this doesn't model; the well-known auto-injected options below don't need it since they're built directly as their proper typed `DhcpOption` variant.

**Auto-injected options** (`services/dhcp/mantis-dhcp/src/options.rs`, not stored as `DhcpOption` rows):
- Option 1 (subnet mask) — from subnet CIDR.
- Option 3 (router) — from `scope.router_ip`.
- Option 6 (DNS servers) — `scope.dns_servers`, falling back to the Mantis filter node IP.
- Option 15 (domain name) — from `scope.domain_name`.
- Options 51/58/59 — lease/T1/T2 from scope timing fields.
- Option 54 (server ID) — this host's configured address (`MANTIS_DHCP_SERVER_IP`).

#### DhcpRelayConfig

```
DhcpRelayConfig {
    id              UUID
    scope_id        UUID             FK → DhcpScope
    relay_ip        inet             // giaddr this scope accepts relayed traffic from
    circuit_id_hex  string | null    // option 82 sub-option 1 (hex) — must also match if set
    remote_id_hex   string | null    // option 82 sub-option 2 (hex) — must also match if set
}
```

There is deliberately no `DhcpHaConfig` table. See §22.6 — HA needs no configuration at all under the shared-DB allocation model, so the Kea-HA-peer-protocol config it used to hold has nothing to replace it.

---

### 22.3 Lease allocation

There is no config push step — mantis-dhcp reads `dhcp_scopes` et al. directly (10s refresh) and writes `dhcp_leases` directly. The interesting part is making that write race-safe across multiple mantis-dhcp instances sharing one Postgres (`db::allocate` / `db::claim_specific` in `services/dhcp/mantis-dhcp/src/db.rs`):

```
DISCOVER (non-binding preview, no lock, no write):
  reservation for this scope+mac? → offer its IP.
  existing active lease for this mac? → offer the same IP (renewing client).
  else → peek_free_ip: read dhcp_leases, offer the first address in
          [range_start, range_end] not currently active/declined.

REQUEST (binding — this is where races must be resolved):
  BEGIN;
  SELECT pg_advisory_xact_lock(hashtextextended(scope_id, 0));  -- only one
                                                                  allocator for
                                                                  this scope,
                                                                  anywhere, runs
                                                                  past this point
  reservation? requested IP must match it (else NAK) → upsert lease row.
  requested IP given (selecting an OFFER, or INIT-REBOOT)?
      → in-pool and not held by a *different* mac → upsert; else NAK.
  no requested IP (RENEWING/REBINDING) → renew existing row, or allocate fresh.
  COMMIT;  -- releases the advisory lock
```

A free address has no row to lock, so the usual `SELECT ... FOR UPDATE` pattern doesn't apply to "find a free one" — the advisory lock (keyed on the scope's UUID) is what serializes the scan-then-insert sequence across every mantis-dhcp instance and every replica. Expired leases are deleted outright by a 30s sweep, not soft-marked, so they're immediately visible to the next scan.

---

### 22.4 DDNS

On a successful ACK (or a RELEASE), mantis-dhcp POSTs directly to the control plane's `/internal/dhcp-event` endpoint — the same endpoint and the same ownership-guard logic (`dhcp_internal_routers.py`) that used to sit behind Kea's `run_script` hook and a shell script; only the caller changed, from a hook script piping through `jq` to a Rust `reqwest` call.

```
POST /api/v1/internal/dhcp-event handler:
  - `add` → `_upsert_client_entry` + (if DDNS enabled) `_upsert_a_record`/`_upsert_aaaa_record`, with ownership-guard checks (a DHCP client can't hijack another host's DNS name; see the ddns_owner_mac/ddns_owner_duid checks in `dhcp_internal_routers.py`).
  - `expire`/`delete` → matching `_delete_a_record`/`_delete_aaaa_record`, refusing to delete anything it can't prove ownership of (no mac/duid, or a mismatched one).
  - A failed POST is queued in `dhcp_ddns_retries` (mantis-dhcp's own table, migration `a3d7e91c4f56` — not part of the Python domain model, Rust is the only reader/writer) and retried on a 10s tick with backoff (30s doubling, capped at 30min), giving up after 8 attempts.
```

---

### 22.5 Client registry

No separate sync loop is needed: `/internal/dhcp-event`'s `add` handler upserts `ClientEntry` directly as part of handling the event mantis-dhcp already sends for DDNS, so client-registry population is a side effect of the same call rather than a second polling process reading a lease table.

---

### 22.6 HA

There is no HA *configuration* — running a second mantis-dhcp instance against the same Postgres **is** HA, active/active, because the row lock in §22.3's allocation transaction is the only coordination two allocators ever need. No peer list, no heartbeat interval, no mode selector, nothing to keep in sync between instances beyond the DB they already share.

The one real constraint: mantis-dhcp binds `:67` with `network_mode: host` (§22.1), and two processes can't bind the same port on the same host. So a second instance means a second *host* (or, on Kubernetes, `hostNetwork: true` pods scheduled to different nodes) — not two containers on one box, which is why the dev compose file only runs one instance.

---

### 22.7 Relay (honest status)

Implemented: a relayed packet's scope is chosen either by matching `giaddr` against a `DhcpRelayConfig.relay_ip` row, or — if none is configured — by the conventional fallback of finding the scope whose subnet CIDR contains `giaddr` (`Snapshot::find_scope_for_relay`). Direct-attached (unrelayed) traffic is dispatched by `Snapshot::find_scope_for_direct`: on Linux, `main.rs` binds one dedicated socket per distinct scope `interface` at startup (`SO_BINDTODEVICE` + `SO_REUSEADDR`, alongside the always-on wildcard socket) so traffic arriving on that interface is matched to its scope exactly, no ambiguity; on other platforms (or an interface `bind_device` fails on, e.g. it doesn't exist on this host) only the wildcard socket runs, which disambiguates cleanly only when exactly one enabled scope has no `interface` restriction. A newly-added scope `interface` needs a process restart to get its own dedicated socket — sockets are bound once from the startup snapshot, not re-bound on every 10s config refresh.

`circuit_id_hex`/`remote_id_hex` are enforced when set: a relay_ip match alone isn't sufficient for a `DhcpRelayConfig` row that also specifies a circuit/remote id — the packet's own Option 82 (Relay Agent Information) sub-options 1/2 must match too (`relay_agent_info` extracts them; `Snapshot::find_scope_for_relay` checks them). This isn't full Kea-style "client-classing" (routing to a different *option set* per class) — there's still only one option set per scope (§22.2) — it's an additional authentication factor alongside `relay_ip`.

**Server identifier (option 54) per interface**: each dedicated per-interface socket auto-derives *that interface's own* address at startup (`main.rs`'s `interface_ipv4_addr`, `getifaddrs(3)`, Linux-only like the socket itself) and stamps it into every reply that goes out on it — `server::server_ip_for` prefers this over the single operator-configured `MANTIS_DHCP_SERVER_IP` fallback, which is now used only for relayed traffic and any scope with no `interface` restriction (both always arrive on the wildcard socket, with no single interface to derive an address from). This matters because a client's later unicast RENEW targets whatever address it was handed as option 54 — stamping one global address into every reply regardless of which of the host's subnets it's actually going out on would hand a client on a second NIC's subnet an address it may not even be able to route to. `MANTIS_DHCP_SERVER_IP` is optional now (a missing fallback just means relayed/interface-less traffic gets no reply, logged as a warning, rather than a wrong one) — the install scripts and compose files warn rather than refuse to start when it's unset.

---

### 22.8 PXE

`scope.pxe_next_server`/`pxe_boot_filename` set the default `siaddr`/boot-filename for a scope; `DhcpStaticLease.next_server`/`boot_filename` override it per reservation (`server.rs::siaddr_for`). Both are wired into every OFFER/ACK.

Architecture-aware PXE is implemented as a single BIOS/UEFI split rather than a full client-class system (no other part of this schema has one — see §22.2): `pxe_uefi_boot_filename` (scope) / `uefi_boot_filename` (reservation, migration `b6e2a814f9c3`) override the BIOS/default filename when the client's option 93 (Client System Architecture, RFC 4578) indicates anything other than code 0 (legacy BIOS) — `server.rs::is_uefi_client`/`select_boot_filename`. A scope that only ever set the BIOS field keeps serving every client the same file, UEFI or not, exactly as before this existed. Finer-grained PXE profiles (per-arch-code, not just BIOS-vs-UEFI) would need a real client-class concept this doesn't have.

---

### 22.9 DHCPv6 (RFC 8415)

A second daemon, `mantis-dhcp6` — a separate binary/process (own `[::]:547` socket, own `Server6`/`Snapshot6`/`Counters6`, `services/dhcp/mantis-dhcp/src/{config6,db6,options6,server6}.rs` + `src/bin/mantis-dhcp6.rs`) sharing only the DDNS-retry-queue plumbing and the advisory-lock/hot-reload idioms with the v4 daemon (both now live behind a shared `mantis_dhcp` library crate, `src/lib.rs`). Reads `dhcp_scopes6`/`dhcp_static_leases6` directly, same live-config/no-push-step model as v4, and owns `dhcp_leases6`.

- **Messages handled**: SOLICIT/ADVERTISE, REQUEST/RENEW/REBIND/REPLY, RELEASE, DECLINE, INFORMATION-REQUEST, CONFIRM. Rapid Commit is never honored — every SOLICIT gets a two-message exchange, never a one-message Reply.
- **IA_NA**: a per-scope address pool (`pool_start`/`pool_end`) allocated by DUID, same advisory-lock-per-scope HA model as v4 (`pg_advisory_xact_lock`, namespace `2` vs. v4's `0` so the two daemons' locks never collide). Unlike v4's small pools, a v6 range can span a /64 — far too large to linearly scan — so `db6::allocate_na` picks a uniformly random candidate and retries on collision (bounded, `RANDOM_PICK_ATTEMPTS`) rather than scanning; pool exhaustion is therefore only ever inferred probabilistically, never proven exactly the way v4's free-count is.
- **IA_PD**: each `DhcpScope6` carries at most one `pd_prefix`/`pd_prefix_len` — there's no prefix *pool*, just that one prefix, delegated to at most one DUID at a time (`db6::allocate_pd`, lock namespace `3`). A scope with no `pd_prefix` set never satisfies an IA_PD request.
- **Only the first IA_NA and first IA_PD option in a message is served** — a client asking for more than one address/prefix per message only gets the first, the same single-binding-per-identifier simplification v4 already made for MAC addresses (§22.2).
- **Relay**: `server6.rs` unwraps `RelayForw` nesting manually at the byte level rather than through dhcproto's typed `RelayMessage`/`RelayMsg` API, which always tries to decode a `RelayMsg` option's payload as another `RelayMessage` — fine for genuine multi-hop chains, wrong for the far more common case of a single relay wrapping a plain client message. The innermost relay's `link_addr` picks the scope (subnet containment, v6's counterpart of v4's giaddr fallback); there's no relay-authentication allow-list yet (v4's circuit/remote-id check, §22.7) — an honest gap, same category §22.9 used to flag the whole daemon before this existed. Replies are always unicast straight back to whichever address actually sent the UDP datagram (the client or the nearest relay) — RFC 8415 makes this unconditional, so there's no giaddr-style dest computation the way v4 needs.
- **DDNS**: AAAA records via the same `/internal/dhcp-event` endpoint and retry queue as v4 (`ddns.rs`'s `V6Event`/`post_v6`, `family="6"`, keyed by DUID instead of MAC — `dhcp_internal_routers.py` already supported this side unchanged).
- **Direct-attach (unrelayed)**: a single wildcard socket best-effort joins the standard relay/server multicast group (`ff02::1:2`) on the default interface; no per-interface `SO_BINDTODEVICE` dispatch yet (v4 has this — §22.7), so multiple direct-attach scopes with no `interface` filter can't be disambiguated on this daemon yet.
- **Not implemented**: per-scope/per-reservation custom `dhcp_options` passthrough (v4-only, `option_space = 'dhcp4'`), Domain Search List (option 24 — needs a DNS-name wire encoding this crate doesn't otherwise depend on), and Client FQDN (option 39) hostname extraction — a DDNS "add" event's hostname comes only from the reservation's configured `hostname`, never from the client's own request.

---

### 22.10 Management UI

The **DHCP** section in the left nav: Scopes, Reservations, Leases, Status (per-subnet utilisation), and DHCPv6 (scope/reservation CRUD only, per §22.9). There is no HA tab and no "push to Kea" affordance anywhere — both were removed along with Kea, since neither concept exists anymore (§22.6, §22.3).

---

### 22.11 Observability

`GET /metrics` on mantis-dhcp itself (`metrics.rs`), opt-in via `MANTIS_DHCP_METRICS_BIND_ADDR` (blank = disabled, same convention as mantis-filter's `BLOCKPAGE_BIND_ADDR`) — no external exporter needed, unlike Kea's `stat_cmds` hook + Stork/`kea-exporter`.

- **DORA counters** (`dhcp_discover_total`, `dhcp_offer_total`, `dhcp_request_total`, `dhcp_ack_total`, `dhcp_nak_total`, `dhcp_release_total`, `dhcp_decline_total`, `dhcp_inform_total`): in-process atomics, incremented directly in `server.rs`'s dispatch — a REQUEST is counted once as `request` and again as whichever of `ack`/`nak` its actual reply turned out to be.
- **`dhcp_pool_assigned{scope_id,scope_name}` / `dhcp_pool_declined{...}`**: gauges, queried from `dhcp_leases` at scrape time (`db::scope_utilization`) — the same aggregate `/api/v1/dhcp/stats` computes for the Status tab, not a second in-memory copy that could drift from it.
- **`dhcp_ddns_retry_queue_depth`**: gauge, `count(*)` on `dhcp_ddns_retries` (§22.4) at scrape time.

No `DhcpPoolExhaustedEvent`-style alert yet — that's a Prometheus alerting-rule concern once someone's actually running a scraper against this, not something mantis-dhcp needs to compute itself.

**Per-request logging**: `tracing::debug!` on every packet's receipt (message type, MAC/DUID, matched scope or why none matched), every server-identifier validation drop, and the outcome (reply type, or why none was sent) — `server.rs`/`server6.rs`'s `handle()`. Off by default (`RUST_LOG` unset behaves as `info` — startup/shutdown/warnings only, no per-packet noise); set `RUST_LOG=debug` (or `RUST_LOG=mantis_dhcp=debug` to scope it to just this crate) and watch `journalctl -u mantis-dhcp -f` / `-u mantis-dhcp6 -f` to see individual requests. Before this, the *only* way to observe live traffic was a raw `tcpdump`/`tshark` capture on the DHCP ports — nothing in the daemon itself said anything about a legitimate request that simply didn't match a scope or got silently dropped by RFC-mandated validation.

**Daemon liveness (`dhcp_daemon_heartbeats`)**: neither daemon had any liveness signal reaching the control plane before this — a crashed or bootlooping process (e.g. a leftover `kea-dhcp4` still holding `:67` from before the migration) showed up nowhere except `journalctl`; the Status tab's lease/utilisation numbers just stopped updating silently, with nothing telling anyone *why*. Identity is `(hostname, family)`, not a fresh id per process boot — only one instance per host can ever run a given family (host networking, one process per bound port, §22.6), so a restart must take over the *same* row rather than leaving the old, now-dead instance's row sitting there stale next to a new one. `db::register_instance`/`db6::register_instance` run once at startup (upserting on the `(hostname, family)` unique constraint: fresh `instance_id`, `started_at` and `last_seen_at` reset to now — a genuine takeover, not a blind merge); `db::touch_heartbeat`/`db6::touch_heartbeat` then just refresh `last_seen_at` by `instance_id` on the same tick as the existing config-refresh loop (`scope_refresh_interval_s`, 10s by default). `hostname` is best-effort via `/proc/sys/kernel/hostname`; when it can't be determined, registration falls back to one row per restart (Postgres never matches `NULL` against `NULL` in a unique index) — an accepted, rare edge case. Rows are never auto-pruned: a stale row *is* the signal an operator wants to keep seeing, not something that should quietly vanish after a timeout. `GET /api/v1/dhcp/health` (`require_role("operator")`, since hostnames/topology aren't tenant-scoped data) flags a row `stale` once its `last_seen_at` is more than 30s old (3x the heartbeat cadence). Surfaced on the Status tab as a green/red badge per instance.

---

### 22.12 Security

- **Rogue DHCP prevention**: out of scope for mantis-dhcp itself — a network-layer concern (DHCP snooping on managed switches).
- **Relay authentication**: a scope with `DhcpRelayConfig` rows only accepts relayed traffic from those giaddrs — an untrusted relay elsewhere on the same subnet is rejected outright, not matched via the subnet-containment fallback (`Snapshot::find_scope_for_relay`). A row can additionally require a specific Option 82 circuit-id/remote-id (§22.7); the subnet-containment fallback itself is unauthenticated by design — it's only used for scopes that never configured an allow-list at all.
- **DDNS ownership**: enforced by MAC/DUID matching in `dhcp_internal_routers.py` (§22.4) — a DHCP client's own hostname option can never overwrite a DNS record it doesn't already own.
- **Client-supplied data**: every field in a DHCP packet (hostname, client-id, MAC) is attacker-controlled; the DDNS path validates/escapes before it ever reaches a zone file (see `_validate_record_field` in `dhcp_internal_routers.py`) — this was true of the old `mantis-ddns-bridge.sh` path too and remains true here.
- **PXE**: TFTP/boot-file address is operator-configured; mantis-dhcp does not run a TFTP or HTTP boot server itself, only injects the option.

### 22.13 Conflict detection

Before an OFFER, mantis-dhcp can ICMP-echo the candidate address to catch a device already squatting an IP the server never allocated (a static-IP device someone forgot to reserve, a leftover from a pre-migration setup, etc). Linux-only (`conflict.rs`) — needs a raw ICMP socket, `CAP_NET_RAW`, same capability already granted for `SO_BINDTODEVICE` (§22.1); on non-Linux the probe stub always reports "no reply seen" and OFFER proceeds as before.

- `pick_conflict_free_candidate` (server.rs): pulls a candidate via `db::peek_free_ip_excluding`, probes it, and on a reply marks it `mark_declined_preemptive` (state=declined) and retries with it excluded — bounded by `conflict_probe_max_attempts` (default 4), each probe capped at `conflict_probe_timeout` (default 300ms). Exhausting attempts without a clean address means no OFFER goes out for that DISCOVER.
- Scoping: only the DISCOVER pool-scan path is probed. A direct REQUEST for a specific address (renewal, or a client asserting a prior offer) goes through `db::allocate` unprobed — that path already has an explicit requester, so an ICMP round-trip there would only add latency without a matching security benefit.
- Opt-out: `MANTIS_DHCP_CONFLICT_DETECTION=0` (or `false`) skips probing entirely, trading the extra OFFER latency away in favor of relying on DHCPDECLINE alone — same tradeoff most DHCP servers with this feature expose as a toggle.

---

### 22.14 Deviation register — mantis-dhcp vs. Kea/ISC practice (verified 2026-07-25)

§26 R8 raised a specific worry: replacing a 20-year-old, widely-deployed DHCP implementation (Kea) with a from-scratch one means inheriting none of its accumulated hardening against real-world edge cases, and every config knob in a mature server exists because a real deployment broke without it. This section is the result of actually checking — Kea's current security-advisory history and configuration reference, fetched 2026-07-25, not recalled from memory — against what mantis-dhcp actually does, item by item. Where a citation in an earlier informal review of this codebase turned out to be wrong (two CVE numbers were misremembered and don't correspond to real Kea advisories), it's corrected here rather than repeated.

**Kea's own CVE history says the worry is justified, and current.** Eleven public advisories, [kb.isc.org/docs/all-kea-advisories](https://kb.isc.org/docs/all-kea-advisories):

| CVE | Class | Released |
|---|---|---|
| CVE-2026-3608 | Stack overflow, unauthenticated remote crash, all four Kea daemons | 2026-03-25 |
| CVE-2025-11232 | Invalid characters cause an assertion failure (crash) | 2025-10-29 |
| CVE-2025-40779 | Crash from a specific client-option/subnet-selection interaction | 2025-08-27 |
| CVE-2025-32803 / -32802 / -32801 | Local file-permission/path/hook-loading issues (info leak, local privesc) | 2025-05-28 |
| CVE-2019-6474 | Malformed client request causes exit on restart | 2019-08-28 |
| CVE-2019-6473 | Invalid hostname option terminates kea-dhcp4 | 2019-08-28 |
| CVE-2019-6472 | Malformed DUID packet terminates kea-dhcp6 | 2019-08-28 |
| CVE-2018-5739 | Memory leak exhausts resources | 2018-07-11 |
| CVE-2015-8373 | Unexpected termination on a malformed packet | 2015-12-22 |

**8 of 11 are crash/DoS from parsing attacker-controlled input** — the exact class this section is about — and the most recent one is four months old at the time of writing, in a project with a dedicated security team and over a decade of production hardening. This is direct, current evidence that "fuzz the parser, contain the panic" isn't defense against a hypothetical; it's defense against the single most common failure mode this entire protocol family has.

**Fuzzing found three of them here in under a minute.** `services/dhcp/mantis-dhcp/fuzz/` (cargo-fuzz, added this pass) targets the exact two calls `main.rs`/`bin/mantis-dhcp6.rs` make on every unauthenticated UDP packet: `dhcproto::v4::Message::decode` and, for v6, this codebase's own hand-rolled `unwrap_relay` (`server6.rs`) feeding into `dhcproto::v6::Message::decode`. A ~20-second run against each found:

| Where | Panic | Release-build impact |
|---|---|---|
| `dhcproto-0.15.0/src/v4/options.rs:706` | `debug_assert!(len == 3)` on `ClientNetworkInterface` (option 94) | Masked — `debug_assert!` compiles out under this workspace's release profile (`services/dhcp/Dockerfile:15` builds `--release`, and no `[profile.release]` override enables debug-assertions) |
| `dhcproto-0.15.0/src/v4/options.rs:735` | `debug_assert!(len == 4)` on a different fixed-length option | Masked, same reason — a *second*, independent instance of the same pattern, suggesting more exist unfound |
| `dhcproto-0.15.0/src/v6/options.rs:653` | `attempt to subtract with overflow` on an attacker-controlled length | Masked, and — checked, not assumed — its downstream consequence doesn't crash a release build either: the DHCP testbench (`testbench/dhcp`, `t_fuzzer_found_crash_is_contained_not_fatal6`) sends this exact input at a real `--release` build and the daemon answers a normal SOLICIT right afterward with `dhcp6_handler_panics_total` unmoved. An earlier draft of this row guessed the wrapped garbage length would "very likely" trip a second, non-maskable bounds-check panic; it doesn't, at least not here — corrected rather than left as an unverified guess |

None of these are fixed in this codebase (they're in the `dhcproto` dependency, not our code) and none are reported upstream as part of this pass. What *is* fixed here is the reason it's survivable regardless of whether any given bug happens to be release-masked: `main.rs`'s decode call moved from the recv loop itself into the per-packet spawned task (§26 R7/R2, this pass) specifically because of this finding — decoding above the task-spawn boundary would mean a panic during parsing unwinds through the wildcard socket's own task, which for that socket *is* the process's main task. Tokio's per-task panic isolation (validated both by `main.rs`'s `joinset_isolates_a_panicking_task_and_still_releases_its_permit` unit test with a synthetic panic, and by the DHCP testbench's two `fuzzer_found_crash_is_contained_not_fatal[6]` checks sending these exact real crash inputs at a live `--release` daemon) doesn't care whether a panic came from `debug_assert!`, an overflow check, or a bounds check — it isolates the class, not the instance, which is what makes this the right fix even though none of the three specific bugs found here happen to fire in this project's actual release build.

**Not wired into CI.** The harness exists and is proven to find real bugs quickly; it needs a nightly toolchain and (for the libFuzzer backend) a working `clang`, neither of which this project's stable-toolchain CI currently provisions. Running it here required a throwaway `rustlang/rust:nightly` container. Wiring a short (30–60s per target), bounded fuzz smoke-test into CI is the natural next step and is *not yet done* — tracked as an open item, not silently assumed complete.

**Lease reclamation, against Kea's actual verified defaults** ([kea.readthedocs.io, Lease Expiration](https://kea.readthedocs.io/en/kea-2.2.0/arm/lease-expiration.html)):

| Concept | Kea parameter, verified default | mantis-dhcp | Note |
|---|---|---|---|
| Grace period before an expired-but-recently-active lease's address is handed to a *different* client | `hold-reclaimed-time` = 3600s | `expired_hold_s` (`MANTIS_DHCP_EXPIRED_HOLD_S`) = 300s | Built this pass — previously immediate (§22.3 originally deleted an expired lease the instant `expires_at` passed, with no hold at all). 300s, not 3600s: covers a lost RENEW/REBIND retry (seconds to low minutes per RFC 2131 timers) without holding a small pool's addresses idle for an hour. The schema had already reserved state value 2 for exactly this ("expired-reclaimed", `models.py`'s `DhcpLease.state` comment) before this pass wired it up — see below. |
| Rows processed per reclamation pass | `max-reclaim-leases` = 100 | `reclaim_batch_limit` (`MANTIS_DHCP_RECLAIM_BATCH_LIMIT`) = 1000 | Built this pass — previously unbounded (a single `DELETE` with no `LIMIT`, §26 R7). Not directly comparable 1:1: Kea's one number bounds one combined pass; mantis-dhcp applies the same bound independently to three steps (state 0→2 mark, state 1 probation-delete, state 2 hold-delete) via a `ctid IN (SELECT ... LIMIT n)` subquery each. |
| Wall-clock cap per reclamation pass | `max-reclaim-time` = 250ms | 🚧 not built | Only row-count is bounded, not wall-clock time. A real gap: a batch of 1000 rows could still take longer than 250ms depending on I/O conditions. Flagged, not fixed this pass. |
| Escalating warning if leases keep going unprocessed | `unwarned-reclaim-cycles` = 5 | 🚧 not built | Every sweep just logs at `debug`/`warn` per-event; no cycle-count escalation. Minor, noted for completeness. |
| Grace period before a *declined* address is reused | `decline-probation-period` = 86400s | `decline_probation_s` (`MANTIS_DHCP_DECLINE_PROBATION_S`) = 86400s | Already matched before this pass; confirmed correct against the real default rather than assumed. |

**Client identity: verified no bug, and mantis-dhcp is structurally safer than Kea's own default here.** Kea's `match-client-id` defaults to **`true`** — client-identifier (option 61) takes precedence over the MAC address unless an operator explicitly sets it to `false` ([search-verified, ISC docs](https://kb.isc.org/docs/understanding-client-classification) and Kea's `dhcp4-srv` reference). That default is exactly the configuration that produces the classic PXE bug: firmware and OS sending different option-61 values for the same physical machine get treated as two different clients, and split into two leases. Tracing every call site in `db.rs`/`server.rs` (this pass, task-scoped verification) confirms `client_id` is stored (`INSERT`/`UPDATE ... client_id = $n`) but never once appears in a `WHERE` clause or an identity comparison anywhere in this codebase — `mac_address` is the sole key for every allocation, renewal, and conflict decision. mantis-dhcp doesn't need an operator to know to flip a setting to avoid this bug; it never offers the riskier option in the first place. No code change — this was already correct, just unverified until now.

**Option 82 (Relay Agent Information) is now echoed.** RFC 3046 §2.2: a server that acts on the option (mantis-dhcp does, for relay-based scope selection, §22.7) must echo it back verbatim in the reply — the relay uses the echoed sub-options to pick which downstream port to forward the reply out of, and strips the option before it reaches the client. Before this pass, `base_reply` built every OFFER/ACK/NAK/INFORM-ACK without it; a reply could be silently dropped by real relay hardware despite this daemon correctly consuming the option on the way in. Fixed in `server.rs::base_reply`, covering all four reply types uniformly since they all flow through it.

**Option 57 (Maximum DHCP Message Size) / option 52 (Overload) — investigated, no equivalent gap found worth the same fix shape.** Neither was read or set anywhere before this pass. Unlike Kea's PXE-heavy deployments, this daemon's own well-known option set (`options::build`) is small — subnet mask, router, DNS, domain name, three lease timers, server id — and its PXE fields (`siaddr`, boot filename) are fixed BOOTP header fields, not variable options competing for the same space, so option 52 overload genuinely has little to do here. The real exposure is operator-added custom `dhcp_options` rows (`options::apply_custom`), unbounded in count/size by design. Rather than truncating or rejecting a configuration a human intentionally set (a much riskier behavioral change), `main.rs` now logs a warning (`warn_if_reply_oversized`) when an assembled reply exceeds the client's own declared option-57 limit, or the classic 576-byte BOOTP/DHCP floor when the client declared none — visibility for the misconfiguration case, not silent enforcement. v6 has no equivalent: RFC 8415 defines no client-max-message-size option, resting instead on IPv6's own 1280-byte minimum link MTU guarantee (RFC 8200) — nothing to replicate there.

**Named owner.** This register exists so the deviations above don't have to be re-discovered from scratch next time someone asks "are we sure this is safe" — but a register is not a substitute for an actual owner. §26 R8's ask for a named owner for the CVE-monitoring/fuzzing process is still open.

---

## 23. Fleet Observability — Per-Node Statistics

> **🪓 Sequencing changed 2026-07-25 (§26.10).** This epic is correct and still
> ships, but not next. Two things must land first: a performance bench (§26 R7
> — this section adds per-query instrumentation to the hottest path in the
> product, and no benchmark exists to prove FO6 "zero measurable cost"), and
> per-node credentials (§26 R3 — the heartbeat this section defines is one more
> thing forgeable with the fleet's single shared token). See §16 phases 11–13
> and sprint-plan.md's Epic P/Q/O ordering.

Every other subsystem in this document has an operator-facing surface in the UI. The filter fleet — the only component actually on the DNS hot path — has none. A filter node today is anonymous: `telemetry.rs`'s event payload carries `group_id`, `client_ip`, `qname` and decision context but nothing identifying **which node** produced it, so every row in `query_events` looks like it came from the same nowhere. The Prometheus exporter that once lived in `metrics_init.rs` was removed outright (the file no longer exists — see §14's Metrics row) — "observability handled via the control plane telemetry API" was the stated reason, but that API only ever grew query analytics, never node analytics. The result is that the three questions an operator actually asks during an incident have no answer anywhere in the product:

- *Is every node enforcing the same policy?* A node stuck on an old bundle keeps answering queries, correctly signed and verified, using yesterday's block lists. Nothing anywhere reports a bundle version per node (§11 lists stale-bundle alerting as 🚧).
- *Is one node behaving differently from the rest?* Version skew after a partial rolling upgrade, a SERVFAIL spike confined to one host, a 90/10 traffic split from anycast/VIP misrouting — all invisible.
- *Are the numbers in Analytics even complete?* `TelemetryEmitter::emit` drops events on a full channel with a `warn!` and nothing else. When the control plane is slow or unreachable, the Analytics dashboard and every SIEM export path silently under-report, and the only trace is a line in the node's own journal.

That last one is the sharpest: an observability gap that quietly corrupts the observability that does exist.

mantis-dhcp already solved the *identity* half of this problem (§22.11, `dhcp_daemon_heartbeats`) and the *counters* half (§22.11, opt-in `/metrics` with in-process relaxed atomics). This section applies both to the filter fleet rather than inventing a third idiom, and adds the piece neither has: a fleet view in the UI.

---

### 23.1 Requirements

| ID | Requirement |
|---|---|
| FO1 | Every filter node is individually identifiable and its liveness visible in the UI, with the same stale-not-pruned semantics as `dhcp_daemon_heartbeats`. |
| FO2 | Policy-bundle and upstream-bundle version **per node**, so config skew across the fleet is a glance, not an investigation. |
| FO3 | Query pressure per node: QPS, latency distribution, cache effectiveness, rcode mix, block ratio. |
| FO4 | Telemetry drop count is a first-class, visible number — never only a log line. |
| FO5 | Per-node upstream health, so a divergence between nodes (A says a resolver is dead, B says it's fine) is diagnosable without SSH. |
| FO6 | Zero measurable cost on the DNS hot path. Currently **unverifiable**, not just unmet — see §26 R7. Existing hot-path code already has an uncaught regression (`ZoneStore::lookup` allocates a `String` per configured zone on every single query, §24.3/§26 R7) that a bench would have caught; §23 must not add more instrumentation to that path before one exists. |
| FO7 | No new authentication surface on the node, and no requirement that the control plane be able to reach the node. Note this doesn't fix §26 R3 (the shared fleet-wide token) — it just means this section isn't the place that fixes it either; Epic P is. |
| FO8 | Fleet topology is operator data, not tenant data — tenant-scoped users must not see it at all. |
| FO9 | One counter set feeding both the UI and any Prometheus scrape; no second, driftable copy. |

---

### 23.2 Node identity

`MANTIS_NODE_NAME`, falling back to `/proc/sys/kernel/hostname` — the same best-effort helper mantis-dhcp uses (`mantis_dhcp::hostname`, copied rather than shared: a two-line `read_to_string` is not worth a crate dependency from filter onto the DHCP engine).

The env var is not optional cosmetics. mantis-dhcp gets away with bare hostname because it runs `network_mode: host` (§22.6), so its hostname is the real host's. mantis-filter has no such constraint and is routinely containerised or run as a sidecar, where the hostname is a random 12-hex-digit container id that changes on every restart — which would make the fleet table a graveyard of dead one-shot rows. `MANTIS_NODE_NAME` set to something stable and meaningful (`filter-vpn-gw-01`) is the documented deployment requirement for any non-host-networked install; the hostname fallback covers the LXC/systemd profile (§17) where it is already correct.

Identity is `(node_name)` alone — unlike the DHCP daemons there is no `family` axis, and unlike a per-boot UUID a restart must take over the *same* row rather than leaving a dead one beside it. `started_at` moving forward is what marks a restart; `instance_id` is refreshed on takeover so a counter reset is unambiguous rather than looking like a wrapped counter.

---

### 23.3 What a node measures

**In-process, relaxed atomics** (`services/filter/mantis-filter/src/node.rs`), mirroring `metrics.rs`'s `Counters` in mantis-dhcp:

```rust
pub struct NodeStats {
    // Monotonic counters — control plane diffs consecutive heartbeats for rates.
    queries_total:      AtomicU64,
    blocked_total:      AtomicU64,
    allowed_total:      AtomicU64,
    stub_zone_total:    AtomicU64,
    cache_hits:         AtomicU64,
    cache_misses:       AtomicU64,
    rcode_noerror:      AtomicU64,
    rcode_nxdomain:     AtomicU64,
    rcode_servfail:     AtomicU64,
    rcode_refused:      AtomicU64,
    rcode_other:        AtomicU64,
    telemetry_dropped:  AtomicU64,
    no_bundle_servfail: AtomicU64,
    cache_evictions:    AtomicU64,
    // Coarse log2 latency histogram: bucket i covers [2^i, 2^(i+1)) us,
    // i = 63 - leading_zeros(us), clamped to 0..15. Top bucket is >=32ms.
    latency_buckets:    [AtomicU64; 16],
}
```

**The single instrumentation point is `TelemetryEmitter::emit`.** Every call site that resolves a query already hands `emit` exactly the fields these counters need — `decision`, `response_code`, `cache_hit`, `latency_us` — so `NodeStats::record()` is called once at the top of `emit`, *before* the `try_send`, and the whole rest of `lib.rs` is untouched. This is deliberate: scattering counter bumps through `build_response_inner` would be more code, more merge-conflict surface, and would risk a future decision path being added without its counter. It also means counters stay accurate when the telemetry channel is saturated — the drop path bumps `telemetry_dropped` and the query is still counted, so a node under backpressure reports *more* signal, not less.

Two paths do not flow through `emit` and get an explicit one-line bump each:

- The bootstrap/unmatched-route `ServFail` early return in `build_response_inner` (the `bootstrap_fail_open()` branch) — the one case where a node is answering *nothing* usefully, which is precisely what an operator needs to see.
- `DnsCache::insert`'s eviction branch, for `cache_evictions`.

**Sampled at heartbeat time, not tracked continuously** — same reasoning as §22.11's pool-utilisation gauges (compute where it's cheap, don't keep a second copy that can drift):

| Field | Source |
|---|---|
| `cache_entries` | new `DnsCache::len()` — one read lock per 10 s |
| `rss_kb`, `open_fds` | `/proc/self/statm`, `/proc/self/fd` — best-effort, `None` on non-Linux |
| `policy_bundles[]` | `{group_id, version, age_s}` per `BundleStore` (one in single-tenant mode, one per tenant under `TenantRouter`) |
| `upstream_bundles[]` | `{tenant_id, version}` from `UpstreamBundleStore` |
| `upstream_members[]` | `HealthStore::snapshot(pool, resolver)` per member of the live upstream bundle → `{pool_id, resolver_id, healthy, latency_ema_us, consecutive_failures}` |
| `key_pin_configured` | `MANTIS_CONTROL_PUBLIC_KEY_SHA256` non-empty |
| `build_version` | `env!("CARGO_PKG_VERSION")` |

The `upstream_members` block is the payoff for FO5. `HealthStore` is explicitly per-node and uncoordinated by design (§21.4 — "no shared health state to avoid distributed coordination on the hot path"), which is the right call for resolution and exactly the wrong property for diagnosis: the *divergence* between nodes' independent verdicts is the diagnostic signal. Node A alone calling a resolver dead means A's egress path is broken, not the resolver. Shipping the verdicts read-only to the control plane keeps the hot path uncoordinated while making the divergence visible.

**Not in v1: in-flight query count.** It is the truest saturation signal, but it is the one metric that cannot be derived at the `emit` choke point — it needs an increment/decrement guard around request handling in both `run_udp_server` and `run_tcp_server` (and their router-mode twins), which is the hot-path scatter this design otherwise avoids. QPS plus p99 latency covers saturation adequately for a first cut. Deferred, marked in code.

---

### 23.4 Transport — push, not scrape

The node POSTs to `POST /api/v1/nodes/heartbeat` every 10 s, authenticated by `MANTIS_SERVICE_TOKEN` via the existing `with_service_token` helper — the same channel and the same credential `/query-events`, `/routing-table` and `/public-key` already use. No new listener, no new credential, no new port to firewall (FO7).

Push rather than scrape, despite §22.11 having gone the other way for DHCP, because the constraints differ:

- The UI tab needs the data **in Postgres**. A Prometheus endpoint on the node cannot feed a control-plane API; adopting scrape-only would mean the fleet tab is available only to deployments that also run Prometheus *and* wire it back, which is not a product feature.
- Filter nodes are routinely deployed behind NAT (small-site Proxmox CTs, §17), where control-plane-initiated connections are the awkward direction. The node already dials out every 10 s for bundles.

The heartbeat body is the full counter snapshot (absolute values, not deltas) plus the sampled gauges. Absolute values mean a lost heartbeat costs resolution, not correctness — the next one still diffs correctly against the last stored sample, which a delta-based protocol could not do.

Failure is silent and non-fatal by exactly the same rule as telemetry flush: a node whose control plane is down must keep resolving DNS. `warn!` and move on.

---

### 23.5 Data model

```python
class FilterNodeHeartbeat(Base):
    """Liveness + load snapshot for a running mantis-filter instance
    (design.md §23). Identity is `node_name` (MANTIS_NODE_NAME, else
    hostname) — a restart takes over the same row rather than leaving a
    dead one beside it, same reasoning as DhcpDaemonHeartbeat's
    (hostname, family). Rows are never auto-pruned: a stale row *is* the
    signal an operator wants to keep seeing.

    Counters are the node's absolute monotonic values as of `last_seen_at`;
    `prev_stats` holds the previous sample so rates come from a stored pair
    rather than a time-series table. An `instance_id` change means the
    process restarted and counters reset — the rate calculation must return
    None for that interval, not a negative or absurd rate.
    """
    __tablename__ = "filter_node_heartbeats"

    node_name:          Mapped[str] = mapped_column(String(255), primary_key=True)
    instance_id:        Mapped[str] = mapped_column(String(36))
    build_version:      Mapped[str] = mapped_column(String(32))
    started_at:         Mapped[datetime]
    last_seen_at:       Mapped[datetime]
    prev_seen_at:       Mapped[datetime | None]
    key_pin_configured: Mapped[bool]
    # Whole snapshot as posted, plus the previous one. JSONB, not 30
    # columns: these are display-only aggregates read as a unit by exactly
    # one endpoint, never filtered or joined on, and the field set will
    # keep moving as metrics are added. A column per counter would mean a
    # migration per metric for zero query benefit.
    stats:              Mapped[dict] = mapped_column(JSONB)
    prev_stats:         Mapped[dict | None] = mapped_column(JSONB, nullable=True)
```

JSONB for the counter payload is a deliberate exception to this codebase's otherwise strongly-typed schema, justified narrowly: it is never a query predicate, never joined, never aggregated in SQL, and read whole by a single endpoint. The Pydantic model on the ingest side still validates every field, so the typing lives where it matters — at the trust boundary — rather than in DDL that would need a migration each time a counter is added.

`query_events.node_id` — `String(64)`, nullable, **no index in v1**. Sent once per batch (`QueryEventBatch.node_id`, not per event: a 500-event flush would otherwise repeat the same string 500 times on the wire) and stamped onto each row. It unlocks per-node time-series by reusing the existing `/analytics/*` endpoints with one extra filter, which is why it lands now rather than later. The index is deferred until a per-node analytics query actually ships: `query_events` is the highest-volume table in the system and the one retention already has to work hardest on (`retention.py`), so an index nothing reads yet is pure write cost.

---

### 23.6 API

`services/control/mantis_control/api/node_routers.py`:

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/v1/nodes/heartbeat` | `require_service_token` | Upsert on `node_name`, rotating `stats` → `prev_stats`. Returns `202`. |
| `GET /api/v1/nodes` | `require_role("operator")` | Every filter node plus every DHCP daemon row, one unified shape, with rates computed and skew flags set. |

`GET /api/v1/nodes` returns a `role` discriminator (`"filter"` / `"dhcp4"` / `"dhcp6"`) and folds in `dhcp_daemon_heartbeats` rather than making the UI call two endpoints and reconcile two shapes. The DHCP rows populate only the identity/liveness fields; load counters are `null` for them. Staleness uses the same 3×-cadence rule as §22.11 — 30 s for both, since both heartbeat every 10 s.

Rates are computed server-side from the `(prev_stats, prev_seen_at)` / `(stats, last_seen_at)` pair, and are `null` — never zero, never negative — when `instance_id` changed between samples or when `prev_stats` is absent. Latency percentiles are interpolated linearly within the log2 buckets and reported as such; they are approximate by construction and the UI labels them `~p95`, not `p95`. An honest approximation beats a precise-looking number derived from a histogram that cannot support it.

Fleet-level flags are computed in the same response, since they are properties of the set rather than of any row: `bundle_version_skew` (any node's policy-bundle version behind the fleet max for its group), `build_version_skew`, and `traffic_share` per node.

---

### 23.7 UI — Nodes page

New top-level nav entry in `Shell.tsx`, `minRole: "operator"`, between `/upstream` and `/dhcp` — it belongs with the infrastructure pages, not with the tenant-facing analytics ones.

`pages/NodesPage.tsx`, one table, one row per node, no tab bar: filter and DHCP daemons are both "a process that should be alive on a host", and splitting them into tabs would hide exactly the correlation an operator wants (the filter node and the DHCP daemon on the same host both went stale ten seconds ago). Columns: node, role, status badge, build, bundle version + age, uptime, QPS, ~p95, cache hit %, block %, SERVFAIL rate, traffic share.

Skew and drop conditions surface as banners above the table, not as a column someone has to notice: *"2 nodes on policy bundle v41, fleet is on v43 (oldest 2 h 14 m)"*, *"filter-gw-03 dropped 12,847 telemetry events in the last hour — Analytics and SIEM export are under-reporting for this node"*. A per-row expansion carries the detail: rcode breakdown, latency histogram, per-tenant bundle list, and the upstream member health matrix from FO5.

The DHCP Status tab's existing per-instance badge stays where it is; it is scope-local context on a page about DHCP, and duplicating rather than moving it costs nothing.

---

### 23.8 Prometheus

`NodeStats` is exposed at an opt-in `/metrics` endpoint on the filter node under `MANTIS_FILTER_METRICS_BIND_ADDR` — same convention, same default-disabled posture, and the same axum-based text-exposition shape as mantis-dhcp's `metrics.rs`. This is not a second metrics system: it is a second *reader* of the one `Arc<NodeStats>` the heartbeat task also reads (FO9), roughly thirty lines. It restores what `metrics_init.rs` removed, without reintroducing the split-brain of two independent counter sets — and it means the fleet tab and an existing Grafana stack agree by construction.

A control-plane-side fleet aggregate endpoint (the whole fleet's last-known snapshot re-exported as Prometheus text from one URL, avoiding per-node scrape reachability entirely) is a natural follow-on and explicitly not in this sprint.

---

### 23.9 Security

- **RBAC**: `operator` on `GET /api/v1/nodes`, verbatim the reasoning `/api/v1/dhcp/health` already carries — hostnames, build versions, bundle versions and fleet topology are infrastructure data, not tenant-scoped data. A tenant-scoped user gets `403`, not a filtered list: an empty-but-successful response would still leak the existence of the fleet view, and there is no tenant-relevant subset of this data to return.
- **Ingest auth** is `require_service_token` — identical trust tier to `/query-events`. A leaked service token could already forge query events; it can now additionally forge a node's stats. That is a strict subset of the existing blast radius, not a new tier.
- **`node_name` is node-supplied and therefore attacker-controlled** given a compromised token. It is length-bounded at ingest, and it is never interpolated into SQL, a shell, or a filesystem path — it is a primary key and a React text node. Worth stating explicitly because "the node tells us its own name" is exactly the shape of input that gets trusted by accident later.
- **No secrets in the payload.** `key_pin_configured` is a boolean, never the pin. The bundle version is an integer, never bundle content.

---

### 23.10 Retention

Heartbeat rows are never auto-pruned, for §22.11's reason: a stale row *is* the signal. At one row per node the table is bounded by fleet size, and a decommissioned node is deleted by an operator — an explicit act, so that a node that vanished because it *died* can never be mistaken for one that vanished because it was retired.

No time-series table for node metrics. The pair-of-samples design gives current rates, and once `query_events.node_id` is populated the existing `/analytics/timeseries` provides real per-node history from data already being stored under an existing retention policy. Adding a second, separately-retained metrics table to answer a question an existing table already answers is the kind of thing that looks free at design time and turns into a retention job, a partitioning decision and a disk alert.

---

### 23.11 Deliberately out of scope

- **In-flight query gauge** — §23.3; needs hot-path scatter that nothing else in this design needs, and QPS + p99 covers it for now.
- **Alerting.** Every input an alert rule wants (node down, stale bundle, SERVFAIL spike, telemetry drops > 0, block-ratio anomaly) is now computed and exposed; turning them into notifications is §11's 🚧 alerting work, which needs a delivery-channel decision this section has no opinion on. Banners in the UI are the v1 answer.
- **Per-tenant or per-group counter labels** on node stats. Cardinality on the node grows with tenant count and the hot path pays for it; the same breakdown is already available from `query_events`, where it costs nothing extra.
- **Node control actions** (drain, restart, force bundle refresh from the UI). Read-only observability first; a write path to the fleet is a separate security surface and a separate design.
- **Cross-node cache or health coordination.** §21.4's uncoordinated-by-design property is deliberate; this section observes the divergence, it does not resolve it.

---

## 24. DNS Zones — Authoritative Local Records

Every deployment that runs DHCP also wants its own names: `printer.lan`, `nas.corp.example.com`, a wildcard for an internal app. Forwarding those to a public resolver either leaks internal topology or returns NXDOMAIN. This section covers the authoritative local-zone feature — the answer path that runs *before* policy and upstream routing, and the DNS half of the DHCP→DNS integration described in §22.4.

Shipped ahead of the sprint sequence (see sprint-plan.md, "Shipped outside the sprint sequence"), which is why it carries no epic number.

---

### 24.1 Data model

```python
class DnsZone(Base):                     # dns_zones, UNIQUE (tenant_id, name)
    id, tenant_id (FK tenants, nullable) # NULL = admin-only global zone
    name          str(255)               # "lan", "corp.example.com" — lowercased, no trailing dot
    zone_type     str(20)                # "local" — only value enforced; "forward"/"passthrough"
                                          # still exist in code pending removal, see below
    description, enabled, ttl_default    # ttl_default 300s, inherited by records with ttl=NULL

class DnsRecord(Base):                   # dns_records, FK → dns_zones (cascade delete)
    name          str(255)               # "@" (apex), "www", "*", "mail"
    record_type   str(10)                # A AAAA CNAME MX TXT NS PTR SRV CAA
    ttl           int | null             # NULL → inherit zone.ttl_default
    data          str(1024)
    priority      int | null             # MX / SRV
    enabled       bool
    ddns_owner_mac   str(17)  | null     # set only by the v4 DDNS bridge
    ddns_owner_duid  str(128) | null     # set only by the v6 DDNS bridge
```

**`forward`/`passthrough` zone types are cut (§26.9)** — they fully overlap §21.2's already-enforced `domain_suffix` upstream routes. `zone_type` and `forwarder` still exist in the schema/API/UI pending a follow-up code change to remove them; treat both as dead going forward, not as a feature to build against.

**`ddns_owner_*` is the security-relevant field.** A record created through the zone-editing API has both owner columns `NULL`, and the DDNS bridge must never overwrite such a record. A record created by DDNS carries the MAC (v4) or DUID (v6) of the client that owns the name, and an event from a *different* client is rejected. Without this, any DHCP client could set its hostname option to `printer` and hijack that name's A record — the DHCP hostname option being fully attacker-controlled (§22.12). Enforcement lives in `dhcp_internal_routers._upsert_a_record`.

---

### 24.2 Distribution to the filter node

`GET /api/v1/local-zones?group_id=…` (`require_service_token`) returns the group's tenant's enabled `local` zones flattened to one row per enabled record, with the owner name already expanded to an FQDN (`@` → the zone apex, otherwise `name.zone`) and TTLs already resolved against `ttl_default`. Filter nodes poll it on the same machine-to-machine cadence and with the same service-token credential as `/routing-table` and the policy bundle — no user JWT, no new listener.

Flattening server-side is deliberate: the node holds a lookup table, not a zone hierarchy, so apex expansion and TTL inheritance are computed once in Python rather than reimplemented in Rust with a second chance to diverge.

Unlike the policy bundle, this payload is **not** ed25519-signed — it is fetched over the same authenticated channel as the routing table, which is also unsigned. That is a consistency argument, not a security one: if the bundle's signature is worth having against a compromised distribution path, this payload has the same exposure. Recorded as a real asymmetry rather than a decision.

---

### 24.3 Answer path (filter node)

`zone_store.rs` holds an `ArcSwap<ZoneData>`: a list of zone apex names plus a `HashMap<normalized_owner_name, Vec<Record>>`. Lookup is three-valued:

| Result | Meaning | Node behaviour |
|---|---|---|
| `NotLocal` | qname falls outside every hosted zone | fall through to the normal Bloom-filter decision + upstream forward |
| `Answer(records)` | name is inside a local zone; empty vec = the name exists but has no record of the queried type | answer authoritatively (empty ⇒ NODATA) |
| `NxDomain` | name is inside a local zone but exists at no type | authoritative NXDOMAIN, **no upstream fallback** |

The NODATA/NXDOMAIN distinction is the part worth stating: a name that exists with only unsupported record types still gets a (possibly empty) map entry, so it reads as NODATA rather than NXDOMAIN. Collapsing the two would tell a client the name does not exist when it does, and clients cache the two negative answers differently.

This check runs early in `build_response_inner`, before route evaluation and before the Bloom lookup — so a locally-hosted name can never be blocked by a category feed, and never incurs upstream latency. Telemetry records `decision = "stub_zone"`, `matched_rule = "stub_zone"`, which is what makes local-zone traffic separable in Analytics and in SIEM export. See §21.6 for how this diverges from the originally-designed `stub_zone` route type.

Records whose `name` or rdata fails to parse are skipped with a `warn!` rather than failing the whole refresh — one malformed row must not take the zone offline.

---

### 24.4 API and UI

`zone_routers.py` (`tags=["dns-zones"]`):

| Endpoint | Auth |
|---|---|
| `GET /api/v1/dns-zones`, `GET /dns-zones/{id}`, `GET /dns-zones/{id}/records` | authenticated, tenant-filtered |
| `POST/PATCH/DELETE /dns-zones`, `.../records` | `require_role("operator")` |
| `GET /dns-zones/{id}/export` | authenticated, tenant-filtered — BIND-format zone file download |

Every mutation writes an audit-log entry (`dns_zone.create` / `.update` / `.delete` and the record equivalents). Tenant scoping goes through `_get_zone_or_403`; a zone with `tenant_id = NULL` is admin-only.

UI: `ZonesPage.tsx` (zone list, create/edit, export) and `ZoneDetailPage.tsx` (record editor), nav entry `/zones` with no `minRole` — visible to any authenticated user, with mutations gated server-side at `operator`.

---

### 24.5 Security

The zone-file export is the sharp edge, and both defences exist in code:

- **Zone names** are constrained to a hostname/label-sequence regex (`_ZONE_NAME_RE`). `export_zone` writes the zone name verbatim into `$ORIGIN`/SOA/NS lines *and* into the `Content-Disposition` header, so an unvalidated name could inject a CRLF into the header or an `$INCLUDE /etc/passwd` directive into a file explicitly meant to be handed to a real nameserver.
- **Record `name` and `data`** are rejected at write time if they begin with `$` (`_validate_record_field`). BIND-family loaders treat a leading `$` as a control directive, and both fields are written as the first two fields on their line. No legitimate owner name or rdata needs a leading `$`, so this is rejected on input rather than escaped on output — one rule at the trust boundary instead of an escaping rule every future writer has to remember.
- **Defence in depth on export:** newlines and `$` are additionally stripped from the zone name at export time, covering rows written before `_ZONE_NAME_RE` existed.
- **DDNS ownership** — §24.1's `ddns_owner_mac`/`ddns_owner_duid`, enforced in `dhcp_internal_routers.py`.

---

### 24.6 Not built

- ❌ **`forward` and `passthrough` zone types** — cut, see §24.1. Not a gap to fill; a type set to remove.
- 🚧 **Zone file import.** Export exists; there is no `$ORIGIN`-parsing import path, which is the harder and more dangerous direction.
- 🚧 **DNSSEC signing of local zones.** Answers are unsigned; §21.5 concerns validation of *upstream* answers, not signing of ours.
- 🚧 **Secondary / AXFR.** No zone transfer in either direction — the control plane is the only source and filter nodes poll it.
- 🚧 **Signed local-zone payload** — §24.2.

---

## 25. Block Page

When a query is blocked, `NXDOMAIN` tells the user nothing. The block page turns a block into an explanation: which category matched, which policy, who to ask for an exception.

The full design — template model, resolution order, branding fields, the HTTP listener, and the reasoning behind serving it from the filter node rather than the control plane — is in **[`design-block-page.md`](design-block-page.md)**, written before this section existed and not duplicated here. This section exists so the feature is discoverable from the main design document.

What is built:

- **Per-group template with tenant-wide default fallback.** `resolve_block_template` (`block_page.py`) resolves a group's own override, else the tenant default (`group_id IS NULL`), else none. Both the policy compiler (which needs the hot-path fields — mode, redirect target, TTL) and the filter node's block-page listener (which needs the branding fields) call the same resolver, so the two can never disagree about which template applies.
- **Block modes:** `BLOCK_MODE_NXDOMAIN`, `BLOCK_MODE_ZERO_IP`, `BLOCK_MODE_REDIRECT`. Only `REDIRECT` reaches the block page; the other two answer at the DNS layer and never involve HTTP.
- **Filter-node listener** (`blockpage.rs`), bound via `BLOCKPAGE_BIND_ADDR` (blank = disabled — the same opt-in convention as mantis-dhcp's `/metrics`, §22.11). Serving it from the node keeps the redirect target on the host that answered the query, so a blocked client never needs to reach the control plane.
- **Branding:** logo, text, colours, contact address, editable per template. Migrations `b3f1c2a90d4e` (templates) and `fc7584542ce8` (logo/text).
- **UI:** `BlockPageCard.tsx` with a live preview; `GET/PUT /api/v1/groups/{group_id}/block-page-template`.

Like §24, this shipped outside the sprint sequence and carries no epic number.

---

## 26. Architecture Review — Foundation Risks (2026-07-25)

A chief-architect pass over the codebase against an enterprise deployment
bar, done after §1–§25 were brought current with what's actually built. The
core engineering holds up: plane separation, ed25519 bundle signing,
DB-coordinated DHCP HA. What doesn't hold up is the enterprise story sitting
on top of it — and Epic O (§23) was about to make that worse by adding a page
to a console that can't yet be safely operated at scale, on a hot path that's
never been benchmarked.

Each risk below is stated with what's actually in the code, why it matters in
an enterprise deployment specifically (not in general), and a fix direction.
§26.9–§26.11 turn this into a re-sequenced delivery path — see
sprint-plan.md's Epic P / Epic Q / Epic O for the sprint-level breakdown.

---

### 26.1 R1 — Bloom false positives block real domains, with no confirmation tier

§15 already named this risk ("pair with exact-match confirmation tier for the
(rare) FP on block-critical lists") — it was never built. `mantis-policy`'s
own doc comment says a bloom check can yield "false negatives, possible false
positives", and a positive goes straight to a block with no second check.

**Why it matters here specifically:** an FP is non-deterministic across
tenants (different bundle, different bits) and unreproducible by support —
"the payment processor is unreachable, but only for us, and only sometimes"
is not a debuggable ticket. §4e873b3's fixed FP-rate bug shows this isn't
hypothetical.

**Fix:** on a bloom hit, check a sorted/`fst` exact-match set before
blocking. Bloom becomes the fast *negative* filter it should always have
been; the exact check only costs anything on the (minority) block path.

---

### 26.2 R2 — Postgres is a hard dependency for DHCP lease allocation

DNS survives control-plane loss by design (last-good bundle, §21.3). **DHCP
does not.** Every REQUEST takes a `pg_advisory_xact_lock` inside a
transaction (§22.3) — Postgres down means no lease, means a device cannot
join the network at all, full stop.

**Why it matters here specifically:** this is a regression against the Kea
integration it replaced, which served leases from a local file. §22.6 sells
DB-coordinated allocation as "the entire HA story" — it is also the entire
single-point-of-failure story, and there's a single Postgres instance with no
Patroni behind it (§6, §14).

**Fix:** local lease cache serving renewals when the DB is unreachable, or
make Postgres HA non-optional in the reference deployment. As shipped, the
product's availability floor for DHCP is one `postgres` process.

---

### 26.3 R3 — One shared service token for the entire fleet

`MANTIS_SERVICE_TOKEN` is a single static string
(`auth.py::require_service_token`, `hmac.compare_digest` against one
configured value) used by every filter node and every DHCP daemon in the
fleet. No per-node identity, no scoping, no rotation, no revocation.

**Why it matters here specifically:** compromise one filter node in one
branch office and the attacker holds fleet-wide credentials — every tenant's
bundle, forged query events, poisoned analytics and SIEM export. §23's
heartbeat (once built) adds heartbeat forgery to that list, which is exactly
why §23 is sequenced after this fix, not before it (§26.10).

**Fix:** per-node credential — mTLS client cert or, at minimum, a per-node
token — with rotation and revocation. §9 already lists mTLS as 🚧; this is
the concrete reason it's worth building rather than aspirational polish
(§14's Security row updated accordingly).

---

### 26.4 R4 — Tenant isolation is application-code-only

No Postgres row-level security anywhere in the schema. Every tenant-scoped
query relies on a developer remembering to call `user_tenant_filter` /
`check_tenant_access` (`auth.py`) — across 16 router modules.

**Why it matters here specifically:** this is a multi-tenant MSP product. One
missed filter on one endpoint is a silent cross-tenant data leak, and nothing
in the codebase or CI would catch it before a customer does.

**Fix, cheapest first:** a test that enumerates every tenant-scoped route and
fails if it doesn't apply the filter. Then Postgres RLS as defense in depth,
so the DB itself is the backstop rather than only application discipline.

---

### 26.5 R5 — Signing is inconsistent, so it's partly theater

The policy bundle is ed25519-signed (`crypto.py`, §21.3). `/routing-table`
and `/local-zones` (§24.2) are fetched over the same authenticated channel
but are **not** signed.

**Why it matters here specifically:** the routing table decides which
tenant's policy a client receives in the first place — poisoning it is at
least as damaging as poisoning the bundle it routes to. If the threat model
that justifies bundle signatures is real, it applies here too; if it isn't,
the bundle signature is ceremony rather than defense.

**Fix:** sign `/routing-table` and `/local-zones` the same way, or explicitly
document why they're excluded from the threat model the bundle signature
defends against. Either answer is fine; the current silent inconsistency
isn't.

---

### 26.6 R6 — Query logs are PII and there's no compliance story

The client registry (`ClientEntry`, §20.6) maps IP → hostname →
**`owner`** (a person's name) → device type and tags, and that gets embedded
in every SIEM export. That's per-person browsing history with an identity
attached, for every DNS query.

Retention is a single global setting (`QUERY_EVENT_RETENTION_DAYS`,
`retention.py::prune_query_events`) — not per-tenant, so a tenant in a
stricter jurisdiction gets the same retention window as one with none.
There's no right-to-erasure endpoint, no field-level encryption on the
registry's PII columns, and no data-residency control (§15 already flags
residency as an open risk; the client registry made the exposure concrete
rather than resolving it).

**Why it matters here specifically:** for any EU customer this is not a
🚧-someday item — it's a sales blocker and, if mishandled, a legal one.

**Fix:** per-tenant retention override, a right-to-erasure path (delete/
anonymize a `ClientEntry` and its associated `query_events`), and
documentation of the residency story per deployment profile.

---

### 26.7 R7 — No control-plane ↔ filter-node version contract, and no perf benchmark to protect it

`gen:api:check` (UI CI) catches drift between the OpenAPI schema and the
generated TypeScript client. **Nothing equivalent exists between the control
plane and the filter/DHCP binaries** — no protobuf breaking-change gate in
CI, no schema version carried in the bundle, no compatibility matrix. Upgrade
the control plane while twelve nodes are still on the old binary and the
result is undefined, not degraded.

Separately, and just as structural: **there is no performance benchmark
anywhere in this repository.** No `benches/` directory, no perf job in CI,
and the "Sprint 4 baseline" the sprint plan's Cross-cutting section and
Epic O's exit criteria both cite as the regression gate was never recorded.
Every "10% p99 gate" reference in this document has nothing to compare
against.

That gap is not theoretical — it already let a real regression through
unnoticed. `zone_store.rs::ZoneStore::lookup` runs on **every** query before
cache or policy, and its `is_local` check does this:

```rust
data.zones.iter().any(|z|
    qname == *z || qname.ends_with(&format!(".{z}")))
```

`normalize(qname)` allocates a `String` up front, and `format!(".{z}")`
allocates a second `String` **per configured zone, per query** — evaluated
in full for every query that *isn't* local, i.e. close to 100% of real
traffic. Fifty zones means fifty-one allocations before any actual filtering
work starts. The fix is small (`qname.strip_suffix(z)` guarded by a leading
`.`, or a precomputed suffix set) — the point is that a regression this
obvious sits in the hot path of a DNS resolver and nothing in CI could have
caught it.

**Fix:** stand up a bench harness and a recorded baseline first (this is
Epic P's first sprint, precisely so §23's per-query instrumentation has
something to be checked against before it ships), fix the zone-lookup
allocation as part of standing it up, then add a protobuf compat gate and a
schema version field to the bundle format.

---

### 26.8 R8 — Owning DHCPv4 + DHCPv6 is a bigger bet than §22.1's rewrite case admits

§22.1's case for replacing Kea is about *integration* cost — a broken
`config-set` push path, state that didn't survive a Kea restart, fragile hook
packaging. That case is sound. But the real cost of owning a DHCP
implementation is the ten-year tail: RFC edge cases, interop with every
embedded client that's ever shipped, CVE surface on a daemon that's
unauthenticated by protocol design on a pre-auth network segment.

The codebase's own docs already show that tail starting: `server6.rs` unwraps
`RelayForw` nesting by hand at the byte level because dhcproto's typed API
gets the common case wrong (§22.9); only the first IA_NA/IA_PD per message is
served; there's no v6 relay allow-list yet; v6 has no per-interface dispatch;
v6 pool exhaustion is only ever inferred probabilistically. That's a lot of
protocol surface for a small team to own indefinitely, on a daemon that hands
out network configuration to every device that asks.

**Not a call to revert** — a call to budget for it explicitly: fuzzing on
both wire parsers (v4 and v6), an interop test matrix against real client
implementations, and a named owner for the CVE process. Otherwise the bill
arrives unplanned.

---

### 26.9 Cut from the roadmap

Formally removed, not deferred — each cross-references where the decision is
recorded in full:

| Cut | Where recorded | Why |
|---|---|---|
| OpenVPN AS cluster integration | §7 | Never built; DHCP option 6 / manual VPN DNS push already deliver the actual goal (filtered DNS regardless of gateway) at a fraction of the engineering and licensing cost |
| Kubernetes, Kafka/NATS, Redis Cluster, ClickHouse, etcd/Consul, Vault, Patroni, SPIFFE/SPIRE as *stated targets* | Banner, §9, §14 | Eight unbuilt distributed-systems dependencies in the design doc invite doubt about everything else in it, for a realistic deployment (Proxmox host / small cluster) that Postgres and an in-process cache already serve. Revisit only when an actual customer's scale forces it — not before |
| `forward` / `passthrough` DNS zone types | §24.1, §24.6 | Fully overlap §21.2's already-enforced `domain_suffix` upstream routes; a second, unenforced mechanism for the same outcome is a config surface that silently does nothing |

**Kept, explicitly, despite being in the cut list above:** mTLS between the
control plane and the fleet (§9, §14) — it's not aspirational polish, it's
the fix for R3, a real credential-compromise blast-radius problem.

---

### 26.10 Re-sequenced delivery path

Epic O (§23) does not start next. It isn't wrong, it's premature: it adds
observability to a fleet whose credentials, isolation guarantees, and
hot-path performance haven't been validated yet, and it adds per-query
instrumentation with no benchmark to check it against.

1. **Epic P — Foundation hardening** (no new features): bench harness + p99
   baseline in CI, fix the zone-lookup allocation (§26 R7); bloom exact-match
   confirmation tier (R1); per-node credentials with rotation/revocation
   (R3); protobuf compat gate + bundle schema version (R7); tenant-isolation
   coverage test, then Postgres RLS (R4).
2. **Epic Q — Enterprise entry ticket:** OIDC/SAML + SCIM (retires the local
   password store); canary bundle rollout + automatic rollback (pairs
   naturally with Epic P's per-node identity — this is *why* per-node
   identity is worth having, beyond a table in a UI); per-tenant retention +
   right-to-erasure + residency documentation (R6).
3. **Epic O — Fleet observability**, reframed: not "a Nodes page" for its own
   sake, but the control surface canary rollout needs and the data source
   that unblocks §21.4's `HealthTab.tsx` placeholder. Same code as originally
   designed in §23 — a materially better reason to build it.

Sprint-level breakdown: sprint-plan.md, Epic P / Epic Q / Epic O (renumbered).

---

### 26.11 Missing for enterprise, on no roadmap at all

Not risks in already-shipped code — gaps in what's planned. Listed so they
don't get silently assumed away by "Epic O ships eventually."

| Gap | Why it blocks an enterprise deployment |
|---|---|
| SSO (OIDC/SAML) + SCIM + MFA | Not a feature, a procurement gate — no RFP clears without it. Also the reason a password database exists at all right now (§19.1 U1). Epic Q. |
| Policy change management (staging/preview/approval/scheduled rollout) | A policy edit goes live on the next poll with no review step, for a system that can black-hole a company's DNS. |
| Canary rollout + automatic rollback | A bad bundle propagates to 100% of the fleet at once today (§12 lists canary as 🚧). Highest blast-radius gap in the product. Epic Q. |
| Policy as code (Terraform provider / GitOps) | Enterprises want policy in version control with PR review, not clicked into a UI. Also solves change management above. |
| Encrypted client→resolver DNS (DoT/DoH/DoQ listener) | Outbound is enforced (DoT/DoH to upstreams, §21); **inbound is plain `:1053` UDP/TCP** (`main.rs`, confirmed — no encrypted listener exists). In an enterprise deployment the untrusted hop is the client's, not the resolver's. |
| Alerting delivery | Open since Sprint 1 (§11); Epic O defers to it again. A dashboard nobody's watching at 3am isn't operability. |
| Secrets management (rotation, KMS, access audit) | Plaintext env files at 0600 with no rotation and no access log. |
| Tested backup/restore with a documented RTO/RPO | `pg_dump` before upgrades is a backup step, not a DR plan, and it's never been drilled (§12). |
| Audit-log immutability | "Append-only" today is a convention, not a guarantee — any DB admin can `UPDATE` the table. SOC2 scope will ask (§9). |
| Response-rate limiting (RRL) | The filter node is effectively an open resolver on `:53`/`:1053` with no RRL — a participant in reflection/amplification without it (§9). |

---
