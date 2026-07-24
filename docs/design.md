# Enterprise DNS Filtering Platform — Design Document

**Codename:** Mantis-DNS
**Status:** Draft v1.2
**Date:** 2026-07-01
**Audience:** Platform engineering, network security, SRE

> **Deployment profiles.** The platform targets two profiles from one codebase:
> - **Cloud/cluster** — Kubernetes + OpenVPN AS cluster, anycast, full HA (§4–§12).
> - **Proxmox VE single-host / small-cluster** — OpenVPN server co-located on the same hypervisor, collapsed control plane, no Kubernetes (§17).
>
> Category-based content filtering with auto-updating feeds (porn, gambling, firearms, etc.) is a first-class feature in both profiles (§18).

> **⚠️ Build status.** §4–§9, §11–§12, §14, and roadmap phases 3/5/6 (§16) describe
> the **target cloud/K8s design** — they are not implemented. Nothing in this repo
> today runs Kubernetes, Kafka/NATS, Redis Cluster, ClickHouse, etcd/Consul, Vault,
> Patroni, or SPIFFE/SPIRE. Items pulled from these sections are marked `🚧 not
> built` inline below. What's actually running is the **Proxmox VE profile (§17)**:
> a single-process Rust filter node, one PostgreSQL instance, filesystem-based
> bundle distribution, in-memory rate limiting — see [`ARCHITECTURE.md`](../ARCHITECTURE.md)
> for the as-built summary. §17.2 already flags object store/Kafka/ClickHouse as
> optional-and-unused at this scale; §18–§21 carry their own "current state" notes
> where relevant.

---

## 1. Summary

Pi-hole is a single-node, SQLite-backed DNS sinkhole built for a home network. This document redesigns its capabilities — DNS-based ad/tracker/malware blocking, per-client policy, query logging, and a management UI — into a horizontally scalable, multi-tenant, highly available platform suitable for enterprise deployment, co-located with an **OpenVPN Access Server (AS) cluster** so that VPN clients receive filtered, policy-controlled DNS regardless of which gateway node they connect to.

The core architectural shift is the separation of the system into three planes:

- **Data plane** — stateless DNS resolvers/filters that answer queries at line rate.
- **Control plane** — policy, blocklist, and configuration distribution.
- **Management plane** — API, UI, multi-tenant administration, audit.

This separation is the single most important departure from Pi-hole, which collapses all three into one process and one SQLite file.

---

## 2. Goals & Non-Goals

### 2.1 Goals

| # | Goal |
|---|------|
| G1 | Horizontal scalability of DNS query handling (stateless filter nodes). |
| G2 | High availability: no single point of failure; survive node and AZ loss. |
| G3 | Co-residency / tight integration with an OpenVPN AS cluster. |
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

## 3. Pi-hole Baseline & Its Limits

| Concern | Pi-hole today | Enterprise requirement |
|---------|---------------|------------------------|
| Storage | SQLite on local disk | Replicated, HA datastore |
| Scaling | Single host (or manual sync via tools like gravity-sync) | Stateless autoscaling fleet |
| HA | None native | Active-active, multi-AZ |
| Policy scope | Global + limited per-client groups | Multi-tenant, hierarchical groups |
| Config distribution | Local `gravity.db` rebuild | Versioned, pushed to fleet |
| API/UI | PHP web admin, single instance | Stateless API, SSO, RBAC, audit |
| Logging | Local query log | Central pipeline, retention, search |
| Upstream privacy | Optional | DoT/DoH enforced |
| Secrets | Local config files | Vault / KMS |

---

## 4. High-Level Architecture

```
                         ┌──────────────────────────────────────────────┐
                         │              MANAGEMENT PLANE                  │
                         │  Admin API · Web UI (SPA) · SSO/OIDC · RBAC    │
                         │  Audit log · Tenant mgmt · Policy authoring    │
                         └───────────────┬──────────────────────────────┘
                                         │ (gRPC/REST, mTLS)
                         ┌───────────────▼──────────────────────────────┐
                         │               CONTROL PLANE                    │
                         │  Policy compiler · Blocklist ingester          │
                         │  Config store (etcd/Consul) 🚧 · Dist. bus 🚧   │
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
            └────────────► shared cache (Redis cluster) 🚧 ◄────────────┘
            │
            │ query events (async, fire-and-forget)
            ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  TELEMETRY PIPELINE 🚧: Kafka/NATS → stream processor → ClickHouse │
   │  OpenTelemetry traces · Loki/ELK logs                             │
   └─────────────────────────────────────────────────────────────────┘

   OpenVPN AS cluster 🚧 pushes DHCP-option DNS = Anycast VIP 🚧 of filter fleet
```

### 4.1 Request path (cache miss)

1. VPN client resolves `ads.example.com`. OpenVPN AS pushed DNS = anycast VIP.
2. L4 LB / anycast routes UDP/TCP/853 to nearest healthy **filter node**.
3. Node identifies tenant + client group from source context (see §7).
4. Policy engine evaluates compiled rule set (blocklist bloom filter → exact match → allowlist override).
5. If blocked → return sinkhole answer (NXDOMAIN / 0.0.0.0 / custom) per policy.
6. If allowed → check local cache → shared Redis cache → upstream recursor (DoT/DoH).
7. Answer returned; query event emitted async to telemetry bus.

Target: cache hit served entirely in-node, no control-plane dependency on the hot path.

---

## 5. Component Design

### 5.1 Filter node (data plane)

- **Stateless.** Holds only: cache + the latest signed policy bundle (in memory + local disk cache). Can be killed/replaced anytime.
- **DNS frontend.** CoreDNS or a custom Go/Rust server. CoreDNS chosen for plugin model; custom plugin chain: `tenant-resolve → policy → cache → forward`. *As built: a custom Rust server (`services/filter`), not CoreDNS — see ARCHITECTURE.md.*
- **Policy engine.** Evaluates against compiled bundle. Blocklists stored as **bloom filter + sorted hash set** for O(1) negative checks and bounded memory (millions of domains in tens of MB).
- **Resolver.** Forwards allowed misses to internal recursive resolver pool (Unbound/Knot) 🚧 over DoT, or directly to vetted upstreams.
- **Local cache.** In-process LRU with TTL honoring; optional read-through to shared Redis 🚧 for cross-node warm cache.

Scaling: add nodes behind anycast/LB. No coordination needed — pure function of (query, policy bundle).

### 5.2 Control plane

- **Source of truth:** PostgreSQL (HA: Patroni/RDS Multi-AZ 🚧 — as built: single PostgreSQL instance, no HA). Stores tenants, policies, group definitions, blocklist subscriptions, allow/deny overrides.
- **Blocklist ingester:** scheduled jobs fetch external lists (StevenBlack, URLhaus, threat feeds), normalize, dedupe, diff. Produces canonical domain sets.
- **Policy compiler:** takes DB policy + ingested lists → emits a **signed, versioned policy bundle** per tenant/group (bloom filter blob + override tables + metadata). Bundles are immutable and content-addressed.
- **Distribution:** bundles published to object store (S3-compatible) 🚧; pointer/version published to **etcd/Consul** 🚧. Filter nodes watch the config store and pull new bundles. Push-on-change + periodic reconcile. *As built: filesystem/HTTP pull, see §17.2.*
- **Signing:** bundles signed (e.g. cosign/ed25519). Nodes verify before applying. Prevents poisoned policy.

### 5.3 Management plane

- **API:** gRPC 🚧 + REST gateway, stateless, behind LB. All writes go to PostgreSQL; triggers recompile. *As built: REST (FastAPI) only, no gRPC.*
- **UI:** SPA (React) talking to API. No PHP, no per-node state.
- **AuthN:** OIDC/SAML SSO (Okta/Entra/Keycloak) 🚧. Service-to-service mTLS 🚧.
- **AuthZ:** RBAC + tenant scoping. Roles: super-admin, tenant-admin, policy-author, read-only/auditor.
- **Audit:** every mutation appended to immutable audit log (separate store, WORM/retention 🚧).

### 5.4 Telemetry pipeline 🚧 (target design — see §20 for what's actually shipped: DB-stored query events + pull/webhook SIEM export, no message bus)

- Query events are **enriched at the filter node** before leaving the data plane: client IP, query type, response code, matched category, matched feed ID, and resolution latency are attached at source — not inferred later from partial data.
- Enriched events → message bus (Kafka or NATS JetStream) 🚧, partitioned by tenant.
- Stream processor → **ClickHouse** 🚧 for high-cardinality, fast analytical query logs with TTL-based retention.
- **OpenTelemetry** 🚧 traces on the resolve path; **Loki/ELK** 🚧 for operational logs.
- Dashboards (in-app, off the telemetry/metrics APIs): QPS, block ratio, cache hit ratio, p50/p99 latency, upstream health, per-tenant volume.
- **SIEM export layer** (§20): query event stream exposed via pull API (cursor-based REST) and push webhook, in JSON or CEF format, so any SIEM can consume without a custom connector.

---

## 6. Data Stores

| Store | Tech | Role | HA strategy | Status |
|-------|------|------|-------------|--------|
| Source of truth | PostgreSQL | Tenants, policy, config | Patroni / Multi-AZ, sync replica | 🚧 single instance, no HA |
| Config/version | etcd or Consul | Bundle pointers, node registry | Raft quorum, ≥3 nodes | 🚧 not built |
| Bundle storage | S3-compatible object store | Immutable signed bundles | Multi-AZ, versioned | 🚧 filesystem instead (§17.2) |
| Shared cache | Redis Cluster | Cross-node DNS cache | Sharded + replicas | 🚧 not built |
| Query logs | ClickHouse | Analytics, search, retention | Sharded + replicated | 🚧 Postgres instead |
| Audit | Append-only (Postgres/ClickHouse + object archive) | Compliance | WORM archive | 🚧 not built |
| SIEM config | PostgreSQL | Webhook + syslog sink endpoints, delivery state, cursor | Same as source of truth | ✅ built (§20) |
| Secrets | Vault / cloud KMS | Keys, upstream creds | HA Vault | 🚧 env vars instead |

**Key principle:** the hot DNS path depends on *none* of these synchronously. It reads only the in-memory policy bundle and local cache. Control/management stores being down degrades management, not resolution.

---

## 7. OpenVPN AS Cluster Integration

This is the deployment context, so it gets dedicated treatment.

### 7.1 Topology

- OpenVPN AS runs as a cluster (multiple nodes behind a UDP/TCP LB or DNS round-robin; shared user/config DB).
- Filter fleet deployed **alongside** each AS node (sidecar pattern) **or** as a shared anycast fleet — see options below.

### 7.2 DNS hand-off

- AS pushes DNS server to clients via `--dhcp-option DNS <addr>` in the client config / group config.
- Set this to the **anycast VIP** (or per-node loopback if sidecar) of the filter fleet — never a single node IP.
- Push `--dhcp-option DOMAIN` and block client-side DNS leakage (`block-outside-dns` on Windows; `redirect-gateway` / route DNS through tunnel).

### 7.3 Tenant & client identification

The hard problem: a query arriving at a filter node must map to a tenant + client group for correct policy. Options, in order of preference:

1. **Per-VPN-group anycast/listener.** Each AS user-group (e.g. `contractors`, `engineering`, `tenant-acme`) pushes a distinct DNS VIP or a distinct loopback. Filter node maps listener → tenant/group. Clean, no per-query lookup.
2. **Source-IP → identity map.** AS assigns VPN IP pools per group; filter node maps client subnet → group. Requires AS to publish the IP-pool→identity table to the control plane (small, slow-changing).
3. **EDNS Client Subnet / custom EDNS tag.** AS or a shim tags queries. More invasive; use only if 1–2 insufficient.

Recommendation: **(1)** for tenant separation, **(2)** for finer per-group policy within a tenant.

### 7.4 Deployment options

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **A. Sidecar** | Filter node on each AS host, client DNS = 127.0.0.1 / link-local | Lowest latency, no extra LB, fate-shared with AS node | Filter scaling tied to AS node count |
| **B. Shared anycast fleet** | Separate filter fleet, AS pushes anycast VIP | Independent scaling, fewer nodes | Extra network hop, needs anycast/LB |
| **C. Hybrid** | Sidecar cache + shared control plane + central recursors | Best latency + independent recursor scaling | Most moving parts |

Recommended default: **C (Hybrid)** — sidecar filter+cache for latency and AS fate-sharing, shared control plane and recursor pool for scale and consistency.

### 7.5 Failure behavior

- If sidecar filter dies, AS node health check pulls it from rotation (client reconnects to healthy AS node → healthy sidecar).
- If control plane unreachable, filter keeps serving last good signed bundle (bounded staleness, alert fires).
- Fail-open vs fail-closed is a **per-tenant policy**: security tenants fail-closed (block on policy-load failure), general tenants fail-open (resolve normally, log degraded).

---

## 8. Scalability & Performance

- **Stateless filter nodes** → linear horizontal scale; autoscale on QPS/CPU 🚧 (currently: manual scale-out, one node per host/CT — §17.3).
- **Bloom-filter blocklists** → millions of domains, tens of MB RAM, O(1) negative lookups, no DB on hot path.
- **Two-tier cache** (in-process LRU + Redis cluster 🚧) → high hit ratio, cross-node warm cache 🚧 (currently: in-process LRU only, no cross-node sharing).
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
- **Internal:** mTLS between all planes 🚧; SPIFFE/SPIRE for workload identity 🚧.
- **Bundle integrity:** signed, content-addressed bundles; nodes reject unsigned/invalid. *Built (ed25519 signing, `crypto.py`).*
- **DNS hardening:** rate limiting per source (built: login endpoint only, in-memory — `rate_limit.py`), response-rate-limiting (RRL) 🚧 to resist amplification, DNSSEC validation at recursor 🚧.
- **AuthN/Z:** SSO 🚧 + RBAC + per-tenant isolation; least-privilege service accounts.
- **Secrets:** Vault/KMS 🚧, no secrets on disk in plaintext (as built: env vars / systemd `EnvironmentFile`, 0600).
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
- Each group maps to an OpenVPN AS user-group (see §7.3).
- Query logs partitioned and access-controlled per tenant.

---

## 11. Observability

- **Metrics:** QPS, block ratio, cache hit ratio, latency histograms, upstream errors, bundle version per node — surfaced via the control plane telemetry API and the in-app Analytics dashboard.
- **Logs (Loki/ELK) 🚧:** operational; structured JSON.
- **Query analytics (ClickHouse 🚧):** per-tenant top domains, blocked categories, client breakdown, retention by policy. *As built: PostgreSQL.*
- **Traces (OpenTelemetry) 🚧:** resolve path spans for latency debugging.
- **Alerting 🚧:** stale bundle, node down, upstream failure, block-ratio anomaly (possible misconfig or attack), Redis/PG health.
- **SLOs 🚧:** availability of resolution (e.g. 99.99%), p99 latency, bundle freshness.

---

## 12. Deployment & Operations

- **Packaging:** containers (OCI) — built (Docker Compose images). Filter node also ships as a native `.deb`. Control-plane/UI each independently deployable.
- **Orchestration:** Kubernetes 🚧 for control/management plane and shared filter fleet; sidecar filters deployed with AS nodes (systemd or co-located pods). *As built: systemd units (native install) or Docker Compose — see `charts/mantis-dns` for an early, unverified Helm chart.*
- **IaC:** Terraform 🚧 for infra, Helm 🚧 for k8s workloads, GitOps (Argo/Flux) 🚧 for config. *As built: shell installers (`infra/lxc/*.sh`) + Ansible-shaped provisioning notes in §17.5, not yet an Ansible playbook.*
- **Rollout:** canary policy bundles to a subset of nodes 🚧; automatic rollback on error-rate spike 🚧. Blue/green for control-plane services 🚧. *As built: the update scripts (`scripts/update.sh`, `infra/lxc/install*.sh`) do backup → deploy → health-check → keep-previous-generation → manual rollback instructions on failure — no automatic traffic-based rollback.*
- **Backup/DR:** PostgreSQL PITR 🚧 (as built: `pg_dump` before upgrades), object-store versioning 🚧, etcd snapshots 🚧, ClickHouse backups 🚧. Multi-AZ 🚧; documented RTO/RPO 🚧.
- **Upgrades:** filter nodes are cattle — rolling replace 🚧 (as built: in-place restart per node, no rolling fleet orchestration). Schema migrations gated and reversible — built (Alembic).

---

## 13. Migration Path (from a Pi-hole deployment)

1. **Import** existing Pi-hole blocklists, allow/deny entries, and group definitions into the control-plane PostgreSQL schema.
2. **Stand up** control plane + one filter node; validate parity of blocking decisions against the old Pi-hole on a query replay.
3. **Shadow mode:** run filter fleet in parallel, mirror queries, compare answers, no client impact.
4. **Cutover** one OpenVPN AS group at a time by changing the pushed DNS option to the new VIP.
5. **Decommission** Pi-hole after all groups migrated and logs/retention validated.

---

## 14. Technology Choices (reference, not mandatory)

| Layer | Primary | Alternative | Status |
|-------|---------|-------------|--------|
| DNS frontend | CoreDNS (custom plugins) | Knot Resolver, custom Rust | ✅ built, but as *custom Rust* — CoreDNS was never adopted |
| Recursor | Unbound | Knot Resolver | 🚧 filter forwards to configured upstream pools directly (§21), no local recursor |
| Source DB | PostgreSQL + Patroni | CockroachDB | 🚧 PostgreSQL only, no Patroni/HA |
| Config store | etcd | Consul | 🚧 not built |
| Shared cache | Redis Cluster | KeyDB / Dragonfly | 🚧 not built |
| Bus | Kafka | NATS JetStream | 🚧 not built |
| Query analytics | ClickHouse | Druid | 🚧 PostgreSQL instead |
| Metrics | In-app Analytics dashboard (telemetry API) | External APM (optional) | ✅ built |
| Secrets | Vault | Cloud KMS | 🚧 env vars / systemd `EnvironmentFile` instead |
| Orchestration | Kubernetes | Nomad | 🚧 systemd / Docker Compose; early Helm chart exists (`charts/mantis-dns`), unverified |

---

## 15. Open Questions / Risks

- **DNS leak enforcement** on heterogeneous VPN clients (Windows `block-outside-dns`, macOS/Linux split-DNS behavior) — needs per-OS validation.
- **Anycast vs LB** in the specific cloud/on-prem network — depends on routing capability.
- **Bloom-filter false positives** — bounded by sizing; pair with exact-match confirmation tier for the (rare) FP on block-critical lists.
- **Per-query tenant resolution cost** if option §7.3(1) is not feasible.
- **Compliance scope** (data residency of query logs per tenant) — may force regional ClickHouse shards.

---

## 16. Phased Roadmap

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 0 | Control-plane schema, blocklist ingester, policy compiler, signed bundles | ✅ built |
| 0b | Category taxonomy + feed registry + auto-update pipeline with sanity gates (§18) | ✅ built |
| 0c | Proxmox VE appliance: CT templates + Ansible, collapsed control plane (§17) | 🚧 partial — shell installers exist (`infra/lxc/*.sh`), no Ansible/CT-template packaging yet |
| 1 | Stateless filter node (CoreDNS plugin chain), bundle pull + verify, local cache | ✅ built (custom Rust, not CoreDNS) |
| 2 | OpenVPN AS integration (sidecar + VIP), tenant/group mapping | 🚧 works with community OpenVPN via DHCP-option/manual DNS push; no AS/sidecar/VIP automation |
| 3 | Telemetry pipeline (Kafka → ClickHouse), in-app analytics dashboards | 🚧 dashboards ✅ built on PostgreSQL; Kafka/ClickHouse not built |
| 4 | Management API + UI, SSO/RBAC, audit | 🚧 API/UI/audit ✅ built; SSO not built |
| 5 | HA hardening, multi-AZ, DR drills, canary rollout, autoscaling | 🚧 not built |
| 6 | Migration tooling, shadow mode, production cutover | 🚧 not built |

---

## 17. Deployment Profile: Proxmox VE Hypervisor

Many deployments are not a cloud Kubernetes fleet but a **single Proxmox VE host (or small PVE cluster)** that already runs an **OpenVPN server** (community `openvpn`, not necessarily AS). This profile collapses the architecture without changing the code — same containers, fewer of them, control plane co-resident.

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
- Object store, Kafka, ClickHouse are **optional** at this scale: query logs can land in Postgres or a local ClickHouse CT only if analytics are wanted.

### 17.3 HA on a PVE cluster (optional)

- For a **multi-node PVE cluster**, run `mantis-filter` as a CT on each node and use **PVE HA + a shared VIP** (keepalived/VRRP CT, or pfSense/CARP if present) so VPN clients hit a floating DNS IP.
- `mantis-control` runs as a single HA-managed CT (PVE HA restarts it on another node on failure); it is **not** on the DNS hot path, so brief downtime only delays policy updates.
- Postgres replication optional; for most PVE sites, PVE HA failover of one control CT + ZFS replication of its disk is sufficient.

### 17.4 Resourcing (rule of thumb, single host)

| CT | vCPU | RAM | Disk | Notes |
|----|------|-----|------|-------|
| mantis-filter | 2 | 1–2 GB | 4 GB | bloom filters + cache in RAM |
| mantis-control | 2 | 2–4 GB | 20 GB+ | Postgres + feeds + UI |
| (optional) clickhouse | 2 | 4 GB | size to retention | only if analytics wanted |

### 17.5 Provisioning

- Ship as a **Proxmox CT template / appliance** (or `pveam`-style image) plus an Ansible playbook that: creates the CTs, wires the bridge, configures OpenVPN's `dhcp-option DNS`, seeds the control DB, enables category feeds.
- Updates: `git`/registry-pulled container images; control CT self-updates feeds (§18). One-command upgrade script.

### 17.6 What carries over vs the cloud profile

| Concern | Cloud profile | Proxmox profile |
|---------|---------------|-----------------|
| Filter nodes | Autoscaled fleet, anycast | 1 CT/host, optional VIP |
| Control plane | k8s services, etcd, S3 | 1 CT, shared volume |
| Bundle distribution | object store + etcd watch | bind-mount + version file |
| Telemetry | Kafka → ClickHouse | Postgres or optional CT |
| VPN | OpenVPN AS cluster | community OpenVPN on host |
| HA | Multi-AZ | PVE HA + VRRP VIP |

Same policy/category/bundle logic, signed bundles, RBAC, and UI in both — only the scale-out plumbing differs.

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

- Categories are **system-defined taxonomy**; tenants/groups toggle them on/off (maps to the multi-tenancy model in §10 and OpenVPN groups in §7.3).
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

### 19.1 Current state (honest baseline)

The UI shipped through Sprint 6 is a **working prototype, not an enterprise product**. It proves the API contract end to end (tenant/group/policy CRUD, category toggles, overrides, bundle compile, feed management, live telemetry) but is deliberately unpolished:

- Browser-native `prompt()` / `alert()` / `confirm()` for all input and feedback.
- Hand-rolled `fetch` + `useState`, no server-state caching, no optimistic updates, no retry.
- Raw HTML tables with no pagination, virtualization, sorting, or filtering — they will not survive a feed of 500k domains or a query log of millions of rows.
- No authentication, no routing, no design system, no empty/loading/error states, no accessibility, no tests.

This section is the plan to take it from prototype to a console an enterprise would actually procure and operate. It supersedes the single "UI polish" bullet previously buried in Sprint 8.

### 19.2 Enterprise requirements (what "enterprise-grade" actually means here)

| # | Requirement | Why it's non-negotiable |
|---|-------------|-------------------------|
| U1 | Authentication + session management (OIDC/SAML SSO) | No enterprise runs an unauthenticated admin console; ties to §9 RBAC. |
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
 ├── auth/                OIDC PKCE flow, session context, role guards
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
| Auth | **oidc-client-ts** | Standard OIDC PKCE against Keycloak/Okta/Entra (§9). |
| Toasts/modals | Mantine notifications + modals | Replaces every `alert()`/`confirm()`. |
| Testing | **Vitest + Testing Library**, **Playwright** (E2E), **Storybook** + Chromatic (visual regression) | Component, end-to-end, and visual coverage. |
| Quality gates | ESLint, Prettier, `tsc --noEmit`, bundle-size check | Enforced in CI (§ Cross-cutting). |

### 19.4 Information architecture

- **App shell**: persistent left nav (Tenants, Feeds, Analytics, Audit, Settings), top bar with tenant/org switcher, global search, user menu, theme toggle.
- **Breadcrumbs** for deep navigation (Tenant → Group → Policy).
- **Tenant context** is global state: selecting a tenant scopes every subsequent view; super-admins get an "all tenants" overview.
- **Empty / loading / error states** are first-class for every data view (skeleton loaders, actionable empty states, error boundaries — not blank screens).

### 19.5 Key views to (re)build

1. **Policy editor** — replace the prototype: category toggles with live domain counts and per-category action (block / log-only / allow), override management with validated domain input, a **domain test box** (enter a domain → see which category/feed matches and the resulting decision — the explainability feature from §18.5, still unbuilt), bundle compile + propagation status indicator.
2. **Feed manager** — catalog browser with search/filter, per-feed ingest status + last-run/next-run, sanity-gate rejection surfacing, license display, add/edit/delete with real forms.
3. **Query-log explorer** — server-side paginated, filterable by tenant/group/decision/time-range, backed by ClickHouse once §6 lands (Postgres for now).
4. **Analytics dashboard** — block ratio, QPS, cache-hit ratio, top blocked domains, per-category volume; native charts backed by the telemetry/metrics APIs (already implemented).
5. **Audit log viewer** — immutable, filterable, exportable.
6. **Settings** — SSO config, RBAC role assignment, API keys, white-label branding.

### 19.6 Accessibility & i18n

- Target **WCAG 2.1 AA**: keyboard-operable everything, visible focus, ARIA on custom widgets, contrast-checked theme tokens. Mantine/AntD give most of this; the audit is on us.
- Wrap user-facing strings in an i18n layer (e.g. `react-i18next`) from the start — retrofitting localization is far more expensive than scaffolding it early, even if only `en` ships initially.

### 19.7 Phased delivery (folds into the sprint plan)

| Phase | Deliverable |
|-------|-------------|
| UI-0 | Foundation: component library, TanStack Query, OpenAPI-generated client, app shell + routing, theme. Port existing prototype views onto it (no new features, just the platform). |
| UI-1 | Auth + RBAC: OIDC login, session, role-gated nav/actions (depends on backend §9 / Sprint 8). |
| UI-2 | Data grids: feed manager + query-log explorer with server-side pagination/sort/filter/virtualization. |
| UI-3 | Forms + UX: replace all prompt/alert/confirm with validated forms, modals, toasts, confirmation dialogs. |
| UI-4 | Analytics + audit: dashboards, domain-test explainability box, audit log viewer. |
| UI-5 | Hardening: a11y audit (WCAG AA), i18n scaffolding, E2E + visual-regression tests, performance budget in CI. |

UI-0 is the unlock and should land before piling on features — every feature built on the prototype's hand-rolled foundation is throwaway work.

---

## 20. SIEM Integration

Enterprise DNS filtering produces the highest-fidelity network telemetry available: every DNS query from every device, timestamped to the microsecond, with a policy decision attached. That data belongs in the SIEM, not siloed in Mantis. This section defines the integration architecture.

---

### 20.1 Design principles

1. **Enrich at source, not at the SIEM.** The filter node has full context (client IP, matched category, matched feed, latency) that the SIEM cannot reconstruct from raw DNS traffic. Enrichment at the SIEM requires custom parsers and is fragile; enrichment at the filter node is authoritative.
2. **Both pull and push.** Pull (REST cursor API) works with any SIEM that has an HTTP poller — zero additional infrastructure. Push (webhook) covers real-time requirements and SIEMs that only receive. The same enriched event model feeds both.
3. **Standard formats.** JSON for API-native SIEMs (Elastic, Splunk HEC, Panther, Chronicle). CEF (Common Event Format) for legacy SIEMs (ArcSight, QRadar, many MSSPs). Format is a serialization choice, not a separate pipeline.
4. **Delivery guarantees.** At-least-once delivery with idempotency keys. Cursor-based pull is inherently resumable. Webhook push includes retry with exponential backoff and a dead-letter log visible in the UI.
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

**Current implementation state (Sprint 6 baseline):** `group_id`, `qname`, `decision`, `occurred_at` are stored. All other fields are targeted for Sprint 14 enrichment work.

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

### 20.4 Webhook push

#### Configuration model

```
SiemWebhook {
    id              UUID
    tenant_id       UUID | null     // null = org-wide (admin only)
    name            string          // human label, e.g. "Splunk HEC prod"
    url             string          // HTTPS only in production
    secret          string          // stored encrypted; used for HMAC-SHA256 signing
    format          "json" | "cef"
    batch_size      int             // events per POST, default 200, max 2000
    flush_interval_s int            // max seconds between POSTs, default 30
    enabled         bool
    filter_decision "all" | "block" | "allow"  // only push matching decisions
    last_delivered_at  timestamp | null
    last_error         string | null
    consecutive_failures int        // reset to 0 on success
}
```

#### Delivery

Each POST to the webhook URL:
```
POST <url>
Content-Type: application/json          (or text/plain for CEF)
X-Mantis-Signature: sha256=<hex>         HMAC-SHA256 of raw body, keyed on secret
X-Mantis-Delivery-Id: <uuid>             idempotency key for this batch
X-Mantis-Timestamp: <unix_ms>

{ "events": [...], "delivery_id": "...", "cursor": "..." }
```

The receiving SIEM must return 2xx within 10 s. On failure:
- Retry with exponential backoff: 5 s, 30 s, 2 min, 10 min, 1 h.
- After 6 consecutive failures, mark webhook `enabled=false` and emit an alert to the Mantis audit log + (if configured) an operator notification.
- Backlog is bounded: if the webhook is disabled or consistently failing, events are still available via the pull API.

#### HMAC verification (receiver side)
```python
import hmac, hashlib
expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
received = request.headers["X-Mantis-Signature"].removeprefix("sha256=")
assert hmac.compare_digest(expected, received)
```

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
| Splunk | HTTP Event Collector (HEC) webhook | JSON | Set `url` to HEC endpoint, token in header via `secret` field; or use pull with Splunk's REST input |
| Elastic (SIEM/Security) | Webhook → Logstash/Elastic Agent HTTP input | JSON | Or use pull with Filebeat HTTP poller |
| Microsoft Sentinel | Webhook → Log Analytics Data Collector API | JSON (CEF optionally via AMA) | Azure Function as relay is optional |
| IBM QRadar | Pull API → Universal DSM, or syslog | CEF (`format=cef`) | Syslog sink (§20.8) feeds QRadar's native syslog listener directly |
| Palo Alto Cortex XSIAM | Webhook | JSON | Native HTTP event ingestion |
| Chronicle (Google SecOps) | Webhook | JSON (UDM mapping via ingestion API) | |
| Panther | Pull API | JSON | Native REST poller |
| Wazuh | Syslog sink (§20.8), or Pull API → `<localfile>` JSON log tailing | CEF via syslog, or JSON | Wazuh's built-in `<remote>` syslog listener consumes the syslog sink directly — no polling script needed. The pull-script bridge (`integrations/wazuh/README.md`) predates syslog support and remains for stock configs that don't want an inbound listener open. |
| Any MSSP | Pull API | CEF | MSSP controls polling cadence |

---

### 20.8 Syslog export

**Built (Sprint 22).** RFC 5424 syslog is a thin adapter on top of the same enriched event model — iterate the event stream, serialize as CEF or JSON into the MSG field, and write to a TCP/TLS/UDP socket. The control-plane config is a `SiemSyslog` table parallel to `SiemWebhook`, with the same cursor/backoff/auto-disable delivery shape but no signing secret (syslog has no HMAC concept).

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

**Transport.** TLS is the recommended default; verification uses the system CA trust store, with SNI/certificate checks against the configured hostname even though the connection itself dials a pre-resolved IP literal (closes the same DNS-rebinding TOCTOU gap `resolve_pinned_webhook_url` closes for the webhook path — see `resolve_pinned_syslog_host` in `ssrf_guard.py`). UDP is supported for collectors that only speak classic syslog, but is explicitly best-effort: no application-layer acknowledgment exists for any transport here (a TCP/TLS write success only means the collector's kernel accepted the bytes), and UDP is additionally lossy at the network layer with no delivery signal at all. The delivery cursor only advances on a successful send, so a refused/closed connection is retried like any other failure — a receiver that silently drops accepted bytes is outside what any of these transports can detect.

**Host validation.** `check_probe_target_safe` (not the stricter `check_webhook_url_safe`) gates sink hosts: only loopback and link-local/cloud-metadata addresses are blocked, since self-hosted collectors are routinely on RFC-1918 addresses, same reasoning as §20.4's webhook guard.

**Retention interaction.** `prune_query_events` (§6) takes the minimum `last_delivered_seq` across every *enabled* `SiemWebhook` **and** `SiemSyslog` sink as a safety bound — a row isn't pruned until every enabled sink of either kind has delivered it, same protection extended to the new sink type.

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

**Stub zones (authoritative answers):** for domains the tenant owns that should be answered from local data without forwarding (e.g. `corp.local` records managed by the DNS Zones feature, §DNS-Zones), the route type `stub_zone` overrides pool routing entirely and answers from the local zone database. This is a zero-latency path (no upstream needed) and is the mechanism by which the DNS Zones feature integrates with the upstream routing model.

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
