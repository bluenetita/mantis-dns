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
                         │  Config store (etcd/Consul) · Distribution bus │
                         │  PostgreSQL (source of truth) + object store   │
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
            └────────────► shared cache (Redis cluster) ◄────────────┘
            │
            │ query events (async, fire-and-forget)
            ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  TELEMETRY PIPELINE: Kafka/NATS → stream processor → ClickHouse   │
   │  OpenTelemetry traces · Loki/ELK logs                             │
   └─────────────────────────────────────────────────────────────────┘

   OpenVPN AS cluster pushes DHCP-option DNS = Anycast VIP of filter fleet
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
- **DNS frontend.** CoreDNS or a custom Go/Rust server. CoreDNS chosen for plugin model; custom plugin chain: `tenant-resolve → policy → cache → forward`.
- **Policy engine.** Evaluates against compiled bundle. Blocklists stored as **bloom filter + sorted hash set** for O(1) negative checks and bounded memory (millions of domains in tens of MB).
- **Resolver.** Forwards allowed misses to internal recursive resolver pool (Unbound/Knot) over DoT, or directly to vetted upstreams.
- **Local cache.** In-process LRU with TTL honoring; optional read-through to shared Redis for cross-node warm cache.

Scaling: add nodes behind anycast/LB. No coordination needed — pure function of (query, policy bundle).

### 5.2 Control plane

- **Source of truth:** PostgreSQL (HA: Patroni/RDS Multi-AZ). Stores tenants, policies, group definitions, blocklist subscriptions, allow/deny overrides.
- **Blocklist ingester:** scheduled jobs fetch external lists (StevenBlack, URLhaus, threat feeds), normalize, dedupe, diff. Produces canonical domain sets.
- **Policy compiler:** takes DB policy + ingested lists → emits a **signed, versioned policy bundle** per tenant/group (bloom filter blob + override tables + metadata). Bundles are immutable and content-addressed.
- **Distribution:** bundles published to object store (S3-compatible); pointer/version published to **etcd/Consul**. Filter nodes watch the config store and pull new bundles. Push-on-change + periodic reconcile.
- **Signing:** bundles signed (e.g. cosign/ed25519). Nodes verify before applying. Prevents poisoned policy.

### 5.3 Management plane

- **API:** gRPC + REST gateway, stateless, behind LB. All writes go to PostgreSQL; triggers recompile.
- **UI:** SPA (React) talking to API. No PHP, no per-node state.
- **AuthN:** OIDC/SAML SSO (Okta/Entra/Keycloak). Service-to-service mTLS.
- **AuthZ:** RBAC + tenant scoping. Roles: super-admin, tenant-admin, policy-author, read-only/auditor.
- **Audit:** every mutation appended to immutable audit log (separate store, WORM/retention).

### 5.4 Telemetry pipeline

- Query events are **enriched at the filter node** before leaving the data plane: client IP, query type, response code, matched category, matched feed ID, and resolution latency are attached at source — not inferred later from partial data.
- Enriched events → message bus (Kafka or NATS JetStream), partitioned by tenant.
- Stream processor → **ClickHouse** for high-cardinality, fast analytical query logs with TTL-based retention.
- **OpenTelemetry** traces on the resolve path; **Loki/ELK** for operational logs.
- Dashboards (in-app, off the telemetry/metrics APIs): QPS, block ratio, cache hit ratio, p50/p99 latency, upstream health, per-tenant volume.
- **SIEM export layer** (§20): query event stream exposed via pull API (cursor-based REST) and push webhook, in JSON or CEF format, so any SIEM can consume without a custom connector.

---

## 6. Data Stores

| Store | Tech | Role | HA strategy |
|-------|------|------|-------------|
| Source of truth | PostgreSQL | Tenants, policy, config | Patroni / Multi-AZ, sync replica |
| Config/version | etcd or Consul | Bundle pointers, node registry | Raft quorum, ≥3 nodes |
| Bundle storage | S3-compatible object store | Immutable signed bundles | Multi-AZ, versioned |
| Shared cache | Redis Cluster | Cross-node DNS cache | Sharded + replicas |
| Query logs | ClickHouse | Analytics, search, retention | Sharded + replicated |
| Audit | Append-only (Postgres/ClickHouse + object archive) | Compliance | WORM archive |
| SIEM config | PostgreSQL | Webhook endpoints, delivery state, cursor | Same as source of truth |
| Secrets | Vault / cloud KMS | Keys, upstream creds | HA Vault |

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

- **Stateless filter nodes** → linear horizontal scale; autoscale on QPS/CPU.
- **Bloom-filter blocklists** → millions of domains, tens of MB RAM, O(1) negative lookups, no DB on hot path.
- **Two-tier cache** (in-process LRU + Redis cluster) → high hit ratio, cross-node warm cache.
- **Recursor pool** scaled independently; only cache misses for allowed domains reach it.
- **Anycast** spreads load to nearest node; LB health checks eject bad nodes in seconds.

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
- **Internal:** mTLS between all planes; SPIFFE/SPIRE for workload identity.
- **Bundle integrity:** signed, content-addressed bundles; nodes reject unsigned/invalid.
- **DNS hardening:** rate limiting per source, response-rate-limiting (RRL) to resist amplification, DNSSEC validation at recursor.
- **AuthN/Z:** SSO + RBAC + per-tenant isolation; least-privilege service accounts.
- **Secrets:** Vault/KMS, no secrets on disk in plaintext.
- **Audit:** immutable, exportable for compliance (SOC2/ISO27001).
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
- **Logs (Loki/ELK):** operational; structured JSON.
- **Query analytics (ClickHouse):** per-tenant top domains, blocked categories, client breakdown, retention by policy.
- **Traces (OpenTelemetry):** resolve path spans for latency debugging.
- **Alerting:** stale bundle, node down, upstream failure, block-ratio anomaly (possible misconfig or attack), Redis/PG health.
- **SLOs:** availability of resolution (e.g. 99.99%), p99 latency, bundle freshness.

---

## 12. Deployment & Operations

- **Packaging:** containers (OCI). Filter node, control-plane services, UI/API each independently deployable.
- **Orchestration:** Kubernetes for control/management plane and shared filter fleet; sidecar filters deployed with AS nodes (systemd or co-located pods).
- **IaC:** Terraform for infra, Helm for k8s workloads, GitOps (Argo/Flux) for config.
- **Rollout:** canary policy bundles to a subset of nodes; automatic rollback on error-rate spike. Blue/green for control-plane services.
- **Backup/DR:** PostgreSQL PITR, object-store versioning, etcd snapshots, ClickHouse backups. Multi-AZ; documented RTO/RPO.
- **Upgrades:** filter nodes are cattle — rolling replace. Schema migrations gated and reversible.

---

## 13. Migration Path (from a Pi-hole deployment)

1. **Import** existing Pi-hole blocklists, allow/deny entries, and group definitions into the control-plane PostgreSQL schema.
2. **Stand up** control plane + one filter node; validate parity of blocking decisions against the old Pi-hole on a query replay.
3. **Shadow mode:** run filter fleet in parallel, mirror queries, compare answers, no client impact.
4. **Cutover** one OpenVPN AS group at a time by changing the pushed DNS option to the new VIP.
5. **Decommission** Pi-hole after all groups migrated and logs/retention validated.

---

## 14. Technology Choices (reference, not mandatory)

| Layer | Primary | Alternative |
|-------|---------|-------------|
| DNS frontend | CoreDNS (custom plugins) | Knot Resolver, custom Rust |
| Recursor | Unbound | Knot Resolver |
| Source DB | PostgreSQL + Patroni | CockroachDB |
| Config store | etcd | Consul |
| Shared cache | Redis Cluster | KeyDB / Dragonfly |
| Bus | Kafka | NATS JetStream |
| Query analytics | ClickHouse | Druid |
| Metrics | In-app Analytics dashboard (telemetry API) | External APM (optional) |
| Secrets | Vault | Cloud KMS |
| Orchestration | Kubernetes | Nomad |

---

## 15. Open Questions / Risks

- **DNS leak enforcement** on heterogeneous VPN clients (Windows `block-outside-dns`, macOS/Linux split-DNS behavior) — needs per-OS validation.
- **Anycast vs LB** in the specific cloud/on-prem network — depends on routing capability.
- **Bloom-filter false positives** — bounded by sizing; pair with exact-match confirmation tier for the (rare) FP on block-critical lists.
- **Per-query tenant resolution cost** if option §7.3(1) is not feasible.
- **Compliance scope** (data residency of query logs per tenant) — may force regional ClickHouse shards.

---

## 16. Phased Roadmap

| Phase | Deliverable |
|-------|-------------|
| 0 | Control-plane schema, blocklist ingester, policy compiler, signed bundles |
| 0b | Category taxonomy + feed registry + auto-update pipeline with sanity gates (§18) |
| 0c | Proxmox VE appliance: CT templates + Ansible, collapsed control plane (§17) |
| 1 | Stateless filter node (CoreDNS plugin chain), bundle pull + verify, local cache |
| 2 | OpenVPN AS integration (sidecar + VIP), tenant/group mapping |
| 3 | Telemetry pipeline (Kafka → ClickHouse), in-app analytics dashboards |
| 4 | Management API + UI, SSO/RBAC, audit |
| 5 | HA hardening, multi-AZ, DR drills, canary rollout, autoscaling |
| 6 | Migration tooling, shadow mode, production cutover |

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
| IBM QRadar | Pull API → Universal DSM | CEF (`format=cef`) | Or syslog relay (future §20.8) |
| Palo Alto Cortex XSIAM | Webhook | JSON | Native HTTP event ingestion |
| Chronicle (Google SecOps) | Webhook | JSON (UDM mapping via ingestion API) | |
| Panther | Pull API | JSON | Native REST poller |
| Wazuh | Pull API → `<localfile>` JSON log tailing | JSON | No generic inbound webhook receiver exists on stock Wazuh; a polling script + `<wodle name="command">` bridges pull → local log. See `integrations/wazuh/README.md`. |
| Any MSSP | Pull API | CEF | MSSP controls polling cadence |

---

### 20.8 Future: syslog export

Syslog (RFC 5424, TLS) is a thin adapter on top of the same enriched event model — iterate the event stream, serialize as CEF, and write to a TCP/TLS socket. Not in scope for Sprint 14 but the data model is compatible. The control-plane config gains a `SiemSyslog` table parallel to `SiemWebhook`.

---

### 20.9 Sprint plan update (superseded — see sprint-plan.md Sprints 14–16)

| Sprint | Scope |
|---|---|
| **Sprint 14** | QueryEvent enrichment (client_ip, qtype, rcode, matched_category, matched_feed_id, latency_us) in Rust filter node + Postgres schema. Pull API `/api/v1/siem/events` with cursor pagination, tenant/decision filters, JSON + CEF format. Auth gated (operator+). |
| **Sprint 15** | `SiemWebhook` model + delivery engine (async, retry/backoff, HMAC signing). Webhook management UI in Settings. Delivery status + last-error surface. |
| **Sprint 16** | Client registry (CRUD API + UI, auto-discovery from query events, `client_name` embedded in events). |

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

## 22. DHCP — ISC Kea Integration

Mantis-DNS provides enterprise DHCP management by integrating **ISC Kea DHCP** as a co-located sidecar rather than re-implementing the DHCP protocol stack. Kea is the industry-standard successor to ISC dhcpd: it handles the full RFC 2131/8415 wire protocol, conflict detection, relay agent processing, HA failover, and DNSSEC — all battle-tested and actively maintained. Mantis contributes what Kea lacks: a multi-tenant control plane, a UI, DDNS bridging into Mantis DNS Zones, client registry integration, and tenant-aware policy enforcement.

**The result is the same operational outcome as a custom engine with a fraction of the implementation risk:**

- A new device plugs into the VPN or network → Kea assigns an IP → Mantis DDNS bridge writes A + PTR into DNS Zones → device appears in the client registry → visible in SIEM export — all without operator action.
- Scope/reservation/option changes made in the Mantis UI are immediately pushed to Kea's running config via Kea's direct HTTP management API; no daemon restart required.

---

### 22.1 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Mantis node (Docker Compose)                                  │
│                                                               │
│  ┌──────────────┐   REST      ┌─────────────────────────┐   │
│  │  mantis-ctrl  │ ──────────► │  kea-dhcp4 HTTP :8004   │   │
│  │  (FastAPI)   │ ──────────► │  kea-dhcp6 HTTP :8006   │   │
│  │              │                      │ commands            │
│  │  config-gen  │             ┌────────▼────────────────┐   │
│  │  lease-sync  │ ◄──────────│  kea-dhcp4 (UDP :67)    │   │
│  │  ddns-bridge │  Postgres   │  kea-dhcp6 (UDP :547)   │   │
│  └──────┬───────┘             └────────┬────────────────┘   │
│         │                              │ leases              │
│  ┌──────▼───────────────────────────────▼────────────────┐  │
│  │  PostgreSQL 17                                         │  │
│  │  schema: mantis.*   +   kea.dhcp4_leases               │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

**Kea services:**
- `kea-dhcp4` — DHCPv4 server (UDP port 67); Postgres lease backend.
- `kea-dhcp6` — DHCPv6 server (UDP port 547); same Postgres instance, separate schema.
- Direct HTTP control sockets — `kea-dhcp4` listens on `:8004` and `kea-dhcp6` listens on `:8006` for live config updates without restart.

**Mantis components added for Kea integration:**
- **`KeaConfigGenerator`** — Python class that translates Mantis DB models to Kea JSON config and pushes it via Kea's management API (`config-set`, `subnet4-add`, `subnet4-del`, `reservation-add`).
- **`DhcpLeaseSyncLoop`** — asyncio background task; reads `kea.dhcp4_leases` (Kea's native Postgres table) every 30 s and upserts `ClientEntry` records in the Mantis client registry.
- **`DhcpDdnsBridge`** — called by Kea's `run_script` hook on DHCP4_LEASE_COMMITTED / DHCP4_LEASE_EXPIRED; writes/deletes A + PTR records in Mantis DNS Zones via the internal records API.

---

### 22.2 Mantis data model (shadow tables)

Mantis maintains its own shadow of the DHCP configuration. This decouples the UI and API from Kea's JSON format, enables tenant isolation (Kea has no tenant concept), and allows offline planning before pushing to Kea.

**Kea's lease table (`kea.dhcp4_leases`) is authoritative for live lease state.** Mantis does not maintain a duplicate `DhcpLease` table; it reads directly from the Kea schema.

#### DhcpScope

```
DhcpScope {
    id                  UUID             PK
    tenant_id           UUID             FK → Tenant; indexed
    name                string(255)
    description         text | null
    // addressing (maps to Kea subnet4.subnet)
    subnet              cidr             // e.g. "10.8.1.0/24"
    range_start         inet             // start of dynamic pool
    range_end           inet             // end of dynamic pool
    exclusions          inet[]           // IPs excluded from the pool
    // binding
    interface           string(64) | null   // Kea "interface" field; null = all
    relay_agent_cidr    cidr | null         // giaddr CIDR for relay scope selection
    vlan_id             int | null          // informational
    // lease timing (maps to Kea valid-lifetime, renew-timer, rebind-timer)
    lease_time_s        int              default 86400
    max_lease_time_s    int              default 604800
    renew_time_s        int | null       // T1; null → Kea default (50% of valid-lifetime)
    rebind_time_s       int | null       // T2; null → Kea default (87.5%)
    // DNS integration
    domain_name         string(255) | null  // Kea option 15
    ddns_enabled        bool             default false
    ddns_zone_id        UUID | null      // FK → DnsZone; required if ddns_enabled
    ddns_ttl_s          int              default 300
    // Kea sync state
    kea_subnet_id       int | null       // Kea's internal subnet4 id after push
    last_pushed_at      timestamp | null
    // meta
    enabled             bool             default true
    created_at          timestamp
    updated_at          timestamp
}
```

#### DhcpStaticLease

Maps to Kea's `reservations` array within a subnet. Can also be a global reservation (subnet-independent).

```
DhcpStaticLease {
    id              UUID             PK
    scope_id        UUID | null      FK → DhcpScope; null = global reservation
    tenant_id       UUID             FK → Tenant
    mac_address     string(17)       // lowercase, colon-delimited; MAC or DUID
    ip_address      inet             // reserved IP
    hostname        string(255) | null
    description     text | null
    client_id       string(255) | null   // option 61; Kea "client-id" field
    next_server     inet | null          // option 66 TFTP for PXE (siaddr)
    boot_filename   string(255) | null   // option 67
    enabled         bool             default true
    created_at      timestamp
}
```

#### DhcpOption

Per-scope or per-reservation DHCP options. Kea accepts these as the `option-data` array.

```
DhcpOption {
    id              UUID
    scope_id        UUID | null          // null = global; FK → DhcpScope
    static_lease_id UUID | null          // FK → DhcpStaticLease (reservation-level)
    option_code     int                  // 1–254 (DHCPv4) or 0–65535 (DHCPv6)
    option_space    string default "dhcp4"
    value           text                 // Kea "data" field (CSV or hex)
    always_send     bool default false   // Kea "always-send"
}
```

**Automatically injected options** (generated by `KeaConfigGenerator`, not stored in `DhcpOption`):
- Option 1 (subnet mask) — from subnet CIDR.
- Option 6 (DNS servers) — Mantis filter node IPs for the scope's tenant.
- Option 15 (domain name) — from `scope.domain_name`.
- Option 28 (broadcast) — from subnet CIDR.
- Options 51/58/59 — lease/T1/T2 from scope timing fields.
- Option 54 (server ID) — Kea sets automatically.

#### DhcpRelayConfig

```
DhcpRelayConfig {
    id              UUID
    scope_id        UUID             FK → DhcpScope
    relay_ip        inet             // giaddr whitelist entry; maps to Kea relay.ip-addresses
    circuit_id_hex  string | null    // option 82 sub-option 1 match (hex)
    remote_id_hex   string | null    // option 82 sub-option 2 match (hex)
    // Kea client-class name generated from this for option-82 routing
}
```

#### DhcpHaConfig

```
DhcpHaConfig {
    id                  UUID
    tenant_id           UUID         // informational; HA is per-Kea-instance not per-tenant
    mode                "hot-standby" | "load-balancing" | "passive-backup"
    this_server_name    string       // Kea "this-server-name"
    peers               jsonb        // array of {name, url, role, auto-failover}
    heartbeat_delay_ms  int default 10000
    max_response_delay_ms int default 60000
    max_ack_delay_ms    int default 10000
    max_unacked_clients int default 10
    // generated Kea HA config pushed via config-set
    updated_at          timestamp
}
```

---

### 22.3 Kea config push

`KeaConfigGenerator` maintains a full Kea `Dhcp4` JSON config in memory and pushes it to the running daemon:

```
Push flow (on any DhcpScope / DhcpStaticLease / DhcpOption change):
  1. Build full kea-dhcp4.conf JSON from Mantis DB:
       subnet4 array    ← DhcpScope (enabled only)
       reservations     ← DhcpStaticLease per scope
       option-data      ← DhcpOption per scope/reservation + auto-injected options
       relay            ← DhcpRelayConfig per scope
       client-classes   ← generated for option-82 circuit-id / remote-id routing
       hooks-libraries  ← run_script (DDNS bridge), lease_cmds, host_cmds, stat_cmds
       ha               ← DhcpHaConfig if set
  2. POST http://kea:8004/ {"command":"config-set","arguments":{...}}
  3. On success: UPDATE DhcpScope SET kea_subnet_id=..., last_pushed_at=now() WHERE ...
  4. On failure: log KeaConfigPushFailedEvent; expose error in UI.

Alternative (incremental, for single-scope changes):
  - Use subnet4-add / subnet4-del / subnet4-update commands via lease_cmds hook.
  - Use reservation-add / reservation-del commands via host_cmds hook.
  - Incremental path used when only one scope changed; full config-set used after HA or
    hook config changes that require a full reload.
```

---

### 22.4 DDNS bridge

Kea's `run_script` hook library calls a script on each lease event. The script POSTs to the Mantis control-plane internal endpoint, which then calls the DNS Zones records API.

```
Kea hook config (generated):
  "hooks-libraries": [{
    "library": "/usr/lib/kea/hooks/libdhcp_run_script.so",
    "parameters": {
      "name": "/etc/kea/mantis-ddns-bridge.sh",
      "sync": false
    }
  }]

mantis-ddns-bridge.sh:
  curl -s -X POST http://mantis-ctrl:8000/api/v1/internal/dhcp-event \
       -H "Authorization: Bearer ${MANTIS_INTERNAL_TOKEN}" \
       -H "Content-Type: application/json" \
       -d "{\"event\":\"${KEA_LEASE4_TYPE}\", \"ip\":\"${KEA_LEASE4_ADDRESS}\",
            \"mac\":\"${KEA_LEASE4_HWADDR}\", \"hostname\":\"${KEA_LEASE4_HOSTNAME}\"}"

POST /api/v1/internal/dhcp-event handler:
  - DHCP4_LEASE_COMMITTED → upsert A record + PTR in ddns_zone_id zone.
  - DHCP4_LEASE_EXPIRED / DHCP4_LEASE_RELEASED → delete A + PTR records.
  - Enqueue retry (3× exponential backoff) on DNS Zones API failure.
  - DDNS skipped if scope.ddns_enabled=false or hostname is null.
```

---

### 22.5 Lease sync → client registry

```
DhcpLeaseSyncLoop (30 s interval):
  SELECT address, hwaddr, hostname, vendor_id, state, lease_type
    FROM kea.dhcp4_leases
   WHERE state IN (0, 1)         -- 0=active 1=offered
     AND expire > now() - interval '5 minutes'   -- include recently-expired for cleanup
     AND subnet_id = ANY($known_kea_subnet_ids);

  For each row:
    - Upsert ClientEntry(ip, mac, hostname, device_type inferred from vendor_id option 60).
    - Set tags: ["dhcp-managed", "kea-lease"].
    - Set group_id from DhcpScope.relay_agent_cidr → DhcpScopeGroupBinding.group_id.
```

---

### 22.6 HA

Kea's built-in HA hook (`libdhcp_ha.so`) handles failover without VRRP:

| Mode | Behaviour |
|---|---|
| `hot-standby` | Primary handles all traffic; standby listens and syncs lease DB; takes over automatically on primary failure. Both Kea instances share the same Postgres `kea.dhcp4_leases` table — no proprietary sync needed. |
| `load-balancing` | Each peer owns roughly half the address range; failover is peer-triggered. |
| `passive-backup` | Primary active; backup receives lease updates but never takes over autonomously. |

Mantis generates the Kea HA config section from `DhcpHaConfig` and pushes it via `config-set`. No keepalived/VRRP configuration is required.

---

### 22.7 Option 82 / relay

Kea handles relay agent (giaddr) processing natively. Mantis models relay configuration as `DhcpRelayConfig` rows and translates them to:
- `relay.ip-addresses` array in each subnet4 config (giaddr whitelist).
- Kea `client-class` expressions for circuit-id / remote-id routing (option 82 sub-options).

Unknown giaddr → Kea discards; `run_script` logs `DhcpRelayUnknownAgentEvent` to Mantis audit log.

---

### 22.8 PXE

PXE options are configured as `DhcpOption` rows (option code 66/67/17) at scope or reservation level. Architecture-aware PXE (option 93) is expressed as Kea `client-class` conditions:

```json
{"name": "UEFI-x64",
 "test": "option[93].hex == 0x0007",
 "option-data": [{"code": 67, "data": "shimx64.efi"}]}
```

`KeaConfigGenerator` generates these classes from `DhcpPxeProfile` rows and includes them in the config push.

---

### 22.9 DHCPv6

`kea-dhcp6` runs as a separate Docker Compose service alongside `kea-dhcp4`, sharing the same Postgres instance (separate Kea schema). Mantis shadow tables:

- `DhcpV6Scope` — maps to Kea `subnet6`; CIDR `/48`–`/128`, IA_NA address range, IA_PD prefix pool.
- `DhcpV6StaticLease` — Kea DHCPv6 reservation (DUID-based).

DDNS bridge: same `mantis-ddns-bridge.sh` script handles `DHCP6_LEASE_COMMITTED` events → AAAA + `ip6.arpa` PTR records via Mantis DNS Zones API.

---

### 22.10 Management UI

A new **DHCP** section in the left nav:

**Scopes** — table (subnet, range, utilization bar, DDNS badge, last-pushed); Add/Edit modal with CIDR validator, range picker, lease timing, DDNS zone selector, relay IPs; scope detail opens Options and Static leases sub-tables.

**Leases** — live read from `kea.dhcp4_leases` via Mantis proxy API; state badge; filters by scope/state/MAC/hostname/expiry; "Convert to reservation" one-click; bulk delete-expired; CSV export; utilization gauge per scope (green <75%, amber 75–90%, red >90%).

**Reservations** — MAC/IP/hostname table; bulk CSV import; inline conflict detection (red badge if IP has active dynamic lease for a different MAC).

**HA / Relay** — HA mode selector + peer config form; live Kea HA state (`partner-down`, `load-balancing`, etc.) via `ha-heartbeat` management API command; relay IP whitelist; option 82 client-class table.

**DDNS status** (within scope detail) — recent bridge events (hostname, IP, action, status, timestamp); retry queue depth; `ddns_zone_id` zone selector.

---

### 22.11 Observability

Kea exposes statistics via the `stat_cmds` hook and its Prometheus exporter (Stork agent or `kea-exporter`). Mantis augments with tenant-scoped metrics:

| Source | Metric / Event |
|---|---|
| Kea stat_cmds | `pkt4-discover-received`, `pkt4-offer-sent`, `pkt4-ack-sent`, `pkt4-nak-sent` per subnet |
| Kea stat_cmds | `declined-addresses`, `reclaimed-declined-addresses` per subnet |
| Mantis lease sync | `dhcp_leases_active{scope_id}`, `dhcp_pool_utilization_pct{scope_id}` |
| Mantis DDNS bridge | `dhcp_ddns_updates_total{scope_id, action, status}` |
| Mantis | `DhcpPoolExhaustedEvent` — alert at 90% pool utilization |
| Mantis audit log | Every config push, reservation add/del, HA state transition |
| Kea run_script | `DhcpRelayUnknownAgentEvent` logged on unrecognised giaddr |

---

### 22.13 Security

- **Rogue DHCP prevention**: Mantis does not prevent rogue servers — that is a network-layer concern (DHCP snooping on managed switches). However, Mantis logs `DhcpUnknownServerEvent` if it receives a DHCP reply packet (not a request) on its listening interface, which may indicate a rogue server.
- **Relay agent authentication**: giaddr whitelist validation (§22.5) prevents option 82 injection from untrusted relays.
- **DDNS authentication**: TSIG keys are per-tenant, stored encrypted (same mechanism as §20.4 webhook secrets), never exposed in plaintext via the API.
- **Lease data in audit log**: every DHCPACK, DHCPNAK, and DHCPRELEASE is appended to the audit log with actor=`dhcp-engine`, enabling forensic reconstruction of "who had IP 10.8.1.47 at 14:32 UTC on 2026-06-01".
- **PXE security**: TFTP server address is operator-configured; Mantis does not run a TFTP server itself, only injects the option. UEFI HTTP boot URLs must be HTTPS.

---
