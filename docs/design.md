# Enterprise DNS Filtering Platform — Design Document

**Codename:** Aegis-DNS
**Status:** Draft v1.1
**Date:** 2026-06-30
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
   │  Prometheus metrics · OpenTelemetry traces · Loki/ELK logs        │
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

- Query events → message bus (Kafka or NATS JetStream), partitioned by tenant.
- Stream processor enriches (geo, category) → **ClickHouse** for high-cardinality, fast analytical query logs with TTL-based retention.
- **Prometheus** for node/system metrics; **OpenTelemetry** traces on the resolve path; **Loki/ELK** for operational logs.
- Dashboards (Grafana): QPS, block ratio, cache hit ratio, p50/p99 latency, upstream health, per-tenant volume.

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

- **Metrics (Prometheus):** QPS, block ratio, cache hit ratio, latency histograms, upstream errors, bundle version per node, recursor pool health.
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
| Metrics | Prometheus + Grafana | VictoriaMetrics |
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
| 3 | Telemetry pipeline (Kafka → ClickHouse), Grafana dashboards |
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
│  │ CT: openvpn     │   │ CT: aegis-      │  │ CT: aegis-     │  │
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

- Run components as **LXC containers** (lightweight, recommended) or VMs. Minimum: 2 CTs — `aegis-filter` + `aegis-control` — plus the existing `openvpn` CT/host.
- OpenVPN pushes `dhcp-option DNS <aegis-filter IP>` on the tunnel bridge. Add `block-outside-dns` (Windows) and route DNS through the tunnel to stop leaks.
- No anycast, no external LB needed on a single host. The filter CT IP is the resolver.

### 17.2 Collapsed control plane

- Postgres can run as a small instance in the `aegis-control` CT (or SQLite-compatible mode for very small sites — but Postgres preferred for the category/audit schema).
- Bundle distribution degenerates to a **shared volume / bind-mount** (or local HTTP) between control and filter CTs. The signed-bundle + version-pointer mechanism is unchanged; the "bus" is just the filesystem. Filter still verifies signature before applying.
- Object store, Kafka, ClickHouse are **optional** at this scale: query logs can land in Postgres or a local ClickHouse CT only if analytics are wanted.

### 17.3 HA on a PVE cluster (optional)

- For a **multi-node PVE cluster**, run `aegis-filter` as a CT on each node and use **PVE HA + a shared VIP** (keepalived/VRRP CT, or pfSense/CARP if present) so VPN clients hit a floating DNS IP.
- `aegis-control` runs as a single HA-managed CT (PVE HA restarts it on another node on failure); it is **not** on the DNS hot path, so brief downtime only delays policy updates.
- Postgres replication optional; for most PVE sites, PVE HA failover of one control CT + ZFS replication of its disk is sufficient.

### 17.4 Resourcing (rule of thumb, single host)

| CT | vCPU | RAM | Disk | Notes |
|----|------|-----|------|-------|
| aegis-filter | 2 | 1–2 GB | 4 GB | bloom filters + cache in RAM |
| aegis-control | 2 | 2–4 GB | 20 GB+ | Postgres + feeds + UI |
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

*End of document.*
