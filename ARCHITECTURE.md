# Architecture

Mantis-DNS separates DNS filtering into three planes, so the DNS hot path never
depends synchronously on policy authoring, storage, or UI availability.

```
                         ┌──────────────────────────────────────────────┐
                         │              MANAGEMENT PLANE                  │
                         │  Admin API · Web UI (SPA) · Auth · RBAC        │
                         └───────────────┬──────────────────────────────┘
                                         │ REST/gRPC
                         ┌───────────────▼──────────────────────────────┐
                         │               CONTROL PLANE                    │
                         │  Policy compiler · Blocklist/feed ingester     │
                         │  PostgreSQL (source of truth)                  │
                         └───────────────┬──────────────────────────────┘
                                         │ signed policy bundle (protobuf)
                                ┌────────▼────────┐
                                │   FILTER NODE    │
                                │  DNS frontend    │
                                │  Policy engine   │
                                │  Local cache     │
                                │  Recursor/fwd    │
                                └──────────────────┘
```

- **Filter node** (`services/filter`, Rust) — stateless DNS resolver. Holds the
  latest signed policy bundle in memory and answers queries against a bloom
  filter of blocked domains. Never calls the control plane on the query path.
- **Control plane** (`services/control`, Python/FastAPI) — source of truth
  (PostgreSQL): tenants, groups, policies, feed subscriptions. Compiles policy
  + ingested blocklists into a signed, versioned bundle the filter node pulls.
- **Management UI** (`apps/ui`, TypeScript/React) — talks to the control
  plane's REST API. Tenant/group/policy administration, feed management,
  analytics.
- **Kea** (`services/kea`) — DHCP, hands out the filter node as the resolver
  to clients on the network it serves.

## Cross-language contract

[`proto/bundle.proto`](proto/bundle.proto) is the wire format both Rust and
Python build against. The bloom-filter hashing scheme is duplicated (not
shared as code) in `services/filter/mantis-policy/src/lib.rs` and
`services/control/mantis_control/compiler/bloom.py` — these two must stay in
lockstep; see the fixture tests in `services/control/tests/test_bloom.py`.

## Request path (cache miss)

1. Client's resolver (set via DHCP/Kea or VPN push) sends a query to a filter node.
2. Filter node resolves the query against the current signed policy bundle
   (bloom filter → allow/deny override).
3. Blocked → sinkhole response. Allowed → local cache → upstream resolver (DoT/DoH).
4. Answer returned; query event recorded for analytics.

## Deployment topologies

See the [README's Production deploy section](README.md#production-deploy) for
how these components map onto Docker Compose, a standalone `.deb`, Kubernetes
(Helm), or a cloud-init VM appliance.

## Full design document

This file is the as-built summary. The complete design — multi-tenancy model,
HA/scaling strategy, OpenVPN AS integration, category-feed auto-update
pipeline, SIEM export, upstream resolver pools — lives in
[`docs/design.md`](docs/design.md). Sprint-by-sprint delivery status is in
[`docs/sprint-plan.md`](docs/sprint-plan.md).
