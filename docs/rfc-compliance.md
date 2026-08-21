# DNS Protocol Conformance — Audit & Plan

Status: written 2026-08-21 against `effeb54`. **All four phases (§3) touched
this same day**: 1 and 2 shipped in full, 3 and 4 shipped partially — see
sprint-plan.md Epic R Sprints 30–33 and design.md §27 for the as-built
summary, and each phase's own section below for what turned out to need
real, separate future work rather than fitting this pass. Nothing in this
document remains pure audit-only at this point; every finding either shipped
or has an explicit, reasoned deferral. Companion to [`design.md`](design.md);
the DHCP side already has an equivalent register in design.md §22.14 — this
was the DNS counterpart it never got.

## 0. Scope — what "fully RFC compliant" can mean here

"Fully RFC compliant" is not a finite target: the DNS RFC surface is ~200
documents, and most describe roles Mantis does not play (recursive iterator,
DNSSEC signer, zone-transfer master, registry EPP). Compliance is only
meaningful per *role*. Mantis-filter plays exactly three:

| Role | Where | Governing RFCs |
|---|---|---|
| **Forwarding/caching resolver** (client-facing) | `lib.rs::build_response`, `resolve_records`, `cache.rs` | 1034, 1035, 2181, 2308, 6891, 7766, 8020, 8482, 8914, 9520 |
| **Small authoritative server** for stub zones | `zone_store.rs` | 1034 §4.3.2, 1035, 2308, 4592 |
| **Stub resolver** (upstream-facing) | `upstream_bundle.rs`, hickory-resolver | 7858 (DoT), 8484 (DoH), 5452, 4035 — mostly delegated to hickory |

This document scopes conformance to those three roles, plus RFC 8906
("A Common Operational Problem in DNS Servers — Failure To Communicate"),
which is the de-facto conformance checklist the DNS flag-day testers measure.

Explicitly **out of scope**, and not a compliance gap: being a full recursive
resolver (design.md §21.5 already delegates that upstream), DNSSEC signing of
local zones (§24.6), AXFR/IXFR as a server (§24.6), DoQ (§21.9).

## 1. Architectural fork in the road (decide before Phase 1)

The listeners are hand-rolled on tokio rather than using `hickory-server`.
sprint-plan.md's risk table already flags this: *"Truncation and TCP-fallback
handling are therefore ours"*. Roughly half the findings below — opcode
dispatch, class dispatch, EDNS version/BADVERS, TC policy, TCP framing — are
things `hickory-server`'s `ServerFuture` + `RequestHandler` implement already,
and are exactly the things a hand-rolled loop forgets.

**Option A (recommended): keep the hand-rolled loops, add one `protocol.rs`.**
The loops carry things `hickory-server` does not model — the tenant source-IP
router, the per-listener concurrency semaphores, the bootstrap fail-open
window. Rewriting them onto `RequestHandler` moves that logic rather than
deleting it, and every `Message`-level fix below lands in one new module
shared by all four server loops (`run_udp_server`, `run_tcp_server`,
`run_router_udp_server`, `run_router_tcp_server`). Additive, reviewable diff.

**Option B: adopt `hickory-server`.** Gets Phase 1 items and C3 for free,
costs a rewrite of four listener loops plus the router, and puts the
concurrency bounds (which exist because of a real, incident-shaped comment in
`run_udp_server`) behind someone else's scheduling. Not recommended now;
revisit if the conformance surface keeps growing.

Everything below assumes Option A.

## 2. Findings

Severity: **A** = wrong on the wire today, breaks real clients · **B** =
MUST/SHOULD-level gap with observable impact · **C** = SHOULD-level hardening
· **D** = deliberate deviation, document rather than fix.

### A — wrong on the wire today

| # | Finding | Where | RFC |
|---|---|---|---|
| A1 | **Queries with QR=1 are answered.** A response injected at the listener is parsed as a query and replied to. Two Mantis nodes pointed at each other, or a spoofed response, produce a packet loop and a free amplifier. Nothing reads `Message::message_type()`. | `lib.rs:751` `build_response`; UDP loops `lib.rs:518`, `router.rs:461` | 1035 §4.1.1 |
| A2 | **Every opcode is treated as QUERY.** `response.set_op_code(query.op_code())` copies the opcode, then the *zone* section of an UPDATE (or a NOTIFY, or obsolete IQUERY) is read as a question and answered. Must be `NOTIMP` for anything but QUERY. | `lib.rs:765` | 1035 §4.1.1, 3425, 2136 |
| A3 | **QCLASS is ignored.** Only `query_type()` is read. A `CH`-class query is forwarded upstream as `IN` and the `IN` answer returned under a `CH` question. Must be `REFUSED`/`NOTIMP` for non-`IN`; `CH TXT version.bind`/`id.server` optionally served locally. | `lib.rs:769-777` | 1035 §3.2.4, 4892 |
| A4 | **No SOA in the authority section of any negative answer.** NXDOMAIN and NODATA go out with an empty authority section on all three paths — stub zone (`lib.rs:796`), block (`lib.rs:946`, `:969`), upstream (`lib.rs:998`, `:1055`). Downstream resolvers cannot negative-cache, so every repeat of a non-existent name comes back to us in full. Highest traffic-impact item in this document. | `lib.rs:781-802`, `922`, `979` | 2308 §3 |
| A5 | **EDNS is dropped entirely on the TCP path.** `enforce_udp_size_limit` is the only place a response OPT record is built, and it is called from the UDP loops only. An EDNS query over TCP gets a response with no OPT — no EDE, no cookies, no keepalive, and no way for the client to tell we understood EDNS at all. | `lib.rs:663`, `router.rs:427` (no OPT); OPT built only at `lib.rs:887` | 6891 §6.1.1 |
| A6 | **EDNS version is never checked.** An `EDNS(1)` query is processed as `EDNS(0)` instead of being answered `BADVERS` (extended RCODE 16) with an OPT carrying our max supported version. The classic `ednscomp` failure. | `lib.rs:881-893` | 6891 §6.1.3 |
| A7 | **Empty non-terminals in local zones return NXDOMAIN.** `ZoneStore::lookup` is a flat `HashMap` probe on the exact owner name: with only `_ldap._tcp.corp.lab` present, a query for `_tcp.corp.lab` returns *authoritative* NXDOMAIN instead of NODATA. Per RFC 8020 a downstream cache then treats everything below it as non-existent — including the record that does exist. Breaks SRV/DNS-SD. | `zone_store.rs:229-236` | 1034 §4.3.2, 8020 |
| A8 | **No CNAME chasing in local zones.** Records are filtered by exact `record_type() == qtype`, so a name holding only a CNAME answers NODATA to an A query instead of returning the CNAME (and, for in-zone targets, following it). | `zone_store.rs:232-235` | 1034 §4.3.2 |
| A9 | **TXT records over 255 bytes cannot be encoded.** `RData::TXT(TXT::new(vec![entry.data.clone()]))` puts the whole value in one character-string; the 255-byte wire limit then fails the *entire message* encode and the client gets nothing rather than a truncated answer. DKIM keys and long SPF records routinely exceed 255 bytes. Needs chunking into 255-byte character-strings. **Verify the exact failure mode before fixing** — it may surface at `to_bytes()` (silent drop, `lib.rs:557`) rather than at publish time. | `zone_store.rs:131` | 1035 §3.3.14 |

### B — MUST/SHOULD gaps with observable impact

| # | Finding | Where | RFC |
|---|---|---|---|
| B1 | **No Extended DNS Errors on blocked answers.** A DNS filtering product is precisely the case RFC 8914 codes 15 (Blocked), 16 (Censored), 17 (Filtered) were written for; without them a blocked name is indistinguishable from a broken one, in the client's diagnostics and in ours. Small change, high product value. | `lib.rs:922` `apply_block_response`, plus zone NXDOMAIN | 8914 |
| B2 | **DNSSEC-aware clients cannot be served.** The DO bit is never read, RRSIG/NSEC records are never requested upstream (`Forwarder::lookup` asks one qtype and returns `lookup.records()` only), AD and CD are never propagated. A validating stub behind a Mantis node can validate nothing. Interaction with filtering: DO=1 on a blocked name must return the block plus EDE, never a bogus signature. | `lib.rs:763-767`, `1009-1045`, `upstream_bundle.rs:480` | 4035 §3.2, 6840 §5.7 |
| B3 | **SERVFAIL is never cached.** Every upstream failure re-queries upstream on every packet. RFC 9520 makes caching resolution failures a MUST (1 s ≤ TTL ≤ 5 min) precisely because the uncached case turns one broken zone into a retry storm against the upstream pool. `DnsCache` already has the negative-entry machinery — this is one more `NegativeKind`. | `lib.rs:1075`, `cache.rs:30` | 9520 |
| B4 | **Special-use domain names are forwarded upstream.** `.onion` (MUST NOT be forwarded), `.local` (mDNS, MUST NOT), `.invalid`, `.test`, `.example`, `.home.arpa`, and the RFC 6303 private reverse zones (`10.in-addr.arpa`, `16-31.172.in-addr.arpa`, `168.192.in-addr.arpa`, `254.169.in-addr.arpa`, IPv6 ULA/link-local) all leak to the public resolver pool today. Privacy leak as much as a compliance gap. `ZoneStore` is the natural home: a built-in, always-present set of locally-served empty zones consulted after tenant zones. | `lib.rs:781`, `zone_store.rs` | 6761, 7686, 6762 §12, 8375, 6303 |
| B5 | **QTYPE=ANY is forwarded verbatim.** The largest-response qtype in DNS is proxied straight through — the classic reflection-amplification lever. RFC 8482 permits answering ANY minimally (one arbitrary RRset, or HINFO). Should also be answered from the local zone rather than forwarded when the name is local. | `lib.rs:979` | 8482 |
| B6 | **AXFR/IXFR and meta-qtypes are forwarded.** Transfer qtypes over UDP are undefined and must be refused, not proxied; OPT/TSIG/TKEY as a QTYPE must be FORMERR. | `lib.rs:979` | 5936 §4.2, 6895 |
| B7 | **RD=0 is echoed but not honored.** `set_recursion_desired(query.recursion_desired())` copies the bit, then the query is recursed anyway. A non-recursive query must be answered from local data (stub zone / cache) only and otherwise refused — this is also how open-resolver scanners fingerprint us. | `lib.rs:766`, `1009` | 1034 §4.3.1, 1035 §4.1.1 |
| B8 | **RA=1 is unconditional**, including on the bootstrap `SERVFAIL` path and for unmatched-route sources we will never recurse for. | `lib.rs:767`, `825` | 1035 §4.1.1 |
| B9 | **No local zone apex SOA or NS.** A zone with no SOA is not a zone: `SOA`/`NS` queries at the apex return NODATA, and A4's negative-answer SOA has nothing to source from. Either the control plane synthesizes an apex SOA + at least one NS per zone, or the filter node does it deterministically from the zone name. Prerequisite for A4 on the stub-zone path. | `zone_store.rs`, control plane `/api/v1/local-zones` | 1034 §4.2, 1035 §3.3.13 |
| B10 | **No wildcard support in local zones.** `*.corp.lab` is stored as a literal owner name and never matches anything. | `zone_store.rs:229` | 1034 §4.3.3, 4592 |
| B11 | **Unparseable packets are silently dropped.** If the 12-byte header parses but the rest does not, RFC 8906 conformance expects `FORMERR` with the ID echoed, not silence — silence is indistinguishable from packet loss and makes clients wait out their full timeout. | `lib.rs:518`, `642`, `router.rs:391`, `461` | 1035 §4.1.1, 8906 |
| B12 | **QDCOUNT > 1 is mis-answered.** All questions are echoed into the response (`lib.rs:768-770`) but only the first is answered. Must be `FORMERR`. | `lib.rs:768-777` | 1035 §4.1.2 |

### C — hardening / SHOULD-level

| # | Finding | Where | RFC |
|---|---|---|---|
| C1 | **No DNS Cookies.** Any node reachable off-link is an off-path spoofing and amplification target; cookies are the cheap standard mitigation and pair naturally with the EDNS work in Phase 1. | new `protocol.rs` | 7873, 9018 |
| C2 | **Truncation drops answers one at a time and keeps the authority/additional sections.** Additional should be shed first, and a TC response is conventionally sent with an empty answer section so the client retries over TCP rather than acting on a partial RRset. | `lib.rs:895-908` | 1035 §4.1.1, 6891 §7 |
| C3 | **TCP queries are processed strictly serially per connection.** One slow upstream lookup head-of-line-blocks every pipelined query behind it. RFC 7766 explicitly permits (and expects) out-of-order responses. | `lib.rs:612` `handle_tcp_connection`, `router.rs:344` | 7766 §6.2.1.1, §7 |
| C4 | **No `edns-tcp-keepalive`.** With TCP the fallback for every truncated answer, signalling an idle timeout beats silently closing at `TCP_IDLE_TIMEOUT` (30 s). | `lib.rs:626` | 7828 |
| C5 | **UDP replies may leave from the wrong source address.** The listener binds `0.0.0.0` and replies with `send_to`, so on a multi-homed node the kernel picks the source IP by route, not by the address the query arrived on; the client discards the reply. Needs `IP_PKTINFO`/`IPV6_RECVPKTINFO` and `sendmsg`. Operational bug on any node with more than one address — a normal shape for an edge filter node. | `lib.rs:514`, `router.rs:457` | 1035 (implied), operational |
| C6 | **No RRL (response rate limiting).** Not an RFC, but BCP 140 is the reason the source-IP router exists; an unmatched source still gets a reflected SERVFAIL packet. | `router.rs:483` | 5358 (BCP 140) |
| C7 | **`id.server`/`hostname.bind` unimplemented** — trivial once A3's class dispatch exists, and Epic O already introduces `MANTIS_NODE_NAME` as the natural value. | with A3 | 4892, 5001 (NSID) |

### D — deliberate deviations to document, not fix

| # | Deviation | Where | Note |
|---|---|---|---|
| D1 | **`min_ttl_s` raises TTLs above the authoritative value.** `TtlPolicy::clamp_positive` does `ttl.max(min_ttl_s)` and writes the raised TTL into the records handed to the client — RFC 2181 §8 makes the TTL an upper bound, so extending it is a deviation. Unbound's `cache-min-ttl` does the same and documents it the same way. Keep; consider applying the floor to our own cache entry only, not to the record TTL sent downstream. | `lib.rs:86-93`, `1029-1035` | 2181 §8 |
| D2 | **All records in a forwarded response are flattened to one TTL** (the minimum across the whole returned set, including a CNAME chain's separate RRsets). Safe direction, coarser than RFC 2181 §5.2 requires. | `lib.rs:1027` | 2181 §5.2 |
| D3 | **Block answers are synthesized, not signed.** A blocked name that is DNSSEC-signed upstream cannot validate — inherent to DNS filtering, which is exactly why B1's EDE codes exist. | `lib.rs:922` | 8914 |
| D4 | **`www.` is stripped during policy normalization.** Deliberate (design.md §18.3) and not a protocol behavior — it affects the policy decision, never the name on the wire. Recorded so a future reader does not "fix" it. | `lib.rs:335` | — |
| D5 | **DDNS from mantis-dhcp is a direct database write, not an RFC 2136 UPDATE.** Correct for a system that owns both ends; noted because "DDNS" normally implies 2136. | `services/dhcp/mantis-dhcp/src/ddns.rs` | 2136, 4703 |

## 3. Plan

Four phases, each independently shippable and independently testable, each
ending with the conformance suite in §4 passing a strictly larger subset.

### Phase 1 — Query sanity + EDNS, in one shared module (**shipped 2026-08-21**)

`services/filter/mantis-filter/src/protocol.rs`, called from all four server
loops so no listener can drift from another. As built:

- `validate_query(&Message, node_name: &str) -> QueryAction` — rejects
  non-QUERY opcode (A2, NOTIMP), non-IN class (A3, REFUSED, with CH TXT
  `version.bind`/`hostname.bind`/`id.server` answered locally per C7),
  QDCOUNT≠1 (B12, FORMERR), AXFR/IXFR (B6, REFUSED) and OPT/TSIG as a QTYPE
  (B6, FORMERR).
- `should_process(&Message) -> bool` — QR=1 check (A1), kept separate from
  `validate_query` since the correct action is silence, not a rejection
  reply; `build_response` now returns `Option<Message>` and every call site
  sends nothing on `None`.
- `negotiate_edns(query, &mut response) -> bool` — echoes OPT on **both**
  transports (A5, called once from `build_response` rather than only from
  the UDP-only `enforce_udp_size_limit`), returns whether the query's EDNS
  version is unsupported so the caller can answer BADVERS (A6).
  `enforce_udp_size_limit` keeps the size/TC job and now sheds the
  additional section before clearing the answer section wholesale on
  truncation (C2), rather than popping records one at a time.
- `formerr_for_unparseable(&[u8]) -> Option<Message>` (B11) — decodes just
  the 12-byte header via `hickory_proto::op::Header::read` when the full
  message fails to parse, and replies FORMERR with the echoed ID; `None`
  when even the header doesn't parse, or when it says the malformed packet
  wasn't a query either.
- RD=0 honored in `resolve_records` (B7: a cache miss with RD=0 is REFUSED,
  never triggers an outbound lookup) and RA cleared in `build_response`'s
  closed-bootstrap/unmatched-route ServFail branch (B8).

**Not built in Phase 1:** EDE (B1) and DNS Cookies (C1) — both need either
the authority-section plumbing Phase 2 adds or new server-side state, and
were cut to keep this slice mechanical. `scripts/conformance.sh`
(`ednscomp`/`dig` against a live compose stack) — the exit criteria below
were instead verified via `protocol.rs`'s and `lib.rs`'s unit/integration
test suites (101 + 22 tests, all passing) plus `cargo clippy -D warnings`;
the wire-level tool gate is still open.

**Exit (partially verified — see above):** `dig +opcode=UPDATE`, `+qr`,
`-c CH`, `+edns=1`, `-t AXFR`, `+norecurse` each get the correct rcode over
both UDP and TCP, confirmed by `protocol::tests` and `lib.rs`'s
`build_response_*` tests exercising the same cases without a live server.
`ednscomp` itself has not been run.

### Phase 2 — Negative answers, and the local zone as a real zone (**shipped 2026-08-21**)

The highest traffic win (A4) plus its prerequisites. As built, split across
`zone_store.rs`, `cache.rs`, `lib.rs`, and one control-plane change:

- Apex SOA/NS: **control-plane-authored** (B9), `get_local_zone_records` in
  `services/control/mantis_control/api/routers.py` synthesizes an apex SOA
  for every zone it serves (mname/rname matching `export_zone`'s existing
  BIND-format convention, serial derived from `DnsZone.updated_at`) plus an
  apex NS unless the zone already defines one explicitly — as predicted,
  `DnsZone`'s `updated_at`/`ttl_default`/`name` were already enough, no
  migration needed. `zone_store.rs` *also* synthesizes a fallback SOA
  Rust-side (`synthesize_soa`) for defense in depth if a zone somehow ships
  with none, so the authority section is never silently empty either way.
- SOA in the authority section of every NXDOMAIN/NODATA (A4), all three
  paths. **The predicted `Forwarder` trait signature change (B9's "largest
  single edit") turned out to be unnecessary**: `hickory_resolver::ResolveError`
  already carries the upstream's authority-section SOA on exactly the
  NXDOMAIN/NODATA error path both `DotForwarder` and `UpstreamBundleForwarder`
  already return errors through (`ResolveError::into_soa()` — RFC 2308
  support hickory already had, `resolve_records` just wasn't asking for it).
  `resolve_records` downcasts the error, extracts the SOA, and caches it
  alongside the negative-cache entry so a repeat *cache hit* still carries it.
- Empty non-terminals → NODATA (A7), CNAME at any qtype (A8), single-label
  wildcards (B10, not the full RFC 4592 closest-encloser algorithm — a
  documented simplification). ANY's local half (B5) was already adequate
  (NODATA, never forwarded) and needed no change; the forwarding half stays
  Phase 4.
- TXT chunking (A9) — 255-byte character-strings, split on a UTF-8 char
  boundary.
- Built-in special-use / RFC 6303 empty zones (B4) as a second,
  always-present list `ZoneStore::lookup` falls back to after tenant zones —
  a tenant zone with the same apex still wins.
- SERVFAIL caching (B3) — new `NegativeKind::ServFail`, fixed 30s TTL
  independent of the tenant's `negative_ttl_s` per RFC 9520.

**Not built in Phase 2:** the wildcard implementation is deliberately
single-label only (see B10 above) — a query two labels below a wildcard
falls through to NXDOMAIN rather than matching, which the full RFC 4592
algorithm would catch. Zone-file *import* (parsing `$ORIGIN`/`$TTL` back into
the DB) remains out of scope, unchanged from design.md §24.6.

**Exit (verified):** `zone_store.rs`, `cache.rs`, and `lib.rs` unit tests
cover every finding above end to end, including one that builds a real
`hickory_resolver::ResolveError` via `ProtoError::nx_error` to prove the SOA
extraction against the actual upstream error shape rather than a mock. The
control-plane synthesis is covered by `test_local_zones_endpoint.py`. Full
Rust workspace test suite, `cargo clippy -D warnings`, `ruff`, and `mypy` all
pass. `scripts/conformance.sh` (live `dig`/`ednscomp` gate) remains unbuilt,
same gap noted in Phase 1.

### Phase 3 — DNSSEC transparency (B2) (**partially shipped 2026-08-21 — see below**)

The plan below is what this section said *before* implementation. Actually
building it surfaced a fact the original two options both missed: hickory's
high-level `Resolver::lookup()` API — what every `Forwarder` impl in this
crate is built on — filters its answer down to the single requested record
type before handing it back. RRSIG/NSEC/NSEC3 records literally never reach
`Lookup.records()` no matter what DO does on the wire, because they're a
different `RecordType` than the one asked for. Getting them out requires a
lower-level client (`hickory-client`'s `AsyncClient`/raw `DnsHandle`, not
`hickory-resolver`'s `Resolver`) — a new dependency and a second resolution
path, not a flag flip. That reframes the phase:

- **Shipped:** AD propagation from *this resolver's own* validation.
  `hickory_resolver::lookup::Lookup::dnssec_record_iter()` exposes each
  returned record's `Proof` (`Secure`/`Insecure`/`Bogus`/`Indeterminate`) —
  data the resolver already computes internally whenever `dnssec_strict`
  turns on `ResolverOpts::validate` (§21.5), just never surfaced past the
  `Vec<Record>` conversion. `Forwarder::lookup` now returns `LookupOutcome
  { records, authenticated }` (`dnssec_outcome()` in lib.rs, used by both
  `DotForwarder` and `UpstreamBundleForwarder`'s `do_lookup`) — `authenticated`
  is `true` only when every returned record proved `Secure`, cached alongside
  the record set so a repeat cache hit still asserts AD correctly. This is
  **not** "validate locally" in the sense original option 2 meant (§21.5's
  concern) — no new validation happens; it only *surfaces* validation that
  `dnssec_strict` was already performing and previously threw away.
- **Shipped:** DO is echoed back to the client on our own response
  (`negotiate_edns`, protocol.rs) — cheap, safe, and something Phase 1 should
  arguably have done already.
- **Not shipped, and not close to a small fix:** RRSIG/NSEC/NSEC3
  pass-through and per-query CD-driven bypass of `dnssec_strict`. Both need
  the lower-level client described above (CD-bypass specifically needs a
  *second*, non-validating resolver instance selectable per query — today
  `dnssec_strict` is baked into one `Resolver` per pool at build time,
  `upstream_bundle.rs:532`). This is real, separate infrastructure work, not
  a Phase 3 line item — track it as its own future epic if a customer
  actually needs a validating-stub downstream of a Mantis node, rather than
  padding this phase further.

Neither original option was fully right: option 1 ("transparent pass-through")
undersold the client-library rewrite it actually requires; option 2
("validate locally, set AD ourselves") was closer to what shipped, but its
"makes the filter node a validator" framing overstated it — `dnssec_strict`
already made hickory a validator per §21.5's own as-built note; this phase
just stopped hiding the result.

### Phase 4 — Hardening (**partially shipped 2026-08-21 — see below**)

B1, C1, C3, and C4 shipped. C5 and C6 didn't — both are substantial,
self-contained systems-engineering projects that don't fit a "harden the
protocol layer" pass, for reasons only clear once actually scoped:

- **Shipped — B1 (Extended DNS Errors, RFC 8914).** Every blocked answer now
  carries an EDE option, info-code 17 (Filtered — RFC 8914 §4.18's own
  wording is "a filtering policy configured by an operator/administrator,"
  which is exactly what every block this filter node produces is), plus the
  matched category or override rule as free-form diagnostic text. No-op if
  the client never negotiated EDNS. `protocol::attach_extended_error`,
  called from `build_response`'s `Decision::Block` arm.
- **Shipped — C4 (`edns-tcp-keepalive`, RFC 7828).** TCP responses now carry
  the keepalive option advertising `TCP_IDLE_TIMEOUT` (30s). No-op without
  EDNS. `protocol::attach_tcp_keepalive`, called from both TCP send paths.
- **Shipped — C1 (DNS Cookies, RFC 7873), foundation only.** Computes and
  verifies a server cookie (`secret || client_ip || client_cookie`,
  SHA-256, truncated to 8 bytes — a simplified keyed hash, not HMAC, judged
  adequate for this threat model) so a resolver that speaks RFC 7873 gets a
  correct, stable exchange. **Deliberately does not reject anything on a
  mismatch.** The original plan for this item assumed BADCOOKIE-on-mismatch
  was the point; re-reading RFC 7873 §5.2 before implementing found that
  wrong — a mismatch is the *expected*, harmless result of this process
  restarting and rotating its secret (§5 explicitly allows exactly that
  rotation policy) or a client's address changing mid-session (NAT
  rebinding, mobile roaming), and BADCOOKIE is an *optional* policy a server
  MAY apply specifically when under load, not something a bare mismatch
  justifies. Enforcing it unconditionally would be non-compliant and would
  break every client on every deploy. So what shipped is correct protocol
  machinery — a stable, verifiable cookie exchange — not yet a deployed
  spoofing defense; it's what a future load-triggered BADCOOKIE policy (C6)
  would need to consult, not a substitute for one.
- **Shipped — C3 (TCP out-of-order pipelining, RFC 7766 §6.2.1.1, §7).**
  Both TCP loops (`lib.rs::handle_tcp_connection`,
  `router.rs::run_router_tcp_server`) now split the connection into an
  `OwnedReadHalf`/`OwnedWriteHalf` pair: the reader spawns each query onto
  its own task (bounded, `MAX_PIPELINED_TCP_QUERIES_PER_CONN` = 16) and a
  single writer task drains an mpsc channel of encoded answers in
  completion order. Verified with a real integration test
  (`tests/tcp_pipelining.rs`) that pipelines a slow query and a fast query
  back to back with no read in between, and asserts the fast one's answer
  comes off the wire first.
- **Not shipped — C5 (`IP_PKTINFO` source-address selection).** Real bug (a
  multi-homed node's replies leave from whichever address the kernel's
  routing table picks, not the address the query arrived on), but fixing it
  needs `sendmsg`/`recvmsg` with ancillary control-message data — outside
  what tokio's `UdpSocket` exposes (`recv_from`/`send_to` only). That means
  either raw libc syscalls on the socket's raw fd or a new dependency
  (`socket2` gets the socket options but not the cmsg send/receive path
  itself), platform-specific unsafe code, and — critically — no way to
  verify it actually works without real multi-homed hardware, which this
  environment doesn't have. Shipping unsafe socket code that can't be
  tested here is worse than not shipping it.
- **Not shipped — C6 (response rate limiting, BCP 140).** Not a missing
  function so much as a whole feature: per-source token-bucket or
  sliding-window tracking, memory-bounded under sustained attack load, with
  a "similar responses" grouping heuristic BCP 140 leaves intentionally
  vague. Doing this carelessly creates a *new* DoS vector in either
  direction — unbounded memory growth under a real flood, or legitimate
  clients incorrectly throttled — which is a worse outcome than the gap it
  would close. This is exactly the load signal C1's cookie foundation above
  is waiting for; the two should land together as their own scoped piece of
  work, not squeezed into a hardening pass already covering four unrelated
  items.

### Documentation changes

- New **design.md §27 "DNS protocol conformance"**, structured like §22.14's
  DHCP deviation register — the D table above is its seed content. §27 becomes
  the permanent home; this file stays the one-time audit.
- Cross-references from §21.5 (DNSSEC → Phase 3), §24.6 (the zone "not built"
  list gains A7/A8/B9/B10) and §26.11.
- sprint-plan.md: new **Epic R — DNS protocol conformance**, sprints mapping
  1:1 onto the four phases. Sequencing against the existing plan: Epic R
  Phases 1–2 should precede **Epic O Sprint 29**, whose per-rcode counters
  would otherwise baseline the pre-fix rcode mix and become meaningless the
  moment the fixes land.

## 4. How compliance gets verified

Without a suite this becomes a checklist someone ticks by reading. Gates,
cheapest first:

- **`tests/dns_server.rs`** (exists) gains one integration case per finding ID
  above. sprint-plan.md's risk table already names this file as the home for
  hand-rolled-listener behavior, so no new test infrastructure is needed.
- **`ednscomp`** (DNS flag-day tool) plus `dig` invocations in a
  `scripts/conformance.sh` run against a compose-brought-up node. Covers
  A2/A3/A5/A6/B7/B11/B12 mechanically.
- **`dnsviz`** for Phase 3 only.
- CI: the script runs in the existing `rust` job after `cargo test`, gating
  merges the same way `clippy -D warnings` does today.

## 5. Honest summary

- **All 9 findings that were wrong on the wire when this was written are now
  fixed** (A1–A9, Phases 1–2, both shipped 2026-08-21).
- **Phases 1–2 held essentially all the value**, as predicted, and are done.
  Phase 3 partially shipped (AD propagation, DO echo). Phase 4 shipped B1,
  C1 (foundation), C3, C4; C5 and C6 remain — both real, self-contained
  projects rather than a hardening-pass line item, and neither blocks
  anyone today.
- **Two different trait-shape predictions from this audit, two different
  outcomes.** Phase 2's predicted `Forwarder` signature change turned out
  unnecessary (`ResolveError::into_soa()` already had the SOA). Phase 3's
  turned out *necessary*, but for a different reason than either original
  option guessed — not "for pass-through" but to surface a `Proof` value
  hickory already computed internally and simply discarded on the way to
  `Vec<Record>`. Same lesson each time: check what the dependency already
  tracks before assuming *what shape* a trait needs to grow into, in either
  direction.
- **The real finding from Phase 3 is architectural, not a missed line of
  code**: `hickory-resolver`'s `Resolver::lookup()` filters every answer down
  to one requested record type, so RRSIG/NSEC/NSEC3 can never reach a
  `Forwarder` built on it — DO on the wire doesn't change that. True
  pass-through needs a lower-level client (`hickory-client`) as a second
  resolution path, which is why it's now explicitly future work rather than
  a lingering Phase 3 checkbox.
- **The wildcard fix (B10) is intentionally partial**: single-label
  expansion only, not the full RFC 4592 closest-encloser algorithm. Revisit
  only if a real deployment needs multi-level wildcards.
- **A plan predicting BADCOOKIE-on-mismatch turned out wrong on a re-read of
  the actual RFC.** RFC 7873 §5.2 makes that an optional under-load policy,
  not a default — enforcing it unconditionally would reject legitimate
  clients on every one of this process's own restarts (which rotate the
  cookie secret by design, §5). Caught before writing the enforcement code,
  not after; what shipped is the correct, smaller-scoped foundation.
- **"Fully compliant" stays false in the strict sense** as long as filtering
  exists at all (D3): synthesizing an answer for a signed name is a protocol
  lie by construction. The achievable goal was always *conformant except
  where the product's purpose requires a documented deviation, with every
  deviation signalled to the client via EDE* — B1 now does exactly that for
  every blocked answer, closing the item this document rated highest-value
  relative to its size.
