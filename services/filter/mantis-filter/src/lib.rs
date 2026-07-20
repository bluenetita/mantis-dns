/*
 * Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Mantis filter node: DNS frontend + policy engine.

mod blockpage;
mod cache;
pub mod health_monitor;
mod router;
mod telemetry;
mod tls_pin;
pub mod upstream_bundle;
pub mod zone_store;

pub use telemetry::{QueryEventInput, TelemetryEmitter};
pub use zone_store::{
    fetch_and_publish_zone, fetch_local_zone_records, LocalZoneRecordDto, ZoneLookup, ZoneStore,
};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use cache::DnsCache;
use ed25519_dalek::VerifyingKey;
use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use mantis_bundle::{BlockMode, Bundle, BundleStore};
use mantis_policy::BloomFilter;
use prost::Message as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

pub type DotResolver = Resolver<TokioConnectionProvider>;

/// How long to float/cap a positive answer's TTL, and how long to cache a
/// negative (NXDOMAIN/NODATA) result. `UpstreamBundleForwarder` overrides
/// this from the tenant's `UpstreamBundle.tenant_policy`; forwarders with no
/// notion of a tenant policy (e.g. `DotForwarder`) get sane fixed defaults.
#[derive(Clone, Copy, Debug)]
pub struct TtlPolicy {
    pub min_ttl_s: u32,
    /// 0 means "no cap" (mirrors the `ttl_seconds` convention in
    /// `apply_block_response`: 0 = unset, fall back to a default).
    pub max_ttl_s: u32,
    /// 0 means "use the fixed default" rather than "cache negatives for 0s"
    /// — an operator leaving this unset shouldn't silently disable negative
    /// caching altogether.
    pub negative_ttl_s: u32,
}

impl Default for TtlPolicy {
    fn default() -> Self {
        Self {
            min_ttl_s: 0,
            max_ttl_s: 0,
            negative_ttl_s: 60,
        }
    }
}

impl TtlPolicy {
    fn clamp_positive(&self, ttl: u32) -> u32 {
        let ttl = ttl.max(self.min_ttl_s);
        if self.max_ttl_s > 0 {
            ttl.min(self.max_ttl_s)
        } else {
            ttl
        }
    }

    fn negative_ttl(&self) -> u32 {
        if self.negative_ttl_s > 0 {
            self.negative_ttl_s
        } else {
            60
        }
    }
}

/// Abstraction over upstream resolution. Returns the full answer-section record
/// set for any qtype so the filter node forwards AAAA, MX, TXT, PTR, etc.
/// exactly as received from the upstream resolver.
///
/// `categories` is the pre-computed set of policy-bundle category IDs that
/// the qname matched (regardless of block/allow action). `UpstreamBundleForwarder`
/// uses this to evaluate `"category"` upstream routes; other impls ignore it.
#[async_trait::async_trait]
pub trait Forwarder: Send + Sync {
    async fn lookup(
        &self,
        qname: &str,
        qtype: RecordType,
        categories: &[String],
    ) -> Result<Vec<Record>>;

    fn ttl_policy(&self) -> TtlPolicy {
        TtlPolicy::default()
    }
}

pub struct DotForwarder(DotResolver);

impl DotForwarder {
    /// DNS-over-TLS to Cloudflare (design.md §9). The UpstreamBundleForwarder
    /// supersedes this in production once an upstream bundle is loaded; this
    /// is the last-resort fallback when no bundle is present.
    pub fn new_default() -> Self {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::cloudflare_tls(),
            TokioConnectionProvider::default(),
        )
        .with_options(ResolverOpts::default())
        .build();
        Self(resolver)
    }
}

#[async_trait::async_trait]
impl Forwarder for DotForwarder {
    async fn lookup(
        &self,
        qname: &str,
        qtype: RecordType,
        _categories: &[String],
    ) -> Result<Vec<Record>> {
        let name: Name = qname.parse().context("invalid qname")?;
        let lookup = self.0.lookup(name, qtype).await?;
        Ok(lookup.records().to_vec())
    }
}

/// Holds the control plane's Ed25519 public key, re-fetched on every poll tick
/// (see `refresh_public_key`) rather than once at startup. Without this, a
/// signing-key rotation on the control plane (e.g. `signing_key.bin`
/// regenerated because a reinstall changed the process's working directory)
/// would silently and permanently reject every future bundle until someone
/// noticed and restarted every filter node by hand.
pub struct PublicKeyStore(ArcSwap<VerifyingKey>);

impl PublicKeyStore {
    pub fn new(key: VerifyingKey) -> Self {
        Self(ArcSwap::from_pointee(key))
    }

    pub fn current(&self) -> VerifyingKey {
        **self.0.load()
    }

    fn set(&self, key: VerifyingKey) {
        self.0.store(Arc::new(key));
    }
}

pub struct AppState {
    pub store: BundleStore,
    pub zones: ZoneStore,
    pub public_key: PublicKeyStore,
    pub cache: DnsCache,
    pub forwarder: Box<dyn Forwarder>,
    pub telemetry: TelemetryEmitter,
}

impl AppState {
    pub fn new(public_key: VerifyingKey) -> Self {
        Self::with_forwarder(public_key, Box::new(DotForwarder::new_default()))
    }

    pub fn with_forwarder(public_key: VerifyingKey, forwarder: Box<dyn Forwarder>) -> Self {
        Self {
            store: BundleStore::empty(),
            zones: ZoneStore::empty(),
            public_key: PublicKeyStore::new(public_key),
            cache: DnsCache::new(10_000),
            forwarder,
            telemetry: TelemetryEmitter::noop(),
        }
    }

    pub fn with_telemetry(mut self, telemetry: TelemetryEmitter) -> Self {
        self.telemetry = telemetry;
        self
    }

    pub fn purge_cache(&self) {
        self.cache.purge_expired();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
}

pub struct DecisionOutcome {
    pub decision: Decision,
    pub matched_rule: &'static str,
    pub matched_category: Option<String>,
    pub matched_feed_id: Option<String>,
}

/// Lookup order per design.md §18.4: allow-override beats everything;
/// deny-override beats categories; categories beat default-allow.
///
/// ACTION_LOG_ONLY categories never block (design.md §7: "log-only lets an
/// org observe before enforcing"), but a match still needs to reach
/// telemetry — otherwise toggling a category to log-only makes it silently
/// invisible instead of observable, defeating the entire point of the mode.
/// The first log-only match found is remembered and returned only if no
/// ACTION_BLOCK category matches first; ACTION_BLOCK is still checked across
/// every category before any log-only match is allowed to win, since a
/// blocking category must always take precedence over merely observing.
pub fn decide(bundle: &Bundle, qname: &str) -> DecisionOutcome {
    let qname = normalize(qname);

    if bundle.allow_overrides.iter().any(|d| normalize(d) == qname) {
        return DecisionOutcome {
            decision: Decision::Allow,
            matched_rule: "override_allow",
            matched_category: None,
            matched_feed_id: None,
        };
    }
    if bundle.deny_overrides.iter().any(|d| normalize(d) == qname) {
        return DecisionOutcome {
            decision: Decision::Block,
            matched_rule: "override_deny",
            matched_category: None,
            matched_feed_id: None,
        };
    }

    let mut log_only_match: Option<DecisionOutcome> = None;
    for category in &bundle.categories {
        let action = category.action;
        if action == mantis_bundle::Action::Block as i32 {
            if let Some(bf) = BloomFilter::from_category(category) {
                if bf.might_contain(&qname) {
                    return DecisionOutcome {
                        decision: Decision::Block,
                        matched_rule: "category",
                        matched_category: Some(category.category_id.clone()),
                        matched_feed_id: (!category.source_feed_id.is_empty())
                            .then(|| category.source_feed_id.clone()),
                    };
                }
            }
        } else if action == mantis_bundle::Action::LogOnly as i32 && log_only_match.is_none() {
            if let Some(bf) = BloomFilter::from_category(category) {
                if bf.might_contain(&qname) {
                    log_only_match = Some(DecisionOutcome {
                        decision: Decision::Allow,
                        matched_rule: "category_log_only",
                        matched_category: Some(category.category_id.clone()),
                        matched_feed_id: (!category.source_feed_id.is_empty())
                            .then(|| category.source_feed_id.clone()),
                    });
                }
            }
        }
    }
    log_only_match.unwrap_or(DecisionOutcome {
        decision: Decision::Allow,
        matched_rule: "default",
        matched_category: None,
        matched_feed_id: None,
    })
}

/// Returns IDs of every category whose bloom filter matches `qname`, regardless
/// of the category's block/allow action. Used by the upstream router to select
/// a pool based on content type (e.g. route "cdn" traffic to a low-latency pool).
fn matched_categories(bundle: &Bundle, qname: &str) -> Vec<String> {
    let normalized = normalize(qname);
    bundle
        .categories
        .iter()
        .filter_map(|cat| {
            BloomFilter::from_category(cat)
                .filter(|bf| bf.might_contain(&normalized))
                .map(|_| cat.category_id.clone())
        })
        .collect()
}

/// Must mirror `_normalize_domain` in
/// services/control/mantis_control/feeds/parsers.py exactly: feeds are
/// ingested with a leading "www." stripped (design.md §18.3), so a bloom
/// filter built from "pornhub.com" has no entry for "www.pornhub.com" at
/// all — without stripping it here too, every "www."-prefixed query for an
/// otherwise-blocked domain silently bypasses the category block.
fn normalize(domain: &str) -> String {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    match domain.strip_prefix("www.") {
        Some(rest) => rest.to_string(),
        None => domain,
    }
}

/// Emits a query-event for a stub-zone answer/NXDOMAIN, matching the shape of
/// the bloom-filter decision path so zone hits show up in the same
/// query-events feed rather than going dark. `bundle` may not be loaded yet
/// (rare — a policy bundle is normally compiled before a group's filter node
/// comes up), in which case group_id is reported empty rather than skipping
/// telemetry entirely.
fn emit_zone_telemetry(
    telemetry: &TelemetryEmitter,
    bundle: Option<&Bundle>,
    client_ip: &IpAddr,
    qname: &str,
    qtype_str: &str,
    response: &Message,
    start: std::time::Instant,
) {
    telemetry.emit(QueryEventInput {
        group_id: bundle.map(|b| b.group_id.clone()).unwrap_or_default(),
        client_ip: client_ip.to_string(),
        qname: qname.to_string(),
        qtype: qtype_str.to_string(),
        decision: "stub_zone",
        matched_rule: "stub_zone",
        matched_category: None,
        matched_feed_id: None,
        response_code: format!("{:?}", response.response_code()),
        cache_hit: None,
        latency_us: start.elapsed().as_micros().min(u32::MAX as u128) as u32,
    });
}

pub async fn fetch_public_key(control_url: &str) -> Result<VerifyingKey> {
    let client = reqwest::Client::new();
    let bytes = with_service_token(client.get(format!("{control_url}/api/v1/public-key")))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    if let Ok(expected_pin) = std::env::var("MANTIS_CONTROL_PUBLIC_KEY_SHA256") {
        verify_public_key_pin(bytes.as_ref(), &expected_pin)?;
    }
    let arr: [u8; 32] = bytes
        .as_ref()
        .try_into()
        .context("public key response was not 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

fn normalize_sha256_pin(pin: &str) -> String {
    pin.trim()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| pin.trim())
        .chars()
        .filter(|c| *c != ':')
        .flat_map(char::to_lowercase)
        .collect()
}

fn verify_public_key_pin(bytes: &[u8], expected_pin: &str) -> Result<()> {
    let expected = normalize_sha256_pin(expected_pin);
    if expected.is_empty() {
        return Ok(());
    }
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("MANTIS_CONTROL_PUBLIC_KEY_SHA256 must be a sha256 hex digest");
    }

    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected {
        bail!("control-plane public key sha256 pin mismatch");
    }
    Ok(())
}

/// Re-fetches the control plane's public key and updates `keys` in place if
/// it changed. Called on every poll tick (not just at startup) so a signing-
/// key rotation on the control plane self-heals instead of requiring a
/// filter-node restart.
pub async fn refresh_public_key(keys: &PublicKeyStore, control_url: &str) -> Result<()> {
    let fetched = fetch_public_key(control_url).await?;
    if fetched != keys.current() {
        info!(
            "control-plane public key changed — updating (was this an intentional key rotation?)"
        );
        keys.set(fetched);
    }
    Ok(())
}

pub async fn fetch_and_publish_bundle(
    store: &BundleStore,
    public_key: &VerifyingKey,
    control_url: &str,
    group_id: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let resp =
        with_service_token(client.get(format!("{control_url}/api/v1/groups/{group_id}/bundle")))
            .send()
            .await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        debug!("no bundle compiled yet for group {group_id}");
        return Ok(());
    }
    let bytes = resp.error_for_status()?.bytes().await?;
    let bundle = Bundle::decode(bytes.as_ref())?;

    match store.try_publish(bundle, public_key) {
        Ok(()) => info!("published new bundle for group {group_id}"),
        Err(e) if e.to_string().contains("refusing to publish stale bundle") => {
            debug!("bundle for group {group_id} unchanged");
        }
        Err(e) => warn!("rejected bundle for group {group_id}: {e}"),
    }
    Ok(())
}

pub async fn refresh_bundle(state: &AppState, control_url: &str, group_id: &str) -> Result<()> {
    let key = state.public_key.current();
    fetch_and_publish_bundle(&state.store, &key, control_url, group_id).await
}

pub async fn bundle_refresh_loop(
    state: Arc<AppState>,
    control_url: String,
    group_id: String,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        if let Err(e) = refresh_public_key(&state.public_key, &control_url).await {
            warn!("public key refresh failed (keeping last known good key): {e}");
        }
        if let Err(e) = refresh_bundle(&state, &control_url, &group_id).await {
            warn!("bundle refresh failed: {e}");
        }
    }
}

pub async fn zone_refresh_loop(
    state: Arc<AppState>,
    control_url: String,
    group_id: String,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        if let Err(e) = fetch_and_publish_zone(&state.zones, &control_url, &group_id).await {
            warn!("local zone refresh failed: {e}");
        }
    }
}

// ── UDP server ─────────────────────────────────────────────────────────────────

/// Maximum UDP queries answered concurrently. Without this bound, a single
/// slow query (upstream resolution to a black-holed/slow nameserver) used to
/// stall the one `recv_from` loop for its full timeout — a handful of such
/// queries per second was enough to starve every other client on the node.
/// Excess queries beyond this bound are dropped rather than queued; the
/// client's stub resolver retries or falls back to TCP.
pub(crate) const MAX_CONCURRENT_UDP_QUERIES: usize = 2000;

pub async fn run_udp_server(socket: UdpSocket, state: Arc<AppState>) -> Result<()> {
    let local_addr = socket.local_addr()?;
    info!("mantis-filter UDP DNS listener bound on {local_addr}");
    let socket = Arc::new(socket);
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UDP_QUERIES));
    let mut buf = [0u8; 4096];

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let query = match Message::from_bytes(&buf[..len]) {
            Ok(m) => m,
            Err(e) => {
                debug!("dropping unparseable UDP packet from {peer}: {e}");
                continue;
            }
        };

        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!(
                    "UDP concurrency limit ({MAX_CONCURRENT_UDP_QUERIES}) reached, dropping query from {peer}"
                );
                continue;
            }
        };
        let state = state.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let bundle = state.store.current();
            let mut response = build_response(
                &query,
                bundle.as_deref(),
                &state.zones,
                peer.ip(),
                &state.cache,
                state.forwarder.as_ref(),
                &state.telemetry,
                false, // single-tenant mode: bundle-is-None is bootstrap-only, never "unmatched route"
            )
            .await;
            enforce_udp_size_limit(&query, &mut response);
            match response.to_bytes() {
                Ok(bytes) => {
                    if let Err(e) = socket.send_to(&bytes, peer).await {
                        warn!("UDP send_to {peer} failed: {e}");
                    }
                }
                Err(e) => warn!("failed to encode UDP response for {peer}: {e}"),
            }
        });
    }
}

// ── TCP server ─────────────────────────────────────────────────────────────────

/// Maximum concurrent TCP DNS connections. Excess connections are accepted
/// then immediately closed so clients get a clean FIN rather than a timeout.
pub(crate) const MAX_TCP_CONNECTIONS: usize = 500;

/// How long to wait for the next query's 2-byte length prefix before closing
/// an idle TCP DNS connection — RFC 7766 leaves the exact policy to the
/// server; 30s matches common recursive-resolver defaults (e.g. Unbound's
/// tcp-idle-timeout). Without this, a connection that sends nothing at all
/// (a handful is enough to exhaust MAX_TCP_CONNECTIONS) holds its semaphore
/// permit — and blocks every other client sharing this listener from getting
/// a DNS answer over TCP — forever.
pub(crate) const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for the rest of a message once its length prefix has
/// already been read — much shorter than TCP_IDLE_TIMEOUT, since a
/// well-behaved client sends the body immediately after announcing its
/// length; a slow/partial send past this point is indistinguishable from an
/// attacker deliberately trickling bytes to hold the connection open.
pub(crate) const TCP_BODY_TIMEOUT: Duration = Duration::from_secs(5);

/// DNS-over-TCP server (RFC 1035 §4.2.2). Spawns one task per accepted
/// connection; each connection may carry multiple pipelined queries.
pub async fn run_tcp_server(listener: TcpListener, state: Arc<AppState>) -> Result<()> {
    let local_addr = listener.local_addr()?;
    info!("mantis-filter TCP DNS listener bound on {local_addr}");
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONNECTIONS));

    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!("TCP DNS connection limit ({MAX_TCP_CONNECTIONS}) reached, dropping {peer}");
                continue; // drop stream → FIN sent to client
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_tcp_connection(stream, peer.ip(), &state).await {
                debug!("TCP DNS connection from {peer} ended: {e}");
            }
        });
    }
}

async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    peer_ip: IpAddr,
    state: &AppState,
) -> Result<()> {
    loop {
        let msg_len = match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_u16()).await {
            Ok(Ok(n)) => n as usize,
            // Clean close from the client.
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => {
                debug!("TCP DNS connection from {peer_ip} idle for {TCP_IDLE_TIMEOUT:?}, closing");
                break;
            }
        };
        if msg_len == 0 {
            break;
        }

        let mut buf = vec![0u8; msg_len];
        match tokio::time::timeout(TCP_BODY_TIMEOUT, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => {
                debug!("TCP DNS connection from {peer_ip} timed out mid-message, closing");
                break;
            }
        }

        let query = match Message::from_bytes(&buf) {
            Ok(m) => m,
            Err(e) => {
                debug!("unparseable TCP DNS message from {peer_ip}: {e}");
                break;
            }
        };

        let bundle = state.store.current();
        let response = build_response(
            &query,
            bundle.as_deref(),
            &state.zones,
            peer_ip,
            &state.cache,
            state.forwarder.as_ref(),
            &state.telemetry,
            false, // single-tenant mode: bundle-is-None is bootstrap-only, never "unmatched route"
        )
        .await;

        match response.to_bytes() {
            Ok(bytes) => {
                stream.write_u16(bytes.len() as u16).await?;
                stream.write_all(&bytes).await?;
            }
            Err(e) => {
                warn!("failed to encode TCP DNS response: {e}");
                break;
            }
        }
    }
    Ok(())
}

pub use blockpage::{run_block_page_server, BlockPageBundles};
pub use health_monitor::{run_health_monitor, HealthStore};
pub use router::{
    refresh_routes, routing_refresh_loop, run_router_tcp_server, run_router_udp_server,
    test_support, TenantRouter,
};
pub use upstream_bundle::{
    fetch_upstream_bundle, upstream_bundle_refresh_loop, UpstreamBundle, UpstreamBundleForwarder,
    UpstreamBundleStore,
};

/// Whether to resolve normally (bypassing policy) during the bootstrap
/// window before this process's first bundle has loaded. See the
/// `bundle is None` branch of `build_response` for the full rationale.
/// Defaults to false (ServFail) — the safe default matches what every
/// deployment already gets today, so this is opt-in only.
fn bootstrap_fail_open() -> bool {
    std::env::var("MANTIS_BOOTSTRAP_FAIL_OPEN")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

/// Adds the MANTIS_SERVICE_TOKEN bearer header to outbound M2M requests.
pub fn with_service_token(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Ok(tok) = std::env::var("MANTIS_SERVICE_TOKEN") {
        rb.bearer_auth(tok)
    } else {
        rb
    }
}

// ── Core decision + response ───────────────────────────────────────────────────

/// `unmatched_route` is true only when the caller is `run_router_udp_server`/
/// `run_router_tcp_server` (multi-tenant source-IP routing mode) and the
/// peer's source IP matched *no* configured tenant subnet at all — as
/// opposed to matching a route whose `BundleStore` simply hasn't loaded a
/// bundle yet (genuine bootstrap window). `MANTIS_BOOTSTRAP_FAIL_OPEN` must
/// never apply to the former: an unmatched IP has no tenant identity or
/// policy to "fail open into" — resolving it anyway turns any traffic that
/// merely fails to match a routing entry (a stray client, a misconfigured
/// subnet, or literally anyone who can reach the listener) into a permanent,
/// silent open resolver, indistinguishable from the one-time startup window
/// the flag exists for. Single-tenant callers (`run_udp_server`/
/// `run_tcp_server`) always pass `false`: their `bundle is None` case really
/// is bootstrap-only, per the comment below.
pub(crate) async fn build_response(
    query: &Message,
    bundle: Option<&Bundle>,
    zones: &ZoneStore,
    client_ip: IpAddr,
    cache: &DnsCache,
    forwarder: &dyn Forwarder,
    telemetry: &TelemetryEmitter,
    unmatched_route: bool,
) -> Message {
    let start = std::time::Instant::now();
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(query.op_code());
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);
    for q in query.queries() {
        response.add_query(q.clone());
    }

    let Some(question) = query.queries().first() else {
        response.set_response_code(ResponseCode::FormErr);
        return response;
    };
    let qname = question.name().to_utf8();
    let qtype = question.query_type();
    let qtype_str = format!("{qtype:?}");

    // Stub zones (design.md §7.3, §DNS-Zones) win outright: if the qname
    // falls under a locally-hosted zone, answer authoritatively without
    // ever consulting the policy bundle or forwarding upstream.
    match zones.lookup(&qname, qtype) {
        ZoneLookup::Answer(records) => {
            response.set_authoritative(true);
            response.set_response_code(ResponseCode::NoError);
            for rec in records {
                response.add_answer(rec);
            }
            emit_zone_telemetry(
                telemetry, bundle, &client_ip, &qname, &qtype_str, &response, start,
            );
            return response;
        }
        ZoneLookup::NxDomain => {
            response.set_authoritative(true);
            response.set_response_code(ResponseCode::NXDomain);
            emit_zone_telemetry(
                telemetry, bundle, &client_ip, &qname, &qtype_str, &response, start,
            );
            return response;
        }
        ZoneLookup::NotLocal => {}
    }

    let Some(bundle) = bundle else {
        // No bundle has loaded yet for the resolved tenant (single-tenant
        // mode) — or, in single-tenant mode specifically, this only happens
        // in the window before this process's very first successful
        // fetch+verify: try_publish never clears the store back to None on a
        // later failed refresh, so once any bundle has loaded, the
        // last-known-good one stays active and this branch is never reached
        // again for the life of the process. There's no Bundle to read
        // on_load_failure from yet (the field lives on the bundle itself),
        // so the bootstrap-window behavior is controlled by
        // MANTIS_BOOTSTRAP_FAIL_OPEN instead — defaulting to closed
        // (ServFail) since resolving with no policy applied at all is unsafe
        // for a tenant that hasn't even completed provisioning yet.
        //
        // `unmatched_route` overrides this to always ServFail regardless of
        // the env var — see its doc comment above.
        if !unmatched_route && bootstrap_fail_open() {
            resolve_records(&qname, qtype, &[], cache, forwarder, &mut response).await;
        } else {
            response.set_response_code(ResponseCode::ServFail);
        }
        return response;
    };

    let outcome = decide(bundle, &qname);
    // All category IDs the qname matches (any action), used for upstream routing.
    let categories = matched_categories(bundle, &qname);
    let mut cache_hit: Option<bool> = None;

    match outcome.decision {
        Decision::Block => {
            apply_block_response(bundle, &qname, qtype, &mut response);
        }
        Decision::Allow => {
            cache_hit = Some(
                resolve_records(&qname, qtype, &categories, cache, forwarder, &mut response).await,
            );
        }
    }

    telemetry.emit(QueryEventInput {
        group_id: bundle.group_id.clone(),
        client_ip: client_ip.to_string(),
        qname,
        qtype: qtype_str,
        decision: match outcome.decision {
            Decision::Block => "block",
            Decision::Allow => "allow",
        },
        matched_rule: outcome.matched_rule,
        matched_category: outcome.matched_category,
        matched_feed_id: outcome.matched_feed_id,
        response_code: format!("{:?}", response.response_code()),
        cache_hit,
        latency_us: start.elapsed().as_micros().min(u32::MAX as u128) as u32,
    });

    response
}

/// Highest EDNS0 payload size this server will ever advertise/honor, even if
/// a client asks for more — keeps worst-case UDP responses well clear of
/// common path-MTU/fragmentation limits.
const MAX_UDP_PAYLOAD: u16 = 4096;

/// RFC 1035 §4.2.1 / RFC 6891: a UDP response must not exceed the
/// requester's advertised max payload (EDNS0 OPT in the query), or 512
/// bytes for a classic (non-EDNS) query. Without this, an oversized answer
/// set (many records, a long CNAME chain) just ships as an oversized UDP
/// datagram — silently dropped by strict middleboxes/firewalls, or
/// fragmented, with the client never learning to retry over TCP.
///
/// Call this on the UDP send path only (right before `to_bytes()`); TCP has
/// no such limit and must not have its answers dropped.
pub(crate) fn enforce_udp_size_limit(query: &Message, response: &mut Message) {
    let max_payload = match query.extensions().as_ref() {
        Some(edns) => {
            let negotiated = edns.max_payload().clamp(512, MAX_UDP_PAYLOAD);
            // RFC 6891 §6.1.1: echo an OPT record back so the client knows
            // this server understood EDNS0 and what payload size to expect.
            let mut resp_edns = Edns::new();
            resp_edns.set_max_payload(negotiated);
            response.set_edns(resp_edns);
            negotiated
        }
        None => 512,
    } as usize;

    let fits = matches!(response.to_bytes(), Ok(bytes) if bytes.len() <= max_payload);
    if fits {
        return;
    }

    response.set_truncated(true);
    while !response.answers().is_empty() {
        response.answers_mut().pop();
        match response.to_bytes() {
            Ok(bytes) if bytes.len() <= max_payload => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
}

/// Synthesizes the DNS answer for a blocked query per the bundle's
/// `block_response` policy:
/// - unspecified / NXDOMAIN → NXDOMAIN (historical default).
/// - ZERO_IP → `0.0.0.0` (A) / `::` (AAAA) with NOERROR.
/// - REDIRECT → the configured redirect IP for A/AAAA with NOERROR, so a web
///   navigation lands on the block-page listener.
///
/// In the ZERO_IP/REDIRECT modes the blocked name is treated as *existing*: a
/// query for a type we have no address for returns NODATA (NOERROR, no answer)
/// rather than NXDOMAIN, so a missing AAAA never poisons the A lookup on
/// dual-stack stub resolvers.
fn apply_block_response(bundle: &Bundle, qname: &str, qtype: RecordType, response: &mut Message) {
    let block = bundle.block_response.as_ref();
    let mode = block.map(|b| b.mode()).unwrap_or(BlockMode::Unspecified);

    let ttl = |default: u32| {
        block
            .map(|b| b.ttl_seconds)
            .filter(|t| *t > 0)
            .unwrap_or(default)
    };

    let (v4, v6, ttl) = match mode {
        BlockMode::Redirect => (
            block.and_then(|b| b.redirect_ipv4.parse::<Ipv4Addr>().ok()),
            block.and_then(|b| b.redirect_ipv6.parse::<Ipv6Addr>().ok()),
            ttl(30),
        ),
        BlockMode::ZeroIp => (
            Some(Ipv4Addr::UNSPECIFIED),
            Some(Ipv6Addr::UNSPECIFIED),
            ttl(30),
        ),
        // BLOCK_MODE_NXDOMAIN and unspecified.
        _ => {
            response.set_response_code(ResponseCode::NXDomain);
            return;
        }
    };

    let rdata = match qtype {
        RecordType::A => v4.map(|ip| RData::A(A::from(ip))),
        RecordType::AAAA => v6.map(|ip| RData::AAAA(AAAA::from(ip))),
        _ => None,
    };

    // Name is already normalized from the query; a parse failure here should
    // not happen, but fall back to NXDOMAIN rather than panic.
    match (rdata, Name::from_utf8(qname)) {
        (Some(rdata), Ok(name)) => {
            response.set_response_code(ResponseCode::NoError);
            response.add_answer(Record::from_rdata(name, ttl, rdata));
        }
        // Name exists (it's redirected/sinkholed) but no record of this type.
        (None, _) => {
            response.set_response_code(ResponseCode::NoError);
        }
        (Some(_), Err(_)) => {
            response.set_response_code(ResponseCode::NXDomain);
        }
    }
}

/// Resolves any qtype through the cache then forwarder. Returns `true` on
/// cache hit. Propagates NXDOMAIN vs NODATA correctly. Caches negative
/// (NXDOMAIN/NODATA) results too — without this, a flood of queries for
/// random non-existent subdomains never hits the cache and forces an
/// upstream round-trip on every single packet.
async fn resolve_records(
    qname: &str,
    qtype: RecordType,
    categories: &[String],
    cache: &DnsCache,
    forwarder: &dyn Forwarder,
    response: &mut Message,
) -> bool {
    let qtype_u16 = u16::from(qtype);

    if let Some(hit) = cache.get(qname, qtype_u16) {
        match hit {
            cache::CacheLookup::Records(records) => {
                response.set_response_code(ResponseCode::NoError);
                for rec in records {
                    response.add_answer(rec);
                }
            }
            cache::CacheLookup::Negative(cache::NegativeKind::NxDomain) => {
                response.set_response_code(ResponseCode::NXDomain);
            }
            cache::CacheLookup::Negative(cache::NegativeKind::NoData) => {
                response.set_response_code(ResponseCode::NoError);
            }
        }
        return true;
    }

    let policy = forwarder.ttl_policy();
    match forwarder.lookup(qname, qtype, categories).await {
        Ok(records) if records.is_empty() => {
            // Some Forwarder impls (any custom implementation, and the test
            // MockForwarder) signal NODATA via Ok(vec![]) rather than the
            // is_no_records_found() error path below. cache.put() no-ops on
            // an empty Vec, so without this branch this answer is served
            // correctly once but never negative-cached — every repeat query
            // forces a fresh upstream round-trip, defeating the negative-
            // caching DoS mitigation this cache otherwise provides.
            response.set_response_code(ResponseCode::NoError);
            cache.put_negative(
                qname.to_string(),
                qtype_u16,
                cache::NegativeKind::NoData,
                Duration::from_secs(u64::from(policy.negative_ttl())),
            );
        }
        Ok(mut records) => {
            let raw_ttl = records.iter().map(|r| r.ttl()).min().unwrap_or(60);
            let ttl = policy.clamp_positive(raw_ttl);
            // Apply the clamped TTL to the records themselves, not just the
            // cache entry's expiry — otherwise a tenant's min/max_ttl_s
            // policy only shrinks our own cache lifetime while the client's
            // resolver still caches the raw, unclamped upstream TTL.
            for rec in &mut records {
                rec.set_ttl(ttl);
            }
            cache.put(
                qname.to_string(),
                qtype_u16,
                records.clone(),
                Duration::from_secs(u64::from(ttl)),
            );
            response.set_response_code(ResponseCode::NoError);
            for rec in records {
                response.add_answer(rec);
            }
        }
        Err(e) => {
            // hickory surfaces both NXDOMAIN and NODATA as a "no records found"
            // error; is_nx_domain() reads the embedded response_code to tell
            // them apart. Downcast rather than string-match: the Debug/Display
            // text for this error doesn't reliably contain "NXDomain"/
            // "NoRecordsFound" substrings across hickory versions.
            let resolve_err = e.downcast_ref::<hickory_resolver::ResolveError>();
            match resolve_err {
                Some(re) if re.is_nx_domain() => {
                    response.set_response_code(ResponseCode::NXDomain);
                    cache.put_negative(
                        qname.to_string(),
                        qtype_u16,
                        cache::NegativeKind::NxDomain,
                        Duration::from_secs(u64::from(policy.negative_ttl())),
                    );
                }
                Some(re) if re.is_no_records_found() => {
                    // NODATA: name exists, no records of this type.
                    response.set_response_code(ResponseCode::NoError);
                    cache.put_negative(
                        qname.to_string(),
                        qtype_u16,
                        cache::NegativeKind::NoData,
                        Duration::from_secs(u64::from(policy.negative_ttl())),
                    );
                }
                _ => {
                    debug!("upstream resolution failed for {qname} ({qtype:?}): {e}");
                    response.set_response_code(ResponseCode::ServFail);
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    fn test_key(seed: u8) -> VerifyingKey {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        signing_key.verifying_key()
    }

    #[test]
    fn public_key_store_returns_the_key_it_was_built_with() {
        let key = test_key(1);
        let store = PublicKeyStore::new(key);
        assert_eq!(store.current(), key);
    }

    #[test]
    fn public_key_store_reflects_a_hot_swap() {
        let store = PublicKeyStore::new(test_key(1));
        let new_key = test_key(2);
        store.set(new_key);
        assert_eq!(store.current(), new_key);
    }

    #[test]
    fn public_key_pin_accepts_matching_sha256() {
        let bytes = [42u8; 32];
        let pin = hex::encode(Sha256::digest(bytes));
        verify_public_key_pin(&bytes, &pin).unwrap();
        verify_public_key_pin(&bytes, &format!("sha256:{pin}")).unwrap();
    }

    #[test]
    fn public_key_pin_rejects_mismatch() {
        let bytes = [42u8; 32];
        let wrong = "00".repeat(32);
        assert!(verify_public_key_pin(&bytes, &wrong).is_err());
    }

    struct EmptyOkForwarder;

    #[async_trait::async_trait]
    impl Forwarder for EmptyOkForwarder {
        async fn lookup(
            &self,
            _qname: &str,
            _qtype: RecordType,
            _categories: &[String],
        ) -> Result<Vec<Record>> {
            // Some Forwarder impls signal NODATA this way rather than via
            // an is_no_records_found() error — see resolve_records.
            Ok(vec![])
        }
    }

    fn a_query(qname: &str) -> Message {
        let mut query = Message::new();
        query.set_message_type(MessageType::Query);
        query.add_query(Query::query(qname.parse().unwrap(), RecordType::A));
        query
    }

    fn oversized_response(n: usize) -> Message {
        let mut response = Message::new();
        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::NoError);
        let name: Name = "bulky.example.".parse().unwrap();
        for i in 0..n {
            response.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A(std::net::Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8))),
            ));
        }
        response
    }

    #[test]
    fn udp_size_limit_leaves_small_response_untouched() {
        let query = a_query("small.example.");
        let mut response = oversized_response(1);
        enforce_udp_size_limit(&query, &mut response);
        assert!(!response.truncated());
        assert_eq!(response.answers().len(), 1);
        assert!(response.to_bytes().unwrap().len() <= 512);
    }

    #[test]
    fn udp_size_limit_truncates_and_sets_tc_without_edns() {
        // No EDNS in the query -> classic 512-byte ceiling. 60 A records is
        // comfortably over that.
        let query = a_query("bulky.example.");
        let mut response = oversized_response(60);
        assert!(response.to_bytes().unwrap().len() > 512, "test fixture must actually be oversized");

        enforce_udp_size_limit(&query, &mut response);

        assert!(response.truncated(), "TC bit must be set when answers were dropped");
        assert!(response.answers().len() < 60, "some answers must have been dropped");
        let bytes = response.to_bytes().unwrap();
        assert!(bytes.len() <= 512, "final response must fit the negotiated payload, got {}", bytes.len());
    }

    #[test]
    fn udp_size_limit_honors_larger_edns_payload_and_echoes_opt() {
        // Same oversized answer set, but the client advertised EDNS0 with a
        // payload large enough to hold it — must NOT be truncated, and the
        // response must carry an echoed OPT record (RFC 6891 §6.1.1).
        let mut query = a_query("bulky.example.");
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        query.set_edns(edns);

        let mut response = oversized_response(60);
        enforce_udp_size_limit(&query, &mut response);

        assert!(!response.truncated());
        assert_eq!(response.answers().len(), 60);
        assert!(response.extensions().is_some(), "server must echo an OPT record when the query had one");
        assert!(response.to_bytes().unwrap().len() <= 4096);
    }

    #[test]
    fn udp_size_limit_clamps_edns_payload_to_server_ceiling() {
        // A client advertising an absurdly large payload must not get a
        // response bigger than MAX_UDP_PAYLOAD.
        let mut query = a_query("bulky.example.");
        let mut edns = Edns::new();
        edns.set_max_payload(65535);
        query.set_edns(edns);

        let mut response = oversized_response(400); // large enough to exceed 4096 too
        enforce_udp_size_limit(&query, &mut response);

        let bytes = response.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_UDP_PAYLOAD as usize, "got {} bytes", bytes.len());
        assert!(response.truncated());
    }

    #[test]
    fn to_bytes_never_exceeds_the_tcp_length_prefix_range_even_for_a_huge_answer_set() {
        // handle_tcp_connection/run_router_tcp_server cast `bytes.len() as
        // u16` for the RFC 1035 §4.2.2 length prefix with no explicit bound
        // check of their own — that's only sound because hickory's encoder
        // (BinEncoder::with_offset) hard-caps every Message::to_bytes() call
        // at u16::MAX bytes by construction, truncating the answer set and
        // setting the TC bit rather than ever producing a longer buffer.
        // This pins that guarantee down so a hickory upgrade that changed it
        // would fail a test here instead of silently corrupting TCP framing.
        let response = oversized_response(50_000);
        let bytes = response.to_bytes().unwrap();
        assert!(bytes.len() <= u16::MAX as usize, "got {} bytes", bytes.len());
    }

    #[tokio::test]
    async fn no_bundle_loaded_yet_respects_bootstrap_fail_open_env_var() {
        // Single test (not two) because MANTIS_BOOTSTRAP_FAIL_OPEN is
        // process-global env state and cargo runs tests in the same binary
        // concurrently by default — two separate tests toggling it would
        // race each other's reads.
        async fn query_with_no_bundle(unmatched_route: bool) -> Message {
            build_response(
                &a_query("bootstrap.example."),
                None,
                &ZoneStore::empty(),
                "127.0.0.1".parse().unwrap(),
                &DnsCache::new(10),
                &EmptyOkForwarder,
                &TelemetryEmitter::noop(),
                unmatched_route,
            )
            .await
        }

        // No MANTIS_BOOTSTRAP_FAIL_OPEN set — must preserve today's safe
        // default (ServFail) for the pre-first-load bootstrap window.
        std::env::remove_var("MANTIS_BOOTSTRAP_FAIL_OPEN");
        assert_eq!(query_with_no_bundle(false).await.response_code(), ResponseCode::ServFail);

        std::env::set_var("MANTIS_BOOTSTRAP_FAIL_OPEN", "true");
        // EmptyOkForwarder returns Ok(vec![]) — NOERROR/NODATA, not ServFail,
        // proving the query was actually forwarded rather than blocked.
        assert_eq!(query_with_no_bundle(false).await.response_code(), ResponseCode::NoError);

        // Regression test: an unmatched source IP in multi-tenant router
        // mode must ALWAYS ServFail, even with MANTIS_BOOTSTRAP_FAIL_OPEN
        // set — that flag is for the one-time startup window before a
        // resolved tenant's first bundle load, not for traffic with no
        // resolvable tenant identity at all (still set from the assertion
        // above, so this genuinely proves the override wins).
        assert_eq!(query_with_no_bundle(true).await.response_code(), ResponseCode::ServFail);
        std::env::remove_var("MANTIS_BOOTSTRAP_FAIL_OPEN");
    }

    #[tokio::test]
    async fn resolve_records_negative_caches_an_empty_ok_answer() {
        let cache = DnsCache::new(10);
        let forwarder = EmptyOkForwarder;
        let mut response = Message::new();

        let hit = resolve_records(
            "empty-ok.example.",
            RecordType::AAAA,
            &[],
            &cache,
            &forwarder,
            &mut response,
        )
        .await;

        assert!(!hit, "first call is a cache miss, not a hit");
        assert_eq!(response.answers().len(), 0);
        // The key assertion: an Ok(vec![]) upstream answer must still land
        // in the cache as NODATA, not silently skip caching entirely.
        match cache.get("empty-ok.example.", u16::from(RecordType::AAAA)) {
            Some(cache::CacheLookup::Negative(cache::NegativeKind::NoData)) => {}
            other => panic!("expected a cached NODATA entry, got {}", other.is_some()),
        }
    }

    #[test]
    fn normalize_strips_leading_www_to_match_feed_ingestion() {
        // Must mirror _normalize_domain in feeds/parsers.py — feeds are
        // stored with "www." already stripped, so a query for
        // "www.<blocked-domain>" only matches the bloom filter if this
        // strip happens here too.
        assert_eq!(normalize("www.pornhub.com"), "pornhub.com");
        assert_eq!(normalize("WWW.Example.COM."), "example.com");
        assert_eq!(normalize("pornhub.com"), "pornhub.com");
        assert_eq!(normalize("pornhub.com."), "pornhub.com");
        // Must not strip domains that merely start with "www" without the
        // dot (a real, if unusual, registrable domain).
        assert_eq!(normalize("wwwx.example.com"), "wwwx.example.com");
    }

    /// `num_hashes: 0` makes `might_contain` return true for any domain
    /// unconditionally (the hash-check loop never runs) — a cheap way to
    /// build a category that deterministically "matches" in a test without
    /// needing a real FNV-hashed bitset.
    fn category(
        id: &str,
        action: mantis_bundle::Action,
        source_feed_id: &str,
    ) -> mantis_bundle::CategorySet {
        mantis_bundle::CategorySet {
            category_id: id.into(),
            source_feed_id: source_feed_id.into(),
            feed_version: "".into(),
            license: "".into(),
            bloom: Some(mantis_bundle::gen::BloomParams { num_hashes: 0, num_bits: 8, seed: 0 }),
            bloom_bits: vec![0xFFu8],
            action: action as i32,
        }
    }

    #[test]
    fn decide_log_only_category_match_does_not_block_but_is_reported() {
        // Regression test: a log-only category match used to be silently
        // dropped (the loop `continue`d past any non-Block action), so
        // toggling a category to log-only made it invisible instead of
        // observable — defeating the point of the mode (design.md §7).
        let bundle = Bundle {
            categories: vec![category("social", mantis_bundle::Action::LogOnly, "feed-1")],
            ..Default::default()
        };
        let outcome = decide(&bundle, "chat.example.com");
        assert_eq!(outcome.decision, Decision::Allow, "log-only must never block");
        assert_eq!(outcome.matched_rule, "category_log_only");
        assert_eq!(outcome.matched_category.as_deref(), Some("social"));
        assert_eq!(outcome.matched_feed_id.as_deref(), Some("feed-1"));
    }

    #[test]
    fn decide_block_category_beats_log_only_match() {
        let bundle = Bundle {
            categories: vec![
                category("social", mantis_bundle::Action::LogOnly, "feed-1"),
                category("malware", mantis_bundle::Action::Block, "feed-2"),
            ],
            ..Default::default()
        };
        let outcome = decide(&bundle, "evil.example.com");
        assert_eq!(outcome.decision, Decision::Block);
        assert_eq!(outcome.matched_rule, "category");
        assert_eq!(outcome.matched_category.as_deref(), Some("malware"));
    }

    #[test]
    fn decide_no_category_match_stays_default_allow() {
        let bundle = Bundle {
            categories: vec![category("social", mantis_bundle::Action::Block, "feed-1")],
            ..Default::default()
        };
        // num_bits=0 forces might_contain to return false regardless of
        // num_hashes — an empty/unconfigured filter must not match anything.
        let mut b = bundle;
        b.categories[0].bloom = Some(mantis_bundle::gen::BloomParams { num_hashes: 0, num_bits: 0, seed: 0 });
        let outcome = decide(&b, "anything.example.com");
        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.matched_rule, "default");
    }
}
