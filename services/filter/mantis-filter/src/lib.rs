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

mod cache;
pub mod health_monitor;
mod router;
mod telemetry;
pub mod upstream_bundle;
pub mod zone_store;

pub use telemetry::{QueryEventInput, TelemetryEmitter};
pub use zone_store::{fetch_and_publish_zone, fetch_local_zone_records, LocalZoneRecordDto, ZoneLookup, ZoneStore};

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use mantis_bundle::{Bundle, BundleStore};
use mantis_policy::BloomFilter;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use cache::DnsCache;
use ed25519_dalek::VerifyingKey;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use prost::Message as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

pub type DotResolver = Resolver<TokioConnectionProvider>;

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
    async fn lookup(&self, qname: &str, qtype: RecordType, _categories: &[String]) -> Result<Vec<Record>> {
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
    for category in &bundle.categories {
        if category.action != mantis_bundle::Action::Block as i32 {
            continue;
        }
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
    }
    DecisionOutcome {
        decision: Decision::Allow,
        matched_rule: "default",
        matched_category: None,
        matched_feed_id: None,
    }
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

fn normalize(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
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
    let arr: [u8; 32] = bytes
        .as_ref()
        .try_into()
        .context("public key response was not 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

/// Re-fetches the control plane's public key and updates `keys` in place if
/// it changed. Called on every poll tick (not just at startup) so a signing-
/// key rotation on the control plane self-heals instead of requiring a
/// filter-node restart.
pub async fn refresh_public_key(keys: &PublicKeyStore, control_url: &str) -> Result<()> {
    let fetched = fetch_public_key(control_url).await?;
    if fetched != keys.current() {
        info!("control-plane public key changed — updating (was this an intentional key rotation?)");
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
    let resp = with_service_token(client.get(format!("{control_url}/api/v1/groups/{group_id}/bundle")))
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

pub async fn run_udp_server(socket: UdpSocket, state: Arc<AppState>) -> Result<()> {
    let local_addr = socket.local_addr()?;
    info!("mantis-filter UDP DNS listener bound on {local_addr}");
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

        let bundle = state.store.current();
        let response = build_response(
            &query,
            bundle.as_deref(),
            &state.zones,
            peer.ip(),
            &state.cache,
            state.forwarder.as_ref(),
            &state.telemetry,
        )
        .await;
        match response.to_bytes() {
            Ok(bytes) => {
                if let Err(e) = socket.send_to(&bytes, peer).await {
                    warn!("UDP send_to {peer} failed: {e}");
                }
            }
            Err(e) => warn!("failed to encode UDP response for {peer}: {e}"),
        }
    }
}

// ── TCP server ─────────────────────────────────────────────────────────────────

/// Maximum concurrent TCP DNS connections. Excess connections are accepted
/// then immediately closed so clients get a clean FIN rather than a timeout.
pub(crate) const MAX_TCP_CONNECTIONS: usize = 500;

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
        let msg_len = match stream.read_u16().await {
            Ok(n) => n as usize,
            // Clean close from the client.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        if msg_len == 0 {
            break;
        }

        let mut buf = vec![0u8; msg_len];
        stream.read_exact(&mut buf).await?;

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

pub use health_monitor::{run_health_monitor, HealthStore};
pub use router::{
    refresh_routes, routing_refresh_loop, run_router_tcp_server, run_router_udp_server,
    test_support, TenantRouter,
};
pub use upstream_bundle::{
    fetch_upstream_bundle, upstream_bundle_refresh_loop, UpstreamBundle, UpstreamBundleForwarder,
    UpstreamBundleStore,
};

/// Adds the MANTIS_SERVICE_TOKEN bearer header to outbound M2M requests.
pub fn with_service_token(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Ok(tok) = std::env::var("MANTIS_SERVICE_TOKEN") {
        rb.bearer_auth(tok)
    } else {
        rb
    }
}

// ── Core decision + response ───────────────────────────────────────────────────

pub(crate) async fn build_response(
    query: &Message,
    bundle: Option<&Bundle>,
    zones: &ZoneStore,
    client_ip: IpAddr,
    cache: &DnsCache,
    forwarder: &dyn Forwarder,
    telemetry: &TelemetryEmitter,
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
            emit_zone_telemetry(telemetry, bundle, &client_ip, &qname, &qtype_str, &response, start);
            return response;
        }
        ZoneLookup::NxDomain => {
            response.set_authoritative(true);
            response.set_response_code(ResponseCode::NXDomain);
            emit_zone_telemetry(telemetry, bundle, &client_ip, &qname, &qtype_str, &response, start);
            return response;
        }
        ZoneLookup::NotLocal => {}
    }

    let Some(bundle) = bundle else {
        response.set_response_code(ResponseCode::ServFail);
        return response;
    };

    let outcome = decide(bundle, &qname);
    // All category IDs the qname matches (any action), used for upstream routing.
    let categories = matched_categories(bundle, &qname);
    let mut cache_hit: Option<bool> = None;

    match outcome.decision {
        Decision::Block => {
            response.set_response_code(ResponseCode::NXDomain);
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

/// Resolves any qtype through the cache then forwarder. Returns `true` on
/// cache hit. Propagates NXDOMAIN vs NODATA correctly.
async fn resolve_records(
    qname: &str,
    qtype: RecordType,
    categories: &[String],
    cache: &DnsCache,
    forwarder: &dyn Forwarder,
    response: &mut Message,
) -> bool {
    let qtype_u16 = u16::from(qtype);

    if let Some(records) = cache.get(qname, qtype_u16) {
        response.set_response_code(ResponseCode::NoError);
        for rec in records {
            response.add_answer(rec);
        }
        return true;
    }

    match forwarder.lookup(qname, qtype, categories).await {
        Ok(records) => {
            let ttl = records.iter().map(|r| r.ttl()).min().unwrap_or(60);
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
                }
                Some(re) if re.is_no_records_found() => {
                    // NODATA: name exists, no records of this type.
                    response.set_response_code(ResponseCode::NoError);
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
}
