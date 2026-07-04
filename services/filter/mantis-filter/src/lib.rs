//! Mantis filter node: DNS frontend + policy engine.

mod cache;
pub mod health_monitor;
mod router;
mod telemetry;
pub mod upstream_bundle;

pub use telemetry::{QueryEventInput, TelemetryEmitter};

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use mantis_bundle::{Bundle, BundleStore};
use mantis_policy::BloomFilter;
use anyhow::{Context, Result};
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

pub struct AppState {
    pub store: BundleStore,
    pub public_key: VerifyingKey,
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
            public_key,
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

pub async fn fetch_and_publish_bundle(
    store: &BundleStore,
    public_key: &VerifyingKey,
    control_url: &str,
    group_id: &str,
) -> Result<()> {
    let resp = reqwest::get(format!("{control_url}/api/v1/groups/{group_id}/bundle")).await?;
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
    fetch_and_publish_bundle(&state.store, &state.public_key, control_url, group_id).await
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
        if let Err(e) = refresh_bundle(&state, &control_url, &group_id).await {
            warn!("bundle refresh failed: {e}");
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
            // hickory surfaces both NXDOMAIN and NODATA as NoRecordsFound;
            // the embedded response_code field distinguishes them.
            let err_str = format!("{e:?}");
            if err_str.contains("NoRecordsFound") {
                if err_str.contains("NXDomain") {
                    response.set_response_code(ResponseCode::NXDomain);
                } else {
                    // NODATA: name exists, no records of this type.
                    response.set_response_code(ResponseCode::NoError);
                }
            } else {
                debug!("upstream resolution failed for {qname} ({qtype:?}): {e}");
                response.set_response_code(ResponseCode::ServFail);
            }
        }
    }
    false
}
