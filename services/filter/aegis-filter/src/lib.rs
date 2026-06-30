//! Aegis filter node: DNS frontend + policy engine.
//!
//! Sprint 4 scope: real cache + DoT upstream forwarding. Tenant resolution
//! is still a single global bundle (per-listener/source-IP tenant mapping is
//! Sprint 5, see design.md §7.3).

mod cache;
pub mod metrics_init;
mod router;
mod telemetry;

pub use telemetry::TelemetryEmitter;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use aegis_bundle::{Bundle, BundleStore};
use aegis_policy::BloomFilter;
use anyhow::{Context, Result};
use cache::DnsCache;
use ed25519_dalek::VerifyingKey;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use prost::Message as _;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

pub type DotResolver = Resolver<TokioConnectionProvider>;

/// Abstraction over upstream resolution so tests/CI don't depend on live
/// network + port 853 egress (the real DoT path is exercised by the example
/// client against a running Docker deployment instead — see README).
#[async_trait::async_trait]
pub trait Forwarder: Send + Sync {
    async fn lookup_a(&self, qname: &str) -> Result<(Vec<Ipv4Addr>, u32)>;
}

pub struct DotForwarder(DotResolver);

impl DotForwarder {
    /// DNS-over-TLS to Cloudflare by default (design.md §9: upstream privacy
    /// via DoT/DoH). Override target is a Sprint-4-follow-up config knob,
    /// not yet wired to an env var.
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
    async fn lookup_a(&self, qname: &str) -> Result<(Vec<Ipv4Addr>, u32)> {
        let lookup = self.0.lookup_ip(qname).await?;
        let ttl = lookup
            .as_lookup()
            .records()
            .iter()
            .map(|r| r.ttl())
            .min()
            .unwrap_or(60);
        let ips: Vec<Ipv4Addr> = lookup
            .iter()
            .filter_map(|ip| match ip {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .collect();
        Ok((ips, ttl))
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

    /// Builder-style: attach a real telemetry emitter (defaults to a no-op
    /// that silently drops events, used by tests and until main.rs opts in).
    pub fn with_telemetry(mut self, telemetry: TelemetryEmitter) -> Self {
        self.telemetry = telemetry;
        self
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
}

/// Lookup order per design.md §18.4: deny-override beats categories beats
/// default-allow; allow-override always wins over everything else.
pub fn decide(bundle: &Bundle, qname: &str) -> Decision {
    let qname = normalize(qname);

    if bundle.allow_overrides.iter().any(|d| normalize(d) == qname) {
        return Decision::Allow;
    }
    if bundle.deny_overrides.iter().any(|d| normalize(d) == qname) {
        return Decision::Block;
    }
    for category in &bundle.categories {
        if category.action != aegis_bundle::Action::Block as i32 {
            continue;
        }
        if let Some(bf) = BloomFilter::from_category(category) {
            if bf.might_contain(&qname) {
                return Decision::Block;
            }
        }
    }
    Decision::Allow
}

fn normalize(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// Fetches the control plane's verification key once at startup.
pub async fn fetch_public_key(control_url: &str) -> Result<VerifyingKey> {
    let bytes = reqwest::get(format!("{control_url}/api/v1/public-key"))
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

/// Fetches the latest compiled bundle for a group and publishes it into
/// `store` if newer than what's currently loaded. Safe to call repeatedly
/// (e.g. on a poll loop). Shared by the single-tenant `AppState` path and the
/// multi-tenant `TenantRouter` path (router.rs), one per routed group.
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

/// Single-tenant convenience wrapper around [`fetch_and_publish_bundle`].
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

/// Binds a UDP DNS listener and serves requests against `state` until the
/// socket errors out. Single global bundle for Sprint 3 — no per-tenant
/// listener routing yet.
pub async fn run_udp_server(socket: UdpSocket, state: Arc<AppState>) -> Result<()> {
    let local_addr = socket.local_addr()?;
    info!("aegis-filter DNS listener bound on {local_addr}");
    let mut buf = [0u8; 4096];

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let query = match Message::from_bytes(&buf[..len]) {
            Ok(m) => m,
            Err(e) => {
                debug!("dropping unparseable packet from {peer}: {e}");
                continue;
            }
        };

        let bundle = state.store.current();
        let response = build_response(
            &query,
            bundle.as_deref(),
            &state.cache,
            state.forwarder.as_ref(),
            &state.telemetry,
        )
        .await;
        match response.to_bytes() {
            Ok(bytes) => {
                if let Err(e) = socket.send_to(&bytes, peer).await {
                    warn!("send_to {peer} failed: {e}");
                }
            }
            Err(e) => warn!("failed to encode response for {peer}: {e}"),
        }
    }
}

pub use router::{refresh_routes, routing_refresh_loop, run_router_udp_server, test_support, TenantRouter};

/// Core decision + response logic, parameterized over the resolved bundle so
/// both the single-tenant `AppState` path and the multi-tenant `TenantRouter`
/// path (see router.rs) share it instead of duplicating the response-building
/// rules.
pub(crate) async fn build_response(
    query: &Message,
    bundle: Option<&Bundle>,
    cache: &DnsCache,
    forwarder: &dyn Forwarder,
    telemetry: &TelemetryEmitter,
) -> Message {
    let start = std::time::Instant::now();
    let response = build_response_inner(query, bundle, cache, forwarder, telemetry).await;
    metrics::histogram!("aegis_dns_response_seconds").record(start.elapsed().as_secs_f64());
    response
}

async fn build_response_inner(
    query: &Message,
    bundle: Option<&Bundle>,
    cache: &DnsCache,
    forwarder: &dyn Forwarder,
    telemetry: &TelemetryEmitter,
) -> Message {
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

    let Some(bundle) = bundle else {
        // No bundle loaded yet (or no tenant matched, in router mode).
        // Fail-open by default at this stage (dev-friendly); per-tenant
        // FailurePolicy enforcement lands in Sprint 9 HA hardening.
        metrics::counter!("aegis_dns_queries_total", "decision" => "no_bundle").increment(1);
        response.set_response_code(ResponseCode::ServFail);
        return response;
    };

    match decide(bundle, &qname) {
        Decision::Block => {
            metrics::counter!("aegis_dns_queries_total", "decision" => "block").increment(1);
            telemetry.emit(&bundle.group_id, &qname, "block");
            response.set_response_code(ResponseCode::NXDomain);
        }
        Decision::Allow => {
            metrics::counter!("aegis_dns_queries_total", "decision" => "allow").increment(1);
            telemetry.emit(&bundle.group_id, &qname, "allow");
            if question.query_type() == RecordType::A {
                resolve_a_record(&qname, question.name().clone(), cache, forwarder, &mut response)
                    .await;
            } else {
                // Only A records are resolved/cached/forwarded as of Sprint 4 —
                // everything else gets an empty NOERROR (effectively NODATA).
                response.set_response_code(ResponseCode::NoError);
            }
        }
    }
    response
}

async fn resolve_a_record(
    qname: &str,
    record_name: hickory_proto::rr::Name,
    cache: &DnsCache,
    forwarder: &dyn Forwarder,
    response: &mut Message,
) {
    if let Some(ips) = cache.get(qname) {
        metrics::counter!("aegis_dns_cache_total", "result" => "hit").increment(1);
        response.set_response_code(ResponseCode::NoError);
        for ip in ips {
            response.add_answer(Record::from_rdata(record_name.clone(), 60, RData::A(A(ip))));
        }
        return;
    }
    metrics::counter!("aegis_dns_cache_total", "result" => "miss").increment(1);

    match forwarder.lookup_a(qname).await {
        Ok((ips, ttl)) => {
            cache.put(qname.to_string(), ips.clone(), Duration::from_secs(ttl as u64));

            response.set_response_code(ResponseCode::NoError);
            for ip in ips {
                response.add_answer(Record::from_rdata(record_name.clone(), ttl, RData::A(A(ip))));
            }
        }
        Err(e) => {
            metrics::counter!("aegis_dns_upstream_errors_total").increment(1);
            debug!("upstream resolution failed for {qname}: {e}");
            response.set_response_code(ResponseCode::ServFail);
        }
    }
}
