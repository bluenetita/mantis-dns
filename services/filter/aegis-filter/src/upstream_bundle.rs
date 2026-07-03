//! Upstream configuration bundle (design.md §21.3, Sprint 17–18).
//!
//! The control plane compiles an `UpstreamBundle` per tenant — a signed JSON
//! document containing resolver profiles, pool definitions, routing rules, and
//! tenant policy. This module fetches it, verifies the ed25519 signature,
//! stores it for use by the forwarder, and evaluates per-query routing.
//!
//! ## Signing contract (must match upstream_routers.py `_sign_bundle_body`)
//!   - HTTP response body  = canonical JSON (sort_keys, no whitespace)
//!   - X-Aegis-Signature   = hex-encoded ed25519 signature over those body bytes
//!
//! ## Sprint 17 vs Sprint 18
//!   Sprint 17: fetch + verify + simple first-member forwarding.
//!   Sprint 18: route evaluator (domain_suffix/exact/default), health-aware
//!              member selection, DNSSEC strict mode (hickory validate=true),
//!              real DoH via Protocol::Https (requires https-ring feature).

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwapOption;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::health_monitor::HealthStore;
use crate::Forwarder;

// ── Bundle JSON types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ResolverConfig_ {
    pub id: String,
    pub protocol: String, // "dot" | "doh" | "do53"
    pub address: String,
    pub port: u16,
    pub tls_hostname: Option<String>,
    pub doh_path: String,
    pub doh_method: String,
    pub timeout_ms: u64,
    pub connect_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PoolMember {
    pub resolver_id: String,
    pub weight: u32,
    pub priority: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PoolConfig {
    pub id: String,
    pub strategy: String,
    pub members: Vec<PoolMember>,
    pub health_check_interval_s: u64,
    pub health_check_timeout_ms: u64,
    pub health_check_query: String,
    pub health_check_type: String,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    pub fallback_pool_id: Option<String>,
    pub min_healthy_members: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    pub match_type: String, // domain_suffix|domain_exact|qtype|category|default
    pub match_value: Option<String>,
    pub pool_id: String,
    pub priority: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TenantPolicy {
    pub dnssec_validation: String, // "strict"|"opportunistic"|"disabled"
    pub blocked_response_type: String,
    pub min_ttl_s: u32,
    pub max_ttl_s: u32,
    pub negative_ttl_s: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamBundle {
    pub version: u64,
    pub tenant_id: String,
    /// Routes sorted ascending by priority by the control plane.
    pub routes: Vec<RouteConfig>,
    pub pools: HashMap<String, PoolConfig>,
    pub resolvers: HashMap<String, ResolverConfig_>,
    pub tenant_policy: TenantPolicy,
}

// ── Store ──────────────────────────────────────────────────────────────────────

pub struct UpstreamBundleStore {
    current: ArcSwapOption<UpstreamBundle>,
}

impl UpstreamBundleStore {
    pub fn empty() -> Self {
        Self {
            current: ArcSwapOption::const_empty(),
        }
    }

    pub fn publish(&self, bundle: UpstreamBundle) {
        if let Some(existing) = self.current.load().as_ref() {
            if bundle.version <= existing.version {
                debug!(
                    "upstream bundle for tenant {} unchanged (v{})",
                    bundle.tenant_id, bundle.version
                );
                return;
            }
        }
        info!(
            "upstream bundle published for tenant {} v{}",
            bundle.tenant_id, bundle.version
        );
        self.current.store(Some(Arc::new(bundle)));
    }

    pub fn current(&self) -> Option<Arc<UpstreamBundle>> {
        self.current.load_full()
    }
}

// ── Fetch + verify ─────────────────────────────────────────────────────────────

pub async fn fetch_upstream_bundle(
    control_url: &str,
    tenant_id: &str,
    public_key: &VerifyingKey,
) -> Result<UpstreamBundle> {
    let url = format!("{control_url}/api/v1/upstream-bundle/{tenant_id}");
    let resp = reqwest::get(&url).await?.error_for_status()?;

    let sig_hex = resp
        .headers()
        .get("X-Aegis-Signature")
        .context("X-Aegis-Signature header missing")?
        .to_str()
        .context("X-Aegis-Signature not valid UTF-8")?
        .to_owned();

    let body = resp.bytes().await?;

    let sig_bytes = hex::decode(&sig_hex).context("X-Aegis-Signature not valid hex")?;
    let sig = Signature::from_slice(&sig_bytes).context("invalid ed25519 signature length")?;
    public_key
        .verify(&body, &sig)
        .context("upstream bundle signature verification failed")?;

    let bundle: UpstreamBundle =
        serde_json::from_slice(&body).context("upstream bundle JSON parse failed")?;

    Ok(bundle)
}

// ── Route evaluator ────────────────────────────────────────────────────────────

fn normalize(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// Returns the pool_id of the best-matching route for `qname`.
/// Routes must be pre-sorted by ascending priority (lower = higher precedence).
///
/// `qtype` and `category` match types require richer context (record type,
/// category membership from the policy bundle) and are deferred to a future
/// sprint when the Forwarder trait carries that information.
pub(crate) fn evaluate_routes<'a>(routes: &'a [RouteConfig], qname: &str) -> Option<&'a str> {
    let normalized = normalize(qname);
    for route in routes {
        let matched = match route.match_type.as_str() {
            "domain_exact" => route
                .match_value
                .as_deref()
                .map(|v| normalize(v) == normalized)
                .unwrap_or(false),
            "domain_suffix" => route
                .match_value
                .as_deref()
                .map(|v| {
                    let suf = normalize(v);
                    normalized == suf || normalized.ends_with(&format!(".{suf}"))
                })
                .unwrap_or(false),
            "default" => true,
            _ => false,
        };
        if matched {
            return Some(&route.pool_id);
        }
    }
    None
}

// ── Member selector ────────────────────────────────────────────────────────────

fn pick_member<'a>(pool: &'a PoolConfig, healthy_ids: &[String]) -> Option<&'a str> {
    match pool.strategy.as_str() {
        "failover" => pool
            .members
            .iter()
            .filter(|m| healthy_ids.contains(&m.resolver_id))
            .min_by_key(|m| (m.priority, m.weight))
            .map(|m| m.resolver_id.as_str()),
        "weighted_round_robin" => pool
            .members
            .iter()
            .filter(|m| healthy_ids.contains(&m.resolver_id))
            .max_by_key(|m| m.weight)
            .map(|m| m.resolver_id.as_str()),
        _ => pool
            .members
            .iter()
            .find(|m| healthy_ids.contains(&m.resolver_id))
            .map(|m| m.resolver_id.as_str()),
    }
}

// ── Resolver cache ─────────────────────────────────────────────────────────────

struct BundleResolverCache {
    bundle_version: u64,
    dnssec_strict: bool,
    resolvers: HashMap<String, Resolver<TokioConnectionProvider>>,
}

// ── Forwarder ──────────────────────────────────────────────────────────────────

pub struct UpstreamBundleForwarder {
    store: Arc<UpstreamBundleStore>,
    health: Arc<HealthStore>,
    fallback: Option<Resolver<TokioConnectionProvider>>,
    cache: ArcSwapOption<BundleResolverCache>,
}

impl UpstreamBundleForwarder {
    pub fn new(store: Arc<UpstreamBundleStore>, health: Arc<HealthStore>) -> Self {
        let fallback = build_fallback_resolver();
        Self {
            store,
            health,
            fallback,
            cache: ArcSwapOption::const_empty(),
        }
    }

    fn get_resolver(
        &self,
        bundle: &UpstreamBundle,
        resolver_id: &str,
    ) -> Option<Resolver<TokioConnectionProvider>> {
        let dnssec_strict = bundle.tenant_policy.dnssec_validation == "strict";

        if let Some(cached) = self.cache.load().as_ref() {
            if cached.bundle_version == bundle.version && cached.dnssec_strict == dnssec_strict {
                return cached.resolvers.get(resolver_id).cloned();
            }
        }

        // Build resolver set for this bundle version + DNSSEC policy.
        let mut resolvers = HashMap::new();
        for (id, cfg) in &bundle.resolvers {
            if let Some(r) = build_hickory_resolver(cfg, cfg.timeout_ms, dnssec_strict) {
                resolvers.insert(id.clone(), r);
            }
        }
        let hit = resolvers.get(resolver_id).cloned();
        self.cache.store(Some(Arc::new(BundleResolverCache {
            bundle_version: bundle.version,
            dnssec_strict,
            resolvers,
        })));
        hit
    }

    async fn lookup_via_fallback(&self, qname: &str) -> Result<(Vec<Ipv4Addr>, u32)> {
        match &self.fallback {
            Some(r) => do_lookup(qname, r).await,
            None => bail!(
                "no upstream resolver available (bundle not loaded, no fallback configured)"
            ),
        }
    }
}

#[async_trait::async_trait]
impl Forwarder for UpstreamBundleForwarder {
    async fn lookup_a(&self, qname: &str) -> Result<(Vec<Ipv4Addr>, u32)> {
        let bundle = match self.store.current() {
            Some(b) => b,
            None => return self.lookup_via_fallback(qname).await,
        };

        let pool_id = match evaluate_routes(&bundle.routes, qname) {
            Some(id) => id.to_string(),
            None => return self.lookup_via_fallback(qname).await,
        };

        let pool = match bundle.pools.get(&pool_id) {
            Some(p) => p,
            None => {
                warn!("upstream route pointed to unknown pool {pool_id}, using fallback");
                return self.lookup_via_fallback(qname).await;
            }
        };

        let healthy_ids = self.health.healthy_members(&pool_id, &pool.members);
        let resolver_id = match pick_member(pool, &healthy_ids) {
            Some(id) => id.to_string(),
            None => {
                warn!("pool {pool_id} has no members, using fallback");
                return self.lookup_via_fallback(qname).await;
            }
        };

        match self.get_resolver(&bundle, &resolver_id) {
            Some(resolver) => do_lookup(qname, &resolver).await,
            None => {
                warn!("no resolver built for {resolver_id}, using fallback");
                self.lookup_via_fallback(qname).await
            }
        }
    }
}

async fn do_lookup(
    qname: &str,
    resolver: &Resolver<TokioConnectionProvider>,
) -> Result<(Vec<Ipv4Addr>, u32)> {
    let lookup = resolver.lookup_ip(qname).await?;
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
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .collect();
    Ok((ips, ttl))
}

// ── Builder helpers ────────────────────────────────────────────────────────────

/// Builds a hickory Resolver from a resolver config.
///
/// `dnssec_strict` sets `ResolverOpts::validate = true`, which (with the
/// `dnssec-ring` cargo feature added in Sprint 18) causes hickory to reject
/// responses that fail DNSSEC validation.
///
/// Returns None and logs a warning if the address cannot be parsed.
pub(crate) fn build_hickory_resolver(
    cfg: &ResolverConfig_,
    timeout_ms: u64,
    dnssec_strict: bool,
) -> Option<Resolver<TokioConnectionProvider>> {
    let addr: IpAddr = match cfg.address.parse() {
        Ok(a) => a,
        Err(e) => {
            warn!("upstream resolver address '{}' invalid: {e}", cfg.address);
            return None;
        }
    };
    let socket_addr = SocketAddr::new(addr, cfg.port);

    // DoH: Protocol::Https requires the `https-ring` cargo feature (Sprint 18).
    // Sprint 17 used Tls as a fallback for doh; Sprint 18 uses the real path.
    let (protocol, http_endpoint) = match cfg.protocol.as_str() {
        "dot" => (Protocol::Tls, None),
        "doh" => (Protocol::Https, Some(cfg.doh_path.clone())),
        _ => (Protocol::Udp, None),
    };

    let tls_dns_name = if matches!(cfg.protocol.as_str(), "dot" | "doh") {
        Some(cfg.tls_hostname.clone().unwrap_or_else(|| cfg.address.clone()))
    } else {
        None
    };

    let ns = NameServerConfig {
        socket_addr,
        protocol,
        tls_dns_name,
        http_endpoint,
        trust_negative_responses: true,
        bind_addr: None,
    };

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(timeout_ms.max(100));
    opts.attempts = 1;
    opts.validate = dnssec_strict;

    Some(
        Resolver::builder_with_config(
            ResolverConfig::from_parts(None, vec![], vec![ns]),
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build(),
    )
}

fn build_fallback_resolver() -> Option<Resolver<TokioConnectionProvider>> {
    let spec = env::var("UPSTREAM_FALLBACK_ADDRESS")
        .unwrap_or_else(|_| "dot:1.1.1.1:853:cloudflare-dns.com".to_string());

    let parts: Vec<&str> = spec.splitn(4, ':').collect();
    let cfg = match parts.as_slice() {
        ["dot", addr, port, tls_name] => {
            let port: u16 = port.parse().ok()?;
            make_resolver_cfg("dot", addr, port, Some(*tls_name))
        }
        ["doh", addr, port, tls_name] => {
            let port: u16 = port.parse().ok()?;
            make_resolver_cfg("doh", addr, port, Some(*tls_name))
        }
        [addr, port] => {
            let port: u16 = port.parse().ok()?;
            make_resolver_cfg("do53", addr, port, None)
        }
        _ => {
            warn!("UPSTREAM_FALLBACK_ADDRESS '{spec}' not parseable; using Cloudflare DoT");
            make_resolver_cfg("dot", "1.1.1.1", 853, Some("cloudflare-dns.com"))
        }
    };

    build_hickory_resolver(&cfg, 5000, false)
}

fn make_resolver_cfg(protocol: &str, addr: &str, port: u16, tls_name: Option<&str>) -> ResolverConfig_ {
    ResolverConfig_ {
        id: "fallback".into(),
        protocol: protocol.into(),
        address: addr.into(),
        port,
        tls_hostname: tls_name.map(str::to_string),
        doh_path: "/dns-query".into(),
        doh_method: "post".into(),
        timeout_ms: 5000,
        connect_timeout_ms: 3000,
    }
}

// ── Refresh loop ───────────────────────────────────────────────────────────────

pub async fn upstream_bundle_refresh_loop(
    store: Arc<UpstreamBundleStore>,
    control_url: String,
    tenant_id: String,
    public_key: VerifyingKey,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match fetch_upstream_bundle(&control_url, &tenant_id, &public_key).await {
            Ok(bundle) => store.publish(bundle),
            Err(e) => warn!("upstream bundle refresh failed for tenant {tenant_id}: {e}"),
        }
    }
}
