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

//! Upstream configuration bundle (design.md §21.3, Sprint 17–18).
//!
//! The control plane compiles an `UpstreamBundle` per tenant — a signed JSON
//! document containing resolver profiles, pool definitions, routing rules, and
//! tenant policy. This module fetches it, verifies the ed25519 signature,
//! stores it for use by the forwarder, and evaluates per-query routing.
//!
//! ## Signing contract (must match upstream_routers.py `_sign_bundle_body`)
//!   - HTTP response body  = canonical JSON (sort_keys, no whitespace)
//!   - X-Mantis-Signature   = hex-encoded ed25519 signature over those body bytes
//!
//! ## Sprint 17 vs Sprint 18
//!   Sprint 17: fetch + verify + simple first-member forwarding.
//!   Sprint 18: route evaluator (domain_suffix/exact/default), health-aware
//!              member selection, DNSSEC strict mode (hickory validate=true),
//!              real DoH via Protocol::Https (requires https-ring feature).

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwapOption;
use ed25519_dalek::{Signature, VerifyingKey};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::health_monitor::HealthStore;
use crate::{tls_pin, Forwarder, TtlPolicy};

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
    /// SHA-256 digests of certificates this resolver's TLS handshake must
    /// present (see `tls_pin::PinnedCertVerifier`). `#[serde(default)]`
    /// because older control-plane builds — and the fallback resolver
    /// config synthesized in `make_resolver_cfg` below — don't set it.
    /// Empty means "no pinning, use normal WebPKI trust" (unchanged
    /// behavior). Was previously entirely absent from this struct: the
    /// control plane already shipped this field in the bundle JSON, but
    /// serde silently drops unknown fields with no `deny_unknown_fields`,
    /// so an admin-configured pin was accepted by the API and stored in the
    /// DB but never actually enforced by the filter node.
    #[serde(default)]
    pub tls_pin_sha256: Vec<String>,
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

    /// The version check and the publish are one atomic `rcu`, not a
    /// separate load-then-store — see BundleStore::try_publish in
    /// mantis-bundle for why a plain load-check-store here would let a
    /// lower-version bundle overwrite a higher one under concurrent publish.
    pub fn publish(&self, bundle: UpstreamBundle) {
        let bundle = Arc::new(bundle);
        let incoming_version = bundle.version;
        let tenant_id = bundle.tenant_id.clone();

        let prev = self.current.rcu(|existing| match existing {
            Some(current) if incoming_version <= current.version => existing.clone(),
            _ => Some(Arc::clone(&bundle)),
        });

        let published = prev.as_ref().is_none_or(|p| incoming_version > p.version);
        if published {
            info!("upstream bundle published for tenant {tenant_id} v{incoming_version}");
        } else {
            debug!("upstream bundle for tenant {tenant_id} unchanged (v{incoming_version})");
        }
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
    let client = reqwest::Client::new();
    let resp = crate::with_service_token(client.get(&url))
        .send()
        .await?
        .error_for_status()?;

    let sig_hex = resp
        .headers()
        .get("X-Mantis-Signature")
        .context("X-Mantis-Signature header missing")?
        .to_str()
        .context("X-Mantis-Signature not valid UTF-8")?
        .to_owned();

    let body = resp.bytes().await?;

    let sig_bytes = hex::decode(&sig_hex).context("X-Mantis-Signature not valid hex")?;
    let sig = Signature::from_slice(&sig_bytes).context("invalid ed25519 signature length")?;
    public_key
        .verify_strict(&body, &sig)
        .context("upstream bundle signature verification failed")?;

    let bundle: UpstreamBundle =
        serde_json::from_slice(&body).context("upstream bundle JSON parse failed")?;

    Ok(bundle)
}

// ── Route evaluator ────────────────────────────────────────────────────────────

fn normalize(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// Returns the pool_id of the best-matching route for `(qname, qtype)`.
/// Routes are pre-sorted ascending by priority (lower value = higher precedence).
///
/// `categories` is the set of policy-bundle category IDs the qname matched
/// (computed by `matched_categories()` in lib.rs before calling the forwarder).
pub(crate) fn evaluate_routes<'a>(
    routes: &'a [RouteConfig],
    qname: &str,
    qtype: RecordType,
    categories: &[String],
) -> Option<&'a str> {
    let normalized = normalize(qname);
    // hickory Debug output for RecordType is the canonical uppercase string ("A", "AAAA", …).
    let qtype_str = format!("{qtype:?}").to_uppercase();
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
            "qtype" => route
                .match_value
                .as_deref()
                .map(|v| v.to_uppercase() == qtype_str)
                .unwrap_or(false),
            "category" => route
                .match_value
                .as_deref()
                .map(|v| categories.iter().any(|c| c == v))
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

/// Per-pool rotation cursor, shared across every concurrent DNS lookup this
/// forwarder serves. Keyed by pool_id since one forwarder picks members for
/// every pool in the tenant's upstream bundle, each needing an independent
/// rotation position. Was previously entirely absent: `pick_member` used
/// `.max_by_key`/`.find`, which deterministically returns the *same* member
/// every single call — "weighted_round_robin"/"round_robin" advertised load
/// balancing that never actually happened; every query pinned one member.
#[derive(Default)]
pub(crate) struct RoundRobinState {
    cursors: Mutex<HashMap<String, u64>>,
}

impl RoundRobinState {
    /// Returns the next cursor value for `pool_id` (0, 1, 2, ... wrapping is
    /// the caller's job via modulo) and advances it for the next call.
    fn next(&self, pool_id: &str) -> u64 {
        let mut cursors = self.cursors.lock().unwrap_or_else(|e| e.into_inner());
        let counter = cursors.entry(pool_id.to_string()).or_insert(0);
        let value = *counter;
        *counter = counter.wrapping_add(1);
        value
    }
}

fn pick_member<'a>(
    pool_id: &str,
    pool: &'a PoolConfig,
    healthy_ids: &[String],
    health: &HealthStore,
    rr: &RoundRobinState,
) -> Option<&'a str> {
    let healthy_members: Vec<&PoolMember> = pool
        .members
        .iter()
        .filter(|m| healthy_ids.contains(&m.resolver_id))
        .collect();
    if healthy_members.is_empty() {
        return None;
    }

    match pool.strategy.as_str() {
        "failover" => healthy_members
            .into_iter()
            .min_by_key(|m| (m.priority, m.weight))
            .map(|m| m.resolver_id.as_str()),
        "weighted_round_robin" => {
            // Deterministic weighted round robin: a monotonically
            // increasing cursor mod the pool's total weight, mapped onto
            // cumulative per-member weight ranges. Over any full cycle of
            // `total_weight` calls, each member is picked exactly `weight`
            // times — proportional distribution without needing a
            // per-member floating "credit" state (nginx's smooth-WRR
            // algorithm) to get the ratio right.
            let total_weight: u64 = healthy_members.iter().map(|m| u64::from(m.weight)).sum();
            if total_weight == 0 {
                return healthy_members.first().map(|m| m.resolver_id.as_str());
            }
            let cursor = rr.next(pool_id) % total_weight;
            let mut acc = 0u64;
            for m in &healthy_members {
                acc += u64::from(m.weight);
                if cursor < acc {
                    return Some(m.resolver_id.as_str());
                }
            }
            healthy_members.last().map(|m| m.resolver_id.as_str())
        }
        "latency" => {
            // Lowest EMA latency wins (health_monitor's probe loop already
            // maintains this per member). An unprobed member reads as 0
            // (MemberHealthSnapshot::default) and so is tried first —
            // consistent with "unknown = optimistically healthy" elsewhere
            // in health_monitor.rs — and self-corrects once real probe data
            // arrives.
            healthy_members
                .into_iter()
                .min_by_key(|m| health.snapshot(pool_id, &m.resolver_id).latency_ema_us)
                .map(|m| m.resolver_id.as_str())
        }
        // "round_robin" and any unrecognized strategy: plain rotation
        // across the healthy set, equal probability per member.
        _ => {
            let idx = (rr.next(pool_id) as usize) % healthy_members.len();
            healthy_members.get(idx).map(|m| m.resolver_id.as_str())
        }
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
    round_robin: RoundRobinState,
}

impl UpstreamBundleForwarder {
    pub fn new(store: Arc<UpstreamBundleStore>, health: Arc<HealthStore>) -> Self {
        let fallback = build_fallback_resolver();
        Self {
            store,
            health,
            fallback,
            cache: ArcSwapOption::const_empty(),
            round_robin: RoundRobinState::default(),
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

    async fn lookup_via_fallback(&self, qname: &str, qtype: RecordType) -> Result<Vec<Record>> {
        match &self.fallback {
            Some(r) => do_lookup(qname, qtype, r).await,
            None => bail!(
                "no upstream resolver available (bundle not loaded, no fallback configured)"
            ),
        }
    }
}

#[async_trait::async_trait]
impl Forwarder for UpstreamBundleForwarder {
    async fn lookup(&self, qname: &str, qtype: RecordType, categories: &[String]) -> Result<Vec<Record>> {
        let bundle = match self.store.current() {
            Some(b) => b,
            None => return self.lookup_via_fallback(qname, qtype).await,
        };

        let pool_id = match evaluate_routes(&bundle.routes, qname, qtype, categories) {
            Some(id) => id.to_string(),
            None => return self.lookup_via_fallback(qname, qtype).await,
        };

        let pool = match bundle.pools.get(&pool_id) {
            Some(p) => p,
            None => {
                warn!("upstream route pointed to unknown pool {pool_id}, using fallback");
                return self.lookup_via_fallback(qname, qtype).await;
            }
        };

        let healthy_ids = self.health.healthy_members(&pool_id, &pool.members);
        let resolver_id = match pick_member(&pool_id, pool, &healthy_ids, &self.health, &self.round_robin) {
            Some(id) => id.to_string(),
            None => {
                warn!("pool {pool_id} has no healthy members, using fallback");
                return self.lookup_via_fallback(qname, qtype).await;
            }
        };

        match self.get_resolver(&bundle, &resolver_id) {
            Some(resolver) => do_lookup(qname, qtype, &resolver).await,
            None => {
                warn!("no resolver built for {resolver_id}, using fallback");
                self.lookup_via_fallback(qname, qtype).await
            }
        }
    }

    fn ttl_policy(&self) -> TtlPolicy {
        match self.store.current() {
            Some(bundle) => TtlPolicy {
                min_ttl_s: bundle.tenant_policy.min_ttl_s,
                max_ttl_s: bundle.tenant_policy.max_ttl_s,
                negative_ttl_s: bundle.tenant_policy.negative_ttl_s,
            },
            None => TtlPolicy::default(),
        }
    }
}

async fn do_lookup(
    qname: &str,
    qtype: RecordType,
    resolver: &Resolver<TokioConnectionProvider>,
) -> Result<Vec<Record>> {
    let name: Name = qname.parse().context("invalid qname")?;
    let lookup = resolver.lookup(name, qtype).await?;
    Ok(lookup.records().to_vec())
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

    if matches!(cfg.protocol.as_str(), "dot" | "doh") && !cfg.tls_pin_sha256.is_empty() {
        apply_tls_pinning(&mut opts, cfg);
    }

    Some(
        Resolver::builder_with_config(
            ResolverConfig::from_parts(None, vec![], vec![ns]),
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build(),
    )
}

/// Replaces `opts.tls_config`'s normal WebPKI verifier with a
/// `PinnedCertVerifier` built from `cfg.tls_pin_sha256` — see tls_pin.rs for
/// why pin-only (not pin-or-CA) is the right model here. Leaves `opts`
/// untouched (falling back to ordinary WebPKI trust) if every configured
/// pin is malformed, rather than refusing to build the resolver at all.
fn apply_tls_pinning(opts: &mut ResolverOpts, cfg: &ResolverConfig_) {
    let pins: Vec<[u8; 32]> = cfg
        .tls_pin_sha256
        .iter()
        .filter_map(|p| {
            let parsed = tls_pin::parse_pin(p);
            if parsed.is_none() {
                warn!("upstream resolver '{}': ignoring malformed tls_pin_sha256 entry '{p}'", cfg.id);
            }
            parsed
        })
        .collect();
    if pins.is_empty() {
        warn!(
            "upstream resolver '{}' configured tls_pin_sha256 but none of the entries parsed \
             — falling back to normal WebPKI trust",
            cfg.id
        );
        return;
    }

    let provider = Arc::new(hickory_proto::rustls::default_provider());
    let verifier = Arc::new(tls_pin::PinnedCertVerifier::new(pins, provider.clone()));
    match rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions() {
        Ok(builder) => {
            opts.tls_config = builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
        }
        Err(e) => warn!("upstream resolver '{}': failed to build pinned TLS config: {e}", cfg.id),
    }
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
        tls_pin_sha256: Vec::new(),
    }
}

// ── Refresh loop ───────────────────────────────────────────────────────────────

/// Re-fetches the control plane's public key on every tick (like
/// `bundle_refresh_loop` does for the policy-bundle path) before fetching the
/// upstream bundle — without this, a signing-key rotation on the control
/// plane permanently breaks upstream-bundle verification until the filter
/// node is restarted by hand, since `public_key` used to be captured once at
/// startup and never refreshed.
pub async fn upstream_bundle_refresh_loop(
    store: Arc<UpstreamBundleStore>,
    control_url: String,
    tenant_id: String,
    public_key: Arc<crate::PublicKeyStore>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        if let Err(e) = crate::refresh_public_key(&public_key, &control_url).await {
            warn!("public key refresh failed (keeping last known good key): {e}");
        }
        match fetch_upstream_bundle(&control_url, &tenant_id, &public_key.current()).await {
            Ok(bundle) => store.publish(bundle),
            Err(e) => warn!("upstream bundle refresh failed for tenant {tenant_id}: {e}"),
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health_monitor::MemberHealthSnapshot;
    use hickory_proto::rr::RecordType;

    fn route(match_type: &str, match_value: Option<&str>, pool_id: &str, priority: i32) -> RouteConfig {
        RouteConfig {
            match_type: match_type.into(),
            match_value: match_value.map(str::to_string),
            pool_id: pool_id.into(),
            priority,
        }
    }

    fn cats(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    // ── domain_exact ──────────────────────────────────────────────────────────

    #[test]
    fn domain_exact_matches_literally() {
        let routes = [route("domain_exact", Some("example.com"), "p1", 0)];
        assert_eq!(evaluate_routes(&routes, "example.com", RecordType::A, &[]), Some("p1"));
    }

    #[test]
    fn domain_exact_case_insensitive() {
        let routes = [route("domain_exact", Some("Example.COM"), "p1", 0)];
        assert_eq!(evaluate_routes(&routes, "example.com", RecordType::A, &[]), Some("p1"));
    }

    #[test]
    fn domain_exact_does_not_match_subdomain() {
        let routes = [route("domain_exact", Some("example.com"), "p1", 0)];
        assert!(evaluate_routes(&routes, "sub.example.com", RecordType::A, &[]).is_none());
    }

    #[test]
    fn domain_exact_strips_trailing_dot() {
        let routes = [route("domain_exact", Some("example.com"), "p1", 0)];
        assert_eq!(evaluate_routes(&routes, "example.com.", RecordType::A, &[]), Some("p1"));
    }

    // ── domain_suffix ─────────────────────────────────────────────────────────

    #[test]
    fn domain_suffix_matches_subdomain() {
        let routes = [route("domain_suffix", Some("example.com"), "p1", 0)];
        assert_eq!(evaluate_routes(&routes, "sub.example.com", RecordType::A, &[]), Some("p1"));
    }

    #[test]
    fn domain_suffix_matches_exact_name_too() {
        let routes = [route("domain_suffix", Some("example.com"), "p1", 0)];
        assert_eq!(evaluate_routes(&routes, "example.com", RecordType::A, &[]), Some("p1"));
    }

    #[test]
    fn domain_suffix_does_not_match_unrelated() {
        let routes = [route("domain_suffix", Some("example.com"), "p1", 0)];
        assert!(evaluate_routes(&routes, "notexample.com", RecordType::A, &[]).is_none());
    }

    // ── qtype ─────────────────────────────────────────────────────────────────

    #[test]
    fn qtype_matches_correct_type() {
        let routes = [route("qtype", Some("AAAA"), "ipv6-pool", 0)];
        assert_eq!(evaluate_routes(&routes, "any.example", RecordType::AAAA, &[]), Some("ipv6-pool"));
    }

    #[test]
    fn qtype_does_not_match_wrong_type() {
        let routes = [route("qtype", Some("AAAA"), "ipv6-pool", 0)];
        assert!(evaluate_routes(&routes, "any.example", RecordType::A, &[]).is_none());
    }

    #[test]
    fn qtype_match_value_case_insensitive() {
        let routes = [route("qtype", Some("mx"), "mail-pool", 0)];
        assert_eq!(evaluate_routes(&routes, "any.example", RecordType::MX, &[]), Some("mail-pool"));
    }

    // ── category ──────────────────────────────────────────────────────────────

    #[test]
    fn category_matches_when_domain_in_category() {
        let routes = [route("category", Some("cdn"), "fast-pool", 0)];
        assert_eq!(
            evaluate_routes(&routes, "static.example", RecordType::A, &cats(&["cdn"])),
            Some("fast-pool")
        );
    }

    #[test]
    fn category_no_match_when_domain_not_in_category() {
        let routes = [route("category", Some("cdn"), "fast-pool", 0)];
        assert!(
            evaluate_routes(&routes, "static.example", RecordType::A, &cats(&["malware"])).is_none()
        );
    }

    #[test]
    fn category_matches_any_of_multiple_categories() {
        let routes = [route("category", Some("streaming"), "media-pool", 0)];
        assert_eq!(
            evaluate_routes(&routes, "v.example", RecordType::A, &cats(&["cdn", "streaming"])),
            Some("media-pool")
        );
    }

    #[test]
    fn category_no_match_with_empty_categories() {
        let routes = [route("category", Some("cdn"), "fast-pool", 0)];
        assert!(evaluate_routes(&routes, "x.example", RecordType::A, &[]).is_none());
    }

    // ── default ───────────────────────────────────────────────────────────────

    #[test]
    fn default_matches_always() {
        let routes = [route("default", None, "catch-all", 0)];
        assert_eq!(evaluate_routes(&routes, "anything.example", RecordType::TXT, &[]), Some("catch-all"));
    }

    #[test]
    fn no_routes_returns_none() {
        assert!(evaluate_routes(&[], "x.example", RecordType::A, &[]).is_none());
    }

    // ── priority ordering ─────────────────────────────────────────────────────

    #[test]
    fn first_matching_route_wins() {
        // Routes are pre-sorted by the control plane; we just take the first match.
        let routes = [
            route("domain_exact", Some("example.com"), "specific", 0),
            route("default", None, "catch-all", 1),
        ];
        assert_eq!(evaluate_routes(&routes, "example.com", RecordType::A, &[]), Some("specific"));
    }

    #[test]
    fn default_used_when_specific_route_misses() {
        let routes = [
            route("domain_exact", Some("other.com"), "specific", 0),
            route("default", None, "catch-all", 1),
        ];
        assert_eq!(evaluate_routes(&routes, "example.com", RecordType::A, &[]), Some("catch-all"));
    }

    #[test]
    fn category_route_beats_default() {
        let routes = [
            route("category", Some("cdn"), "fast-pool", 0),
            route("default", None, "default-pool", 1),
        ];
        assert_eq!(
            evaluate_routes(&routes, "static.example", RecordType::A, &cats(&["cdn"])),
            Some("fast-pool")
        );
    }

    // ── tls_pin_sha256 ────────────────────────────────────────────────────────

    #[test]
    fn resolver_config_deserializes_tls_pin_sha256() {
        // Regression test: this field used to be entirely absent from
        // ResolverConfig_, so serde silently dropped it from the upstream
        // bundle JSON — an admin-configured pin was accepted by the control
        // plane's API and stored in the DB but never reached the filter
        // node's resolver-building code at all.
        let json = r#"{
            "id": "r1", "protocol": "dot", "address": "203.0.113.5", "port": 853,
            "tls_hostname": "resolver.example", "doh_path": "/dns-query",
            "doh_method": "post", "timeout_ms": 5000, "connect_timeout_ms": 3000,
            "tls_pin_sha256": ["aabb", "ccdd"]
        }"#;
        let cfg: ResolverConfig_ = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.tls_pin_sha256, vec!["aabb".to_string(), "ccdd".to_string()]);
    }

    #[test]
    fn resolver_config_defaults_tls_pin_sha256_to_empty_when_absent() {
        // Older control-plane builds (or the synthesized fallback resolver
        // config in make_resolver_cfg) don't send this field at all.
        let json = r#"{
            "id": "r1", "protocol": "do53", "address": "1.1.1.1", "port": 53,
            "tls_hostname": null, "doh_path": "/dns-query",
            "doh_method": "post", "timeout_ms": 5000, "connect_timeout_ms": 3000
        }"#;
        let cfg: ResolverConfig_ = serde_json::from_str(json).unwrap();
        assert!(cfg.tls_pin_sha256.is_empty());
    }

    fn dot_resolver_cfg(pins: Vec<&str>) -> ResolverConfig_ {
        ResolverConfig_ {
            id: "r1".into(),
            protocol: "dot".into(),
            address: "203.0.113.5".into(),
            port: 853,
            tls_hostname: Some("resolver.example".into()),
            doh_path: "/dns-query".into(),
            doh_method: "post".into(),
            timeout_ms: 5000,
            connect_timeout_ms: 3000,
            tls_pin_sha256: pins.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn build_hickory_resolver_applies_pinning_for_a_valid_pin() {
        let valid_pin = "a".repeat(64);
        let cfg = dot_resolver_cfg(vec![&valid_pin]);
        let mut opts = ResolverOpts::default();
        apply_tls_pinning(&mut opts, &cfg);
        // A custom verifier was installed — the default WebPKI-backed
        // ClientConfig's Debug output differs from a config built with
        // `.dangerous().with_custom_certificate_verifier(...)`. We can't
        // easily downcast the trait object, so assert indirectly: building
        // still succeeds end to end.
        assert!(build_hickory_resolver(&cfg, 5000, false).is_some());
    }

    #[test]
    fn build_hickory_resolver_falls_back_to_webpki_when_every_pin_is_malformed() {
        let cfg = dot_resolver_cfg(vec!["not-a-valid-hex-digest"]);
        // Must not panic or fail to build the resolver just because the
        // configured pin couldn't be parsed — falls back to normal trust.
        assert!(build_hickory_resolver(&cfg, 5000, false).is_some());
    }

    #[test]
    fn build_hickory_resolver_ignores_pins_for_non_tls_protocol() {
        // Pinning only makes sense for TLS-based protocols (dot/doh) —
        // do53 has no certificate to pin at all.
        let mut cfg = dot_resolver_cfg(vec![&"a".repeat(64)]);
        cfg.protocol = "do53".into();
        assert!(build_hickory_resolver(&cfg, 5000, false).is_some());
    }

    // ── pick_member ───────────────────────────────────────────────────────────

    fn member(id: &str, weight: u32, priority: u32) -> PoolMember {
        PoolMember { resolver_id: id.into(), weight, priority }
    }

    fn pool_with(strategy: &str, members: Vec<PoolMember>) -> PoolConfig {
        PoolConfig {
            id: "p1".into(),
            strategy: strategy.into(),
            members,
            health_check_interval_s: 30,
            health_check_timeout_ms: 2000,
            health_check_query: ".".into(),
            health_check_type: "soa".into(),
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            fallback_pool_id: None,
            min_healthy_members: 1,
        }
    }

    fn all_healthy(pool: &PoolConfig) -> Vec<String> {
        pool.members.iter().map(|m| m.resolver_id.clone()).collect()
    }

    #[test]
    fn pick_member_returns_none_when_no_members_are_healthy() {
        let pool = pool_with("round_robin", vec![member("a", 1, 0)]);
        let health = HealthStore::empty();
        let rr = RoundRobinState::default();
        assert!(pick_member("p1", &pool, &[], &health, &rr).is_none());
    }

    #[test]
    fn pick_member_round_robin_cycles_through_every_healthy_member() {
        // Regression test: the old implementation used `.find(...)`, which
        // deterministically returns the same (first) member on every call —
        // "round_robin" never actually rotated.
        let pool = pool_with("round_robin", vec![member("a", 1, 0), member("b", 1, 0), member("c", 1, 0)]);
        let healthy = all_healthy(&pool);
        let health = HealthStore::empty();
        let rr = RoundRobinState::default();

        let picks: Vec<&str> = (0..6)
            .map(|_| pick_member("p1", &pool, &healthy, &health, &rr).unwrap())
            .collect();

        assert_eq!(picks, vec!["a", "b", "c", "a", "b", "c"]);
    }

    #[test]
    fn pick_member_round_robin_skips_unhealthy_members() {
        let pool = pool_with("round_robin", vec![member("a", 1, 0), member("b", 1, 0), member("c", 1, 0)]);
        let healthy = vec!["a".to_string(), "c".to_string()]; // "b" is unhealthy
        let health = HealthStore::empty();
        let rr = RoundRobinState::default();

        let picks: Vec<&str> = (0..4)
            .map(|_| pick_member("p1", &pool, &healthy, &health, &rr).unwrap())
            .collect();

        assert_eq!(picks, vec!["a", "c", "a", "c"]);
    }

    #[test]
    fn pick_member_weighted_round_robin_distributes_proportional_to_weight() {
        // Regression test: the old implementation used `.max_by_key(weight)`,
        // which deterministically returns the same highest-weight member on
        // every call — no actual weighted *distribution* ever happened.
        let pool = pool_with("weighted_round_robin", vec![member("a", 3, 0), member("b", 1, 0)]);
        let healthy = all_healthy(&pool);
        let health = HealthStore::empty();
        let rr = RoundRobinState::default();

        let picks: Vec<&str> = (0..8)
            .map(|_| pick_member("p1", &pool, &healthy, &health, &rr).unwrap())
            .collect();

        let a_count = picks.iter().filter(|&&p| p == "a").count();
        let b_count = picks.iter().filter(|&&p| p == "b").count();
        // Over two full 4-call cycles (total_weight=4): "a" (weight 3) picked
        // 6 times, "b" (weight 1) picked 2 times — exactly proportional.
        assert_eq!((a_count, b_count), (6, 2));
    }

    #[test]
    fn pick_member_failover_always_picks_lowest_priority_healthy_member() {
        let pool = pool_with("failover", vec![member("primary", 1, 0), member("backup", 1, 10)]);
        let healthy = all_healthy(&pool);
        let health = HealthStore::empty();
        let rr = RoundRobinState::default();

        for _ in 0..3 {
            assert_eq!(pick_member("p1", &pool, &healthy, &health, &rr), Some("primary"));
        }
    }

    #[test]
    fn pick_member_failover_falls_back_when_primary_is_unhealthy() {
        let pool = pool_with("failover", vec![member("primary", 1, 0), member("backup", 1, 10)]);
        let healthy = vec!["backup".to_string()];
        let health = HealthStore::empty();
        let rr = RoundRobinState::default();
        assert_eq!(pick_member("p1", &pool, &healthy, &health, &rr), Some("backup"));
    }

    #[test]
    fn pick_member_latency_picks_the_lowest_measured_latency() {
        let pool = pool_with("latency", vec![member("slow", 1, 0), member("fast", 1, 0)]);
        let healthy = all_healthy(&pool);
        let health = HealthStore::empty();
        health.update("p1", "slow", MemberHealthSnapshot { healthy: true, latency_ema_us: 50_000, consecutive_failures: 0, consecutive_successes: 1 });
        health.update("p1", "fast", MemberHealthSnapshot { healthy: true, latency_ema_us: 5_000, consecutive_failures: 0, consecutive_successes: 1 });
        let rr = RoundRobinState::default();

        assert_eq!(pick_member("p1", &pool, &healthy, &health, &rr), Some("fast"));
    }

    #[test]
    fn round_robin_state_tracks_pools_independently() {
        let rr = RoundRobinState::default();
        assert_eq!(rr.next("pool-a"), 0);
        assert_eq!(rr.next("pool-a"), 1);
        assert_eq!(rr.next("pool-b"), 0, "pool-b must have its own independent cursor");
        assert_eq!(rr.next("pool-a"), 2);
    }
}
