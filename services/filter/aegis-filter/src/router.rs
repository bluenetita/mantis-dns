//! Multi-tenant source-IP routing (design.md §7.3 option 2, "pattern A" from
//! the OpenVPN AS/CE integration discussion). One shared UDP listener; the
//! peer's source IP is matched against a routing table (fetched from the
//! control plane) to pick which tenant's `BundleStore` answers the query.
//! Cache and forwarder are shared across all tenants — only the block
//! decision differs per tenant, not upstream resolution.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use aegis_bundle::BundleStore;
use anyhow::Result;
use arc_swap::ArcSwap;
use ed25519_dalek::VerifyingKey;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use ipnet::IpNet;
use serde::Deserialize;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::{build_response, cache::DnsCache, fetch_and_publish_bundle, Forwarder, TelemetryEmitter};

#[derive(Deserialize)]
struct RoutingTableEntry {
    cidr: String,
    group_id: String,
}

#[derive(Clone)]
struct RouteEntry {
    net: IpNet,
    group_id: String,
    store: Arc<BundleStore>,
}

pub struct TenantRouter {
    public_key: VerifyingKey,
    cache: DnsCache,
    forwarder: Box<dyn Forwarder>,
    routes: ArcSwap<Vec<RouteEntry>>,
    telemetry: TelemetryEmitter,
}

impl TenantRouter {
    pub fn new(public_key: VerifyingKey, forwarder: Box<dyn Forwarder>) -> Self {
        Self {
            public_key,
            cache: DnsCache::new(10_000),
            forwarder,
            routes: ArcSwap::from_pointee(Vec::new()),
            telemetry: TelemetryEmitter::noop(),
        }
    }

    pub fn with_telemetry(mut self, telemetry: TelemetryEmitter) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// Longest-prefix match: the most specific matching subnet wins, so a
    /// /24 override inside a routed /16 (if that ever happens) behaves as
    /// expected rather than being order-dependent.
    fn match_route(&self, ip: IpAddr) -> Option<Arc<BundleStore>> {
        let routes = self.routes.load();
        routes
            .iter()
            .filter(|r| r.net.contains(&ip))
            .max_by_key(|r| r.net.prefix_len())
            .map(|r| r.store.clone())
    }

    pub fn route_count(&self) -> usize {
        self.routes.load().len()
    }
}

async fn fetch_routing_table(control_url: &str) -> Result<Vec<RoutingTableEntry>> {
    let resp = reqwest::get(format!("{control_url}/api/v1/routing-table"))
        .await?
        .error_for_status()?;
    Ok(resp.json().await?)
}

/// Refreshes the routing table and, for every routed group, fetches its
/// latest bundle. Existing `BundleStore`s are reused across refreshes so a
/// group's policy history (version monotonicity) survives a routing-table
/// reload — only genuinely new groups get a fresh empty store.
pub async fn refresh_routes(router: &TenantRouter, control_url: &str) -> Result<()> {
    let entries = fetch_routing_table(control_url).await?;

    let existing = router.routes.load();
    let mut new_routes = Vec::with_capacity(entries.len());

    for entry in &entries {
        let net: IpNet = match entry.cidr.parse() {
            Ok(n) => n,
            Err(e) => {
                warn!("skipping routing-table entry with invalid CIDR '{}': {e}", entry.cidr);
                continue;
            }
        };
        let store = existing
            .iter()
            .find(|r| r.group_id == entry.group_id)
            .map(|r| r.store.clone())
            .unwrap_or_else(|| Arc::new(BundleStore::empty()));
        new_routes.push(RouteEntry {
            net,
            group_id: entry.group_id.clone(),
            store,
        });
    }

    let route_count = new_routes.len();
    router.routes.store(Arc::new(new_routes));
    debug!("routing table refreshed: {route_count} routes");

    // Refresh each routed group's bundle. Sequential is fine at expected
    // group-count scale (tens, not thousands); parallelize if that changes.
    let routes = router.routes.load();
    for route in routes.iter() {
        if let Err(e) =
            fetch_and_publish_bundle(&route.store, &router.public_key, control_url, &route.group_id).await
        {
            warn!("bundle refresh failed for group {}: {e}", route.group_id);
        }
    }

    Ok(())
}

pub async fn routing_refresh_loop(router: Arc<TenantRouter>, control_url: String, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        if let Err(e) = refresh_routes(&router, &control_url).await {
            warn!("routing table refresh failed: {e}");
        }
    }
}

/// Test-only helpers for injecting routes without a real control-plane HTTP
/// round trip. Exposed plainly (not `#[cfg(test)]`) because integration tests
/// under `tests/` link this crate as a normal dependency, where `cfg(test)`
/// from the lib's own build doesn't apply.
#[doc(hidden)]
pub mod test_support {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    pub fn inject_route(
        router: &TenantRouter,
        net: IpNet,
        group_id: &str,
        bundle: aegis_bundle::Bundle,
        public_key: &VerifyingKey,
    ) {
        let store = Arc::new(BundleStore::empty());
        store
            .try_publish(bundle, public_key)
            .expect("test bundle must verify");
        let mut routes: Vec<RouteEntry> = (**router.routes.load()).clone();
        routes.push(RouteEntry {
            net,
            group_id: group_id.to_string(),
            store,
        });
        router.routes.store(Arc::new(routes));
    }
}

/// Binds a single shared UDP DNS listener and routes each query to the
/// tenant matching the peer's source IP.
pub async fn run_router_udp_server(socket: UdpSocket, router: Arc<TenantRouter>) -> Result<()> {
    let local_addr = socket.local_addr()?;
    info!("aegis-filter multi-tenant DNS listener bound on {local_addr}");
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

        let bundle_store = router.match_route(peer.ip());
        if bundle_store.is_none() {
            debug!("no tenant route matched source IP {}", peer.ip());
        }
        let bundle = bundle_store.as_ref().and_then(|s| s.current());

        let response = build_response(
            &query,
            bundle.as_deref(),
            &router.cache,
            router.forwarder.as_ref(),
            &router.telemetry,
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
