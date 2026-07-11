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

//! Multi-tenant source-IP routing (design.md §7.3 option 2, "pattern A" from
//! the OpenVPN AS/CE integration discussion). One shared UDP listener; the
//! peer's source IP is matched against a routing table (fetched from the
//! control plane) to pick which tenant's `BundleStore` answers the query.
//! Cache and forwarder are shared across all tenants — only the block
//! decision differs per tenant, not upstream resolution.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use mantis_bundle::BundleStore;
use anyhow::Result;
use arc_swap::ArcSwap;
use ed25519_dalek::VerifyingKey;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use ipnet::IpNet;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

use crate::zone_store::fetch_and_publish_zone;
use crate::{
    build_response, cache::DnsCache, fetch_and_publish_bundle, refresh_public_key, Forwarder,
    PublicKeyStore, TelemetryEmitter, ZoneStore,
};

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
    zones: Arc<ZoneStore>,
}

pub struct TenantRouter {
    public_key: PublicKeyStore,
    cache: DnsCache,
    forwarder: Box<dyn Forwarder>,
    routes: ArcSwap<Vec<RouteEntry>>,
    telemetry: TelemetryEmitter,
}

impl TenantRouter {
    pub fn new(public_key: VerifyingKey, forwarder: Box<dyn Forwarder>) -> Self {
        Self {
            public_key: PublicKeyStore::new(public_key),
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
    fn match_route(&self, ip: IpAddr) -> Option<(Arc<BundleStore>, Arc<ZoneStore>)> {
        let routes = self.routes.load();
        routes
            .iter()
            .filter(|r| r.net.contains(&ip))
            .max_by_key(|r| r.net.prefix_len())
            .map(|r| (r.store.clone(), r.zones.clone()))
    }

    pub fn route_count(&self) -> usize {
        self.routes.load().len()
    }

    /// Resolves the current policy bundle for a client IP the same way the DNS
    /// path does (longest-prefix source-IP match). Used by the co-hosted
    /// block-page listener so a redirected client sees its own tenant's policy.
    pub fn bundle_for(&self, ip: IpAddr) -> Option<Arc<mantis_bundle::Bundle>> {
        self.match_route(ip).and_then(|(store, _)| store.current())
    }

    pub fn purge_cache(&self) {
        self.cache.purge_expired();
    }
}

async fn fetch_routing_table(control_url: &str) -> Result<Vec<RoutingTableEntry>> {
    let client = reqwest::Client::new();
    let resp = crate::with_service_token(client.get(format!("{control_url}/api/v1/routing-table")))
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json().await?)
}

/// Refreshes the routing table and, for every routed group, fetches its
/// latest bundle. Existing `BundleStore`s are reused across refreshes so a
/// group's policy history (version monotonicity) survives a routing-table
/// reload — only genuinely new groups get a fresh empty store.
pub async fn refresh_routes(router: &TenantRouter, control_url: &str) -> Result<()> {
    if let Err(e) = refresh_public_key(&router.public_key, control_url).await {
        warn!("public key refresh failed (keeping last known good key): {e}");
    }

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
        let zones = existing
            .iter()
            .find(|r| r.group_id == entry.group_id)
            .map(|r| r.zones.clone())
            .unwrap_or_else(|| Arc::new(ZoneStore::empty()));
        new_routes.push(RouteEntry {
            net,
            group_id: entry.group_id.clone(),
            store,
            zones,
        });
    }

    let route_count = new_routes.len();
    router.routes.store(Arc::new(new_routes));
    debug!("routing table refreshed: {route_count} routes");

    // Fetch all groups' bundles and local-zone records concurrently —
    // independent HTTP round-trips.
    let routes = router.routes.load();
    let mut set = tokio::task::JoinSet::new();
    for route in routes.iter() {
        let store = route.store.clone();
        let key = router.public_key.current();
        let url = control_url.to_string();
        let gid = route.group_id.clone();
        set.spawn(async move {
            if let Err(e) = fetch_and_publish_bundle(&store, &key, &url, &gid).await {
                warn!("bundle refresh failed for group {gid}: {e}");
            }
        });

        let zones = route.zones.clone();
        let url = control_url.to_string();
        let gid = route.group_id.clone();
        set.spawn(async move {
            if let Err(e) = fetch_and_publish_zone(&zones, &url, &gid).await {
                warn!("local zone refresh failed for group {gid}: {e}");
            }
        });
    }
    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            warn!("route refresh task panicked: {e}");
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
        bundle: mantis_bundle::Bundle,
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
            zones: Arc::new(ZoneStore::empty()),
        });
        router.routes.store(Arc::new(routes));
    }
}

/// TCP counterpart to `run_router_udp_server` (RFC 1035 §4.2.2).
pub async fn run_router_tcp_server(listener: TcpListener, router: Arc<TenantRouter>) -> Result<()> {
    let local_addr = listener.local_addr()?;
    info!("mantis-filter multi-tenant TCP DNS listener bound on {local_addr}");
    let sem = Arc::new(tokio::sync::Semaphore::new(crate::MAX_TCP_CONNECTIONS));

    loop {
        let (mut stream, peer) = listener.accept().await?;
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!("TCP DNS connection limit reached, dropping {peer}");
                continue;
            }
        };
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            loop {
                let msg_len = match stream.read_u16().await {
                    Ok(n) => n as usize,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => {
                        debug!("TCP read error from {peer}: {e}");
                        break;
                    }
                };
                if msg_len == 0 {
                    break;
                }

                let mut buf = vec![0u8; msg_len];
                if let Err(e) = stream.read_exact(&mut buf).await {
                    debug!("TCP read_exact from {peer}: {e}");
                    break;
                }

                let query = match Message::from_bytes(&buf) {
                    Ok(m) => m,
                    Err(e) => {
                        debug!("unparseable TCP DNS message from {peer}: {e}");
                        break;
                    }
                };

                let matched = router.match_route(peer.ip());
                if matched.is_none() {
                    debug!("no tenant route matched source IP {}", peer.ip());
                }
                let bundle = matched.as_ref().and_then(|(s, _)| s.current());
                let empty_zones = ZoneStore::empty();
                let zones = matched.as_ref().map(|(_, z)| z.as_ref()).unwrap_or(&empty_zones);

                let response = build_response(
                    &query,
                    bundle.as_deref(),
                    zones,
                    peer.ip(),
                    &router.cache,
                    router.forwarder.as_ref(),
                    &router.telemetry,
                )
                .await;

                match response.to_bytes() {
                    Ok(bytes) => {
                        if stream.write_u16(bytes.len() as u16).await.is_err()
                            || stream.write_all(&bytes).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("failed to encode TCP DNS response for {peer}: {e}");
                        break;
                    }
                }
            }
        });
    }
}

/// Binds a single shared UDP DNS listener and routes each query to the
/// tenant matching the peer's source IP. Spawns one task per query, bounded
/// by `MAX_CONCURRENT_UDP_QUERIES` (see lib.rs) — the same fix as
/// `run_udp_server`: a single serial `recv_from` loop that awaits upstream
/// resolution in-line lets a handful of slow/black-holed queries stall DNS
/// service for every tenant sharing this listener.
pub async fn run_router_udp_server(socket: UdpSocket, router: Arc<TenantRouter>) -> Result<()> {
    let local_addr = socket.local_addr()?;
    info!("mantis-filter multi-tenant DNS listener bound on {local_addr}");
    let socket = Arc::new(socket);
    let sem = Arc::new(tokio::sync::Semaphore::new(crate::MAX_CONCURRENT_UDP_QUERIES));
    let empty_zones: Arc<ZoneStore> = Arc::new(ZoneStore::empty());
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

        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!(
                    "UDP concurrency limit ({}) reached, dropping query from {peer}",
                    crate::MAX_CONCURRENT_UDP_QUERIES
                );
                continue;
            }
        };

        let matched = router.match_route(peer.ip());
        if matched.is_none() {
            debug!("no tenant route matched source IP {}", peer.ip());
        }
        let bundle = matched.as_ref().and_then(|(s, _)| s.current());
        let zones = matched.map(|(_, z)| z).unwrap_or_else(|| empty_zones.clone());
        let router = router.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let response = build_response(
                &query,
                bundle.as_deref(),
                &zones,
                peer.ip(),
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
        });
    }
}
