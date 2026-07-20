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

use std::env;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use mantis_filter::{
    bundle_refresh_loop, fetch_and_publish_zone, fetch_public_key, fetch_upstream_bundle,
    refresh_bundle, run_block_page_server, run_health_monitor, run_router_tcp_server,
    run_router_udp_server, run_tcp_server, run_udp_server, upstream_bundle_refresh_loop,
    zone_refresh_loop, AppState, BlockPageBundles, HealthStore, PublicKeyStore, TelemetryEmitter,
    TenantRouter, UpstreamBundleForwarder, UpstreamBundleStore,
};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info, warn};

/// True if `host` never leaves the local machine (loopback IP or the
/// `localhost` name) — the only case where a plain-HTTP control-plane
/// connection isn't exposed to an on-path attacker.
fn is_loopback_host(host: &str) -> bool {
    // url::Url::host_str() returns bracketed IPv6 literals (e.g. "[::1]"),
    // which IpAddr::parse rejects — strip the brackets before parsing.
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    host.eq_ignore_ascii_case("localhost") || bare.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// Assessment of `control_url`'s exposure to an on-path attacker. `None`
/// means the channel is either not plain HTTP or never leaves the local
/// machine, so there's nothing to warn about.
#[derive(Debug, PartialEq, Eq)]
enum ControlChannelRisk {
    /// Plain HTTP to a remote host, but the trust anchor is pinned — bundle
    /// confidentiality is exposed, integrity is not.
    ConfidentialityOnly,
    /// Plain HTTP to a remote host with no pin — trust-on-first-use over a
    /// channel an attacker can rewrite, so the trust anchor itself can be
    /// substituted.
    Unpinned,
}

/// Pure classification, split out from `warn_if_insecure_control_channel` so
/// the logic is unit-testable without capturing log output.
fn assess_control_channel(control_url: &str, pin_configured: bool) -> Option<ControlChannelRisk> {
    let parsed = reqwest::Url::parse(control_url).ok()?;
    if parsed.scheme() != "http" {
        return None;
    }
    if parsed.host_str().map(is_loopback_host).unwrap_or(false) {
        return None;
    }
    Some(if pin_configured {
        ControlChannelRisk::ConfidentialityOnly
    } else {
        ControlChannelRisk::Unpinned
    })
}

/// Warns loudly when `control_url` is plain HTTP to a non-loopback host: the
/// Ed25519 signature check on fetched bundles only proves integrity against
/// *whatever key this filter node currently trusts* — if
/// MANTIS_CONTROL_PUBLIC_KEY_SHA256 isn't pinned, the very first
/// `/public-key` fetch (and every unpinned re-fetch after a rotation, see
/// `refresh_public_key`) is trust-on-first-use over a channel an on-path
/// attacker can read and rewrite, letting them substitute their own key and
/// sign arbitrary policy bundles the filter will accept. Log-only (not a
/// hard failure) since compose/LXC same-host deployments legitimately use
/// unpinned plain HTTP to a loopback-reachable control plane.
fn warn_if_insecure_control_channel(control_url: &str, pin_configured: bool) {
    match assess_control_channel(control_url, pin_configured) {
        None => {}
        Some(ControlChannelRisk::ConfidentialityOnly) => warn!(
            "CONTROL_URL ({control_url}) is plain HTTP to a remote host — an on-path attacker \
             can read every fetched policy bundle. MANTIS_CONTROL_PUBLIC_KEY_SHA256 is set, so \
             the trust anchor itself is protected, but consider HTTPS for confidentiality."
        ),
        Some(ControlChannelRisk::Unpinned) => error!(
            "CONTROL_URL ({control_url}) is plain HTTP to a remote host and \
             MANTIS_CONTROL_PUBLIC_KEY_SHA256 is NOT set — the initial /public-key fetch (and \
             every re-fetch after a key rotation) is trust-on-first-use over a channel an \
             on-path attacker can rewrite, letting them substitute their own signing key and \
             forge policy bundles this node will accept. Set MANTIS_CONTROL_PUBLIC_KEY_SHA256 \
             or use HTTPS before running this in production."
        ),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let control_url =
        env::var("CONTROL_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());
    let group_id = env::var("GROUP_ID").unwrap_or_default();
    let bind_addr = env::var("DNS_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:1053".to_string());
    let poll_secs: u64 = env::var("BUNDLE_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    // Opt-in co-hosted block-page HTTP listener (e.g. "0.0.0.0:80"). Only
    // started when set, so deployments that don't use REDIRECT block mode —
    // or can't bind a privileged port — are unaffected.
    let block_page_addr = env::var("BLOCKPAGE_BIND_ADDR").ok();

    info!("mantis-filter starting: control_url={control_url} group_id={group_id} bind={bind_addr}");

    let pin_configured = env::var("MANTIS_CONTROL_PUBLIC_KEY_SHA256")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    warn_if_insecure_control_channel(&control_url, pin_configured);

    let public_key = match fetch_public_key(&control_url).await {
        Ok(k) => k,
        Err(e) => {
            error!("could not fetch control plane public key at startup: {e}");
            return Err(e);
        }
    };

    let socket = UdpSocket::bind(&bind_addr).await?;
    let tcp_listener = TcpListener::bind(&bind_addr).await?;

    const CACHE_PURGE_INTERVAL: Duration = Duration::from_secs(60);

    // Build an upstream bundle store shared across both single-tenant and
    // multi-tenant modes. The bundle refreshes on the same poll interval as
    // policy bundles. In multi-tenant mode there is no tenant-specific upstream
    // bundle yet — we use a global default bundle (tenant_id="*") which the
    // control plane generates from global routes. Sprint 18 will make this
    // per-tenant by fetching one bundle per routed tenant.
    let upstream_store = Arc::new(UpstreamBundleStore::empty());
    let upstream_tenant = env::var("UPSTREAM_BUNDLE_TENANT").unwrap_or_else(|_| "*".to_string());

    // Attempt an initial upstream bundle fetch (non-fatal; falls back to
    // UPSTREAM_FALLBACK_ADDRESS env var while the bundle is unavailable).
    match fetch_upstream_bundle(&control_url, &upstream_tenant, &public_key).await {
        Ok(bundle) => upstream_store.publish(bundle),
        Err(e) => warn!("initial upstream bundle fetch failed (will use fallback): {e}"),
    }
    // Own PublicKeyStore for this loop (independent of AppState's/TenantRouter's,
    // which don't exist yet at this point in startup) so a control-plane
    // signing-key rotation doesn't permanently break upstream-bundle
    // verification the way a `VerifyingKey` captured once at startup would —
    // see upstream_bundle_refresh_loop's doc comment.
    let upstream_public_key = Arc::new(PublicKeyStore::new(public_key));
    tokio::spawn(upstream_bundle_refresh_loop(
        upstream_store.clone(),
        control_url.clone(),
        upstream_tenant,
        upstream_public_key,
        Duration::from_secs(poll_secs),
    ));

    // Health monitor: probes each pool member, drives the healthy-member set
    // consumed by UpstreamBundleForwarder when picking a resolver per query.
    let health_store = HealthStore::empty();
    tokio::spawn(run_health_monitor(
        upstream_store.clone(),
        health_store.clone(),
    ));

    let forwarder = Box::new(UpstreamBundleForwarder::new(upstream_store, health_store));

    if !group_id.is_empty() {
        // Legacy single-tenant mode: one GROUP_ID, one bundle. Kept for
        // back-compat with existing deployments; new multi-tenant deployments
        // should leave GROUP_ID unset to use the source-IP router below.
        let telemetry = TelemetryEmitter::start(control_url.clone(), 10_000);
        let state = Arc::new(
            AppState::with_forwarder(public_key, forwarder).with_telemetry(telemetry),
        );
        if let Err(e) = refresh_bundle(&state, &control_url, &group_id).await {
            warn!("initial bundle fetch failed (will retry on poll loop): {e}");
        }
        if let Err(e) = fetch_and_publish_zone(&state.zones, &control_url, &group_id).await {
            warn!("initial local zone fetch failed (will retry on poll loop): {e}");
        }
        if let Some(addr) = &block_page_addr {
            spawn_block_page(addr, BlockPageBundles::Single(state.clone()), control_url.clone())
                .await;
        }
        tokio::spawn(bundle_refresh_loop(
            state.clone(),
            control_url.clone(),
            group_id.clone(),
            Duration::from_secs(poll_secs),
        ));
        tokio::spawn(zone_refresh_loop(
            state.clone(),
            control_url,
            group_id,
            Duration::from_secs(poll_secs),
        ));
        let state_purge = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(CACHE_PURGE_INTERVAL);
            loop {
                ticker.tick().await;
                state_purge.purge_cache();
            }
        });
        let state_tcp = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_tcp_server(tcp_listener, state_tcp).await {
                error!("TCP DNS server exited: {e}");
            }
        });
        run_udp_server(socket, state).await?;
    } else {
        // Multi-tenant mode (design.md §7.3 option 2): tenant resolved by
        // source IP against a routing table fetched from the control plane.
        info!("GROUP_ID not set — running in multi-tenant source-IP routing mode");
        let telemetry = TelemetryEmitter::start(control_url.clone(), 10_000);
        let router = Arc::new(
            TenantRouter::new(public_key, forwarder).with_telemetry(telemetry),
        );
        if let Err(e) = mantis_filter::refresh_routes(&router, &control_url).await {
            warn!("initial routing table fetch failed (will retry on poll loop): {e}");
        }
        if let Some(addr) = &block_page_addr {
            spawn_block_page(addr, BlockPageBundles::Multi(router.clone()), control_url.clone())
                .await;
        }
        tokio::spawn(mantis_filter::routing_refresh_loop(
            router.clone(),
            control_url,
            Duration::from_secs(poll_secs),
        ));
        let router_purge = router.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(CACHE_PURGE_INTERVAL);
            loop {
                ticker.tick().await;
                router_purge.purge_cache();
            }
        });
        let router_tcp = router.clone();
        tokio::spawn(async move {
            if let Err(e) = run_router_tcp_server(tcp_listener, router_tcp).await {
                error!("TCP DNS router exited: {e}");
            }
        });
        run_router_udp_server(socket, router).await?;
    }
    Ok(())
}

/// Binds the block-page HTTP listener and spawns it as a background task. A
/// bind failure (e.g. port 80 without privileges) is logged but non-fatal:
/// DNS serving continues, only the block page is unavailable.
async fn spawn_block_page(addr: &str, bundles: BlockPageBundles, control_url: String) {
    match TcpListener::bind(addr).await {
        Ok(listener) => {
            tokio::spawn(async move {
                if let Err(e) = run_block_page_server(listener, bundles, control_url).await {
                    error!("block-page HTTP server exited: {e}");
                }
            });
        }
        Err(e) => error!("failed to bind block-page listener on {addr}: {e}"),
    }
}

#[cfg(test)]
mod control_channel_risk_tests {
    use super::*;

    #[test]
    fn loopback_ip_is_never_flagged() {
        assert_eq!(assess_control_channel("http://127.0.0.1:8000", false), None);
        assert_eq!(assess_control_channel("http://[::1]:8000", false), None);
    }

    #[test]
    fn localhost_name_is_never_flagged() {
        assert_eq!(assess_control_channel("http://localhost:8000", false), None);
        assert_eq!(assess_control_channel("http://LOCALHOST:8000", false), None);
    }

    #[test]
    fn https_is_never_flagged_regardless_of_pin() {
        assert_eq!(
            assess_control_channel("https://control.example.internal", false),
            None
        );
    }

    #[test]
    fn plain_http_to_remote_host_without_pin_is_unpinned_risk() {
        assert_eq!(
            assess_control_channel("http://control.example.internal", false),
            Some(ControlChannelRisk::Unpinned)
        );
    }

    #[test]
    fn plain_http_to_remote_host_with_pin_is_confidentiality_only() {
        assert_eq!(
            assess_control_channel("http://control.example.internal", true),
            Some(ControlChannelRisk::ConfidentialityOnly)
        );
    }

    #[test]
    fn plain_http_to_remote_ip_without_pin_is_unpinned_risk() {
        assert_eq!(
            assess_control_channel("http://203.0.113.5:8000", false),
            Some(ControlChannelRisk::Unpinned)
        );
    }

    #[test]
    fn unparseable_url_is_not_flagged() {
        assert_eq!(assess_control_channel("not a url", false), None);
    }
}
