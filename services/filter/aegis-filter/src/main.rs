use std::env;
use std::sync::Arc;
use std::time::Duration;

use aegis_filter::{
    bundle_refresh_loop, fetch_public_key, fetch_upstream_bundle, refresh_bundle,
    run_health_monitor, run_router_udp_server, run_udp_server, upstream_bundle_refresh_loop,
    AppState, HealthStore, TelemetryEmitter, TenantRouter, UpstreamBundleForwarder,
    UpstreamBundleStore,
};
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

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

    info!("aegis-filter starting: control_url={control_url} group_id={group_id} bind={bind_addr}");

    let public_key = match fetch_public_key(&control_url).await {
        Ok(k) => k,
        Err(e) => {
            error!("could not fetch control plane public key at startup: {e}");
            return Err(e);
        }
    };

    let socket = UdpSocket::bind(&bind_addr).await?;

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
    tokio::spawn(upstream_bundle_refresh_loop(
        upstream_store.clone(),
        control_url.clone(),
        upstream_tenant,
        public_key,
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
        tokio::spawn(bundle_refresh_loop(
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
        run_udp_server(socket, state).await?;
    } else {
        // Multi-tenant mode (design.md §7.3 option 2): tenant resolved by
        // source IP against a routing table fetched from the control plane.
        info!("GROUP_ID not set — running in multi-tenant source-IP routing mode");
        let telemetry = TelemetryEmitter::start(control_url.clone(), 10_000);
        let router = Arc::new(
            TenantRouter::new(public_key, forwarder).with_telemetry(telemetry),
        );
        if let Err(e) = aegis_filter::refresh_routes(&router, &control_url).await {
            warn!("initial routing table fetch failed (will retry on poll loop): {e}");
        }
        tokio::spawn(aegis_filter::routing_refresh_loop(
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
        run_router_udp_server(socket, router).await?;
    }
    Ok(())
}
