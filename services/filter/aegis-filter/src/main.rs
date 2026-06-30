use std::env;
use std::sync::Arc;
use std::time::Duration;

use aegis_filter::{
    bundle_refresh_loop, fetch_public_key, refresh_bundle, run_router_udp_server, run_udp_server,
    AppState, DotForwarder, TelemetryEmitter, TenantRouter,
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
    let metrics_bind_addr = env::var("METRICS_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:9090".to_string());
    let poll_secs: u64 = env::var("BUNDLE_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    info!("aegis-filter starting: control_url={control_url} group_id={group_id} bind={bind_addr}");

    aegis_filter::metrics_init::install(metrics_bind_addr.parse()?)?;
    info!("metrics exporter listening on {metrics_bind_addr}/metrics");

    let public_key = match fetch_public_key(&control_url).await {
        Ok(k) => k,
        Err(e) => {
            error!("could not fetch control plane public key at startup: {e}");
            return Err(e);
        }
    };

    let socket = UdpSocket::bind(&bind_addr).await?;

    if !group_id.is_empty() {
        // Legacy single-tenant mode: one GROUP_ID, one bundle. Kept for
        // back-compat with existing deployments; new multi-tenant deployments
        // should leave GROUP_ID unset to use the source-IP router below.
        let telemetry = TelemetryEmitter::start(control_url.clone(), 10_000);
        let state = Arc::new(AppState::new(public_key).with_telemetry(telemetry));
        if let Err(e) = refresh_bundle(&state, &control_url, &group_id).await {
            warn!("initial bundle fetch failed (will retry on poll loop): {e}");
        }
        tokio::spawn(bundle_refresh_loop(
            state.clone(),
            control_url,
            group_id,
            Duration::from_secs(poll_secs),
        ));
        run_udp_server(socket, state).await?;
    } else {
        // Multi-tenant mode (design.md §7.3 option 2): tenant resolved by
        // source IP against a routing table fetched from the control plane.
        info!("GROUP_ID not set — running in multi-tenant source-IP routing mode");
        let telemetry = TelemetryEmitter::start(control_url.clone(), 10_000);
        let router = Arc::new(
            TenantRouter::new(public_key, Box::new(DotForwarder::new_default()))
                .with_telemetry(telemetry),
        );
        if let Err(e) = aegis_filter::refresh_routes(&router, &control_url).await {
            warn!("initial routing table fetch failed (will retry on poll loop): {e}");
        }
        tokio::spawn(aegis_filter::routing_refresh_loop(
            router.clone(),
            control_url,
            Duration::from_secs(poll_secs),
        ));
        run_router_udp_server(socket, router).await?;
    }
    Ok(())
}
