use std::env;
use std::sync::Arc;
use std::time::Duration;

use aegis_filter::{bundle_refresh_loop, fetch_public_key, refresh_bundle, run_udp_server, AppState};
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

    let state = Arc::new(AppState::new(public_key));

    if !group_id.is_empty() {
        if let Err(e) = refresh_bundle(&state, &control_url, &group_id).await {
            warn!("initial bundle fetch failed (will retry on poll loop): {e}");
        }
        tokio::spawn(bundle_refresh_loop(
            state.clone(),
            control_url,
            group_id,
            Duration::from_secs(poll_secs),
        ));
    } else {
        warn!("GROUP_ID not set — node will serve with no policy bundle (fail-open ServFail for now)");
    }

    let socket = UdpSocket::bind(&bind_addr).await?;
    run_udp_server(socket, state).await?;
    Ok(())
}
