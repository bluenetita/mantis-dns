//! Aegis filter node entrypoint.
//! Sprint 1 scope: process boots, logs, ready to load a bundle. No DNS listener yet (Sprint 3).

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("aegis-filter starting (skeleton, no DNS listener yet)");

    // TODO(sprint 2): load + verify a signed Bundle from disk/control-plane.
    // TODO(sprint 3): bind UDP/TCP DNS listener via tokio, wire policy lookup into request path.

    Ok(())
}
