//! Prometheus metrics exporter. Named `metrics_init` (not `metrics`) to avoid
//! shadowing the `metrics` crate within this module.

use std::net::SocketAddr;

/// Starts the Prometheus HTTP exporter (`/metrics` on `bind_addr`). Call once
/// at startup before any `metrics::counter!`/`histogram!` calls — those are
/// no-ops until a recorder is installed.
pub fn install(bind_addr: SocketAddr) -> anyhow::Result<()> {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(bind_addr)
        .install()?;
    Ok(())
}
