// Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Prometheus text-exposition `/metrics` endpoint (design.md §22.11). Opt-in
//! (`MANTIS_DHCP_METRICS_BIND_ADDR`, blank = disabled by default) — same
//! convention as mantis-filter's `BLOCKPAGE_BIND_ADDR`, since not every
//! deployment runs a scraper.
//!
//! DORA packet counters live in-process (`Counters`, incremented directly in
//! server.rs's dispatch — no lock contention on the packet-handling hot
//! path, just relaxed atomics). Pool utilisation and DDNS retry-queue depth
//! are queried from Postgres at scrape time instead of tracked in-process —
//! they're already `dhcp_leases`/`dhcp_ddns_retries` aggregates, so scrape
//! time (every 15-30s, typically) is the natural place to compute them
//! rather than keeping a second, driftable copy in memory.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::Router;
use dhcproto::v4::MessageType;
use sqlx::PgPool;
use tokio::net::TcpListener;

#[derive(Default)]
pub struct Counters {
    discover: AtomicU64,
    offer: AtomicU64,
    request: AtomicU64,
    ack: AtomicU64,
    nak: AtomicU64,
    release: AtomicU64,
    decline: AtomicU64,
    inform: AtomicU64,
}

impl Counters {
    pub fn record(&self, mtype: MessageType) {
        let counter = match mtype {
            MessageType::Discover => &self.discover,
            MessageType::Offer => &self.offer,
            MessageType::Request => &self.request,
            MessageType::Ack => &self.ack,
            MessageType::Nak => &self.nak,
            MessageType::Release => &self.release,
            MessageType::Decline => &self.decline,
            MessageType::Inform => &self.inform,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct AppState {
    counters: Arc<Counters>,
    pool: PgPool,
}

pub async fn serve(bind_addr: SocketAddr, counters: Arc<Counters>, pool: PgPool) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!("mantis-dhcp metrics listener bound on {bind_addr}");
    let app = Router::new().route("/metrics", get(handle)).with_state(AppState { counters, pool });
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle(State(state): State<AppState>) -> String {
    let mut out = String::new();
    let c = &state.counters;
    push_counter(&mut out, "dhcp_discover_total", "DHCPDISCOVER packets received", c.discover.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp_offer_total", "DHCPOFFER replies sent", c.offer.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp_request_total", "DHCPREQUEST packets received", c.request.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp_ack_total", "DHCPACK replies sent", c.ack.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp_nak_total", "DHCPNAK replies sent", c.nak.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp_release_total", "DHCPRELEASE packets received", c.release.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp_decline_total", "DHCPDECLINE packets received", c.decline.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp_inform_total", "DHCPINFORM packets received", c.inform.load(Ordering::Relaxed));

    match crate::db::scope_utilization(&state.pool).await {
        Ok(rows) => {
            out.push_str("# HELP dhcp_pool_assigned Active leases in a scope's pool\n");
            out.push_str("# TYPE dhcp_pool_assigned gauge\n");
            for r in &rows {
                out.push_str(&format!(
                    "dhcp_pool_assigned{{scope_id=\"{}\",scope_name=\"{}\"}} {}\n",
                    escape(&r.scope_id), escape(&r.scope_name), r.assigned
                ));
            }
            out.push_str("# HELP dhcp_pool_declined Declined (conflict) addresses in a scope's pool\n");
            out.push_str("# TYPE dhcp_pool_declined gauge\n");
            for r in &rows {
                out.push_str(&format!(
                    "dhcp_pool_declined{{scope_id=\"{}\",scope_name=\"{}\"}} {}\n",
                    escape(&r.scope_id), escape(&r.scope_name), r.declined
                ));
            }
        }
        Err(e) => tracing::warn!("metrics: failed to load scope utilisation: {e}"),
    }

    match crate::db::ddns_retry_queue_depth(&state.pool).await {
        Ok(depth) => push_gauge(&mut out, "dhcp_ddns_retry_queue_depth", "Undelivered DDNS events awaiting retry", depth),
        Err(e) => tracing::warn!("metrics: failed to load ddns retry queue depth: {e}"),
    }

    out
}

fn push_counter(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"));
}

fn push_gauge(out: &mut String, name: &str, help: &str, value: i64) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"));
}

/// Prometheus label values must escape backslash, double-quote, and newline.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_increments_the_matching_counter_only() {
        let c = Counters::default();
        c.record(MessageType::Discover);
        c.record(MessageType::Discover);
        c.record(MessageType::Ack);
        assert_eq!(c.discover.load(Ordering::Relaxed), 2);
        assert_eq!(c.ack.load(Ordering::Relaxed), 1);
        assert_eq!(c.offer.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn record_ignores_message_types_with_no_counter() {
        let c = Counters::default();
        c.record(MessageType::Unknown(255));
        assert_eq!(c.discover.load(Ordering::Relaxed), 0);
        assert_eq!(c.ack.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn escape_handles_quotes_backslashes_and_newlines() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape(r#"has "quotes""#), r#"has \"quotes\""#);
        assert_eq!(escape("back\\slash"), "back\\\\slash");
        assert_eq!(escape("line\nbreak"), "line\\nbreak");
    }

    /// End-to-end: a real listener on an ephemeral port, a real Postgres
    /// query behind it, fetched over a real HTTP client — not just the
    /// string-formatting pieces above.
    #[tokio::test]
    async fn metrics_endpoint_serves_counters_and_db_backed_gauges() {
        let db_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:15432/test".to_string());
        let pool = PgPool::connect(&db_url).await.expect("connect to TEST_DATABASE_URL");

        let counters = Arc::new(Counters::default());
        counters.record(MessageType::Discover);
        counters.record(MessageType::Ack);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/metrics", get(handle)).with_state(AppState { counters, pool });
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let body = reqwest::get(format!("http://{addr}/metrics")).await.unwrap().text().await.unwrap();
        assert!(body.contains("dhcp_discover_total 1"));
        assert!(body.contains("dhcp_ack_total 1"));
        assert!(body.contains("dhcp_offer_total 0"));
        assert!(body.contains("# TYPE dhcp_pool_assigned gauge"));
        assert!(body.contains("dhcp_ddns_retry_queue_depth"));
    }
}
