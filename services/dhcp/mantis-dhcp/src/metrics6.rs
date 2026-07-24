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

//! DHCPv6 counterpart of `metrics.rs` — separate `Counters`/listener since
//! this is a separate process (`bin/mantis-dhcp6.rs`) with its own opt-in
//! bind address (`MANTIS_DHCP6_METRICS_BIND_ADDR`).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::Router;
use dhcproto::v6::MessageType;
use sqlx::PgPool;
use tokio::net::TcpListener;

#[derive(Default)]
pub struct Counters {
    solicit: AtomicU64,
    advertise: AtomicU64,
    request: AtomicU64,
    renew: AtomicU64,
    rebind: AtomicU64,
    reply: AtomicU64,
    release: AtomicU64,
    decline: AtomicU64,
    information_request: AtomicU64,
    confirm: AtomicU64,
}

impl Counters {
    pub fn record(&self, mtype: MessageType) {
        let counter = match mtype {
            MessageType::Solicit => &self.solicit,
            MessageType::Advertise => &self.advertise,
            MessageType::Request => &self.request,
            MessageType::Renew => &self.renew,
            MessageType::Rebind => &self.rebind,
            MessageType::Reply => &self.reply,
            MessageType::Release => &self.release,
            MessageType::Decline => &self.decline,
            MessageType::InformationRequest => &self.information_request,
            MessageType::Confirm => &self.confirm,
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
    tracing::info!("mantis-dhcp6 metrics listener bound on {bind_addr}");
    let app = Router::new().route("/metrics", get(handle)).with_state(AppState { counters, pool });
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle(State(state): State<AppState>) -> String {
    let mut out = String::new();
    let c = &state.counters;
    push_counter(&mut out, "dhcp6_solicit_total", "SOLICIT packets received", c.solicit.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp6_advertise_total", "ADVERTISE replies sent", c.advertise.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp6_request_total", "REQUEST packets received", c.request.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp6_renew_total", "RENEW packets received", c.renew.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp6_rebind_total", "REBIND packets received", c.rebind.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp6_reply_total", "REPLY messages sent", c.reply.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp6_release_total", "RELEASE packets received", c.release.load(Ordering::Relaxed));
    push_counter(&mut out, "dhcp6_decline_total", "DECLINE packets received", c.decline.load(Ordering::Relaxed));
    push_counter(
        &mut out,
        "dhcp6_information_request_total",
        "INFORMATION-REQUEST packets received",
        c.information_request.load(Ordering::Relaxed),
    );
    push_counter(&mut out, "dhcp6_confirm_total", "CONFIRM packets received", c.confirm.load(Ordering::Relaxed));

    match crate::db6::scope_utilization6(&state.pool).await {
        Ok(rows) => {
            out.push_str("# HELP dhcp6_pool_assigned_na Active IA_NA leases in a scope\n");
            out.push_str("# TYPE dhcp6_pool_assigned_na gauge\n");
            for r in &rows {
                out.push_str(&format!(
                    "dhcp6_pool_assigned_na{{scope_id=\"{}\",scope_name=\"{}\"}} {}\n",
                    escape(&r.scope_id), escape(&r.scope_name), r.assigned_na
                ));
            }
            out.push_str("# HELP dhcp6_pool_assigned_pd Active IA_PD delegations in a scope (0 or 1 -- see db6.rs)\n");
            out.push_str("# TYPE dhcp6_pool_assigned_pd gauge\n");
            for r in &rows {
                out.push_str(&format!(
                    "dhcp6_pool_assigned_pd{{scope_id=\"{}\",scope_name=\"{}\"}} {}\n",
                    escape(&r.scope_id), escape(&r.scope_name), r.assigned_pd
                ));
            }
            out.push_str("# HELP dhcp6_pool_declined Declined addresses in a scope\n");
            out.push_str("# TYPE dhcp6_pool_declined gauge\n");
            for r in &rows {
                out.push_str(&format!(
                    "dhcp6_pool_declined{{scope_id=\"{}\",scope_name=\"{}\"}} {}\n",
                    escape(&r.scope_id), escape(&r.scope_name), r.declined
                ));
            }
        }
        Err(e) => tracing::warn!("metrics6: failed to load scope utilisation: {e}"),
    }

    match crate::db::ddns_retry_queue_depth(&state.pool).await {
        Ok(depth) => push_gauge(&mut out, "dhcp_ddns_retry_queue_depth", "Undelivered DDNS events awaiting retry (shared v4/v6 queue)", depth),
        Err(e) => tracing::warn!("metrics6: failed to load ddns retry queue depth: {e}"),
    }

    out
}

fn push_counter(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"));
}

fn push_gauge(out: &mut String, name: &str, help: &str, value: i64) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"));
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_increments_the_matching_counter_only() {
        let c = Counters::default();
        c.record(MessageType::Solicit);
        c.record(MessageType::Solicit);
        c.record(MessageType::Reply);
        assert_eq!(c.solicit.load(Ordering::Relaxed), 2);
        assert_eq!(c.reply.load(Ordering::Relaxed), 1);
        assert_eq!(c.advertise.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn record_ignores_message_types_with_no_counter() {
        let c = Counters::default();
        c.record(MessageType::Unknown(255));
        assert_eq!(c.solicit.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn escape_handles_quotes_backslashes_and_newlines() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape(r#"has "quotes""#), r#"has \"quotes\""#);
    }

    /// End-to-end: a real listener on an ephemeral port, a real Postgres
    /// query behind it, fetched over a real HTTP client.
    #[tokio::test]
    async fn metrics_endpoint_serves_counters_and_db_backed_gauges() {
        let db_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:15432/test".to_string());
        let pool = PgPool::connect(&db_url).await.expect("connect to TEST_DATABASE_URL");

        let counters = Arc::new(Counters::default());
        counters.record(MessageType::Solicit);
        counters.record(MessageType::Reply);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/metrics", get(handle)).with_state(AppState { counters, pool });
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let body = reqwest::get(format!("http://{addr}/metrics")).await.unwrap().text().await.unwrap();
        assert!(body.contains("dhcp6_solicit_total 1"));
        assert!(body.contains("dhcp6_reply_total 1"));
        assert!(body.contains("dhcp6_advertise_total 0"));
        assert!(body.contains("# TYPE dhcp6_pool_assigned_na gauge"));
        assert!(body.contains("dhcp_ddns_retry_queue_depth"));
    }
}
