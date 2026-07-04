//! Fire-and-forget query event telemetry. `emit()` is non-blocking (bounded
//! channel, drops on backpressure rather than ever stalling the DNS hot
//! path) — a background task batches and flushes to the control plane.
//!
//! Sprint 14 (design.md §20): events carry enough context (client IP, matched
//! category/feed, latency, cache hit) for the control plane's SIEM export API
//! to hand a consuming SIEM actionable data without post-processing.

use std::time::Duration;

use serde_json::json;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::warn;

/// Everything the control plane's `QueryEvent` row wants, gathered by the
/// caller at the point of decision (see `build_response_inner` in lib.rs).
pub struct QueryEventInput {
    pub group_id: String,
    pub client_ip: String,
    pub qname: String,
    pub qtype: String,
    pub decision: &'static str,
    pub matched_rule: &'static str,
    pub matched_category: Option<String>,
    pub matched_feed_id: Option<String>,
    pub response_code: String,
    pub cache_hit: Option<bool>,
    pub latency_us: u32,
}

pub struct TelemetryEmitter {
    tx: Sender<QueryEventInput>,
}

impl TelemetryEmitter {
    /// Spawns the background flush task and returns a handle. `channel_capacity`
    /// bounds memory if the control plane is slow/unreachable — once full,
    /// `emit` silently drops events rather than applying backpressure to DNS.
    pub fn start(control_url: String, channel_capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(channel_capacity);
        tokio::spawn(flush_loop(rx, control_url));
        Self { tx }
    }

    /// No background task, no receiver — `emit` always drops. Default for
    /// tests and any path that hasn't opted into real telemetry.
    pub fn noop() -> Self {
        let (tx, _rx) = mpsc::channel(1);
        Self { tx }
    }

    pub fn emit(&self, event: QueryEventInput) {
        use tokio::sync::mpsc::error::TrySendError;
        if let Err(TrySendError::Full(_)) = self.tx.try_send(event) {
            warn!("telemetry channel full — event dropped");
        }
        // TrySendError::Closed means no receiver (noop mode) — silently discard
    }
}

const BATCH_SIZE: usize = 500;
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

async fn flush_loop(mut rx: Receiver<QueryEventInput>, control_url: String) {
    let client = reqwest::Client::new();
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !batch.is_empty() {
                    flush(&client, &control_url, std::mem::take(&mut batch)).await;
                }
            }
            maybe_record = rx.recv() => {
                match maybe_record {
                    Some(record) => {
                        batch.push(record);
                        if batch.len() >= BATCH_SIZE {
                            flush(&client, &control_url, std::mem::take(&mut batch)).await;
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

async fn flush(client: &reqwest::Client, control_url: &str, batch: Vec<QueryEventInput>) {
    let events: Vec<_> = batch
        .iter()
        .map(|r| {
            json!({
                "group_id": r.group_id,
                "client_ip": r.client_ip,
                "qname": r.qname,
                "qtype": r.qtype,
                "decision": r.decision,
                "matched_rule": r.matched_rule,
                "matched_category": r.matched_category,
                "matched_feed_id": r.matched_feed_id,
                "response_code": r.response_code,
                "cache_hit": r.cache_hit,
                "latency_us": r.latency_us,
            })
        })
        .collect();
    let body = json!({ "events": events });

    if let Err(e) = crate::with_service_token(
        client.post(format!("{control_url}/api/v1/query-events")).json(&body),
    )
    .send()
    .await
    {
        warn!("telemetry flush failed (events dropped): {e}");
    }
}
