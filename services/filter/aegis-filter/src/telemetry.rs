//! Fire-and-forget query event telemetry. `emit()` is non-blocking (bounded
//! channel, drops on backpressure rather than ever stalling the DNS hot
//! path) — a background task batches and flushes to the control plane.

use std::time::Duration;

use serde_json::json;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::warn;

struct QueryEventRecord {
    group_id: String,
    qname: String,
    decision: String,
}

pub struct TelemetryEmitter {
    tx: Sender<QueryEventRecord>,
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

    pub fn emit(&self, group_id: &str, qname: &str, decision: &str) {
        let record = QueryEventRecord {
            group_id: group_id.to_string(),
            qname: qname.to_string(),
            decision: decision.to_string(),
        };
        if self.tx.try_send(record).is_err() {
            metrics::counter!("aegis_dns_telemetry_dropped_total").increment(1);
        }
    }
}

const BATCH_SIZE: usize = 500;
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

async fn flush_loop(mut rx: Receiver<QueryEventRecord>, control_url: String) {
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

async fn flush(client: &reqwest::Client, control_url: &str, batch: Vec<QueryEventRecord>) {
    let events: Vec<_> = batch
        .iter()
        .map(|r| json!({"group_id": r.group_id, "qname": r.qname, "decision": r.decision}))
        .collect();
    let body = json!({ "events": events });

    if let Err(e) = client
        .post(format!("{control_url}/api/v1/query-events"))
        .json(&body)
        .send()
        .await
    {
        warn!("telemetry flush failed (events dropped): {e}");
    }
}
