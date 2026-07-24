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

//! Notifies the control plane's `/internal/dhcp-event` endpoint on lease
//! commit/expire, for DDNS (A/AAAA record) + client-registry updates. This
//! reuses the exact HTTP contract Kea's `run_script` hook used to drive
//! (dhcp_internal_routers.py) — same security-reviewed ownership-guard
//! logic on the receiving end — just called directly instead of via a shell
//! script hook.
//!
//! A failed POST (control plane down, network blip) is queued in
//! `dhcp_ddns_retries` (see db.rs) and retried with backoff by
//! [`retry_due`], rather than dropped — a client's DNS record shouldn't
//! silently go stale just because the control plane happened to be
//! restarting when its lease was granted.

use sqlx::PgPool;

use serde::Serialize;

#[derive(Serialize)]
struct DhcpEvent<'a> {
    event: &'a str, // "add" | "expire"
    ip: &'a str,
    hostname: &'a str,
    family: &'a str, // "4" | "6"
    #[serde(skip_serializing_if = "str::is_empty")]
    mac: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    duid: &'a str,
    scope_id: &'a str,
}

pub struct V4Event<'a> {
    pub event: &'a str,
    pub scope_id: &'a str,
    pub ip: std::net::Ipv4Addr,
    pub hostname: Option<&'a str>,
    pub mac: &'a str,
}

pub async fn post_v4(pool: &PgPool, client: &reqwest::Client, ctrl_url: &str, token: &str, ev: V4Event<'_>) {
    let ip = ev.ip.to_string();
    let hostname = ev.hostname.unwrap_or("");
    let body = DhcpEvent { event: ev.event, ip: &ip, hostname, family: "4", mac: ev.mac, duid: "", scope_id: ev.scope_id };

    if let Err(e) = send(client, ctrl_url, token, &body).await {
        tracing::warn!("dhcp-event POST failed, queuing for retry: {e}");
        if let Err(e) = crate::db::enqueue_ddns_retry(
            pool,
            ev.event,
            "4",
            ev.scope_id,
            &ip,
            ev.hostname,
            Some(ev.mac).filter(|m| !m.is_empty()),
            None,
            &e.to_string(),
        )
        .await
        {
            tracing::warn!("failed to queue dhcp-event for retry (event lost): {e}");
        }
    }
}

pub struct V6Event<'a> {
    pub event: &'a str,
    pub scope_id: &'a str,
    pub ip: std::net::Ipv6Addr,
    pub hostname: Option<&'a str>,
    pub duid: &'a str,
}

pub async fn post_v6(pool: &PgPool, client: &reqwest::Client, ctrl_url: &str, token: &str, ev: V6Event<'_>) {
    let ip = ev.ip.to_string();
    let hostname = ev.hostname.unwrap_or("");
    let body = DhcpEvent { event: ev.event, ip: &ip, hostname, family: "6", mac: "", duid: ev.duid, scope_id: ev.scope_id };

    if let Err(e) = send(client, ctrl_url, token, &body).await {
        tracing::warn!("dhcp-event POST failed, queuing for retry: {e}");
        if let Err(e) = crate::db::enqueue_ddns_retry(
            pool,
            ev.event,
            "6",
            ev.scope_id,
            &ip,
            ev.hostname,
            None,
            Some(ev.duid).filter(|d| !d.is_empty()),
            &e.to_string(),
        )
        .await
        {
            tracing::warn!("failed to queue dhcp-event for retry (event lost): {e}");
        }
    }
}

async fn send(client: &reqwest::Client, ctrl_url: &str, token: &str, body: &DhcpEvent<'_>) -> anyhow::Result<()> {
    let url = format!("{}/api/v1/internal/dhcp-event", ctrl_url.trim_end_matches('/'));
    client
        .post(&url)
        .header("X-Internal-Token", token)
        .json(body)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// Drains due retries (see db.rs's `due_ddns_retries`/backoff schedule),
/// called on a periodic tick from main.rs. Each row is retried at most once
/// per call — a row that fails again just gets rescheduled further out by
/// `reschedule_or_giveup_ddns_retry`, it isn't retried in a tight loop here.
pub async fn retry_due(pool: &PgPool, client: &reqwest::Client, ctrl_url: &str, token: &str) {
    let due = match crate::db::due_ddns_retries(pool, 100).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("failed to load due dhcp-event retries: {e}");
            return;
        }
    };

    for row in due {
        let body = DhcpEvent {
            event: &row.event,
            ip: &row.ip,
            hostname: row.hostname.as_deref().unwrap_or(""),
            family: &row.family,
            mac: row.mac.as_deref().unwrap_or(""),
            duid: row.duid.as_deref().unwrap_or(""),
            scope_id: &row.scope_id,
        };

        match send(client, ctrl_url, token, &body).await {
            Ok(()) => {
                if let Err(e) = crate::db::delete_ddns_retry(pool, &row.id).await {
                    tracing::warn!("dhcp-event retry {} delivered but couldn't be dequeued: {e}", row.id);
                }
            }
            Err(e) => {
                match crate::db::reschedule_or_giveup_ddns_retry(pool, &row.id, row.attempts, &e.to_string()).await {
                    Ok(true) => tracing::warn!(
                        "dhcp-event retry {} for {}/{} gave up after max attempts: {e}",
                        row.id, row.scope_id, row.ip
                    ),
                    Ok(false) => {}
                    Err(e2) => tracing::warn!("failed to reschedule dhcp-event retry {}: {e2}", row.id),
                }
            }
        }
    }
}
