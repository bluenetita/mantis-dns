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

//! mantis-dhcp — native DHCPv4 server replacing ISC Kea (design.md §22).
//!
//! Reads dhcp_scopes/dhcp_static_leases/dhcp_relay_configs directly from the
//! same Postgres the control-plane API edits (no push/sync step) and owns
//! its own lease table (dhcp_leases) instead of a separate daemon's schema.
//!
//! Not yet implemented (tracked as an explicit follow-up, not silently
//! missing): DHCPv6 — see design.md §22.9. Per-interface socket dispatch for
//! multi-subnet direct-attach setups (`bind_interface_socket` below) is
//! Linux-only (`SO_BINDTODEVICE`) — on other platforms only the wildcard
//! socket runs, same single-candidate behavior as before (see
//! db::Snapshot::find_scope_for_direct).

use std::sync::Arc;

use arc_swap::ArcSwap;
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use mantis_dhcp::{config, db, ddns, metrics, server};
use sqlx::postgres::PgPoolOptions;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Arc::new(config::Config::from_env()?);
    tracing::info!("mantis-dhcp starting: bind={} server_ip={}", cfg.bind_addr, cfg.server_ip);

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database_url)
        .await?;

    let initial = db::load_snapshot(&pool).await?;
    tracing::info!("loaded {} enabled scope(s)", initial.scopes.len());
    let interfaces = distinct_interfaces(&initial.scopes);
    let snapshot = Arc::new(ArcSwap::from_pointee(initial));

    tokio::spawn(db::refresh_loop(pool.clone(), snapshot.clone(), cfg.scope_refresh_interval_s));

    {
        let pool = pool.clone();
        let snapshot = snapshot.clone();
        let cfg = cfg.clone();
        let http = reqwest::Client::new();
        let interval_s = cfg.lease_sweep_interval_s;
        let probation_s = cfg.decline_probation_s;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_s));
            loop {
                ticker.tick().await;
                match db::sweep_expired(&pool, probation_s).await {
                    Ok(expired) if !expired.is_empty() => {
                        tracing::debug!("swept {} expired/reclaimed lease(s)", expired.len());
                        let snap = snapshot.load();
                        for lease in expired {
                            let Some(hostname) = lease.hostname else { continue };
                            let ddns_enabled =
                                snap.scopes.iter().any(|s| s.id == lease.scope_id && s.ddns_enabled);
                            if !ddns_enabled {
                                continue;
                            }
                            let ev = ddns::V4Event {
                                event: "expire",
                                scope_id: &lease.scope_id,
                                ip: lease.ip,
                                hostname: Some(&hostname),
                                mac: &lease.mac,
                            };
                            ddns::post_v4(&pool, &http, &cfg.control_url, &cfg.internal_token, ev).await;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("lease sweep failed: {e}"),
                }
            }
        });
    }

    {
        let pool = pool.clone();
        let cfg = cfg.clone();
        let http = reqwest::Client::new();
        let interval_s = cfg.ddns_retry_interval_s;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_s));
            loop {
                ticker.tick().await;
                ddns::retry_due(&pool, &http, &cfg.control_url, &cfg.internal_token).await;
            }
        });
    }

    let metrics_counters = Arc::new(metrics::Counters::default());
    if let Some(bind_addr) = cfg.metrics_bind_addr {
        let pool = pool.clone();
        let counters = metrics_counters.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(bind_addr, counters, pool).await {
                tracing::warn!("metrics listener stopped: {e}");
            }
        });
    }

    let srv = server::Server {
        pool,
        snapshot,
        cfg: cfg.clone(),
        http: reqwest::Client::new(),
        metrics: metrics_counters,
    };

    // One socket per distinct scope `interface` (Linux: SO_BINDTODEVICE),
    // bound once at startup — a scope interface added later needs a
    // restart to get its own dedicated socket, same as most DHCP servers'
    // interface config. Each gets its own background task; the wildcard
    // socket (relayed traffic, and scopes with no `interface` set) runs in
    // the foreground below and keeps the process alive.
    for iface in &interfaces {
        match bind_interface_socket(&cfg.bind_addr, iface) {
            Ok(socket) => {
                tracing::info!("bound dedicated DHCP socket on interface {iface:?}");
                let srv = srv.clone();
                let iface = iface.clone();
                tokio::spawn(async move { socket_loop(socket, srv, Some(iface)).await });
            }
            Err(e) => tracing::warn!(
                "could not bind a dedicated socket for interface {iface:?} ({e}) — \
                 direct-attach traffic on it will only be served if it's the sole \
                 interface-less scope (see db::Snapshot::find_scope_for_direct)"
            ),
        }
    }

    let wildcard = bind_socket(&cfg.bind_addr)?;
    socket_loop(wildcard, srv, None).await;
    Ok(())
}

fn distinct_interfaces(scopes: &[db::Scope]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    scopes
        .iter()
        .filter_map(|s| s.interface.clone())
        .filter(|iface| seen.insert(iface.clone()))
        .collect()
}

async fn socket_loop(socket: UdpSocket, srv: server::Server, recv_interface: Option<String>) {
    let mut buf = [0u8; 1500];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("recv_from failed: {e}");
                continue;
            }
        };
        let msg = match dhcproto::v4::Message::decode(&mut Decoder::new(&buf[..n])) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("dropping malformed packet from {src}: {e}");
                continue;
            }
        };
        if msg.opcode() != dhcproto::v4::Opcode::BootRequest {
            continue;
        }

        if let Some(reply) = srv.handle(&msg, recv_interface.as_deref()).await {
            let mut out = Vec::with_capacity(300);
            if let Err(e) = reply.message.encode(&mut Encoder::new(&mut out)) {
                tracing::warn!("failed to encode reply: {e}");
                continue;
            }
            if let Err(e) = socket.send_to(&out, reply.dest).await {
                tracing::warn!("failed to send reply to {}: {e}", reply.dest);
            }
        }
    }
}

fn bind_socket(bind_addr: &str) -> anyhow::Result<UdpSocket> {
    let addr: std::net::SocketAddr = bind_addr.parse()?;
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}

/// Bound with `SO_REUSEADDR` (not `SO_REUSEPORT`) plus a distinct
/// `SO_BINDTODEVICE` per socket — the standard, deterministic technique
/// several real DHCP servers use for this: the kernel scores a
/// device-bound socket higher than the wildcard one for traffic actually
/// arriving on that device, so delivery isn't ambiguous the way it would be
/// with `SO_REUSEPORT`'s hash-based load-balancing across equally-specific
/// sockets.
#[cfg(target_os = "linux")]
fn bind_interface_socket(bind_addr: &str, iface: &str) -> anyhow::Result<UdpSocket> {
    let addr: std::net::SocketAddr = bind_addr.parse()?;
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    socket.bind_device(Some(iface.as_bytes()))?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}

#[cfg(not(target_os = "linux"))]
fn bind_interface_socket(_bind_addr: &str, _iface: &str) -> anyhow::Result<UdpSocket> {
    anyhow::bail!("per-interface socket binding (SO_BINDTODEVICE) is only implemented on Linux")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_with_interface(iface: Option<&str>) -> db::Scope {
        db::Scope {
            id: "s1".to_string(),
            tenant_id: "t1".to_string(),
            name: "s1".to_string(),
            subnet: "10.0.0.0/24".parse().unwrap(),
            range_start: "10.0.0.10".parse().unwrap(),
            range_end: "10.0.0.20".parse().unwrap(),
            router_ip: None,
            dns_servers: vec![],
            domain_name: None,
            interface: iface.map(str::to_string),
            lease_time_s: 3600,
            renew_time_s: None,
            rebind_time_s: None,
            ddns_enabled: false,
            pxe_next_server: None,
            pxe_boot_filename: None,
            pxe_uefi_boot_filename: None,
        }
    }

    #[test]
    fn distinct_interfaces_dedupes_and_skips_none() {
        let scopes = vec![
            scope_with_interface(Some("eth0")),
            scope_with_interface(Some("eth1")),
            scope_with_interface(Some("eth0")),
            scope_with_interface(None),
        ];
        let mut ifaces = distinct_interfaces(&scopes);
        ifaces.sort();
        assert_eq!(ifaces, vec!["eth0".to_string(), "eth1".to_string()]);
    }

    #[test]
    fn distinct_interfaces_empty_when_no_scope_has_one() {
        let scopes = vec![scope_with_interface(None)];
        assert!(distinct_interfaces(&scopes).is_empty());
    }
}
