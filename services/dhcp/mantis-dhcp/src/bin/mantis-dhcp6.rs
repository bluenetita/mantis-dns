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

//! mantis-dhcp6 — native DHCPv6 (RFC 8415) daemon, the v6 counterpart of
//! `main.rs`'s DHCPv4 daemon. Separate binary/process (own port, own
//! Server/Snapshot/Counters types — see `server6.rs`) sharing only the DDNS
//! retry queue plumbing (`ddns.rs`) and the advisory-lock/hot-reload idioms
//! with the v4 daemon.
//!
//! Single wildcard socket only — no per-interface `SO_BINDTODEVICE`
//! dispatch yet (v4's main.rs has this; see `db6::Snapshot6::find_scope_for_direct`'s
//! docs for the resulting disambiguation limit on direct-attached, unrelayed
//! traffic). Best-effort joins the standard relay/server multicast group
//! (`ff02::1:2`) on the default interface so a single-NIC direct-attach
//! deployment still receives client multicast; a relay-fed deployment (the
//! common case for anything but a flat single-segment network) doesn't need
//! that join at all, since relayed traffic already arrives unicast.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use mantis_dhcp::{config6, db6, ddns, metrics6, server6};
use sqlx::postgres::PgPoolOptions;
use tokio::net::UdpSocket;

/// All_DHCP_Relay_Agents_and_Servers (RFC 8415 §7.1).
const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Arc::new(config6::Config::from_env()?);
    tracing::info!("mantis-dhcp6 starting: bind={}", cfg.bind_addr);

    let pool = PgPoolOptions::new().max_connections(10).connect(&cfg.database_url).await?;

    let initial = db6::load_snapshot6(&pool).await?;
    tracing::info!("loaded {} enabled v6 scope(s)", initial.scopes.len());
    let snapshot = Arc::new(ArcSwap::from_pointee(initial));

    tokio::spawn(db6::refresh_loop6(pool.clone(), snapshot.clone(), cfg.scope_refresh_interval_s));

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
                match db6::sweep_expired6(&pool, probation_s).await {
                    Ok(expired) if !expired.is_empty() => {
                        tracing::debug!("swept {} expired/reclaimed v6 lease(s)", expired.len());
                        let snap = snapshot.load();
                        for lease in expired {
                            let Some(hostname) = lease.hostname else { continue };
                            let ddns_enabled =
                                snap.scopes.iter().any(|s| s.id == lease.scope_id && s.ddns_enabled);
                            if !ddns_enabled {
                                continue;
                            }
                            let ev = ddns::V6Event {
                                event: "expire",
                                scope_id: &lease.scope_id,
                                ip: lease.ip,
                                hostname: Some(&hostname),
                                duid: &lease.duid,
                            };
                            ddns::post_v6(&pool, &http, &cfg.control_url, &cfg.internal_token, ev).await;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("v6 lease sweep failed: {e}"),
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

    let metrics_counters = Arc::new(metrics6::Counters::default());
    if let Some(bind_addr) = cfg.metrics_bind_addr {
        let pool = pool.clone();
        let counters = metrics_counters.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics6::serve(bind_addr, counters, pool).await {
                tracing::warn!("v6 metrics listener stopped: {e}");
            }
        });
    }

    let srv = server6::Server { pool, snapshot, cfg: cfg.clone(), http: reqwest::Client::new(), metrics: metrics_counters };

    let socket = bind_socket6(&cfg.bind_addr)?;
    match socket.join_multicast_v6(&ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 0) {
        Ok(()) => tracing::info!("joined ff02::1:2 on the default interface"),
        Err(e) => tracing::warn!(
            "could not join ff02::1:2 ({e}) -- direct-attached (unrelayed) multicast clients on this host \
             won't be reachable; relayed traffic (unicast to this server) is unaffected"
        ),
    }

    socket_loop(socket, srv).await;
    Ok(())
}

async fn socket_loop(socket: UdpSocket, srv: server6::Server) {
    let mut buf = [0u8; 1500];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("recv_from failed: {e}");
                continue;
            }
        };

        // No per-interface socket dispatch yet (see module docs) -- always
        // the wildcard/`None` case in `db6::Snapshot6::find_scope_for_direct`.
        if let Some(reply_bytes) = srv.handle_packet(&buf[..n], None).await {
            if let Err(e) = socket.send_to(&reply_bytes, src).await {
                tracing::warn!("failed to send v6 reply to {src}: {e}");
            }
        }
    }
}

fn bind_socket6(bind_addr: &str) -> anyhow::Result<UdpSocket> {
    let addr: SocketAddr = bind_addr.parse()?;
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}
