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
//! db::Snapshot::find_scope_for_direct). Each bound interface's own address
//! is auto-derived (`interface_ipv4_addr`, `getifaddrs(3)`) for that
//! interface's server-identifier option instead of using one global address
//! for every reply regardless of which subnet it's actually going out on —
//! see config.rs's `server_ip` docs and `server::server_ip_for`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
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
    tracing::info!(
        "mantis-dhcp starting: bind={} server_ip={}",
        cfg.bind_addr,
        cfg.server_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "<unset>".to_string())
    );

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
        let hold_s = cfg.expired_hold_s;
        let batch_limit = cfg.reclaim_batch_limit;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_s));
            loop {
                ticker.tick().await;
                match db::sweep_expired(&pool, probation_s, hold_s, batch_limit).await {
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

    // Liveness signal for the control-plane UI (design.md §22.11) — without
    // this, a crashed or bootlooping daemon has no way to show up anywhere
    // except journalctl; the lease/utilisation numbers the UI already shows
    // just stop updating silently. Registered once here (by (hostname,
    // family) identity, taking over any previous instance's row rather than
    // leaving it stale next to a new one — see `db::register_instance`),
    // then just refreshed by `instance_id` on every tick.
    {
        let instance_id = uuid::Uuid::new_v4().to_string();
        let hostname = mantis_dhcp::hostname();
        if let Err(e) = db::register_instance(&pool, &instance_id, hostname.as_deref()).await {
            tracing::warn!("heartbeat registration failed: {e}");
        }

        let pool = pool.clone();
        let interval_s = cfg.scope_refresh_interval_s;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_s));
            loop {
                ticker.tick().await;
                if let Err(e) = db::touch_heartbeat(&pool, &instance_id).await {
                    tracing::warn!("heartbeat touch failed: {e}");
                }
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

    // One socket per distinct scope `interface` (Linux: SO_BINDTODEVICE),
    // bound once at startup — a scope interface added later needs a
    // restart to get its own dedicated socket, same as most DHCP servers'
    // interface config. Resolved and bound *before* constructing `Server`,
    // since it carries the completed interface -> address map every clone
    // of it (one per socket task, plus the wildcard one) shares.
    let mut interface_sockets = Vec::new();
    let mut interface_server_ips: HashMap<String, Ipv4Addr> = HashMap::new();
    for iface in &interfaces {
        let Some(addr) = interface_ipv4_addr(iface) else {
            tracing::warn!(
                "could not determine {iface:?}'s own IPv4 address — skipping its dedicated socket; \
                 direct-attach traffic on it will only be served if it's the sole interface-less scope \
                 (see db::Snapshot::find_scope_for_direct), using MANTIS_DHCP_SERVER_IP if set"
            );
            continue;
        };
        match bind_interface_socket(&cfg.bind_addr, iface) {
            Ok(socket) => {
                tracing::info!("bound dedicated DHCP socket on interface {iface:?}, server_ip={addr}");
                interface_server_ips.insert(iface.clone(), addr);
                interface_sockets.push((socket, iface.clone()));
            }
            Err(e) => tracing::warn!(
                "could not bind a dedicated socket for interface {iface:?} ({e}) — \
                 direct-attach traffic on it will only be served if it's the sole \
                 interface-less scope (see db::Snapshot::find_scope_for_direct)"
            ),
        }
    }

    if cfg.server_ip.is_none() {
        tracing::warn!(
            "MANTIS_DHCP_SERVER_IP is not set — relayed traffic and any scope with no `interface` \
             restriction will get no DHCP reply at all (option 54 is mandatory and there's no \
             fallback); scopes served through a dedicated per-interface socket with a \
             successfully-resolved address are unaffected"
        );
    }

    let srv = server::Server {
        pool,
        snapshot,
        cfg: cfg.clone(),
        http: reqwest::Client::new(),
        metrics: metrics_counters,
        interface_server_ips,
    };

    // Each dedicated socket gets its own background task; the wildcard
    // socket (relayed traffic, and scopes with no `interface` set) runs in
    // the foreground below and keeps the process alive.
    let max_inflight = cfg.max_inflight_packets;
    for (socket, iface) in interface_sockets {
        let srv = srv.clone();
        tokio::spawn(async move { socket_loop(Arc::new(socket), srv, Some(iface), max_inflight).await });
    }

    let wildcard = bind_socket(&cfg.bind_addr)?;
    socket_loop(Arc::new(wildcard), srv, None, max_inflight).await;
    Ok(())
}

/// This interface's own IPv4 address (`getifaddrs(3)`), for the server
/// identifier a dedicated per-interface socket's replies should carry — see
/// config.rs's `server_ip` docs. `None` if the interface has no IPv4 address
/// configured at all, or (non-Linux) unconditionally, since per-interface
/// sockets themselves are Linux-only (`bind_interface_socket` below).
#[cfg(target_os = "linux")]
fn interface_ipv4_addr(name: &str) -> Option<Ipv4Addr> {
    use std::ffi::CStr;

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return None;
        }
        let mut cur = ifap;
        let mut found = None;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null()
                && i32::from((*ifa.ifa_addr).sa_family) == libc::AF_INET
                && CStr::from_ptr(ifa.ifa_name).to_str() == Ok(name)
            {
                let sockaddr_in = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                found = Some(Ipv4Addr::from(u32::from_be(sockaddr_in.sin_addr.s_addr)));
                break;
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
        found
    }
}

#[cfg(not(target_os = "linux"))]
fn interface_ipv4_addr(_name: &str) -> Option<Ipv4Addr> {
    None
}

fn distinct_interfaces(scopes: &[db::Scope]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    scopes
        .iter()
        .filter_map(|s| s.interface.clone())
        .filter(|iface| seen.insert(iface.clone()))
        .collect()
}

/// One task per received packet, gated by a `max_inflight`-permit semaphore,
/// rather than awaiting `Server::handle` inline in this loop. Two problems
/// that shape stems from:
///
/// - **Throughput.** `handle` does at least one Postgres round-trip; awaited
///   inline, a single slow query stalls every other client's DORA exchange
///   on this socket, DHCP-request-storm-at-boot being exactly the moment
///   that hurts most.
/// - **Fault isolation.** Tokio catches a panic at each spawned task's
///   boundary — the panic doesn't propagate to this loop or to any other
///   in-flight packet's task, only to the one packet that triggered it. Above
///   this loop is the only place per-packet work was ever awaited directly,
///   so it was also the only place a single malformed/unlucky packet could
///   permanently end this socket's service with no crash, no restart, and no
///   signal beyond a log line — see `dhcp_handler_panics_total` in
///   metrics.rs. Spawning turns that into an isolated, counted event.
///
/// The semaphore permit is acquired *before* spawning (not inside the spawned
/// task), so once `max_inflight` tasks are outstanding, this loop itself
/// stops accepting new packets from the socket until one finishes — natural
/// backpressure, rather than spawning without bound under a flood.
async fn socket_loop(socket: Arc<UdpSocket>, srv: server::Server, recv_interface: Option<String>, max_inflight: usize) {
    let mut buf = [0u8; 1500];
    let permits = Arc::new(tokio::sync::Semaphore::new(max_inflight));
    let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    loop {
        // Non-blocking drain of finished handler tasks, so a panic is
        // observed (logged + counted) promptly rather than only when this
        // JoinSet is finally dropped at process shutdown.
        while let Some(res) = tasks.try_join_next() {
            if let Err(e) = res {
                if e.is_panic() {
                    tracing::error!("DHCP packet handler panicked (isolated to this packet): {e}");
                    srv.metrics.record_handler_panic();
                }
            }
        }

        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("recv_from failed: {e}");
                continue;
            }
        };

        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!("max in-flight DHCP packets ({max_inflight}) reached, dropping packet from {src}");
                srv.metrics.record_queue_drop();
                continue;
            }
        };

        // Decoding is deliberately *inside* the spawned task, not above this
        // permit acquisition — `Message::decode` is untrusted-input parsing
        // in a third-party crate, and a cargo-fuzz run against it found a
        // real, reproducible panic (an internal assertion in dhcproto's own
        // option parser) within seconds, triggerable by a single crafted
        // UDP packet from anywhere on the network, no auth needed (design.md
        // §26 R8). Decoding above this line, in the recv loop itself, would
        // put that panic outside the per-task isolation the rest of this
        // loop relies on — it would unwind through `socket_loop`'s own task
        // instead of a spawned one, which for the wildcard socket *is* this
        // process's main task. Moving decode inside the spawned task means
        // the exact same isolation and `dhcp_handler_panics_total` counting
        // that covers `Server::handle` also covers decode.
        let packet = buf[..n].to_vec();
        let srv = srv.clone();
        let socket = socket.clone();
        let recv_interface = recv_interface.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let msg = match dhcproto::v4::Message::decode(&mut Decoder::new(&packet)) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("dropping malformed packet from {src}: {e}");
                    return;
                }
            };
            if msg.opcode() != dhcproto::v4::Opcode::BootRequest {
                return;
            }
            if let Some(reply) = srv.handle(&msg, recv_interface.as_deref()).await {
                let mut out = Vec::with_capacity(300);
                if let Err(e) = reply.message.encode(&mut Encoder::new(&mut out)) {
                    tracing::warn!("failed to encode reply: {e}");
                    return;
                }
                let client_max = match msg.opts().get(dhcproto::v4::OptionCode::MaxMessageSize) {
                    Some(dhcproto::v4::DhcpOption::MaxMessageSize(n)) => Some(*n),
                    _ => None,
                };
                warn_if_reply_oversized(out.len(), client_max, reply.dest);
                if let Err(e) = socket.send_to(&out, reply.dest).await {
                    tracing::warn!("failed to send reply to {}: {e}", reply.dest);
                }
            }
        });
    }
}

/// This daemon never sets option 52 (Overload) or truncates anything to fit
/// — the well-known option set `options::build` assembles is small (subnet
/// mask, router, DNS, domain name, three lease timers, server id), and PXE
/// fields (`siaddr`, `file`/boot filename) are fixed BOOTP header fields,
/// not variable options, so they don't compete for the same space. The one
/// way a reply from this daemon gets large is an operator's own
/// `dhcp_options` custom rows (`options::apply_custom`) — unbounded in
/// count/size by design (design.md §22, "arbitrary option-code passthrough")
/// — or an unusually long `domain_name`. Neither is truncated or rejected
/// here; this only logs, so a misconfiguration shows up as a warning instead
/// of a silently-dropped reply on an embedded/PXE client whose stack can't
/// handle a large UDP payload.
///
/// Compared against the client's own declared limit (option 57, Maximum
/// DHCP Message Size) when present, since that's the authoritative bound;
/// otherwise against 576 bytes, the historical BOOTP/DHCP "every
/// implementation must support at least this much" floor (RFC 1122's
/// minimum IP reassembly buffer size, which RFC 2131 inherits) — a
/// conservative default given plenty of real embedded clients still assume
/// it.
/// The classic BOOTP/DHCP safety floor (RFC 1122's minimum IP reassembly
/// buffer size, inherited by RFC 2131) — used only when the client didn't
/// declare its own limit via option 57.
const LEGACY_SAFE_REPLY_SIZE: usize = 576;

fn safe_reply_size_limit(client_max: Option<u16>) -> usize {
    client_max.map(usize::from).unwrap_or(LEGACY_SAFE_REPLY_SIZE)
}

fn warn_if_reply_oversized(size: usize, client_max: Option<u16>, dest: std::net::SocketAddr) {
    let limit = safe_reply_size_limit(client_max);
    if size > limit {
        match client_max {
            Some(declared) => tracing::warn!(
                "reply to {dest} is {size} bytes, over the {declared}-byte maximum that client itself declared \
                 (option 57) -- it may truncate or silently drop this reply; check for oversized custom \
                 dhcp_options or an unusually long domain_name on this scope"
            ),
            None => tracing::warn!(
                "reply to {dest} is {size} bytes, over the classic {limit}-byte DHCP/BOOTP safety floor -- \
                 some embedded/PXE clients silently drop or truncate replies this large; check for oversized \
                 custom dhcp_options or an unusually long domain_name on this scope"
            ),
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

    #[test]
    fn safe_reply_size_limit_falls_back_to_the_legacy_floor_when_client_declared_nothing() {
        assert_eq!(safe_reply_size_limit(None), LEGACY_SAFE_REPLY_SIZE);
    }

    #[test]
    fn safe_reply_size_limit_honors_a_smaller_client_declared_max() {
        assert_eq!(safe_reply_size_limit(Some(300)), 300);
    }

    #[test]
    fn safe_reply_size_limit_honors_a_larger_client_declared_max() {
        assert_eq!(safe_reply_size_limit(Some(1500)), 1500);
    }

    /// `socket_loop` can't be exercised directly here (it needs a real socket
    /// and a `Server` backed by a real `PgPool`), but its panic-isolation
    /// claim rests entirely on three primitives — a `Semaphore` permit held
    /// by the spawned task, a `JoinSet` the loop drains non-blockingly, and
    /// `JoinError::is_panic()` — used in exactly this combination. This
    /// exercises that combination directly: one task panics, one succeeds;
    /// both must be observable, and the panicking task's permit must still
    /// be released rather than leaking a concurrency slot forever.
    #[tokio::test]
    async fn joinset_isolates_a_panicking_task_and_still_releases_its_permit() {
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

        let permit = permits.clone().try_acquire_owned().expect("first permit available");
        tasks.spawn(async move {
            let _permit = permit;
            panic!("simulated handler panic");
        });

        let result = tasks.join_next().await.expect("the panicking task completes");
        assert!(result.unwrap_err().is_panic(), "a panicking spawned task must surface as JoinError::is_panic()");

        // The panic must not have poisoned the semaphore or leaked the
        // permit — a second task should be able to acquire it immediately.
        let permit2 = permits
            .clone()
            .try_acquire_owned()
            .expect("permit must be available again after the panicking task dropped it");
        tasks.spawn(async move {
            let _permit = permit2;
        });
        let result2 = tasks.join_next().await.expect("the second task completes");
        assert!(result2.is_ok(), "a well-behaved task after a panic must complete normally");
    }
}
