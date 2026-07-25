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

use std::net::Ipv4Addr;

pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// Fallback server identifier (option 54) for traffic that isn't
    /// dispatched through a dedicated per-interface socket: relayed traffic
    /// (arrives on the wildcard socket regardless of which of this host's
    /// interfaces it came in on) and any scope with no `interface`
    /// restriction. A scope *with* an `interface` gets its own dedicated
    /// socket's own address auto-derived at startup instead (`main.rs`'s
    /// `interface_ipv4_addr`, via `getifaddrs(3)`) — a single global address
    /// is wrong for that case whenever the interface's subnet differs from
    /// this one, since a client's later unicast RENEW targets whatever
    /// address it was handed here. `None` is valid (e.g. every scope has its
    /// own `interface` and none are relayed) but risky: anything that does
    /// fall back to it gets no reply at all rather than a wrong one — see
    /// `Server::server_ip_for`.
    pub server_ip: Option<Ipv4Addr>,
    pub control_url: String,
    pub internal_token: String,
    /// Fallback DNS server pushed to clients (option 6) when a scope has no
    /// dns_servers configured — normally the co-located mantis-filter node.
    pub filter_node_ip: Option<Ipv4Addr>,
    pub scope_refresh_interval_s: u64,
    pub lease_sweep_interval_s: u64,
    pub ddns_retry_interval_s: u64,
    /// How long a declined (state 1) address stays excluded from allocation
    /// before `sweep_expired` reclaims it — same purpose as Kea's
    /// `decline-probation-period` (default there, and here, is 24h): the
    /// conflict that caused the decline may have been transient, so a
    /// declined address shouldn't be dead forever.
    pub decline_probation_s: i64,
    /// How long a lease stays in state 2 (expired-reclaimed — an address the
    /// schema already reserved this state for, `DhcpLease.state`'s comment in
    /// models.py, but which `sweep_expired` never used until now) after its
    /// `expires_at` passes before the address becomes available to a
    /// *different* client. Without this, a client whose RENEW/REBIND was
    /// simply delayed or lost — not gone — could have its address reassigned
    /// out from under it the instant `expires_at` ticks over; a client
    /// re-asserting the *same* address during this window (`claim_specific`)
    /// still succeeds, only a different mac requesting it is turned away.
    /// Five minutes covers a lost renewal's retry (T1/T2 timers mean a
    /// well-behaved client retries within seconds to low minutes) without
    /// meaningfully starving a small pool the way an hours-long hold would.
    pub expired_hold_s: i64,
    /// Upper bound on rows a single `sweep_expired` tick will reclaim or
    /// delete, applied independently to each step via a bounded
    /// `ctid IN (SELECT ... LIMIT n)`. `dhcp_leases` is this daemon's largest
    /// table and the sweep runs unattended on a timer — an unbounded
    /// UPDATE/DELETE is fine at normal load (a handful of expiries per tick)
    /// but not a bound worth skipping, since a daemon restarted after being
    /// down for a while could otherwise face a single multi-hour-backlog
    /// statement. A bounded batch just means recovery takes a few extra
    /// 30-second ticks instead of one long one.
    pub reclaim_batch_limit: i64,
    /// Opt-in Prometheus `/metrics` listener (blank = disabled — same
    /// convention as mantis-filter's BLOCKPAGE_BIND_ADDR).
    pub metrics_bind_addr: Option<std::net::SocketAddr>,
    /// ICMP conflict-detection before a DISCOVER's OFFER (conflict.rs).
    /// Linux-only regardless (see conflict.rs's module docs); this also
    /// lets an operator turn it off there to shave the probe latency off
    /// every OFFER if they'd rather rely on DHCPDECLINE alone.
    pub conflict_detection_enabled: bool,
    pub conflict_probe_timeout: std::time::Duration,
    pub conflict_probe_max_attempts: u32,
    /// Upper bound on concurrently-in-flight packet handlers per socket —
    /// the bounded-concurrency equivalent of Kea's `thread-pool-size` +
    /// `packet-queue-size`. Each packet is handled in its own spawned task
    /// (`main.rs`'s `socket_loop`) rather than awaited inline, both so one
    /// slow Postgres call can't stall every other client's DORA exchange and
    /// so a panic in one handler is isolated to that task instead of
    /// silently ending that interface's service forever. This still needs a
    /// ceiling: an unbounded number of concurrent tasks under a packet flood
    /// would trade one failure mode (serialized handling) for another
    /// (unbounded memory/connection-pool pressure). 512 is generous for any
    /// single DORA burst this daemon is realistically sized for (§17.4);
    /// past it, packets are dropped and counted (`dhcp_packet_queue_drops_total`)
    /// rather than queued unboundedly.
    pub max_inflight_packets: usize,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;
        // Optional now -- see `server_ip`'s docs. Still worth setting on any
        // deployment that relays or has an interface-less scope; main.rs
        // warns at startup if it's unset and looks like it'll be needed.
        let server_ip: Option<Ipv4Addr> = match std::env::var("MANTIS_DHCP_SERVER_IP") {
            Ok(v) if !v.is_empty() => Some(v.parse()?),
            _ => None,
        };
        let filter_node_ip = match std::env::var("MANTIS_FILTER_NODE_IP") {
            Ok(v) if !v.is_empty() => Some(v.parse()?),
            _ => None,
        };
        let metrics_bind_addr = match std::env::var("MANTIS_DHCP_METRICS_BIND_ADDR") {
            Ok(v) if !v.is_empty() => Some(v.parse()?),
            _ => None,
        };
        Ok(Self {
            database_url,
            bind_addr: std::env::var("MANTIS_DHCP_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:67".to_string()),
            server_ip,
            control_url: std::env::var("MANTIS_CTRL_URL").unwrap_or_else(|_| "http://control:8000".to_string()),
            internal_token: std::env::var("MANTIS_INTERNAL_TOKEN").unwrap_or_default(),
            filter_node_ip,
            scope_refresh_interval_s: 10,
            lease_sweep_interval_s: 30,
            ddns_retry_interval_s: 10,
            decline_probation_s: std::env::var("MANTIS_DHCP_DECLINE_PROBATION_S")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400),
            expired_hold_s: std::env::var("MANTIS_DHCP_EXPIRED_HOLD_S")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            reclaim_batch_limit: std::env::var("MANTIS_DHCP_RECLAIM_BATCH_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000),
            metrics_bind_addr,
            conflict_detection_enabled: std::env::var("MANTIS_DHCP_CONFLICT_DETECTION")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true),
            conflict_probe_timeout: std::time::Duration::from_millis(300),
            conflict_probe_max_attempts: 4,
            max_inflight_packets: std::env::var("MANTIS_DHCP_MAX_INFLIGHT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(512),
        })
    }
}
