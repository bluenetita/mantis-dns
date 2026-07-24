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

//! ICMP echo ("ping") conflict detection before an OFFER (design.md §22.13):
//! catches an address already in use by some device this server never
//! allocated it to (a statically-configured host, or another DHCP server's
//! client) *before* handing it out, rather than only reacting after the
//! fact via DHCPDECLINE.
//!
//! Linux-only (`#[cfg(target_os = "linux")]`) — a raw ICMP socket needs
//! `CAP_NET_RAW`, already granted for `SO_BINDTODEVICE` (main.rs); on other
//! platforms `probe` always returns `false` (never blocks allocation),
//! same graceful-degradation pattern as per-interface socket dispatch.
//!
//! Only wired into the DISCOVER pool-scan path (`server.rs::handle_discover`
//! via `db::peek_free_ip_excluding`) — the common case, and where real DHCP
//! servers traditionally do this check. A client that jumps straight to
//! REQUEST without a prior DISCOVER (INIT-REBOOT, or a non-conformant
//! client) allocates via `db::allocate` without a probe; adding one there
//! would mean running a multi-hundred-millisecond blocking probe inside a
//! held Postgres transaction (the advisory lock from design.md §22.3),
//! which trades a rare correctness gap for a latency/lock-contention risk
//! on every write — not a trade worth making for the less common path.

use std::net::Ipv4Addr;
use std::time::Duration;

/// Builds an ICMP Echo Request (type 8) message body (no IP header — the
/// kernel adds that for a `SOCK_RAW`/`IPPROTO_ICMP` socket). Only called by
/// `probe_blocking`'s Linux implementation and by this module's own tests —
/// allow(dead_code) so a non-Linux, non-test build doesn't warn.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn build_echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(8 + payload.len());
    pkt.push(8); // type: echo request
    pkt.push(0); // code
    pkt.push(0);
    pkt.push(0); // checksum placeholder, filled in below
    pkt.extend_from_slice(&identifier.to_be_bytes());
    pkt.extend_from_slice(&sequence.to_be_bytes());
    pkt.extend_from_slice(payload);
    let sum = internet_checksum(&pkt);
    pkt[2] = (sum >> 8) as u8;
    pkt[3] = (sum & 0xff) as u8;
    pkt
}

/// RFC 1071 Internet checksum: one's-complement sum of 16-bit words, then
/// one's-complemented. Assumes the checksum field in `data` is already
/// zeroed (true both when computing a new checksum and when verifying one
/// — a correctly-checksummed message sums to `0xFFFF`, i.e. `!0`, though
/// this module never needs to verify one since it only ever reads
/// `type`/`code`/`identifier`/`sequence`, not the checksum itself).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parses a raw IPv4 packet — what a `SOCK_RAW`/`IPPROTO_ICMP` socket's
/// `recv_from` returns on Linux includes the IP header, unlike a
/// `SOCK_DGRAM` ICMP socket — and returns `(type, code, identifier,
/// sequence)` if it looks like a well-formed ICMP message.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_icmp_from_ip_packet(buf: &[u8]) -> Option<(u8, u8, u16, u16)> {
    if buf.is_empty() {
        return None;
    }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if buf.len() < ihl + 8 {
        return None;
    }
    let icmp = &buf[ihl..];
    let identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
    let sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
    Some((icmp[0], icmp[1], identifier, sequence))
}

// Only read by probe_blocking's Linux implementation — allow(dead_code) so
// a non-Linux build (where that fn is a stub) doesn't warn.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ECHO_REPLY_TYPE: u8 = 0;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const PROBE_PAYLOAD: &[u8] = b"mantis-dhcp-conflict-probe";

/// Pings `ip`; returns `true` if any Echo Reply from it arrives within
/// `timeout` (address is in use by something), `false` on timeout or if
/// the probe itself couldn't run (never blocks allocation on an error —
/// see the module docs on why this is a Linux-only best-effort check, not
/// a hard dependency).
pub async fn probe(ip: Ipv4Addr, timeout: Duration) -> bool {
    match tokio::task::spawn_blocking(move || probe_blocking(ip, timeout)).await {
        Ok(Ok(seen)) => seen,
        Ok(Err(e)) => {
            tracing::debug!("conflict probe for {ip} could not run ({e}) — treating as no conflict");
            false
        }
        Err(e) => {
            tracing::debug!("conflict probe task for {ip} didn't complete ({e}) — treating as no conflict");
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn probe_blocking(ip: Ipv4Addr, timeout: Duration) -> anyhow::Result<bool> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::mem::MaybeUninit;
    use std::net::SocketAddr;
    use std::time::Instant;

    let identifier = (std::process::id() & 0xFFFF) as u16;
    let packet = build_echo_request(identifier, 1, PROBE_PAYLOAD);

    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    let dest = SockAddr::from(SocketAddr::new(ip.into(), 0));
    socket.send_to(&packet, &dest)?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 512];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        // SO_RCVTIMEO bounds each individual recv_from call — reset every
        // iteration to the shrinking remainder so unrelated ICMP chatter
        // (which returns immediately, forcing us to loop) can't extend the
        // overall probe past `timeout`.
        socket.set_read_timeout(Some(remaining))?;

        // Same safety justification socket2's own `Read` impl for `Socket`
        // uses: u8 has no invalid bit patterns, so treating an
        // already-initialized &mut [u8] as &mut [MaybeUninit<u8>] is sound.
        let uninit_buf = unsafe { &mut *(&mut buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
        match socket.recv_from(uninit_buf) {
            Ok((n, from)) => {
                let Some(from_addr) = from.as_socket_ipv4() else { continue };
                if *from_addr.ip() != ip {
                    continue; // some other host's ICMP traffic — not ours
                }
                if let Some((typ, _code, id, _seq)) = parse_icmp_from_ip_packet(&buf[..n]) {
                    if typ == ECHO_REPLY_TYPE && id == identifier {
                        return Ok(true);
                    }
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_blocking(_ip: Ipv4Addr, _timeout: Duration) -> anyhow::Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_a_correctly_checksummed_message_is_the_ones_complement_of_0xffff() {
        // A message with its own valid checksum embedded sums to 0xFFFF —
        // internet_checksum of it (computed with the checksum field intact,
        // not zeroed) is therefore !0xFFFF == 0.
        let msg = build_echo_request(0x1234, 1, b"hello");
        assert_eq!(internet_checksum(&msg), 0);
    }

    #[test]
    fn checksum_matches_hand_computed_example() {
        // RFC 1071's own worked example: bytes 0x0001 0xf203 0xf4f5 0xf6f7,
        // checksum 0x220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn build_echo_request_sets_type_code_identifier_sequence() {
        let pkt = build_echo_request(0xABCD, 42, b"payload");
        assert_eq!(pkt[0], 8); // type: echo request
        assert_eq!(pkt[1], 0); // code
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0xABCD);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 42);
        assert_eq!(&pkt[8..], b"payload");
    }

    #[test]
    fn parse_icmp_from_ip_packet_skips_variable_length_ip_header() {
        // IHL=5 (0x45) -> 20-byte IPv4 header, no options.
        let mut ip_packet = vec![0x45u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let icmp = build_echo_request(0x1122, 7, b"x");
        // Overwrite type to Echo Reply (0) as if this were a real reply.
        let mut icmp = icmp;
        icmp[0] = 0;
        ip_packet.extend_from_slice(&icmp);

        let (typ, code, id, seq) = parse_icmp_from_ip_packet(&ip_packet).unwrap();
        assert_eq!(typ, 0);
        assert_eq!(code, 0);
        assert_eq!(id, 0x1122);
        assert_eq!(seq, 7);
    }

    #[test]
    fn parse_icmp_from_ip_packet_rejects_truncated_input() {
        assert_eq!(parse_icmp_from_ip_packet(&[]), None);
        assert_eq!(parse_icmp_from_ip_packet(&[0x45, 0, 0]), None);
    }

    /// Real end-to-end check: loopback always replies to ping. Needs
    /// CAP_NET_RAW (same capability main.rs already requires for
    /// SO_BINDTODEVICE) — run as root or with that capability granted, e.g.
    /// `docker run --cap-add=NET_RAW`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW — run explicitly, e.g. `cargo test -- --ignored`"]
    async fn probe_detects_loopback_as_in_use() {
        let seen = probe(Ipv4Addr::LOCALHOST, Duration::from_millis(500)).await;
        assert!(seen, "127.0.0.1 must always answer a ping");
    }

    /// TEST-NET-2 (RFC 5737, 198.51.100.0/24) is reserved for documentation
    /// — guaranteed to have no real host answering, anywhere, so this is
    /// safe to probe from CI without depending on the network's actual
    /// topology.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW — run explicitly, e.g. `cargo test -- --ignored`"]
    async fn probe_does_not_false_positive_on_an_unused_test_net_address() {
        let seen = probe("198.51.100.1".parse().unwrap(), Duration::from_millis(300)).await;
        assert!(!seen, "a TEST-NET-2 address must never appear to be in use");
    }
}
