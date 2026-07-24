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

//! DORA (DISCOVER/OFFER/REQUEST/ACK) + RELEASE/DECLINE/INFORM handling.
//!
//! Deliberately not raw-socket-based: replies to an un-addressed client are
//! sent as plain broadcast UDP (`SO_BROADCAST`, dest 255.255.255.255:68)
//! rather than a hand-crafted L2 frame via AF_PACKET. RFC 2131 §4.1 makes
//! broadcasting always acceptable even when a unicast-before-configured
//! optimization would also be legal — dnsmasq and other minimal servers make
//! the same call. That optimization, and dispatching direct-attached
//! clients across multiple listening interfaces, are the two things this
//! server doesn't do yet; both are additive, not correctness gaps for a
//! single-interface-or-relayed deployment (see `db::Snapshot::find_scope_for_direct`).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use dhcproto::v4::relay::{RelayCode, RelayInfo};
use dhcproto::v4::{Architecture, DhcpOption, DhcpOptions, Message, MessageType, Opcode, OptionCode};
use sqlx::PgPool;

use crate::config::Config;
use crate::db::{self, Scope, Snapshot};
use crate::options;

#[derive(Clone)]
pub struct Server {
    pub pool: PgPool,
    pub snapshot: Arc<ArcSwap<Snapshot>>,
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub metrics: Arc<crate::metrics::Counters>,
}

pub struct Reply {
    pub message: Message,
    pub dest: SocketAddr,
}

fn mac_from_chaddr(msg: &Message) -> String {
    // Ethernet (hlen 6) covers the overwhelming majority of real clients;
    // chaddr is zero-padded to 16 bytes regardless of hlen.
    let raw = msg.chaddr();
    raw[..6.min(raw.len())]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn message_type(msg: &Message) -> Option<MessageType> {
    match msg.opts().get(OptionCode::MessageType) {
        Some(DhcpOption::MessageType(t)) => Some(*t),
        _ => None,
    }
}

fn requested_ip(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    }
}

/// Option 54 (Server Identifier). Present on a SELECTING-state REQUEST to
/// name the one server the client is accepting; RFC 2131 §4.3.2 requires
/// every other server to silently ignore that REQUEST rather than also
/// ACK/NAK it. Absent on a RENEWING/REBINDING/INIT-REBOOT REQUEST, where
/// there's no selection to defer to and this server must still answer.
fn server_identifier(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    }
}

/// Where to send the reply: to the relay (giaddr) if relayed, otherwise
/// broadcast — see module docs for why this server never needs a raw
/// socket to reach an unconfigured direct-attached client.
fn reply_dest(req: &Message) -> SocketAddr {
    let giaddr = req.giaddr();
    if giaddr != Ipv4Addr::UNSPECIFIED {
        SocketAddr::new(giaddr.into(), 67)
    } else if req.flags().broadcast() || req.ciaddr() == Ipv4Addr::UNSPECIFIED {
        SocketAddr::new(Ipv4Addr::BROADCAST.into(), 68)
    } else {
        // Client already has ciaddr configured (renewing) — the kernel can
        // ARP it normally, so a plain unicast UDP send works.
        SocketAddr::new(req.ciaddr().into(), 68)
    }
}

fn base_reply(req: &Message, yiaddr: Ipv4Addr, siaddr: Ipv4Addr, mtype: MessageType, opts: DhcpOptions) -> Message {
    let mut reply = Message::new(Ipv4Addr::UNSPECIFIED, yiaddr, siaddr, req.giaddr(), req.chaddr());
    reply.set_opcode(Opcode::BootReply);
    reply.set_htype(req.htype());
    reply.set_xid(req.xid());
    reply.set_flags(req.flags());
    let mut opts = opts;
    opts.insert(DhcpOption::MessageType(mtype));
    reply.set_opts(opts);
    reply
}

/// Builds a DHCPNAK per RFC 2131 §4.3.2 + Table 3:
/// - carries the Server Identifier (option 54), which Table 3 marks MUST for
///   a DHCPNAK — a client can't tell whose NAK it is otherwise, and some
///   clients drop a NAK that lacks it;
/// - sets the broadcast flag when the request came via a relay (`giaddr`
///   set), so the relay broadcasts the NAK onto the client's link rather
///   than trying to unicast to a `ciaddr` the NAK is precisely telling the
///   client is invalid.
fn nak_reply(req: &Message, server_ip: Ipv4Addr) -> Message {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::ServerIdentifier(server_ip));
    let mut reply = base_reply(req, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, MessageType::Nak, opts);
    if req.giaddr() != Ipv4Addr::UNSPECIFIED {
        reply.set_flags(req.flags().set_broadcast());
    }
    reply
}

/// Destination for a DHCPNAK. Unlike `reply_dest`, a NAK with no relay is
/// ALWAYS broadcast (RFC 2131 §4.3.2: "the server broadcasts the DHCPNAK to
/// 0xffffffff") — it must never be unicast to the client's `ciaddr`, since
/// the point of the NAK is that that address is not valid on this link.
fn nak_dest(req: &Message) -> SocketAddr {
    let giaddr = req.giaddr();
    if giaddr != Ipv4Addr::UNSPECIFIED {
        SocketAddr::new(giaddr.into(), 67)
    } else {
        SocketAddr::new(Ipv4Addr::BROADCAST.into(), 68)
    }
}

/// A reservation's own PXE next-server (siaddr) overrides the scope default
/// when set — matches Kea's per-reservation `next-server` semantics.
fn siaddr_for(scope: &Scope, reservation: Option<&db::Reservation>) -> Ipv4Addr {
    reservation
        .and_then(|r| r.next_server)
        .or(scope.pxe_next_server)
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

/// Option 93 (Client System Architecture, RFC 4578): anything other than
/// code 0 (legacy BIOS PXE ROM) is treated as UEFI for `select_boot_filename`
/// — the two profiles operators actually care about — rather than modeling
/// every individual RFC 4578 architecture code as its own class.
fn is_uefi_client(req: &Message) -> bool {
    match req.opts().get(OptionCode::ClientSystemArchitecture) {
        Some(DhcpOption::ClientSystemArchitecture(arch)) => *arch != Architecture::X86_Bios,
        _ => false,
    }
}

/// Picks the boot filename to send: a reservation's own value wins over the
/// scope default within whichever arch-class applies, and the UEFI pair is
/// only consulted for a client `is_uefi_client` identifies as UEFI — a
/// scope/reservation that only ever set the BIOS field keeps working
/// exactly as before for every client, UEFI or not.
fn select_boot_filename<'a>(scope: &'a Scope, reservation: Option<&'a db::Reservation>, is_uefi: bool) -> Option<&'a str> {
    if is_uefi {
        if let Some(file) = reservation
            .and_then(|r| r.uefi_boot_filename.as_deref())
            .or(scope.pxe_uefi_boot_filename.as_deref())
        {
            return Some(file);
        }
    }
    reservation.and_then(|r| r.boot_filename.as_deref()).or(scope.pxe_boot_filename.as_deref())
}

/// Pulls circuit-id/remote-id (Option 82 sub-options 1/2) out of a relayed
/// packet, for `find_scope_for_relay`'s optional finer-grained matching —
/// see design.md §22.7.
fn relay_agent_info(req: &Message) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    match req.opts().get(OptionCode::RelayAgentInformation) {
        Some(DhcpOption::RelayAgentInformation(rai)) => {
            let circuit_id = match rai.get(RelayCode::AgentCircuitId) {
                Some(RelayInfo::AgentCircuitId(bytes)) => Some(bytes.clone()),
                _ => None,
            };
            let remote_id = match rai.get(RelayCode::AgentRemoteId) {
                Some(RelayInfo::AgentRemoteId(bytes)) => Some(bytes.clone()),
                _ => None,
            };
            (circuit_id, remote_id)
        }
        _ => (None, None),
    }
}

fn find_scope<'s>(snapshot: &'s Snapshot, req: &Message, recv_interface: Option<&str>) -> Option<&'s Scope> {
    let giaddr = req.giaddr();
    if giaddr != Ipv4Addr::UNSPECIFIED {
        let (circuit_id, remote_id) = relay_agent_info(req);
        snapshot.find_scope_for_relay(giaddr, circuit_id.as_deref(), remote_id.as_deref())
    } else {
        snapshot.find_scope_for_direct(recv_interface)
    }
}

impl Server {
    /// `recv_interface` identifies which socket the packet arrived on — see
    /// `db::Snapshot::find_scope_for_direct`'s docs. `None` for the wildcard
    /// socket (relayed traffic, or a scope with no `interface` restriction).
    pub async fn handle(&self, req: &Message, recv_interface: Option<&str>) -> Option<Reply> {
        let mtype = message_type(req)?;
        self.metrics.record(mtype);
        let snapshot = self.snapshot.load();
        let scope = find_scope(&snapshot, req, recv_interface)?;
        let mac = mac_from_chaddr(req);
        let client_id = match req.opts().get(OptionCode::ClientIdentifier) {
            Some(DhcpOption::ClientIdentifier(bytes)) => Some(hex::encode(bytes)),
            _ => None,
        };
        let requested_hostname = match req.opts().get(OptionCode::Hostname) {
            Some(DhcpOption::Hostname(h)) => Some(h.clone()),
            _ => None,
        };
        let reservation = snapshot.reservation_for(&scope.id, &mac).cloned();
        let custom_options = snapshot.custom_options_for(&scope.id, reservation.as_ref());

        let result = match mtype {
            MessageType::Discover => self.handle_discover(req, scope, &mac, reservation.as_ref(), &custom_options).await,
            MessageType::Request => {
                // A REQUEST addressed to a different server (SELECTING
                // state) must be silently ignored, not ACK'd/NAK'd by us
                // too — see `server_identifier`'s docs.
                if server_identifier(req).is_some_and(|sid| sid != self.cfg.server_ip) {
                    None
                } else {
                    self.handle_request(
                        req,
                        scope,
                        &mac,
                        client_id.as_deref(),
                        requested_hostname.as_deref(),
                        reservation.as_ref(),
                        &custom_options,
                    )
                    .await
                }
            }
            MessageType::Release => {
                // RFC 2131 §4.4.4: a DHCPRELEASE names the server it's
                // addressed to via option 54. Ignore one meant for a
                // different server (e.g. a client that broadcast rather than
                // unicast its RELEASE) rather than tearing down a lease this
                // server still considers ours. Same guard v6 already applies.
                if server_identifier(req).is_some_and(|sid| sid != self.cfg.server_ip) {
                    None
                } else {
                    match db::release(&self.pool, &scope.id, &mac).await {
                        Ok(Some(hostname)) if scope.ddns_enabled => {
                            self.notify_ddns("expire", scope, req.ciaddr(), Some(&hostname), &mac).await;
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!("release failed for {mac} in scope {}: {e}", scope.id),
                    }
                    None
                }
            }
            MessageType::Decline => {
                if let Some(ip) = requested_ip(req) {
                    match db::decline(&self.pool, &scope.id, ip, &mac).await {
                        Ok(true) => {}
                        Ok(false) => tracing::debug!("DECLINE for {ip} in scope {} ignored: not held by {mac}", scope.id),
                        Err(e) => tracing::warn!("decline failed for {ip} in scope {}: {e}", scope.id),
                    }
                }
                None
            }
            MessageType::Inform => self.handle_inform(req, scope, &custom_options).await,
            _ => None,
        };

        // Records OFFER/ACK/NAK — whatever the reply actually turned out to
        // be (e.g. a REQUEST can yield either an ACK or a NAK), rather than
        // assuming from the incoming message type alone.
        if let Some(reply) = &result {
            if let Some(reply_type) = message_type(&reply.message) {
                self.metrics.record(reply_type);
            }
        }
        result
    }

    async fn handle_discover(
        &self,
        req: &Message,
        scope: &Scope,
        mac: &str,
        reservation: Option<&db::Reservation>,
        custom_options: &[db::CustomOption],
    ) -> Option<Reply> {
        let offer_ip = if let Some(res) = reservation {
            res.ip_address
        } else if let Some(existing_ip) = db::active_lease_ip(&self.pool, &scope.id, mac).await {
            // Already holds a lease (renewing client re-discovering) — offer
            // the same address rather than scanning the pool for a new one.
            existing_ip
        } else {
            match self.pick_conflict_free_candidate(scope, mac).await {
                Some(ip) => ip,
                None => return None,
            }
        };

        let mut opts = options::build(scope, self.cfg.server_ip, self.cfg.filter_node_ip);
        options::apply_custom(&mut opts, custom_options);
        let mut reply = base_reply(req, offer_ip, siaddr_for(scope, reservation), MessageType::Offer, opts);
        if let Some(file) = select_boot_filename(scope, reservation, is_uefi_client(req)) {
            reply.set_fname_str(file);
        }
        Some(Reply { message: reply, dest: reply_dest(req) })
    }

    /// Scans the pool for a free address (`db::peek_free_ip_excluding`),
    /// ICMP-probing each candidate before offering it (conflict.rs) —
    /// bounded by `conflict_probe_max_attempts` so a pathological network
    /// (or an attacker answering every probe) can't turn one DISCOVER into
    /// an unbounded scan. A candidate the probe finds in use is recorded as
    /// declined (`mark_declined_preemptive`) so later scans — including
    /// this same scope's, from other mantis-dhcp instances — skip it too,
    /// not just this one OFFER.
    async fn pick_conflict_free_candidate(&self, scope: &Scope, mac: &str) -> Option<Ipv4Addr> {
        let mut excluded = std::collections::HashSet::new();
        let attempts = if self.cfg.conflict_detection_enabled { self.cfg.conflict_probe_max_attempts } else { 1 };

        for _ in 0..attempts.max(1) {
            let candidate = match db::peek_free_ip_excluding(&self.pool, scope, &excluded).await {
                Ok(Some(ip)) => ip,
                Ok(None) => {
                    tracing::warn!("scope {} ({}): pool exhausted, no OFFER for {mac}", scope.name, scope.id);
                    return None;
                }
                Err(e) => {
                    tracing::warn!("peek_free_ip failed for scope {}: {e}", scope.id);
                    return None;
                }
            };

            if !self.cfg.conflict_detection_enabled {
                return Some(candidate);
            }

            if crate::conflict::probe(candidate, self.cfg.conflict_probe_timeout).await {
                tracing::warn!(
                    "scope {} ({}): {candidate} answered an ICMP probe — already in use by something \
                     this server never allocated it to, excluding from allocation",
                    scope.name, scope.id
                );
                if let Err(e) = db::mark_declined_preemptive(&self.pool, &scope.id, candidate).await {
                    tracing::warn!("failed to record conflict for {candidate} in scope {}: {e}", scope.id);
                }
                excluded.insert(candidate);
                continue;
            }

            return Some(candidate);
        }

        tracing::warn!(
            "scope {} ({}): no conflict-free address found for {mac} after {attempts} attempts",
            scope.name, scope.id
        );
        None
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_request(
        &self,
        req: &Message,
        scope: &Scope,
        mac: &str,
        client_id: Option<&str>,
        hostname: Option<&str>,
        reservation: Option<&db::Reservation>,
        custom_options: &[db::CustomOption],
    ) -> Option<Reply> {
        let lease_s = scope.lease_time_s.max(1) as i64;
        let want = requested_ip(req).or_else(|| (req.ciaddr() != Ipv4Addr::UNSPECIFIED).then_some(req.ciaddr()));
        // Falls back to the reservation's configured hostname when the
        // client didn't send one — used for the DDNS notification below too,
        // so a reservation's hostname actually gets its A record even when
        // the client itself is silent about its hostname.
        let effective_hostname = hostname.or_else(|| reservation.and_then(|r| r.hostname.as_deref()));

        let granted: Option<Ipv4Addr> = if let Some(res) = reservation {
            if want.is_some_and(|ip| ip != res.ip_address) {
                None
            } else {
                match db::confirm_reservation(&self.pool, &scope.id, res.ip_address, mac, client_id, effective_hostname, lease_s).await {
                    Ok(()) => Some(res.ip_address),
                    Err(e) => {
                        tracing::warn!("confirm_reservation failed: {e}");
                        None
                    }
                }
            }
        } else if let Some(ip) = want {
            let in_pool = u32::from(ip) >= u32::from(scope.range_start) && u32::from(ip) <= u32::from(scope.range_end);
            if !in_pool {
                None
            } else {
                match db::claim_specific(&self.pool, scope, ip, mac, client_id, hostname, lease_s).await {
                    Ok(true) => Some(ip),
                    Ok(false) => None,
                    Err(e) => {
                        tracing::warn!("claim_specific failed: {e}");
                        None
                    }
                }
            }
        } else {
            match db::allocate(&self.pool, scope, mac, client_id, hostname, lease_s).await {
                Ok(ip) => Some(ip),
                Err(e) => {
                    tracing::warn!("allocate failed for scope {}: {e}", scope.id);
                    None
                }
            }
        };

        let Some(ip) = granted else {
            return Some(Reply { message: nak_reply(req, self.cfg.server_ip), dest: nak_dest(req) });
        };

        if scope.ddns_enabled {
            self.notify_ddns("add", scope, ip, effective_hostname, mac).await;
        }

        let mut opts = options::build(scope, self.cfg.server_ip, self.cfg.filter_node_ip);
        options::apply_custom(&mut opts, custom_options);
        let mut reply = base_reply(req, ip, siaddr_for(scope, reservation), MessageType::Ack, opts);
        if let Some(file) = select_boot_filename(scope, reservation, is_uefi_client(req)) {
            reply.set_fname_str(file);
        }
        Some(Reply { message: reply, dest: reply_dest(req) })
    }

    async fn handle_inform(&self, req: &Message, scope: &Scope, custom_options: &[db::CustomOption]) -> Option<Reply> {
        // RFC 2131 §4.3.5: an INFORM reply MUST NOT carry a lease expiration
        // time (`build_inform` strips options 51/58/59) — the client already
        // has its address and is only asking for configuration parameters.
        let mut opts = options::build_inform(scope, self.cfg.server_ip, self.cfg.filter_node_ip);
        options::apply_custom(&mut opts, custom_options);
        let reply = base_reply(req, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, MessageType::Ack, opts);
        Some(Reply { message: reply, dest: reply_dest(req) })
    }

    async fn notify_ddns(&self, event: &str, scope: &Scope, ip: Ipv4Addr, hostname: Option<&str>, mac: &str) {
        let ev = crate::ddns::V4Event { event, scope_id: &scope.id, ip, hostname, mac };
        crate::ddns::post_v4(&self.pool, &self.http, &self.cfg.control_url, &self.cfg.internal_token, ev).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v4::Flags;

    fn msg(ciaddr: Ipv4Addr, giaddr: Ipv4Addr, chaddr: &[u8], broadcast: bool) -> Message {
        let mut m = Message::new(ciaddr, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, giaddr, chaddr);
        let flags = if broadcast { Flags::new(0).set_broadcast() } else { Flags::new(0) };
        m.set_flags(flags);
        m
    }

    #[test]
    fn mac_from_chaddr_formats_first_six_bytes_lowercase_colon_hex() {
        let chaddr = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &chaddr, false);
        assert_eq!(mac_from_chaddr(&m), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn message_type_reads_option_53() {
        let mut m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        assert_eq!(message_type(&m), None);
        m.opts_mut().insert(DhcpOption::MessageType(MessageType::Discover));
        assert_eq!(message_type(&m), Some(MessageType::Discover));
    }

    #[test]
    fn requested_ip_reads_option_50() {
        let mut m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        assert_eq!(requested_ip(&m), None);
        let want: Ipv4Addr = "10.1.2.3".parse().unwrap();
        m.opts_mut().insert(DhcpOption::RequestedIpAddress(want));
        assert_eq!(requested_ip(&m), Some(want));
    }

    #[test]
    fn server_identifier_reads_option_54() {
        let mut m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        assert_eq!(server_identifier(&m), None);
        let sid: Ipv4Addr = "10.0.0.1".parse().unwrap();
        m.opts_mut().insert(DhcpOption::ServerIdentifier(sid));
        assert_eq!(server_identifier(&m), Some(sid));
    }

    #[test]
    fn relay_agent_info_extracts_circuit_and_remote_id() {
        use dhcproto::v4::relay::{RelayAgentInformation, RelayInfo};

        let mut m = msg(Ipv4Addr::UNSPECIFIED, "192.0.2.1".parse().unwrap(), &[0; 6], false);
        assert_eq!(relay_agent_info(&m), (None, None));

        let mut rai = RelayAgentInformation::default();
        rai.insert(RelayInfo::AgentCircuitId(vec![0x01, 0x02]));
        rai.insert(RelayInfo::AgentRemoteId(vec![0xaa, 0xbb]));
        m.opts_mut().insert(DhcpOption::RelayAgentInformation(rai));

        assert_eq!(relay_agent_info(&m), (Some(vec![0x01, 0x02]), Some(vec![0xaa, 0xbb])));
    }

    #[test]
    fn reply_dest_prefers_relay_when_giaddr_set() {
        let giaddr: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let m = msg(Ipv4Addr::UNSPECIFIED, giaddr, &[0; 6], false);
        assert_eq!(reply_dest(&m), SocketAddr::new(giaddr.into(), 67));
    }

    #[test]
    fn reply_dest_broadcasts_when_broadcast_flag_set() {
        let m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 6], true);
        assert_eq!(reply_dest(&m), SocketAddr::new(Ipv4Addr::BROADCAST.into(), 68));
    }

    #[test]
    fn reply_dest_broadcasts_when_client_has_no_ciaddr_yet() {
        let m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        assert_eq!(reply_dest(&m), SocketAddr::new(Ipv4Addr::BROADCAST.into(), 68));
    }

    #[test]
    fn reply_dest_unicasts_to_ciaddr_when_client_already_configured() {
        let ciaddr: Ipv4Addr = "10.1.2.3".parse().unwrap();
        let m = msg(ciaddr, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        assert_eq!(reply_dest(&m), SocketAddr::new(ciaddr.into(), 68));
    }

    #[test]
    fn nak_dest_broadcasts_even_when_client_has_a_ciaddr() {
        // A renewing client's REQUEST carries a ciaddr, but a NAK to it must
        // still be broadcast (RFC 2131 §4.3.2) — the ciaddr is exactly what
        // the NAK is declaring invalid, so unicasting there could black-hole.
        let ciaddr: Ipv4Addr = "10.1.2.3".parse().unwrap();
        let m = msg(ciaddr, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        assert_eq!(nak_dest(&m), SocketAddr::new(Ipv4Addr::BROADCAST.into(), 68));
    }

    #[test]
    fn nak_dest_routes_through_the_relay_when_giaddr_set() {
        let giaddr: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let m = msg(Ipv4Addr::UNSPECIFIED, giaddr, &[0; 6], false);
        assert_eq!(nak_dest(&m), SocketAddr::new(giaddr.into(), 67));
    }

    #[test]
    fn nak_reply_carries_the_server_identifier() {
        // RFC 2131 Table 3: a DHCPNAK MUST include option 54.
        let m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        let server_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let nak = nak_reply(&m, server_ip);
        assert_eq!(message_type(&nak), Some(MessageType::Nak));
        assert_eq!(nak.opts().get(OptionCode::ServerIdentifier), Some(&DhcpOption::ServerIdentifier(server_ip)));
    }

    #[test]
    fn nak_reply_sets_broadcast_flag_for_a_relayed_request() {
        // RFC 2131 §4.3.2: with giaddr set, the server sets the broadcast bit
        // so the relay broadcasts the NAK onto the client's link.
        let giaddr: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let m = msg(Ipv4Addr::UNSPECIFIED, giaddr, &[0; 6], false);
        let nak = nak_reply(&m, "10.0.0.1".parse().unwrap());
        assert!(nak.flags().broadcast(), "a relayed NAK must have the broadcast bit set");
    }

    #[test]
    fn nak_reply_leaves_broadcast_flag_untouched_for_a_direct_request() {
        let m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        let nak = nak_reply(&m, "10.0.0.1".parse().unwrap());
        assert!(!nak.flags().broadcast(), "a direct (unrelayed) NAK is L3-broadcast already; no need to force the flag");
    }

    fn test_scope(pxe_next_server: Option<Ipv4Addr>) -> Scope {
        Scope {
            id: "s1".to_string(),
            tenant_id: "t1".to_string(),
            name: "test".to_string(),
            subnet: "10.0.0.0/24".parse().unwrap(),
            range_start: "10.0.0.10".parse().unwrap(),
            range_end: "10.0.0.20".parse().unwrap(),
            router_ip: None,
            dns_servers: vec![],
            domain_name: None,
            interface: None,
            lease_time_s: 3600,
            renew_time_s: None,
            rebind_time_s: None,
            ddns_enabled: false,
            pxe_next_server,
            pxe_boot_filename: None,
            pxe_uefi_boot_filename: None,
        }
    }

    #[test]
    fn siaddr_for_prefers_reservation_next_server_over_scope_default() {
        let scope = test_scope(Some("10.0.0.1".parse().unwrap()));
        let res = db::Reservation {
            id: "r1".to_string(),
            ip_address: "10.0.0.15".parse().unwrap(),
            hostname: None,
            next_server: Some("10.0.0.2".parse().unwrap()),
            boot_filename: None,
            uefi_boot_filename: None,
        };
        assert_eq!(siaddr_for(&scope, Some(&res)), "10.0.0.2".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn siaddr_for_falls_back_to_scope_default() {
        let scope = test_scope(Some("10.0.0.1".parse().unwrap()));
        assert_eq!(siaddr_for(&scope, None), "10.0.0.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn siaddr_for_unspecified_when_nothing_configured() {
        let scope = test_scope(None);
        assert_eq!(siaddr_for(&scope, None), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn is_uefi_client_false_when_option_93_absent() {
        let m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        assert!(!is_uefi_client(&m));
    }

    #[test]
    fn is_uefi_client_false_for_legacy_bios_arch() {
        let mut m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        m.opts_mut().insert(DhcpOption::ClientSystemArchitecture(Architecture::X86_Bios));
        assert!(!is_uefi_client(&m));
    }

    #[test]
    fn is_uefi_client_true_for_uefi_arch_codes() {
        let mut m = msg(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 6], false);
        m.opts_mut().insert(DhcpOption::ClientSystemArchitecture(Architecture::X64));
        assert!(is_uefi_client(&m));
    }

    fn scope_with_pxe(bios: Option<&str>, uefi: Option<&str>) -> Scope {
        let mut s = test_scope(None);
        s.pxe_boot_filename = bios.map(str::to_string);
        s.pxe_uefi_boot_filename = uefi.map(str::to_string);
        s
    }

    #[test]
    fn select_boot_filename_uses_bios_field_for_a_bios_client() {
        let scope = scope_with_pxe(Some("pxelinux.0"), Some("shimx64.efi"));
        assert_eq!(select_boot_filename(&scope, None, false), Some("pxelinux.0"));
    }

    #[test]
    fn select_boot_filename_uses_uefi_field_for_a_uefi_client() {
        let scope = scope_with_pxe(Some("pxelinux.0"), Some("shimx64.efi"));
        assert_eq!(select_boot_filename(&scope, None, true), Some("shimx64.efi"));
    }

    #[test]
    fn select_boot_filename_falls_back_to_bios_field_when_no_uefi_field_set() {
        let scope = scope_with_pxe(Some("pxelinux.0"), None);
        assert_eq!(
            select_boot_filename(&scope, None, true),
            Some("pxelinux.0"),
            "a scope with only the BIOS field set must keep serving UEFI clients the same file, unchanged from before this feature existed"
        );
    }

    #[test]
    fn select_boot_filename_reservation_uefi_overrides_scope_uefi() {
        let scope = scope_with_pxe(Some("pxelinux.0"), Some("shimx64.efi"));
        let res = db::Reservation {
            id: "r1".to_string(),
            ip_address: "10.0.0.15".parse().unwrap(),
            hostname: None,
            next_server: None,
            boot_filename: None,
            uefi_boot_filename: Some("custom.efi".to_string()),
        };
        assert_eq!(select_boot_filename(&scope, Some(&res), true), Some("custom.efi"));
    }
}
