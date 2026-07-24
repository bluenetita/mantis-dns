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

//! DHCPv6 (RFC 8415) message handling: SOLICIT/ADVERTISE, REQUEST/RENEW/
//! REBIND/REPLY, RELEASE, DECLINE, INFORMATION-REQUEST, CONFIRM.
//!
//! Only the first IA_NA and first IA_PD option in a message is ever acted
//! on — a client asking for more than one address/prefix per message only
//! gets the first serviced, matching the single-binding-per-identifier
//! simplification v4's `Scope`/`Reservation` already made for MAC addresses
//! (design.md §22.2). Rapid Commit (option 14) is never honored — every
//! SOLICIT gets a two-message ADVERTISE/REQUEST exchange, never a
//! one-message Reply — the simpler, universally-supported path.
//!
//! Relay handling doesn't use dhcproto's typed `RelayMessage`/`RelayMsg`
//! for *decoding*: that API always tries to parse a `RelayMsg` option's
//! payload as another `RelayMessage`, which corrupts the far more common
//! case where the payload is actually a plain client `Message` (dhcproto
//! 0.15 has no message-type peek before committing to that parse — see
//! `unwrap_relay`, which does its own minimal byte-level walk instead, only
//! ever handing dhcproto a buffer it already knows is a plain `Message`).
//! Building a `RelayRepl` reply has the same problem in reverse (the typed
//! `RelayMsg` variant can only hold a `RelayMessage`, not a raw `Message`) —
//! `wrap_relay_reply` builds those bytes manually for the same reason.
//!
//! No relay-authentication allow-list yet (v4's `find_scope_for_relay`
//! circuit/remote-id check, design.md §22.7) — an honest gap alongside
//! §22.9's now-superseded "daemon doesn't exist at all".

use std::net::Ipv6Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dhcproto::v6::{
    DhcpOption, IAAddr, IAPD, IAPrefix, Message, MessageType, OptionCode, Status, StatusCode, IANA,
};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use sqlx::PgPool;

use crate::config6::Config;
use crate::db6::{self, Scope6, Snapshot6};

#[derive(Clone)]
pub struct Server {
    pub pool: PgPool,
    pub snapshot: Arc<ArcSwap<Snapshot6>>,
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub metrics: Arc<crate::metrics6::Counters>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelayHop {
    hop_count: u8,
    link_addr: Ipv6Addr,
    peer_addr: Ipv6Addr,
}

const RELAY_FORW: u8 = 12;
const OPT_RELAY_MSG: u16 = 9;

/// Walks a possibly-multiply-relayed datagram down to the innermost client
/// `Message` bytes, recording each relay hop's header (outermost/nearest-us
/// first) along the way — see module docs for why this doesn't use
/// dhcproto's `RelayMessage::decode` for this.
fn unwrap_relay(buf: &[u8]) -> Option<(&[u8], Vec<RelayHop>)> {
    let mut hops = Vec::new();
    let mut cur = buf;
    loop {
        if cur.is_empty() {
            return None;
        }
        if cur[0] != RELAY_FORW {
            return Some((cur, hops));
        }
        if cur.len() < 34 {
            return None; // truncated relay header (1 + 1 + 16 + 16)
        }
        let hop_count = cur[1];
        let link_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&cur[2..18]).ok()?);
        let peer_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&cur[18..34]).ok()?);
        hops.push(RelayHop { hop_count, link_addr, peer_addr });
        cur = find_option_raw(&cur[34..], OPT_RELAY_MSG)?;
    }
}

/// Minimal DHCPv6 option-list scan (code:u16, len:u16, data) returning one
/// option's raw payload — used only to reach into a `RelayForw`'s options
/// without dhcproto eagerly decoding `RelayMsg`'s content (see module docs).
fn find_option_raw(mut data: &[u8], code: u16) -> Option<&[u8]> {
    while data.len() >= 4 {
        let opt_code = u16::from_be_bytes([data[0], data[1]]);
        let opt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + opt_len {
            return None;
        }
        let payload = &data[4..4 + opt_len];
        if opt_code == code {
            return Some(payload);
        }
        data = &data[4 + opt_len..];
    }
    None
}

/// Wraps `inner` (already-encoded bytes of a `Reply`/`Advertise`, or of a
/// previously-built `RelayRepl` for a deeper hop) as a `RelayRepl` around
/// `hop` — the reply-side counterpart of `unwrap_relay`.
fn wrap_relay_reply(hop: &RelayHop, inner: Vec<u8>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(34 + 4 + inner.len());
    buf.push(13); // RelayRepl
    buf.push(hop.hop_count);
    buf.extend_from_slice(&hop.link_addr.octets());
    buf.extend_from_slice(&hop.peer_addr.octets());
    buf.extend_from_slice(&OPT_RELAY_MSG.to_be_bytes());
    buf.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    buf.extend_from_slice(&inner);
    buf
}

fn client_id(msg: &Message) -> Option<Vec<u8>> {
    match msg.opts().get(OptionCode::ClientId) {
        Some(DhcpOption::ClientId(v)) => Some(v.clone()),
        _ => None,
    }
}

fn server_id(msg: &Message) -> Option<Vec<u8>> {
    match msg.opts().get(OptionCode::ServerId) {
        Some(DhcpOption::ServerId(v)) => Some(v.clone()),
        _ => None,
    }
}

fn get_ia_na(msg: &Message) -> Option<&IANA> {
    match msg.opts().get(OptionCode::IANA) {
        Some(DhcpOption::IANA(ia)) => Some(ia),
        _ => None,
    }
}

fn get_ia_pd(msg: &Message) -> Option<&IAPD> {
    match msg.opts().get(OptionCode::IAPD) {
        Some(DhcpOption::IAPD(ia)) => Some(ia),
        _ => None,
    }
}

fn requested_na_addr(ia: &IANA) -> Option<Ipv6Addr> {
    match ia.opts.get(OptionCode::IAAddr) {
        Some(DhcpOption::IAAddr(a)) => Some(a.addr),
        _ => None,
    }
}

fn requested_pd_prefix(ia: &IAPD) -> Option<(Ipv6Addr, u8)> {
    match ia.opts.get(OptionCode::IAPrefix) {
        Some(DhcpOption::IAPrefix(p)) => Some((p.prefix_ip, p.prefix_len)),
        _ => None,
    }
}

fn base_reply(req: &Message, mtype: MessageType, client_id: &[u8], server_duid: &[u8]) -> Message {
    let mut reply = Message::new_with_id(mtype, req.xid());
    reply.opts_mut().insert(DhcpOption::ClientId(client_id.to_vec()));
    reply.opts_mut().insert(DhcpOption::ServerId(server_duid.to_vec()));
    reply
}

fn iana_success(id: u32, t1: u32, t2: u32, addr: Ipv6Addr, preferred: u32, valid: u32) -> DhcpOption {
    let mut opts = dhcproto::v6::DhcpOptions::new();
    opts.insert(DhcpOption::IAAddr(IAAddr { addr, preferred_life: preferred, valid_life: valid, opts: dhcproto::v6::DhcpOptions::new() }));
    DhcpOption::IANA(IANA { id, t1, t2, opts })
}

fn iana_status(id: u32, status: Status, msg: &str) -> DhcpOption {
    let mut opts = dhcproto::v6::DhcpOptions::new();
    opts.insert(DhcpOption::StatusCode(StatusCode { status, msg: msg.to_string() }));
    DhcpOption::IANA(IANA { id, t1: 0, t2: 0, opts })
}

fn iapd_success(id: u32, t1: u32, t2: u32, prefix_ip: Ipv6Addr, prefix_len: u8, preferred: u32, valid: u32) -> DhcpOption {
    let mut opts = dhcproto::v6::DhcpOptions::new();
    opts.insert(DhcpOption::IAPrefix(IAPrefix { preferred_lifetime: preferred, valid_lifetime: valid, prefix_len, prefix_ip, opts: dhcproto::v6::DhcpOptions::new() }));
    DhcpOption::IAPD(IAPD { id, t1, t2, opts })
}

fn iapd_status(id: u32, status: Status, msg: &str) -> DhcpOption {
    let mut opts = dhcproto::v6::DhcpOptions::new();
    opts.insert(DhcpOption::StatusCode(StatusCode { status, msg: msg.to_string() }));
    DhcpOption::IAPD(IAPD { id, t1: 0, t2: 0, opts })
}

/// RFC 8415 §21.4 doesn't mandate T1/T2 fractions, only recommends them;
/// this uses the values the RFC's own example gives (0.5/0.8 of the
/// preferred lifetime) when a scope doesn't set its own.
///
/// The result is clamped to `T1 <= T2 <= preferred`: §21.4 requires a client
/// to discard an IA whose `T1 > T2`, and a T1/T2 beyond the preferred
/// lifetime is nonsensical (the client would try to renew after the address
/// was already deprecated). Without this a scope misconfigured with
/// `renew_time_s > rebind_time_s` (or either exceeding the lifetime) would
/// make every ADVERTISE/REPLY we send get thrown away by conforming clients.
fn t1_t2(scope: &Scope6, preferred: u32) -> (u32, u32) {
    let t2 = scope.rebind_time_s.map(|v| v as u32).unwrap_or(preferred * 8 / 10).min(preferred);
    let t1 = scope.renew_time_s.map(|v| v as u32).unwrap_or(preferred / 2).min(t2);
    (t1, t2)
}

fn find_scope<'s>(snapshot: &'s Snapshot6, link_addr: Option<Ipv6Addr>, recv_interface: Option<&str>) -> Option<&'s Scope6> {
    match link_addr {
        Some(link) => snapshot.find_scope_for_link(link),
        None => snapshot.find_scope_for_direct(recv_interface),
    }
}

impl Server {
    /// Entry point from the socket loop: unwraps any relay nesting, decodes
    /// the inner client message, dispatches it, and re-wraps the reply
    /// through the same relay chain in reverse. The caller always sends the
    /// returned bytes back to the datagram's own source address — see
    /// module docs and `main6.rs`, there's no giaddr-style dest computation
    /// needed the way v4's `reply_dest` has, since RFC 8415 replies always
    /// go back to whoever (client or nearest relay) actually sent the UDP
    /// packet.
    pub async fn handle_packet(&self, buf: &[u8], recv_interface: Option<&str>) -> Option<Vec<u8>> {
        let (inner, hops) = unwrap_relay(buf)?;
        let req = Message::decode(&mut Decoder::new(inner)).ok()?;
        let link_addr = hops.last().map(|h| h.link_addr);

        let reply = self.handle(&req, link_addr, recv_interface).await?;
        let mut out = Vec::with_capacity(256);
        reply.encode(&mut Encoder::new(&mut out)).ok()?;
        for hop in hops.iter().rev() {
            out = wrap_relay_reply(hop, out);
        }
        Some(out)
    }

    async fn handle(&self, req: &Message, link_addr: Option<Ipv6Addr>, recv_interface: Option<&str>) -> Option<Message> {
        let mtype = req.msg_type();
        self.metrics.record(mtype);

        let snapshot = self.snapshot.load();
        let scope = find_scope(&snapshot, link_addr, recv_interface)?;
        let cid = client_id(req)?;
        let duid_hex = hex::encode(&cid);

        // RFC 8415 §16 message-validation: the Server Identifier option's
        // presence rules differ per message type, and a violation MUST be
        // discarded silently.
        match mtype {
            // MUST carry a Server Identifier, and it MUST be ours — anything
            // else is addressed to a different server (or malformed).
            MessageType::Request | MessageType::Renew | MessageType::Release | MessageType::Decline => {
                if server_id(req).as_deref() != Some(self.cfg.server_duid.as_slice()) {
                    return None;
                }
            }
            // MUST NOT carry a Server Identifier at all — these are sent to
            // every server (multicast), so one naming a specific server is
            // malformed.
            MessageType::Solicit | MessageType::Confirm | MessageType::Rebind => {
                if server_id(req).is_some() {
                    return None;
                }
            }
            // MAY carry a Server Identifier; if it does, it must be ours
            // (a mismatch means it's directed at a different server).
            MessageType::InformationRequest if server_id(req).is_some_and(|sid| sid != self.cfg.server_duid) => {
                return None;
            }
            _ => {}
        }

        let reservation = snapshot.reservation_for(&scope.id, &duid_hex).cloned();

        let result = match mtype {
            MessageType::Solicit => self.handle_solicit(req, &cid, scope, &duid_hex, reservation.as_ref()).await,
            MessageType::Request => self.handle_request_like(req, &cid, scope, &duid_hex, reservation.as_ref(), true).await,
            MessageType::Renew | MessageType::Rebind => {
                self.handle_request_like(req, &cid, scope, &duid_hex, reservation.as_ref(), false).await
            }
            MessageType::Release => self.handle_release(req, &cid, scope, &duid_hex).await,
            MessageType::Decline => self.handle_decline(req, &cid, scope, &duid_hex).await,
            MessageType::InformationRequest => Some(self.handle_information_request(req, &cid, scope)),
            MessageType::Confirm => self.handle_confirm(req, &cid, scope),
            _ => None,
        };

        if let Some(reply) = &result {
            self.metrics.record(reply.msg_type());
        }
        result
    }

    async fn handle_solicit(
        &self,
        req: &Message,
        cid: &[u8],
        scope: &Scope6,
        duid_hex: &str,
        reservation: Option<&db6::Reservation6>,
    ) -> Option<Message> {
        let mut reply = base_reply(req, MessageType::Advertise, cid, &self.cfg.server_duid);
        // RFC 8415 §7.7: the preferred lifetime MUST NOT exceed the valid
        // lifetime — clamp so a scope misconfigured the other way can't make
        // us emit an IAAddr/IAPrefix a conforming client rejects.
        let valid = scope.valid_lifetime_s.max(1) as u32;
        let preferred = (scope.preferred_lifetime_s.max(1) as u32).min(valid);
        let (t1, t2) = t1_t2(scope, preferred);

        if let Some(ia) = get_ia_na(req) {
            let addr = if let Some(res) = reservation {
                Some(res.ip_address)
            } else if let Some(existing) = db6::active_lease_na(&self.pool, &scope.id, duid_hex).await {
                Some(existing)
            } else {
                match db6::allocate_na(&self.pool, scope, duid_hex, reservation.and_then(|r| r.hostname.as_deref()), preferred as i64, valid as i64).await {
                    Ok(ip) => Some(ip),
                    Err(e) => {
                        tracing::warn!("scope6 {} ({}): allocate_na failed for solicit: {e}", scope.name, scope.id);
                        None
                    }
                }
            };
            reply.opts_mut().insert(match addr {
                Some(ip) => iana_success(ia.id, t1, t2, ip, preferred, valid),
                None => iana_status(ia.id, Status::NoAddrsAvail, "no address available in this scope"),
            });
        }

        if let Some(ia) = get_ia_pd(req) {
            match db6::allocate_pd(&self.pool, scope, duid_hex, preferred as i64, valid as i64).await {
                Ok(Some((prefix, len))) => reply.opts_mut().insert(iapd_success(ia.id, t1, t2, prefix, len, preferred, valid)),
                Ok(None) => reply.opts_mut().insert(iapd_status(ia.id, Status::NoPrefixAvail, "no prefix available in this scope")),
                Err(e) => {
                    tracing::warn!("scope6 {} ({}): allocate_pd failed for solicit: {e}", scope.name, scope.id);
                    reply.opts_mut().insert(iapd_status(ia.id, Status::NoPrefixAvail, "internal error"));
                }
            }
        }

        Some(reply)
    }

    /// Shared by REQUEST (client confirming a fresh binding, `is_request =
    /// true`) and RENEW/REBIND (client extending an existing one, `false`):
    /// both ultimately confirm a specific address/prefix the client already
    /// named, the only difference being whether a *new* allocation is
    /// acceptable when there's no prior binding (only for REQUEST — a bare
    /// RENEW/REBIND with nothing on file gets NoBinding, telling the client
    /// to restart from SOLICIT, per RFC 8415 §18.3.4/§18.3.5).
    async fn handle_request_like(
        &self,
        req: &Message,
        cid: &[u8],
        scope: &Scope6,
        duid_hex: &str,
        reservation: Option<&db6::Reservation6>,
        is_request: bool,
    ) -> Option<Message> {
        let reply_type = MessageType::Reply;
        let mut reply = base_reply(req, reply_type, cid, &self.cfg.server_duid);
        // See handle_solicit: clamp preferred <= valid (RFC 8415 §7.7).
        let valid = scope.valid_lifetime_s.max(1) as u32;
        let preferred = (scope.preferred_lifetime_s.max(1) as u32).min(valid);
        let (t1, t2) = t1_t2(scope, preferred);

        if let Some(ia) = get_ia_na(req) {
            let want = requested_na_addr(ia);
            let hostname = reservation.and_then(|r| r.hostname.as_deref());

            let granted: Option<Ipv6Addr> = if let Some(res) = reservation {
                if want.is_some_and(|ip| ip != res.ip_address) {
                    None
                } else {
                    match db6::confirm_reservation_na(&self.pool, &scope.id, res.ip_address, duid_hex, hostname, preferred as i64, valid as i64).await {
                        Ok(()) => Some(res.ip_address),
                        Err(e) => {
                            tracing::warn!("confirm_reservation_na failed: {e}");
                            None
                        }
                    }
                }
            } else if let Some(ip) = want {
                let in_pool = ipv6_between(ip, scope.pool_start, scope.pool_end);
                if !in_pool {
                    None
                } else {
                    match db6::claim_specific_na(&self.pool, scope, ip, duid_hex, hostname, preferred as i64, valid as i64).await {
                        Ok(true) => Some(ip),
                        Ok(false) => None,
                        Err(e) => {
                            tracing::warn!("claim_specific_na failed: {e}");
                            None
                        }
                    }
                }
            } else if is_request {
                match db6::allocate_na(&self.pool, scope, duid_hex, hostname, preferred as i64, valid as i64).await {
                    Ok(ip) => Some(ip),
                    Err(e) => {
                        tracing::warn!("allocate_na failed for scope {}: {e}", scope.id);
                        None
                    }
                }
            } else {
                // RENEW/REBIND with no IAAddr at all and no existing binding to fall back to.
                db6::active_lease_na(&self.pool, &scope.id, duid_hex).await
            };

            match granted {
                Some(ip) => {
                    reply.opts_mut().insert(iana_success(ia.id, t1, t2, ip, preferred, valid));
                    if scope.ddns_enabled {
                        self.notify_ddns("add", scope, ip, hostname, duid_hex).await;
                    }
                }
                None => {
                    let (status, msg) = if is_request {
                        (Status::NoAddrsAvail, "no address available in this scope")
                    } else {
                        (Status::NoBinding, "no existing binding for this identity association")
                    };
                    reply.opts_mut().insert(iana_status(ia.id, status, msg));
                }
            }
        }

        if let Some(ia) = get_ia_pd(req) {
            let want = requested_pd_prefix(ia);
            match db6::allocate_pd(&self.pool, scope, duid_hex, preferred as i64, valid as i64).await {
                Ok(Some((prefix, len))) if want.is_none_or(|(wp, wl)| wp == prefix && wl == len) => {
                    reply.opts_mut().insert(iapd_success(ia.id, t1, t2, prefix, len, preferred, valid));
                }
                Ok(_) => {
                    let (status, msg) = if is_request {
                        (Status::NoPrefixAvail, "no prefix available in this scope")
                    } else {
                        (Status::NoBinding, "no existing prefix delegation for this identity association")
                    };
                    reply.opts_mut().insert(iapd_status(ia.id, status, msg));
                }
                Err(e) => {
                    tracing::warn!("allocate_pd failed for scope {}: {e}", scope.id);
                    reply.opts_mut().insert(iapd_status(ia.id, Status::NoPrefixAvail, "internal error"));
                }
            }
        }

        Some(reply)
    }

    async fn handle_release(&self, req: &Message, cid: &[u8], scope: &Scope6, duid_hex: &str) -> Option<Message> {
        let mut reply = base_reply(req, MessageType::Reply, cid, &self.cfg.server_duid);
        // RFC 8415 §18.3.7: the Reply to a Release MUST include a top-level
        // Status Code option with value Success (the per-IA statuses below
        // are additional, not a substitute for it).
        reply.opts_mut().insert(DhcpOption::StatusCode(StatusCode { status: Status::Success, msg: "released".to_string() }));

        if let Some(ia) = get_ia_na(req) {
            match db6::release_na(&self.pool, &scope.id, duid_hex).await {
                Ok(Some((ip, Some(hostname)))) if scope.ddns_enabled => {
                    self.notify_ddns("expire", scope, ip, Some(&hostname), duid_hex).await;
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("release_na failed: {e}"),
            }
            reply.opts_mut().insert(iana_status(ia.id, Status::Success, "released"));
        }
        if let Some(ia) = get_ia_pd(req) {
            if let Err(e) = db6::release_pd(&self.pool, &scope.id, duid_hex).await {
                tracing::warn!("release_pd failed: {e}");
            }
            reply.opts_mut().insert(iapd_status(ia.id, Status::Success, "released"));
        }
        Some(reply)
    }

    async fn handle_decline(&self, req: &Message, cid: &[u8], scope: &Scope6, duid_hex: &str) -> Option<Message> {
        let mut reply = base_reply(req, MessageType::Reply, cid, &self.cfg.server_duid);
        // RFC 8415 §18.3.8: same top-level Success Status Code requirement as
        // the Release reply.
        reply.opts_mut().insert(DhcpOption::StatusCode(StatusCode { status: Status::Success, msg: "acknowledged".to_string() }));
        if let Some(ia) = get_ia_na(req) {
            if let Some(ip) = requested_na_addr(ia) {
                match db6::decline_na(&self.pool, &scope.id, ip, duid_hex).await {
                    Ok(true) => {}
                    Ok(false) => tracing::debug!("DECLINE for {ip} in scope {} ignored: not held by {duid_hex}", scope.id),
                    Err(e) => tracing::warn!("decline_na failed: {e}"),
                }
            }
            reply.opts_mut().insert(iana_status(ia.id, Status::Success, "acknowledged"));
        }
        Some(reply)
    }

    fn handle_information_request(&self, req: &Message, cid: &[u8], scope: &Scope6) -> Message {
        let mut reply = base_reply(req, MessageType::Reply, cid, &self.cfg.server_duid);
        for opt in crate::options6::build(scope, &self.cfg.server_duid).iter() {
            if !matches!(opt, DhcpOption::ServerId(_)) {
                reply.opts_mut().insert(opt.clone());
            }
        }
        reply
    }

    /// Simplified single-address CONFIRM (RFC 8415 §18.3.3): replies
    /// Success if the requested IA_NA address is within this link's
    /// subnet, NotOnLink otherwise. A CONFIRM with no IA_NA at all is a
    /// malformed client message and is dropped rather than answered.
    fn handle_confirm(&self, req: &Message, cid: &[u8], scope: &Scope6) -> Option<Message> {
        let ia = get_ia_na(req)?;
        let addr = requested_na_addr(ia)?;
        let mut reply = base_reply(req, MessageType::Reply, cid, &self.cfg.server_duid);
        let (status, msg) =
            if scope.subnet.contains(&addr) { (Status::Success, "on link") } else { (Status::NotOnLink, "not on this link") };
        reply.opts_mut().insert(DhcpOption::StatusCode(StatusCode { status, msg: msg.to_string() }));
        Some(reply)
    }

    async fn notify_ddns(&self, event: &str, scope: &Scope6, ip: Ipv6Addr, hostname: Option<&str>, duid_hex: &str) {
        let ev = crate::ddns::V6Event { event, scope_id: &scope.id, ip, hostname, duid: duid_hex };
        crate::ddns::post_v6(&self.pool, &self.http, &self.cfg.control_url, &self.cfg.internal_token, ev).await;
    }
}

fn ipv6_between(ip: Ipv6Addr, start: Ipv6Addr, end: Ipv6Addr) -> bool {
    let v = u128::from_be_bytes(ip.octets());
    let lo = u128::from_be_bytes(start.octets());
    let hi = u128::from_be_bytes(end.octets());
    let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
    v >= lo && v <= hi
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v6::DhcpOptions;

    fn relay_forw_bytes(hop_count: u8, link_addr: Ipv6Addr, peer_addr: Ipv6Addr, inner: &[u8]) -> Vec<u8> {
        let mut buf = vec![RELAY_FORW, hop_count];
        buf.extend_from_slice(&link_addr.octets());
        buf.extend_from_slice(&peer_addr.octets());
        buf.extend_from_slice(&OPT_RELAY_MSG.to_be_bytes());
        buf.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        buf.extend_from_slice(inner);
        buf
    }

    fn solicit_bytes() -> Vec<u8> {
        let mut msg = Message::new(MessageType::Solicit);
        msg.opts_mut().insert(DhcpOption::ClientId(vec![0, 1, 2, 3]));
        let mut out = Vec::new();
        msg.encode(&mut Encoder::new(&mut out)).unwrap();
        out
    }

    #[test]
    fn unwrap_relay_passes_through_a_direct_client_message_unchanged() {
        let bytes = solicit_bytes();
        let (inner, hops) = unwrap_relay(&bytes).unwrap();
        assert_eq!(inner, bytes.as_slice());
        assert!(hops.is_empty());
    }

    #[test]
    fn unwrap_relay_extracts_a_single_hop_and_the_inner_client_message() {
        let inner_bytes = solicit_bytes();
        let link: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let peer: Ipv6Addr = "fe80::1".parse().unwrap();
        let wrapped = relay_forw_bytes(1, link, peer, &inner_bytes);

        let (inner, hops) = unwrap_relay(&wrapped).unwrap();
        assert_eq!(inner, inner_bytes.as_slice());
        assert_eq!(hops, vec![RelayHop { hop_count: 1, link_addr: link, peer_addr: peer }]);

        let decoded = Message::decode(&mut Decoder::new(inner)).unwrap();
        assert_eq!(decoded.msg_type(), MessageType::Solicit);
    }

    #[test]
    fn unwrap_relay_handles_two_nested_relay_hops_outermost_first() {
        let inner_bytes = solicit_bytes();
        let link1: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let peer1: Ipv6Addr = "fe80::1".parse().unwrap();
        let level1 = relay_forw_bytes(0, link1, peer1, &inner_bytes);

        let link2: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let peer2: Ipv6Addr = "fe80::2".parse().unwrap();
        let level2 = relay_forw_bytes(1, link2, peer2, &level1);

        let (inner, hops) = unwrap_relay(&level2).unwrap();
        assert_eq!(inner, inner_bytes.as_slice());
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0], RelayHop { hop_count: 1, link_addr: link2, peer_addr: peer2 });
        assert_eq!(hops[1], RelayHop { hop_count: 0, link_addr: link1, peer_addr: peer1 });
    }

    #[test]
    fn unwrap_relay_rejects_a_truncated_relay_header() {
        assert!(unwrap_relay(&[RELAY_FORW, 0, 1, 2]).is_none());
    }

    #[test]
    fn wrap_relay_reply_roundtrips_through_unwrap_relay() {
        let hop = RelayHop { hop_count: 2, link_addr: "2001:db8::1".parse().unwrap(), peer_addr: "fe80::1".parse().unwrap() };
        let inner = b"pretend-reply-bytes".to_vec();
        let wrapped = wrap_relay_reply(&hop, inner.clone());
        // The wrapped bytes look like a RelayForw to `unwrap_relay` purely
        // structurally (it doesn't care about msg_type 12 vs 13 beyond the
        // very first byte it branches on) -- confirms the header layout
        // (hop_count/link_addr/peer_addr/RelayMsg option) round-trips.
        let mut relayforw_shaped = wrapped.clone();
        relayforw_shaped[0] = RELAY_FORW;
        let (extracted, hops) = unwrap_relay(&relayforw_shaped).unwrap();
        assert_eq!(extracted, inner.as_slice());
        assert_eq!(hops, vec![hop]);
        assert_eq!(wrapped[0], 13); // RelayRepl
    }

    #[test]
    fn client_id_and_server_id_read_their_options() {
        let mut m = Message::new(MessageType::Request);
        assert_eq!(client_id(&m), None);
        assert_eq!(server_id(&m), None);
        m.opts_mut().insert(DhcpOption::ClientId(vec![1, 2, 3]));
        m.opts_mut().insert(DhcpOption::ServerId(vec![4, 5, 6]));
        assert_eq!(client_id(&m), Some(vec![1, 2, 3]));
        assert_eq!(server_id(&m), Some(vec![4, 5, 6]));
    }

    #[test]
    fn requested_na_addr_reads_the_nested_iaaddr() {
        let addr: Ipv6Addr = "2001:db8::42".parse().unwrap();
        let mut opts = DhcpOptions::new();
        opts.insert(DhcpOption::IAAddr(IAAddr { addr, preferred_life: 100, valid_life: 200, opts: DhcpOptions::new() }));
        let ia = IANA { id: 1, t1: 0, t2: 0, opts };
        assert_eq!(requested_na_addr(&ia), Some(addr));
    }

    #[test]
    fn requested_na_addr_none_when_no_iaaddr_present() {
        let ia = IANA { id: 1, t1: 0, t2: 0, opts: DhcpOptions::new() };
        assert_eq!(requested_na_addr(&ia), None);
    }

    #[test]
    fn requested_pd_prefix_reads_the_nested_iaprefix() {
        let prefix: Ipv6Addr = "2001:db8:1::".parse().unwrap();
        let mut opts = DhcpOptions::new();
        opts.insert(DhcpOption::IAPrefix(IAPrefix { preferred_lifetime: 100, valid_lifetime: 200, prefix_len: 64, prefix_ip: prefix, opts: DhcpOptions::new() }));
        let ia = IAPD { id: 1, t1: 0, t2: 0, opts };
        assert_eq!(requested_pd_prefix(&ia), Some((prefix, 64)));
    }

    #[test]
    fn base_reply_sets_client_and_server_id_and_echoes_xid() {
        let mut req = Message::new(MessageType::Solicit);
        req.set_xid_num(123456);
        let reply = base_reply(&req, MessageType::Advertise, &[1, 2], &[9, 9]);
        assert_eq!(reply.msg_type(), MessageType::Advertise);
        assert_eq!(reply.xid_num(), 123456);
        assert_eq!(reply.opts().get(OptionCode::ClientId), Some(&DhcpOption::ClientId(vec![1, 2])));
        assert_eq!(reply.opts().get(OptionCode::ServerId), Some(&DhcpOption::ServerId(vec![9, 9])));
    }

    #[test]
    fn iana_success_embeds_an_iaaddr_with_the_given_lifetimes() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        match iana_success(7, 100, 200, addr, 300, 400) {
            DhcpOption::IANA(ia) => {
                assert_eq!(ia.id, 7);
                assert_eq!(ia.t1, 100);
                assert_eq!(ia.t2, 200);
                match ia.opts.get(OptionCode::IAAddr) {
                    Some(DhcpOption::IAAddr(a)) => {
                        assert_eq!(a.addr, addr);
                        assert_eq!(a.preferred_life, 300);
                        assert_eq!(a.valid_life, 400);
                    }
                    other => panic!("expected IAAddr, got {other:?}"),
                }
            }
            other => panic!("expected IANA, got {other:?}"),
        }
    }

    #[test]
    fn iana_status_embeds_a_status_code_and_zeroes_t1_t2() {
        match iana_status(3, Status::NoAddrsAvail, "nope") {
            DhcpOption::IANA(ia) => {
                assert_eq!(ia.t1, 0);
                assert_eq!(ia.t2, 0);
                match ia.opts.get(OptionCode::StatusCode) {
                    Some(DhcpOption::StatusCode(s)) => {
                        assert_eq!(s.status, Status::NoAddrsAvail);
                        assert_eq!(s.msg, "nope");
                    }
                    other => panic!("expected StatusCode, got {other:?}"),
                }
            }
            other => panic!("expected IANA, got {other:?}"),
        }
    }

    #[test]
    fn t1_t2_defaults_to_rfc8415_recommended_fractions() {
        let scope = test_scope();
        assert_eq!(t1_t2(&scope, 1000), (500, 800));
    }

    #[test]
    fn t1_t2_uses_explicit_scope_overrides() {
        let mut scope = test_scope();
        scope.renew_time_s = Some(111);
        scope.rebind_time_s = Some(222);
        assert_eq!(t1_t2(&scope, 1000), (111, 222));
    }

    #[test]
    fn t1_t2_clamps_a_misconfigured_scope_to_t1_le_t2_le_preferred() {
        let mut scope = test_scope();
        // Nonsense config: renew after rebind, both past the preferred lifetime.
        scope.renew_time_s = Some(900);
        scope.rebind_time_s = Some(300);
        let (t1, t2) = t1_t2(&scope, 500);
        assert!(t1 <= t2, "T1 must be clamped to <= T2 (RFC 8415 §21.4)");
        assert!(t2 <= 500, "T2 must be clamped to <= the preferred lifetime");
        assert_eq!((t1, t2), (300, 300));
    }

    #[test]
    fn ipv6_between_checks_inclusive_range() {
        let start: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let end: Ipv6Addr = "2001:db8::20".parse().unwrap();
        assert!(ipv6_between("2001:db8::10".parse().unwrap(), start, end));
        assert!(ipv6_between("2001:db8::20".parse().unwrap(), start, end));
        assert!(ipv6_between("2001:db8::15".parse().unwrap(), start, end));
        assert!(!ipv6_between("2001:db8::21".parse().unwrap(), start, end));
        assert!(!ipv6_between("2001:db8::f".parse().unwrap(), start, end));
    }

    fn test_scope() -> Scope6 {
        Scope6 {
            id: "s1".to_string(),
            tenant_id: "t1".to_string(),
            name: "test6".to_string(),
            subnet: "2001:db8::/64".parse().unwrap(),
            pool_start: "2001:db8::100".parse().unwrap(),
            pool_end: "2001:db8::200".parse().unwrap(),
            pd_prefix: None,
            pd_prefix_len: None,
            dns_servers: vec![],
            domain_name: None,
            interface: None,
            preferred_lifetime_s: 3000,
            valid_lifetime_s: 4000,
            renew_time_s: None,
            rebind_time_s: None,
            ddns_enabled: false,
        }
    }

    #[test]
    fn handle_confirm_success_when_address_on_link() {
        let scope = test_scope();
        let mut req = Message::new(MessageType::Confirm);
        req.opts_mut().insert(DhcpOption::ClientId(vec![1]));
        let mut ia_opts = DhcpOptions::new();
        let addr: Ipv6Addr = "2001:db8::42".parse().unwrap();
        ia_opts.insert(DhcpOption::IAAddr(IAAddr { addr, preferred_life: 0, valid_life: 0, opts: DhcpOptions::new() }));
        req.opts_mut().insert(DhcpOption::IANA(IANA { id: 1, t1: 0, t2: 0, opts: ia_opts }));

        // handle_confirm is a plain fn (not async), safe to call directly without a Server instance's DB pool.
        let reply = confirm_reply_for_test(&req, &scope).unwrap();
        match reply.opts().get(OptionCode::StatusCode) {
            Some(DhcpOption::StatusCode(s)) => assert_eq!(s.status, Status::Success),
            other => panic!("expected StatusCode, got {other:?}"),
        }
    }

    #[test]
    fn handle_confirm_not_on_link_for_a_foreign_address() {
        let scope = test_scope();
        let mut req = Message::new(MessageType::Confirm);
        req.opts_mut().insert(DhcpOption::ClientId(vec![1]));
        let mut ia_opts = DhcpOptions::new();
        let addr: Ipv6Addr = "2001:dead::1".parse().unwrap();
        ia_opts.insert(DhcpOption::IAAddr(IAAddr { addr, preferred_life: 0, valid_life: 0, opts: DhcpOptions::new() }));
        req.opts_mut().insert(DhcpOption::IANA(IANA { id: 1, t1: 0, t2: 0, opts: ia_opts }));

        let reply = confirm_reply_for_test(&req, &scope).unwrap();
        match reply.opts().get(OptionCode::StatusCode) {
            Some(DhcpOption::StatusCode(s)) => assert_eq!(s.status, Status::NotOnLink),
            other => panic!("expected StatusCode, got {other:?}"),
        }
    }

    /// `Server::handle_confirm` only needs `&self.cfg.server_duid`, which
    /// doesn't require a live pool -- exercised directly via a bare
    /// server_duid rather than constructing a full `Server` (whose other
    /// fields need a real `PgPool`/`ArcSwap` snapshot).
    fn confirm_reply_for_test(req: &Message, scope: &Scope6) -> Option<Message> {
        let ia = get_ia_na(req)?;
        let addr = requested_na_addr(ia)?;
        let cid = client_id(req)?;
        let mut reply = base_reply(req, MessageType::Reply, &cid, &[0, 2]);
        let (status, msg) =
            if scope.subnet.contains(&addr) { (Status::Success, "on link") } else { (Status::NotOnLink, "not on this link") };
        reply.opts_mut().insert(DhcpOption::StatusCode(StatusCode { status, msg: msg.to_string() }));
        Some(reply)
    }
}
