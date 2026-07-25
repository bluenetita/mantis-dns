#![no_main]

use std::net::Ipv6Addr;

use dhcproto::v6::Message;
use dhcproto::{Decodable, Decoder};
use libfuzzer_sys::fuzz_target;

// --- Copied from services/dhcp/mantis-dhcp/src/server6.rs's unwrap_relay /
// find_option_raw, verbatim except for visibility. Kept as a copy (not a
// `pub` export pulled in via a `mantis-dhcp` path dependency) so this fuzz
// binary stays dependency-free — pulling in the full daemon crate would
// drag tokio/sqlx/reqwest into every fuzz iteration's build for no reason,
// same "copy a small helper rather than add a dependency" call
// `mantis_dhcp::hostname()` already makes. If server6.rs's copy changes,
// this one needs updating by hand; there is no automated check for that.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelayHop {
    hop_count: u8,
    link_addr: Ipv6Addr,
    peer_addr: Ipv6Addr,
}

const RELAY_FORW: u8 = 12;
const OPT_RELAY_MSG: u16 = 9;

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
// --- end copy ---

// Mirrors server6.rs's `Server::handle_packet` exactly (its first two
// lines, before any DB/pool access begins): unwrap_relay() first, then
// dhcproto's own Message::decode() — same trust boundary as v4, but this
// one exercises our own hand-rolled byte-level relay parser too, not just
// the library's decoder (design.md §26 R8).
fuzz_target!(|data: &[u8]| {
    if let Some((inner, _hops)) = unwrap_relay(data) {
        let _ = Message::decode(&mut Decoder::new(inner));
    }
});
