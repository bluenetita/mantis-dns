/*
 * Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Query-level RFC 1035/6891 conformance, shared by every listener loop
//! (`run_udp_server`, `run_tcp_server`, `run_router_udp_server`,
//! `run_router_tcp_server`) via `build_response` so no transport can drift
//! from another the way the hand-rolled loops previously did. This is
//! Phase 1 of docs/rfc-compliance.md §3 — see that file for the audit
//! (finding IDs referenced in comments below) and for what is deliberately
//! deferred to later phases (SOA on negative answers, DNSSEC pass-through,
//! DNS cookies, ...).

use std::net::IpAddr;

use hickory_proto::op::{Edns, Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use sha2::{Digest, Sha256};

/// Highest EDNS version this server understands (RFC 6891 §6.1.3) — bump
/// only alongside code that actually speaks a higher version.
const MAX_EDNS_VERSION: u8 = 0;

/// Highest EDNS0 payload size this server will ever advertise/honor, even if
/// a client asks for more — keeps worst-case UDP responses well clear of
/// common path-MTU/fragmentation limits. Also used by
/// `enforce_udp_size_limit`.
pub(crate) const MAX_UDP_PAYLOAD: u16 = 4096;

/// What a listener should do with a freshly-parsed query, decided purely
/// from the header/question section, before any policy or forwarding work.
pub(crate) enum QueryAction {
    /// Well-formed QUERY/IN request for an ordinary qtype — proceed.
    Process,
    /// Answered locally without ever reaching policy/forwarding (CHAOS
    /// class introspection, RFC 4892).
    Answer(Vec<Record>),
    /// Malformed or unsupported in a way that still gets a reply — set this
    /// as the response code, empty answer section.
    Reject(ResponseCode),
}

/// RFC 5936 §4.2 (AXFR/IXFR are meaningless outside a zone transfer this
/// server never performs) and RFC 6895 (OPT/TSIG are meta-types, never
/// valid as a QTYPE).
fn disallowed_qtype_rcode(qtype: RecordType) -> Option<ResponseCode> {
    match qtype {
        RecordType::AXFR | RecordType::IXFR => Some(ResponseCode::Refused),
        RecordType::OPT | RecordType::TSIG => Some(ResponseCode::FormErr),
        _ => None,
    }
}

/// CHAOS-class introspection (RFC 4892 `version.bind`, RFC 5001-flavored
/// `id.server`/`hostname.bind`) — the only CH queries this server answers.
/// `None` means "not one of ours", which the caller turns into REFUSED.
fn answer_chaos(name: &Name, qtype: RecordType, node_name: &str) -> Option<Vec<Record>> {
    if qtype != RecordType::TXT {
        return None;
    }
    let label = name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
    let value = match label.as_str() {
        "version.bind" | "version.server" => "mantis-filter".to_string(),
        "hostname.bind" | "id.server" => node_name.to_string(),
        _ => return None,
    };
    Some(vec![Record::from_rdata(name.clone(), 0, RData::TXT(TXT::new(vec![value])))])
}

/// Header/question-level gate every listener runs before any policy or
/// forwarding work. Rejects: an opcode other than QUERY (A2, NOTIMP), more
/// than one question (B12, FORMERR), a class other than IN — except CH,
/// which gets `answer_chaos`'s narrow TXT introspection (A3, REFUSED
/// otherwise) — and AXFR/IXFR/OPT/TSIG as a QTYPE (B6). The QR=1 check
/// (A1) lives in `should_process` instead, since it must skip *all* of the
/// above, not turn into a reply.
pub(crate) fn validate_query(query: &Message, node_name: &str) -> QueryAction {
    if query.op_code() != OpCode::Query {
        return QueryAction::Reject(ResponseCode::NotImp);
    }
    let questions = query.queries();
    if questions.len() != 1 {
        return QueryAction::Reject(ResponseCode::FormErr);
    }
    let question = &questions[0];
    match question.query_class() {
        DNSClass::IN => {}
        DNSClass::CH => {
            return match answer_chaos(question.name(), question.query_type(), node_name) {
                Some(records) => QueryAction::Answer(records),
                None => QueryAction::Reject(ResponseCode::Refused),
            };
        }
        _ => return QueryAction::Reject(ResponseCode::Refused),
    }
    if let Some(rcode) = disallowed_qtype_rcode(question.query_type()) {
        return QueryAction::Reject(rcode);
    }
    QueryAction::Process
}

/// A1 (RFC 1035 §4.1.1): true only for an actual query. A message with
/// QR=1 (or any other non-query message type) must never be answered —
/// checked first, ahead of `validate_query`, because the correct action is
/// silence, not a rejection reply.
pub(crate) fn should_process(query: &Message) -> bool {
    query.message_type() == MessageType::Query
}

/// Echoes an OPT record on `response` when `query` carried one (RFC 6891
/// §6.1.1 — required so the client learns this server understood EDNS0),
/// clamped to `MAX_UDP_PAYLOAD`, and returns `true` when the query's EDNS
/// version isn't one this server supports (A6) — the caller must then
/// answer BADVERS (§6.1.3) with an empty answer section; the OPT record
/// needed for that to be meaningful is already attached to `response`
/// either way. Called once from `build_response`, so both UDP and TCP
/// responses carry EDNS when the query did (A5) — before this, only the
/// UDP-only `enforce_udp_size_limit` built one. The negotiated payload size
/// itself isn't returned: `enforce_udp_size_limit` (UDP-only, called after
/// `build_response`) recomputes it from `query` directly.
pub(crate) fn negotiate_edns(query: &Message, response: &mut Message) -> bool {
    let Some(req_edns) = query.extensions().as_ref() else {
        return false;
    };
    let max_udp_payload = req_edns.max_payload().clamp(512, MAX_UDP_PAYLOAD);
    let mut resp_edns = Edns::new();
    resp_edns.set_max_payload(max_udp_payload);
    // Phase 3 (partial — see design.md §27.2): echo DO back so the client
    // can tell this server is DNSSEC-aware. This is *not* the same as
    // asking upstream with DO on this client's behalf — `dnssec_strict`
    // (upstream_bundle.rs) already controls that, per resolver, independent
    // of any single query's DO bit; making it per-query would need a
    // second, non-validating resolver instance selectable per request,
    // which is real, separate work, not done here.
    resp_edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
    let bad_version = req_edns.version() > MAX_EDNS_VERSION;
    response.set_edns(resp_edns);
    bad_version
}

/// RFC 8914 §4.18 info-code 17 (Filtered): "the response was filtered due
/// to a filtering policy configured by an operator/administrator" — the
/// exact description of every block this filter node ever produces
/// (category match or an explicit deny-override), so one code covers both.
pub(crate) const EDE_FILTERED: u16 = 17;

/// Attaches an RFC 8914 Extended DNS Error option (B1) to `response`'s OPT
/// record: `info_code` per the IANA EDE registry, `extra_text` optional
/// free-form diagnostic (e.g. which category matched). No-op if the client
/// never negotiated EDNS at all — `negotiate_edns` didn't attach an OPT to
/// echo, and EDE has nowhere to live without one; synthesizing an OPT the
/// client never asked for just to carry an EDE it can't parse either isn't
/// worth the complexity. This is what turns a blocked answer from
/// indistinguishable-from-broken into something the client's own resolver
/// can surface to a user (design.md §27.2's D3: filtering is inherently a
/// protocol deviation — EDE is how it gets signalled instead of hidden).
pub(crate) fn attach_extended_error(response: &mut Message, info_code: u16, extra_text: &str) {
    let Some(edns) = response.extensions_mut().as_mut() else {
        return;
    };
    let mut payload = info_code.to_be_bytes().to_vec();
    payload.extend_from_slice(extra_text.as_bytes());
    edns.options_mut().insert(EdnsOption::Unknown(15, payload));
}

/// EDNS TCP Keepalive value (RFC 7828 §3): `lib.rs::TCP_IDLE_TIMEOUT` (30s)
/// expressed in the option's own units of 100ms.
const TCP_KEEPALIVE_TIMEOUT_UNITS: u16 = 300;

/// C4 / RFC 7828: tells a client how long this server will hold a TCP
/// connection idle before closing it, so a client that supports keepalive
/// can pipeline further queries instead of reconnecting per query, or at
/// least isn't surprised by the close. TCP-only — call this from a TCP send
/// path, never UDP; the option is meaningless outside a persistent
/// transport (§3.1). No-op if the query never negotiated EDNS.
pub(crate) fn attach_tcp_keepalive(response: &mut Message) {
    let Some(edns) = response.extensions_mut().as_mut() else {
        return;
    };
    edns.options_mut().insert(EdnsOption::Unknown(
        u16::from(EdnsCode::Keepalive),
        TCP_KEEPALIVE_TIMEOUT_UNITS.to_be_bytes().to_vec(),
    ));
}

/// DNS Cookies (RFC 7873, C1) — foundation only. Computes and verifies a
/// server cookie so a resolver that supports RFC 7873 gets a correct,
/// stable exchange, but by itself this does not yet *reject* anything on a
/// mismatch: RFC 7873 §5.2 treats BADCOOKIE as an optional policy a server
/// MAY apply when under load, not something a bare mismatch justifies — a
/// mismatch is the *expected*, harmless result of this process restarting
/// and rotating its secret, or a client's address legitimately changing
/// mid-session (NAT rebinding, mobile roaming). Rejecting on every mismatch
/// would be non-compliant and would break every client on every deploy.
/// Real spoofing mitigation needs a load signal (C6/RRL, not built) to
/// decide when to start enforcing BADCOOKIE; until then this is correct
/// protocol machinery, not yet a deployed defense — it's what C6 will need
/// to consult, not a substitute for it.
pub(crate) struct CookieSecret([u8; 16]);

impl CookieSecret {
    /// One random secret per process lifetime — a restart naturally
    /// invalidates every previously issued server cookie, which RFC 7873
    /// explicitly allows (§5) and is the simplest possible rotation policy.
    /// Sourced from `RandomState` rather than a `rand` dependency: each
    /// instance draws fresh keys from the OS CSPRNG specifically to resist
    /// prediction (that's the whole reason std's HashMap uses it), which is
    /// all 16 bytes of secret material for a cookie needs.
    pub(crate) fn generate() -> Self {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let a = RandomState::new().build_hasher().finish();
        let b = RandomState::new().build_hasher().finish();
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&a.to_ne_bytes());
        bytes[8..].copy_from_slice(&b.to_ne_bytes());
        Self(bytes)
    }

    /// `secret || client_ip || client_cookie`, SHA-256, truncated to 8
    /// bytes — a simplified keyed hash, not textbook HMAC. Good enough for
    /// this threat model (an unguessable-without-the-secret token, not a
    /// boundary standing alone against a determined cryptanalytic
    /// adversary); swap for real HMAC-SHA256 if that ever changes.
    fn server_cookie(&self, client_ip: IpAddr, client_cookie: &[u8]) -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        match client_ip {
            IpAddr::V4(v4) => hasher.update(v4.octets()),
            IpAddr::V6(v6) => hasher.update(v6.octets()),
        }
        hasher.update(client_cookie);
        let digest = hasher.finalize();
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        out
    }
}

/// Reads the query's COOKIE option, if any, and attaches the matching
/// COOKIE option (client cookie + this server's cookie for that
/// client/secret pair) to `response` — a no-op if the client didn't send
/// one at all (RFC 7873 §5.1: a server must never add a cookie the client
/// never asked about) or if the option is malformed (shorter than the
/// mandatory 8-byte client cookie).
pub(crate) fn negotiate_cookie(
    query: &Message,
    response: &mut Message,
    secret: &CookieSecret,
    client_ip: IpAddr,
) {
    let Some(req_edns) = query.extensions() else {
        return;
    };
    let Some(EdnsOption::Unknown(_, data)) = req_edns.options().get(EdnsCode::Cookie) else {
        return;
    };
    if data.len() < 8 {
        return;
    }
    let client_cookie = &data[..8];
    let server_cookie = secret.server_cookie(client_ip, client_cookie);
    let Some(resp_edns) = response.extensions_mut().as_mut() else {
        return;
    };
    let mut payload = client_cookie.to_vec();
    payload.extend_from_slice(&server_cookie);
    resp_edns.options_mut().insert(EdnsOption::Unknown(u16::from(EdnsCode::Cookie), payload));
}

/// This process's cookie secret — one per node lifetime (see
/// `CookieSecret::generate`'s doc comment for why that's the right
/// rotation policy), lazily generated on first use rather than threaded as
/// a parameter through `build_response` and every listener loop: it's
/// process-wide state, not something any caller ever needs to vary.
pub(crate) fn cookie_secret() -> &'static CookieSecret {
    static SECRET: std::sync::OnceLock<CookieSecret> = std::sync::OnceLock::new();
    SECRET.get_or_init(CookieSecret::generate)
}

/// Best-effort FORMERR for a packet whose 12-byte header parsed but the
/// rest didn't (B11 / RFC 8906): silence here is indistinguishable from
/// packet loss and leaves the client waiting out its full timeout instead
/// of retrying immediately. Returns `None` when even the header didn't
/// parse (nothing to echo an ID from — truly nothing safe to send) or when
/// the header says this wasn't a query in the first place (A1 still
/// applies to a malformed packet).
pub(crate) fn formerr_for_unparseable(raw: &[u8]) -> Option<Message> {
    let mut decoder = BinDecoder::new(raw);
    let header = Header::read(&mut decoder).ok()?;
    if header.message_type() != MessageType::Query {
        return None;
    }
    let mut response = Message::new();
    response.set_id(header.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(header.op_code());
    response.set_response_code(ResponseCode::FormErr);
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::serialize::binary::BinEncodable;

    fn a_query(qname: &str) -> Message {
        let mut query = Message::new();
        query.set_message_type(MessageType::Query);
        query.add_query(Query::query(qname.parse().unwrap(), RecordType::A));
        query
    }

    #[test]
    fn should_process_accepts_query_rejects_response() {
        let mut query = a_query("example.com.");
        assert!(should_process(&query));
        query.set_message_type(MessageType::Response);
        assert!(!should_process(&query));
    }

    #[test]
    fn validate_query_rejects_non_query_opcode() {
        let mut query = a_query("example.com.");
        query.set_op_code(OpCode::Update);
        assert!(matches!(
            validate_query(&query, "node"),
            QueryAction::Reject(ResponseCode::NotImp)
        ));
    }

    #[test]
    fn validate_query_rejects_multiple_questions() {
        let mut query = a_query("example.com.");
        query.add_query(Query::query("other.example.".parse().unwrap(), RecordType::A));
        assert!(matches!(validate_query(&query, "node"), QueryAction::Reject(ResponseCode::FormErr)));
    }

    #[test]
    fn validate_query_refuses_non_in_non_ch_class() {
        let mut query = Message::new();
        query.set_message_type(MessageType::Query);
        let mut q = Query::query("example.com.".parse().unwrap(), RecordType::A);
        q.set_query_class(DNSClass::HS);
        query.add_query(q);
        assert!(matches!(validate_query(&query, "node"), QueryAction::Reject(ResponseCode::Refused)));
    }

    #[test]
    fn validate_query_answers_chaos_version_bind() {
        let mut query = Message::new();
        query.set_message_type(MessageType::Query);
        let mut q = Query::query("version.bind.".parse().unwrap(), RecordType::TXT);
        q.set_query_class(DNSClass::CH);
        query.add_query(q);
        match validate_query(&query, "filter-1") {
            QueryAction::Answer(records) => assert_eq!(records.len(), 1),
            _ => panic!("expected Answer"),
        }
    }

    #[test]
    fn validate_query_refuses_unknown_chaos_name() {
        let mut query = Message::new();
        query.set_message_type(MessageType::Query);
        let mut q = Query::query("nope.".parse().unwrap(), RecordType::TXT);
        q.set_query_class(DNSClass::CH);
        query.add_query(q);
        assert!(matches!(validate_query(&query, "node"), QueryAction::Reject(ResponseCode::Refused)));
    }

    #[test]
    fn validate_query_refuses_axfr_and_formerrs_opt_qtype() {
        let mut axfr = a_query("example.com.");
        axfr.queries_mut()[0].set_query_type(RecordType::AXFR);
        assert!(matches!(validate_query(&axfr, "node"), QueryAction::Reject(ResponseCode::Refused)));

        let mut opt = a_query("example.com.");
        opt.queries_mut()[0].set_query_type(RecordType::OPT);
        assert!(matches!(validate_query(&opt, "node"), QueryAction::Reject(ResponseCode::FormErr)));
    }

    #[test]
    fn validate_query_processes_ordinary_query() {
        let query = a_query("example.com.");
        assert!(matches!(validate_query(&query, "node"), QueryAction::Process));
    }

    #[test]
    fn negotiate_edns_defaults_to_512_without_edns() {
        let query = a_query("example.com.");
        let mut response = Message::new();
        let bad_version = negotiate_edns(&query, &mut response);
        assert!(!bad_version);
        assert!(response.extensions().is_none());
    }

    #[test]
    fn negotiate_edns_echoes_opt_and_clamps_payload() {
        let mut query = a_query("example.com.");
        let mut edns = Edns::new();
        edns.set_max_payload(65535);
        query.set_edns(edns);
        let mut response = Message::new();
        let bad_version = negotiate_edns(&query, &mut response);
        assert!(!bad_version);
        assert_eq!(response.extensions().as_ref().unwrap().max_payload(), MAX_UDP_PAYLOAD);
    }

    #[test]
    fn negotiate_edns_echoes_the_do_bit() {
        let mut query = a_query("example.com.");
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        query.set_edns(edns);
        let mut response = Message::new();
        negotiate_edns(&query, &mut response);
        assert!(response.extensions().as_ref().unwrap().flags().dnssec_ok);
    }

    #[test]
    fn negotiate_edns_flags_unsupported_version() {
        let mut query = a_query("example.com.");
        let mut edns = Edns::new();
        edns.set_version(1);
        query.set_edns(edns);
        let mut response = Message::new();
        assert!(negotiate_edns(&query, &mut response));
    }

    #[test]
    fn attach_extended_error_is_noop_without_edns() {
        let mut response = Message::new();
        attach_extended_error(&mut response, EDE_FILTERED, "category=malware");
        assert!(response.extensions().is_none());
    }

    #[test]
    fn attach_extended_error_sets_the_option_when_edns_present() {
        let mut query = a_query("example.com.");
        query.set_edns(Edns::new());
        let mut response = Message::new();
        negotiate_edns(&query, &mut response);
        attach_extended_error(&mut response, EDE_FILTERED, "category=malware");

        let opt = response.extensions().as_ref().unwrap().options().get(EdnsCode::Unknown(15));
        let Some(EdnsOption::Unknown(15, payload)) = opt else {
            panic!("expected an EDE option (code 15)");
        };
        assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), EDE_FILTERED);
        assert_eq!(&payload[2..], b"category=malware");
    }

    #[test]
    fn attach_tcp_keepalive_is_noop_without_edns() {
        let mut response = Message::new();
        attach_tcp_keepalive(&mut response);
        assert!(response.extensions().is_none());
    }

    #[test]
    fn attach_tcp_keepalive_sets_the_timeout_option() {
        let mut query = a_query("example.com.");
        query.set_edns(Edns::new());
        let mut response = Message::new();
        negotiate_edns(&query, &mut response);
        attach_tcp_keepalive(&mut response);

        let opt = response.extensions().as_ref().unwrap().options().get(EdnsCode::Keepalive);
        let Some(EdnsOption::Unknown(_, payload)) = opt else {
            panic!("expected a Keepalive option");
        };
        assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), TCP_KEEPALIVE_TIMEOUT_UNITS);
    }

    #[test]
    fn negotiate_cookie_is_noop_without_a_client_cookie() {
        let query = a_query("example.com."); // no EDNS at all
        let mut response = Message::new();
        let secret = CookieSecret::generate();
        negotiate_cookie(&query, &mut response, &secret, "127.0.0.1".parse().unwrap());
        assert!(response.extensions().is_none());
    }

    #[test]
    fn negotiate_cookie_echoes_client_cookie_and_attaches_a_server_cookie() {
        let mut query = a_query("example.com.");
        let mut edns = Edns::new();
        let client_cookie = [1u8, 2, 3, 4, 5, 6, 7, 8];
        edns.options_mut().insert(EdnsOption::Unknown(u16::from(EdnsCode::Cookie), client_cookie.to_vec()));
        query.set_edns(edns);

        let mut response = Message::new();
        negotiate_edns(&query, &mut response);
        let secret = CookieSecret::generate();
        let ip = "203.0.113.7".parse().unwrap();
        negotiate_cookie(&query, &mut response, &secret, ip);

        let opt = response.extensions().as_ref().unwrap().options().get(EdnsCode::Cookie);
        let Some(EdnsOption::Unknown(_, payload)) = opt else {
            panic!("expected a Cookie option");
        };
        assert_eq!(payload.len(), 16, "8-byte client cookie + 8-byte server cookie");
        assert_eq!(&payload[..8], &client_cookie);
        assert_eq!(
            &payload[8..],
            secret.server_cookie(ip, &client_cookie),
            "server cookie must be deterministic for the same secret/IP/client cookie"
        );
    }

    #[test]
    fn negotiate_cookie_server_cookie_differs_by_client_ip() {
        let secret = CookieSecret::generate();
        let client_cookie = [9u8; 8];
        let a = secret.server_cookie("127.0.0.1".parse().unwrap(), &client_cookie);
        let b = secret.server_cookie("127.0.0.2".parse().unwrap(), &client_cookie);
        assert_ne!(a, b, "binding to the client's own IP is the whole point of the cookie");
    }

    #[test]
    fn formerr_for_unparseable_echoes_id_from_valid_header() {
        let query = a_query("example.com.");
        let bytes = query.to_bytes().unwrap();
        // Truncate after the header so the body fails to parse, but the
        // header itself is still intact.
        let response = formerr_for_unparseable(&bytes[..12]).expect("header should parse");
        assert_eq!(response.id(), query.id());
        assert_eq!(response.response_code(), ResponseCode::FormErr);
    }

    #[test]
    fn formerr_for_unparseable_gives_up_on_a_too_short_buffer() {
        assert!(formerr_for_unparseable(&[0u8; 4]).is_none());
    }
}
