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

//! Stub-zone store (design.md §7.3, §DNS-Zones): local DNS zone records,
//! fetched from the control plane's `/api/v1/local-zones` and answered
//! authoritatively without ever reaching the upstream forwarder or the
//! Bloom-filter policy engine.
//!
//! Phase 2 of docs/rfc-compliance.md §3 additionally makes this behave like
//! a real (if small) zone: empty non-terminals answer NODATA instead of
//! NXDOMAIN (A7), a CNAME at the queried name is returned instead of NODATA
//! (A8), single-label wildcards are supported (B10), every negative answer
//! carries the zone's SOA in the authority section (A4), and a fixed set of
//! special-use/RFC 6303 zones are always locally empty so they never leak
//! upstream (B4).

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use arc_swap::ArcSwap;
use hickory_proto::rr::rdata::{A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Deserialize;
use tracing::warn;

/// Wire shape of `mantis_control.api.schemas.LocalZoneRecord`.
#[derive(Deserialize)]
pub struct LocalZoneRecordDto {
    pub name: String,
    pub zone: String,
    pub record_type: String,
    pub ttl: u32,
    pub data: String,
    pub priority: Option<u16>,
}

/// Result of checking a qname against the locally-hosted zones.
pub enum ZoneLookup {
    /// qname falls outside every locally-hosted zone — fall through to the
    /// normal bloom-filter decision + upstream forward path.
    NotLocal,
    /// qname is inside a local zone. Empty `records` means the name exists
    /// but has no record of the queried type (NODATA); non-empty is a real
    /// answer. `soa` is the zone's apex SOA (A4 / RFC 2308 §3) — callers
    /// should add it to the authority section when `records` is empty.
    Answer { records: Vec<Record>, soa: Option<Record> },
    /// qname is inside a local zone but no record exists for that name (or
    /// any wildcard covering it) at any type — authoritative NXDOMAIN, no
    /// upstream fallback. `soa` as above.
    NxDomain { soa: Option<Record> },
}

/// RFC 6761/6762/7686/8375 special-use names and RFC 6303 private reverse
/// zones: always answered as empty local zones (any query -> NXDOMAIN) so
/// they never leak to the upstream resolver pool (B4), regardless of
/// whether the tenant configured any zone at all. A tenant zone with the
/// same apex takes precedence — this list is only consulted when nothing
/// dynamic already claimed the name (see `ZoneStore::lookup`).
///
/// IPv6 coverage is deliberately partial: only the two ranges
/// docs/rfc-compliance.md B4 names (ULA `fc00::/7`, link-local `fe80::/10`)
/// are included. Loopback/unspecified reverse zones are single, rarely
/// queried names and were left out rather than padding this list.
const BUILTIN_EMPTY_ZONES: &[&str] = &[
    "local",
    "localhost",
    "invalid",
    "test",
    "example",
    "onion",
    "home.arpa",
    "10.in-addr.arpa",
    "16.172.in-addr.arpa",
    "17.172.in-addr.arpa",
    "18.172.in-addr.arpa",
    "19.172.in-addr.arpa",
    "20.172.in-addr.arpa",
    "21.172.in-addr.arpa",
    "22.172.in-addr.arpa",
    "23.172.in-addr.arpa",
    "24.172.in-addr.arpa",
    "25.172.in-addr.arpa",
    "26.172.in-addr.arpa",
    "27.172.in-addr.arpa",
    "28.172.in-addr.arpa",
    "29.172.in-addr.arpa",
    "30.172.in-addr.arpa",
    "31.172.in-addr.arpa",
    "168.192.in-addr.arpa",
    "254.169.in-addr.arpa",
    "d.f.ip6.arpa",
    "c.f.ip6.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
];

struct ZoneData {
    /// Tenant zone apex names, normalized (lowercased, no trailing dot).
    zones: Vec<String>,
    /// Normalized owner name -> every record at that name (any type). A name
    /// with only unsupported record types (e.g. CAA "iodef") still gets an
    /// entry here (possibly empty) so it reads as NODATA, not NXDOMAIN.
    records: HashMap<String, Vec<Record>>,
    /// Normalized wildcard *suffix* (owner name with the leading "*." label
    /// stripped) -> the records published at "*.<suffix>" (B10).
    wildcards: HashMap<String, Vec<Record>>,
    /// Every strict ancestor name, within some zone, of a name that has
    /// records — i.e. every empty non-terminal (A7 / RFC 8020). The zone
    /// apex itself is never in here: it always has at least a SOA record
    /// (see `apex_soa`), so it's never empty.
    ancestors: HashSet<String>,
    /// Zone apex (normalized) -> its SOA record, for the authority section
    /// of a negative answer (A4). Populated from an explicit SOA record if
    /// the control plane sent one, else synthesized deterministically —
    /// see `synthesize_soa`.
    apex_soa: HashMap<String, Record>,
}

pub struct ZoneStore {
    data: ArcSwap<ZoneData>,
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// True if `qname` is `zone` or a subdomain of it. Both arguments are
/// already normalized (lowercased, no trailing dot), so this is a plain
/// byte-slice comparison — no `format!` allocation per zone on the hot path.
fn is_subdomain_of(qname: &str, zone: &str) -> bool {
    qname.len() > zone.len()
        && qname.as_bytes()[qname.len() - zone.len() - 1] == b'.'
        && &qname[qname.len() - zone.len()..] == zone
}

/// The most specific zone in `zones` that `qname` falls under (itself or a
/// subdomain), preferring the longest match in the unlikely case a tenant
/// configured nested zones.
fn longest_match<'a>(zones: impl IntoIterator<Item = &'a str>, qname: &str) -> Option<&'a str> {
    zones.into_iter().filter(|z| qname == *z || is_subdomain_of(qname, z)).max_by_key(|z| z.len())
}

/// Every strict ancestor of `owner`, from most to least specific, stopping
/// before `zone` itself (the apex is tracked separately and is never an
/// empty non-terminal once it always carries a SOA).
fn strict_ancestors(owner: &str, zone: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = owner;
    while let Some(dot) = current.find('.') {
        let next = &current[dot + 1..];
        if next.len() <= zone.len() {
            break;
        }
        out.push(next.to_string());
        current = next;
    }
    out
}

/// Clones `record` with its owner name replaced by `new_owner` (a
/// normalized, no-trailing-dot name) — RFC 1034 §4.3.3: a wildcard-matched
/// RRset is returned under the *query* name, not the wildcard's own
/// "*.foo" owner name.
fn rewrite_owner(record: &Record, new_owner: &str) -> Record {
    let mut rec = record.clone();
    if let Ok(name) = format!("{new_owner}.").parse::<Name>() {
        rec.set_name(name);
    }
    rec
}

/// Fallback SOA for a tenant zone that didn't ship an explicit one — every
/// zone must have exactly one for RFC 2308 negative answers to be
/// meaningful (A4) and for the apex to never read as an empty non-terminal.
/// `mname`/`rname` match `export_zone`'s existing convention in
/// zone_routers.py so a zone looks the same however it's produced. A fixed
/// serial (real change tracking, if it matters, belongs to the
/// control-plane-authored SOA this is only a fallback for).
fn synthesize_soa(zone: &str) -> Option<Record> {
    let apex: Name = format!("{zone}.").parse().ok()?;
    let mname: Name = format!("ns1.{zone}.").parse().ok()?;
    let rname: Name = format!("hostmaster.{zone}.").parse().ok()?;
    Some(Record::from_rdata(apex, 300, RData::SOA(SOA::new(mname, rname, 1, 3600, 900, 604800, 300))))
}

/// SOA for a `BUILTIN_EMPTY_ZONES` entry — these have no real owner, so the
/// mname/rname are generic placeholders (the same style Unbound/BIND ship
/// for their own built-in empty zones), not anything a client should ever
/// act on.
fn builtin_soa(zone: &str) -> Record {
    let apex: Name = format!("{zone}.").parse().unwrap_or_else(|_| Name::root());
    let mname: Name = "localhost.".parse().unwrap_or_else(|_| Name::root());
    let rname: Name = "root.localhost.".parse().unwrap_or_else(|_| Name::root());
    Record::from_rdata(apex, 86400, RData::SOA(SOA::new(mname, rname, 1, 3600, 900, 604800, 86400)))
}

/// Splits `data` into RFC 1035 §3.3.14 character-strings of at most 255
/// bytes each, never inside a multi-byte UTF-8 sequence (A9). Without this,
/// a TXT value over 255 bytes (a DKIM key, a long SPF record) failed to
/// encode as a single character-string and the whole message silently
/// dropped, rather than being split the way every real nameserver does it.
fn chunk_txt(data: &str) -> Vec<String> {
    const MAX: usize = 255;
    if data.len() <= MAX {
        return vec![data.to_string()];
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let mut end = (start + MAX).min(data.len());
        while end > start && !data.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            // A single character wider than MAX bytes is impossible in
            // UTF-8 (max 4 bytes/char), but never loop forever regardless.
            end = (start + MAX).min(data.len());
        }
        chunks.push(data[start..end].to_string());
        start = end;
    }
    chunks
}

fn build_record(entry: &LocalZoneRecordDto) -> Option<Record> {
    let name: Name = match entry.name.parse() {
        Ok(n) => n,
        Err(e) => {
            warn!("skipping local zone record with invalid name '{}': {e}", entry.name);
            return None;
        }
    };

    let rdata = match entry.record_type.as_str() {
        "A" => match entry.data.parse::<Ipv4Addr>() {
            Ok(ip) => RData::A(A::from(ip)),
            Err(e) => {
                warn!("skipping A record '{}': invalid address '{}': {e}", entry.name, entry.data);
                return None;
            }
        },
        "AAAA" => match entry.data.parse::<Ipv6Addr>() {
            Ok(ip) => RData::AAAA(AAAA::from(ip)),
            Err(e) => {
                warn!("skipping AAAA record '{}': invalid address '{}': {e}", entry.name, entry.data);
                return None;
            }
        },
        "CNAME" | "NS" | "PTR" => {
            let target: Name = match entry.data.parse() {
                Ok(n) => n,
                Err(e) => {
                    warn!(
                        "skipping {} record '{}': invalid target '{}': {e}",
                        entry.record_type, entry.name, entry.data
                    );
                    return None;
                }
            };
            match entry.record_type.as_str() {
                "CNAME" => RData::CNAME(CNAME(target)),
                "NS" => RData::NS(NS(target)),
                _ => RData::PTR(PTR(target)),
            }
        }
        "MX" => {
            let target: Name = match entry.data.parse() {
                Ok(n) => n,
                Err(e) => {
                    warn!("skipping MX record '{}': invalid exchange '{}': {e}", entry.name, entry.data);
                    return None;
                }
            };
            RData::MX(MX::new(entry.priority.unwrap_or(10), target))
        }
        "TXT" => RData::TXT(TXT::new(chunk_txt(&entry.data))),
        "SRV" => {
            let parts: Vec<&str> = entry.data.split_whitespace().collect();
            let [weight, port, target] = parts[..] else {
                warn!(
                    "skipping SRV record '{}': expected data 'weight port target', got '{}'",
                    entry.name, entry.data
                );
                return None;
            };
            let (Ok(weight), Ok(port)) = (weight.parse::<u16>(), port.parse::<u16>()) else {
                warn!("skipping SRV record '{}': invalid weight/port in '{}'", entry.name, entry.data);
                return None;
            };
            let target: Name = match target.parse() {
                Ok(n) => n,
                Err(e) => {
                    warn!("skipping SRV record '{}': invalid target '{}': {e}", entry.name, target);
                    return None;
                }
            };
            RData::SRV(SRV::new(entry.priority.unwrap_or(0), weight, port, target))
        }
        "CAA" => {
            // Convention: data = "<tag> <value>", tag one of issue/issuewild,
            // value either a CA domain name or ";" for "no CA authorized".
            // "iodef" isn't supported — it needs a `Url` value and pulling in
            // the `url` crate just for that rarely-used tag isn't worth it.
            let parts: Vec<&str> = entry.data.splitn(2, char::is_whitespace).collect();
            let [tag, value] = parts[..] else {
                warn!(
                    "skipping CAA record '{}': expected data '<issue|issuewild> <value>', got '{}'",
                    entry.name, entry.data
                );
                return None;
            };
            let value = value.trim();
            let name = if value == ";" {
                None
            } else {
                match value.parse::<Name>() {
                    Ok(n) => Some(n),
                    Err(e) => {
                        warn!("skipping CAA record '{}': invalid issuer '{}': {e}", entry.name, value);
                        return None;
                    }
                }
            };
            match tag {
                "issue" => RData::CAA(CAA::new_issue(false, name, Vec::new())),
                "issuewild" => RData::CAA(CAA::new_issuewild(false, name, Vec::new())),
                other => {
                    warn!("skipping CAA record '{}': unsupported tag '{other}' (only issue/issuewild)", entry.name);
                    return None;
                }
            }
        }
        "SOA" => {
            // "<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>"
            // — the control-plane-authored apex SOA (A4/B9). A zone with no
            // explicit SOA gets `synthesize_soa`'s fallback instead.
            let parts: Vec<&str> = entry.data.split_whitespace().collect();
            let [mname, rname, serial, refresh, retry, expire, minimum] = parts[..] else {
                warn!(
                    "skipping SOA record '{}': expected 'mname rname serial refresh retry expire minimum', got '{}'",
                    entry.name, entry.data
                );
                return None;
            };
            let (Ok(mname), Ok(rname)) = (mname.parse::<Name>(), rname.parse::<Name>()) else {
                warn!("skipping SOA record '{}': invalid mname/rname in '{}'", entry.name, entry.data);
                return None;
            };
            let parsed = (
                serial.parse::<u32>(),
                refresh.parse::<i32>(),
                retry.parse::<i32>(),
                expire.parse::<i32>(),
                minimum.parse::<u32>(),
            );
            let (Ok(serial), Ok(refresh), Ok(retry), Ok(expire), Ok(minimum)) = parsed else {
                warn!("skipping SOA record '{}': invalid numeric field in '{}'", entry.name, entry.data);
                return None;
            };
            RData::SOA(SOA::new(mname, rname, serial, refresh, retry, expire, minimum))
        }
        other => {
            // Any future record type unsupported by the stub-zone store.
            // Rare in practice; skip rather than fail the whole zone load.
            warn!("skipping unsupported record type '{other}' for '{}'", entry.name);
            return None;
        }
    };

    Some(Record::from_rdata(name, entry.ttl, rdata))
}

impl ZoneStore {
    pub fn empty() -> Self {
        Self {
            data: ArcSwap::from_pointee(ZoneData {
                zones: Vec::new(),
                records: HashMap::new(),
                wildcards: HashMap::new(),
                ancestors: HashSet::new(),
                apex_soa: HashMap::new(),
            }),
        }
    }

    pub fn publish(&self, entries: Vec<LocalZoneRecordDto>) {
        let mut zones: Vec<String> = entries.iter().map(|e| normalize(&e.zone)).collect();
        zones.sort_unstable();
        zones.dedup();

        let mut records: HashMap<String, Vec<Record>> = HashMap::new();
        let mut wildcards: HashMap<String, Vec<Record>> = HashMap::new();
        let mut ancestors: HashSet<String> = HashSet::new();
        let mut apex_soa: HashMap<String, Record> = HashMap::new();

        for entry in &entries {
            let owner = normalize(&entry.name);
            let zone = normalize(&entry.zone);

            // .or_default() first so a name with only unsupported record
            // types still gets a (possibly empty) entry — NODATA, not
            // NXDOMAIN, since the name genuinely exists in the zone.
            let bucket = records.entry(owner.clone()).or_default();
            if let Some(record) = build_record(entry) {
                if record.record_type() == RecordType::SOA && owner == zone {
                    apex_soa.insert(zone.clone(), record.clone());
                }
                if let Some(suffix) = owner.strip_prefix("*.") {
                    wildcards.entry(suffix.to_string()).or_default().push(record.clone());
                }
                bucket.push(record);
            }

            ancestors.extend(strict_ancestors(&owner, &zone));
        }

        // Every zone gets an apex SOA one way or another (A4/B9) — fall back
        // to a synthesized one when the control plane didn't send an
        // explicit SOA record for this zone.
        for zone in &zones {
            apex_soa.entry(zone.clone()).or_insert_with(|| {
                synthesize_soa(zone)
                    .unwrap_or_else(|| panic!("zone name '{zone}' failed to parse as a Name"))
            });
        }

        self.data.store(std::sync::Arc::new(ZoneData { zones, records, wildcards, ancestors, apex_soa }));
    }

    fn lookup_in_zone(data: &ZoneData, qname: &str, zone: &str, qtype: RecordType) -> ZoneLookup {
        let soa = data.apex_soa.get(zone).cloned();

        if let Some(recs) = data.records.get(qname) {
            let matched: Vec<Record> = recs.iter().filter(|r| r.record_type() == qtype).cloned().collect();
            if !matched.is_empty() || qtype == RecordType::CNAME {
                return ZoneLookup::Answer { records: matched, soa };
            }
            // A8: no record of the requested type, but the name has a
            // CNAME — return that instead of NODATA, per RFC 1034 §4.3.2;
            // the client re-queries the target itself.
            let cname: Vec<Record> =
                recs.iter().filter(|r| r.record_type() == RecordType::CNAME).cloned().collect();
            if !cname.is_empty() {
                return ZoneLookup::Answer { records: cname, soa };
            }
            return ZoneLookup::Answer { records: Vec::new(), soa };
        }

        if data.ancestors.contains(qname) {
            // A7: an empty non-terminal is NODATA, not NXDOMAIN — RFC 8020
            // makes a downstream resolver treat NXDOMAIN here as "nothing
            // below this name exists either," which is false.
            return ZoneLookup::Answer { records: Vec::new(), soa };
        }

        // B10: single-label wildcard expansion only — "*.parent" matches a
        // direct child of parent, not further-nested names (a.b.*.zone).
        // The full RFC 4592 closest-encloser algorithm needs NSEC-style
        // tree bookkeeping this store doesn't keep; single-label covers the
        // overwhelmingly common private-zone case ("*.apps.corp.lab").
        if let Some(dot) = qname.find('.') {
            let parent = &qname[dot + 1..];
            if parent.len() >= zone.len() {
                if let Some(recs) = data.wildcards.get(parent) {
                    let matched: Vec<Record> = recs
                        .iter()
                        .filter(|r| r.record_type() == qtype)
                        .map(|r| rewrite_owner(r, qname))
                        .collect();
                    return ZoneLookup::Answer { records: matched, soa };
                }
            }
        }

        ZoneLookup::NxDomain { soa }
    }

    /// `qname` is expected in the same form as `Message`'s question name
    /// (`to_utf8()`), trailing dot and all — `normalize` strips it.
    pub fn lookup(&self, qname: &str, qtype: RecordType) -> ZoneLookup {
        let data = self.data.load();
        let qname = normalize(qname);

        if let Some(zone) = longest_match(data.zones.iter().map(String::as_str), &qname) {
            return Self::lookup_in_zone(&data, &qname, zone, qtype);
        }

        // B4: special-use/RFC 6303 names are always locally empty, even
        // with no tenant zone configured at all — never leak to upstream.
        if let Some(zone) = longest_match(BUILTIN_EMPTY_ZONES.iter().copied(), &qname) {
            return ZoneLookup::NxDomain { soa: Some(builtin_soa(zone)) };
        }

        ZoneLookup::NotLocal
    }
}

pub async fn fetch_local_zone_records(
    control_url: &str,
    group_id: &str,
) -> Result<Vec<LocalZoneRecordDto>> {
    let client = reqwest::Client::new();
    let resp = crate::with_service_token(
        client.get(format!("{control_url}/api/v1/local-zones")).query(&[("group_id", group_id)]),
    )
    .send()
    .await?
    .error_for_status()?;
    Ok(resp.json().await?)
}

pub async fn fetch_and_publish_zone(store: &ZoneStore, control_url: &str, group_id: &str) -> Result<()> {
    let entries = fetch_local_zone_records(control_url, group_id).await?;
    store.publish(entries);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, zone: &str, record_type: &str, data: &str) -> LocalZoneRecordDto {
        LocalZoneRecordDto {
            name: name.to_string(),
            zone: zone.to_string(),
            record_type: record_type.to_string(),
            ttl: 300,
            data: data.to_string(),
            priority: None,
        }
    }

    #[test]
    fn is_subdomain_of_requires_dot_boundary() {
        assert!(is_subdomain_of("passbolt.bluenetworks.lab", "bluenetworks.lab"));
        assert!(!is_subdomain_of("evilbluenetworks.lab", "bluenetworks.lab"));
        assert!(!is_subdomain_of("bluenetworks.lab", "bluenetworks.lab"));
        assert!(!is_subdomain_of("lab", "bluenetworks.lab"));
    }

    #[test]
    fn exact_match_returns_answer() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("passbolt.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5")]);

        match store.lookup("passbolt.bluenetworks.lab.", RecordType::A) {
            ZoneLookup::Answer { records, .. } => assert_eq!(records.len(), 1),
            _ => panic!("expected Answer"),
        }
    }

    #[test]
    fn name_exists_but_wrong_type_is_nodata() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("passbolt.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5")]);

        match store.lookup("passbolt.bluenetworks.lab.", RecordType::AAAA) {
            ZoneLookup::Answer { records, soa } => {
                assert!(records.is_empty());
                assert!(soa.is_some(), "NODATA must carry the zone's SOA (A4)");
            }
            _ => panic!("expected Answer(empty) i.e. NODATA"),
        }
    }

    #[test]
    fn missing_name_under_local_zone_is_nxdomain_with_soa() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("www.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5")]);

        match store.lookup("nope.bluenetworks.lab.", RecordType::A) {
            ZoneLookup::NxDomain { soa } => assert!(soa.is_some(), "NXDOMAIN must carry the zone's SOA (A4)"),
            _ => panic!("expected NxDomain"),
        }
    }

    #[test]
    fn name_outside_any_local_zone_falls_through() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("www.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5")]);

        match store.lookup("example.com.", RecordType::A) {
            ZoneLookup::NotLocal => {}
            _ => panic!("expected NotLocal"),
        }
    }

    #[test]
    fn caa_issue_record_builds_and_answers() {
        let store = ZoneStore::empty();
        store.publish(vec![entry(
            "bluenetworks.lab",
            "bluenetworks.lab",
            "CAA",
            "issue letsencrypt.org",
        )]);

        match store.lookup("bluenetworks.lab.", RecordType::CAA) {
            ZoneLookup::Answer { records, .. } => assert_eq!(records.len(), 1),
            _ => panic!("expected Answer"),
        }
    }

    #[test]
    fn caa_iodef_tag_is_unsupported_and_skipped() {
        let store = ZoneStore::empty();
        store.publish(vec![entry(
            "bluenetworks.lab",
            "bluenetworks.lab",
            "CAA",
            "iodef mailto:security@bluenetworks.lab",
        )]);

        // Zone apex is still registered (it's a local zone), but no record
        // was built for the unsupported tag -> NODATA, not a crash.
        match store.lookup("bluenetworks.lab.", RecordType::CAA) {
            ZoneLookup::Answer { records, .. } => assert!(records.is_empty()),
            _ => panic!("expected Answer(empty) i.e. NODATA"),
        }
    }

    #[test]
    fn suffix_match_does_not_false_positive_on_label_boundary() {
        // "evilbluenetworks.lab." must NOT be treated as inside "bluenetworks.lab."
        let store = ZoneStore::empty();
        store.publish(vec![entry("www.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5")]);

        match store.lookup("evilbluenetworks.lab.", RecordType::A) {
            ZoneLookup::NotLocal => {}
            _ => panic!("expected NotLocal, label-boundary suffix match must not false-positive"),
        }
    }

    #[test]
    fn empty_non_terminal_is_nodata_not_nxdomain() {
        // A7 / RFC 8020: "_tcp.corp.lab" has no records of its own, but a
        // descendant ("_ldap._tcp.corp.lab") does — must be NODATA.
        let store = ZoneStore::empty();
        store.publish(vec![entry("_ldap._tcp.corp.lab", "corp.lab", "SRV", "0 389 dc.corp.lab")]);

        match store.lookup("_tcp.corp.lab.", RecordType::A) {
            ZoneLookup::Answer { records, soa } => {
                assert!(records.is_empty());
                assert!(soa.is_some());
            }
            other => panic!("expected empty Answer (NODATA), got a variant that isn't Answer: {}", matches!(other, ZoneLookup::NxDomain { .. })),
        }
    }

    #[test]
    fn cname_is_returned_for_a_query_of_a_different_type() {
        // A8: "alias.corp.lab" only has a CNAME — an A query must get the
        // CNAME record back, not NODATA.
        let store = ZoneStore::empty();
        store.publish(vec![entry("alias.corp.lab", "corp.lab", "CNAME", "target.corp.lab")]);

        match store.lookup("alias.corp.lab.", RecordType::A) {
            ZoneLookup::Answer { records, .. } => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].record_type(), RecordType::CNAME);
            }
            _ => panic!("expected Answer carrying the CNAME"),
        }
    }

    #[test]
    fn wildcard_matches_a_direct_child_and_rewrites_the_owner() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("*.apps.corp.lab", "corp.lab", "A", "10.0.0.9")]);

        match store.lookup("anything.apps.corp.lab.", RecordType::A) {
            ZoneLookup::Answer { records, .. } => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].name().to_utf8(), "anything.apps.corp.lab.");
            }
            _ => panic!("expected a wildcard-synthesized Answer"),
        }
    }

    #[test]
    fn wildcard_node_with_no_matching_qtype_is_nodata() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("*.apps.corp.lab", "corp.lab", "A", "10.0.0.9")]);

        match store.lookup("anything.apps.corp.lab.", RecordType::AAAA) {
            ZoneLookup::Answer { records, .. } => assert!(records.is_empty()),
            _ => panic!("expected empty Answer (NODATA) for a qtype the wildcard doesn't cover"),
        }
    }

    #[test]
    fn wildcard_does_not_match_a_multi_label_expansion() {
        // Deliberate simplification (single-label only, see lookup_in_zone).
        let store = ZoneStore::empty();
        store.publish(vec![entry("*.apps.corp.lab", "corp.lab", "A", "10.0.0.9")]);

        match store.lookup("a.b.apps.corp.lab.", RecordType::A) {
            ZoneLookup::NxDomain { .. } => {}
            _ => panic!("expected NxDomain for a name two labels below the wildcard"),
        }
    }

    #[test]
    fn zone_gets_a_synthesized_soa_when_none_was_published() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("www.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5")]);

        match store.lookup("nope.bluenetworks.lab.", RecordType::A) {
            ZoneLookup::NxDomain { soa: Some(soa) } => {
                assert_eq!(soa.name().to_utf8(), "bluenetworks.lab.");
            }
            other => panic!("expected NxDomain with a synthesized SOA, got a variant that isn't Answer: {}", matches!(other, ZoneLookup::Answer { .. })),
        }
    }

    #[test]
    fn explicit_soa_record_is_used_over_the_synthesized_fallback() {
        let store = ZoneStore::empty();
        store.publish(vec![
            entry("bluenetworks.lab", "bluenetworks.lab", "SOA", "ns1.bluenetworks.lab. hostmaster.bluenetworks.lab. 42 3600 900 604800 300"),
            entry("www.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5"),
        ]);

        match store.lookup("nope.bluenetworks.lab.", RecordType::A) {
            ZoneLookup::NxDomain { soa: Some(soa) } => {
                let RData::SOA(soa) = soa.data() else { panic!("expected SOA rdata") };
                assert_eq!(soa.serial(), 42);
            }
            other => panic!("expected NxDomain with the explicit SOA, got a variant that isn't Answer: {}", matches!(other, ZoneLookup::Answer { .. })),
        }
    }

    #[test]
    fn txt_over_255_bytes_is_chunked_into_multiple_character_strings() {
        let store = ZoneStore::empty();
        let long_value = "v".repeat(600);
        store.publish(vec![entry("txt.corp.lab", "corp.lab", "TXT", &long_value)]);

        match store.lookup("txt.corp.lab.", RecordType::TXT) {
            ZoneLookup::Answer { records, .. } => {
                assert_eq!(records.len(), 1);
                let RData::TXT(txt) = records[0].data() else { panic!("expected TXT rdata") };
                assert_eq!(txt.txt_data().len(), 3, "600 bytes should split into 3 chunks of <=255");
                for chunk in txt.txt_data() {
                    assert!(chunk.len() <= 255);
                }
            }
            _ => panic!("expected Answer"),
        }
    }

    #[test]
    fn onion_is_a_builtin_empty_zone_even_with_no_tenant_zone_configured() {
        let store = ZoneStore::empty();
        match store.lookup("somesite.onion.", RecordType::A) {
            ZoneLookup::NxDomain { soa } => assert!(soa.is_some()),
            _ => panic!("expected NxDomain for a .onion name — must never reach upstream (B4)"),
        }
    }

    #[test]
    fn rfc1918_reverse_zone_is_a_builtin_empty_zone() {
        let store = ZoneStore::empty();
        match store.lookup("5.0.0.10.in-addr.arpa.", RecordType::PTR) {
            ZoneLookup::NxDomain { .. } => {}
            _ => panic!("expected NxDomain for a 10.in-addr.arpa PTR — must never reach upstream (B4)"),
        }
    }

    #[test]
    fn a_tenant_zone_overrides_the_builtin_empty_zone_with_the_same_apex() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("gateway.10.in-addr.arpa", "10.in-addr.arpa", "PTR", "router.corp.lab")]);

        match store.lookup("gateway.10.in-addr.arpa.", RecordType::PTR) {
            ZoneLookup::Answer { records, .. } => assert_eq!(records.len(), 1),
            _ => panic!("expected the tenant-configured zone to win over the builtin empty zone"),
        }
    }
}
