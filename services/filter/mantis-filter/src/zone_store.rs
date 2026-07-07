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

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use arc_swap::ArcSwap;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SRV, TXT};
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
    /// qname is inside a local zone. Empty means the name exists but has no
    /// record of the queried type (NODATA); non-empty is a real answer.
    Answer(Vec<Record>),
    /// qname is inside a local zone but no record exists for that name at
    /// any type — authoritative NXDOMAIN, no upstream fallback.
    NxDomain,
}

struct ZoneData {
    /// Zone apex names, normalized (lowercased, no trailing dot).
    zones: Vec<String>,
    /// Normalized owner name -> every record at that name (any type).
    records: HashMap<String, Vec<Record>>,
}

pub struct ZoneStore {
    data: ArcSwap<ZoneData>,
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
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
        "TXT" => RData::TXT(TXT::new(vec![entry.data.clone()])),
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
        other => {
            // CAA and any future record types: not yet supported by the
            // stub-zone store. Rare in practice; skip rather than fail the
            // whole zone load.
            warn!("skipping unsupported record type '{other}' for '{}'", entry.name);
            return None;
        }
    };

    Some(Record::from_rdata(name, entry.ttl, rdata))
}

impl ZoneStore {
    pub fn empty() -> Self {
        Self {
            data: ArcSwap::from_pointee(ZoneData { zones: Vec::new(), records: HashMap::new() }),
        }
    }

    pub fn publish(&self, entries: Vec<LocalZoneRecordDto>) {
        let mut zones: Vec<String> = entries.iter().map(|e| normalize(&e.zone)).collect();
        zones.sort_unstable();
        zones.dedup();

        let mut records: HashMap<String, Vec<Record>> = HashMap::new();
        for entry in &entries {
            if let Some(record) = build_record(entry) {
                records.entry(normalize(&entry.name)).or_default().push(record);
            }
        }

        self.data.store(std::sync::Arc::new(ZoneData { zones, records }));
    }

    /// `qname` is expected in the same form as `Message`'s question name
    /// (`to_utf8()`), trailing dot and all — `normalize` strips it.
    pub fn lookup(&self, qname: &str, qtype: RecordType) -> ZoneLookup {
        let data = self.data.load();
        let qname = normalize(qname);

        let is_local = data
            .zones
            .iter()
            .any(|z| qname == *z || qname.ends_with(&format!(".{z}")));
        if !is_local {
            return ZoneLookup::NotLocal;
        }

        match data.records.get(&qname) {
            None => ZoneLookup::NxDomain,
            Some(recs) => ZoneLookup::Answer(
                recs.iter().filter(|r| r.record_type() == qtype).cloned().collect(),
            ),
        }
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
    fn exact_match_returns_answer() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("passbolt.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5")]);

        match store.lookup("passbolt.bluenetworks.lab.", RecordType::A) {
            ZoneLookup::Answer(recs) => assert_eq!(recs.len(), 1),
            _ => panic!("expected Answer"),
        }
    }

    #[test]
    fn name_exists_but_wrong_type_is_nodata() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("passbolt.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5")]);

        match store.lookup("passbolt.bluenetworks.lab.", RecordType::AAAA) {
            ZoneLookup::Answer(recs) => assert!(recs.is_empty()),
            _ => panic!("expected Answer(empty) i.e. NODATA"),
        }
    }

    #[test]
    fn missing_name_under_local_zone_is_nxdomain() {
        let store = ZoneStore::empty();
        store.publish(vec![entry("www.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5")]);

        match store.lookup("nope.bluenetworks.lab.", RecordType::A) {
            ZoneLookup::NxDomain => {}
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
    fn suffix_match_does_not_false_positive_on_label_boundary() {
        // "evilbluenetworks.lab." must NOT be treated as inside "bluenetworks.lab."
        let store = ZoneStore::empty();
        store.publish(vec![entry("www.bluenetworks.lab", "bluenetworks.lab", "A", "10.0.0.5")]);

        match store.lookup("evilbluenetworks.lab.", RecordType::A) {
            ZoneLookup::NotLocal => {}
            _ => panic!("expected NotLocal, label-boundary suffix match must not false-positive"),
        }
    }
}
