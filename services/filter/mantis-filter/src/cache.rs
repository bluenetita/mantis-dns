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

//! DNS record cache keyed by (qname, qtype). TTL + size-bounded.
//!
//! Generalised from the Sprint 4 A-only cache to store arbitrary record sets
//! so AAAA, MX, TXT, PTR, etc. are all cached independently per (name, type)
//! pair without collision.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use hickory_proto::rr::Record;

/// Which kind of negative answer a cached NXDOMAIN/NODATA result represents,
/// so a cache hit can set the right response code without re-asking upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegativeKind {
    NxDomain,
    NoData,
}

enum CacheEntryKind {
    Records(Vec<Record>),
    Negative(NegativeKind),
}

struct CacheEntry {
    kind: CacheEntryKind,
    expires_at: Instant,
}

/// Result of a cache lookup: either the cached positive records, or a
/// negative answer (NXDOMAIN/NODATA) cached from a prior upstream response.
pub enum CacheLookup {
    Records(Vec<Record>),
    Negative(NegativeKind),
}

pub struct DnsCache {
    map: RwLock<HashMap<(String, u16), CacheEntry>>,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn get(&self, qname: &str, qtype: u16) -> Option<CacheLookup> {
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        // DNS names are case-insensitive (RFC 1035/4343) — some clients vary
        // case per query (0x20 anti-spoofing) or simply send mixed case, and
        // without normalizing here "Example.com"/"example.com" would occupy
        // separate cache slots and never share a hit.
        let entry = map.get(&(qname.to_ascii_lowercase(), qtype))?;
        let now = Instant::now();
        if entry.expires_at <= now {
            return None;
        }
        // Report the TTL actually remaining, not the TTL the entry was
        // inserted with — otherwise a record cached 55s ago with TTL=60
        // still claims TTL=60 on a hit, overstating freshness to whatever
        // resolver/client caches this answer downstream.
        let remaining_ttl = u32::try_from(entry.expires_at.duration_since(now).as_secs())
            .unwrap_or(u32::MAX);
        Some(match &entry.kind {
            CacheEntryKind::Records(records) => {
                let mut records = records.clone();
                for rec in &mut records {
                    rec.set_ttl(remaining_ttl);
                }
                CacheLookup::Records(records)
            }
            CacheEntryKind::Negative(kind) => CacheLookup::Negative(*kind),
        })
    }

    fn insert(&self, qname: String, qtype: u16, kind: CacheEntryKind, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        let key = (qname.to_ascii_lowercase(), qtype);
        if map.len() >= self.max_entries && !map.contains_key(&key) {
            let now = Instant::now();
            let victim = map
                .iter()
                .find(|(_, e)| e.expires_at <= now)
                .map(|(k, _)| k.clone())
                .or_else(|| map.keys().next().cloned());
            if let Some(victim) = victim {
                map.remove(&victim);
            }
        }
        map.insert(
            key,
            CacheEntry {
                kind,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    pub fn put(&self, qname: String, qtype: u16, records: Vec<Record>, ttl: Duration) {
        if records.is_empty() {
            return;
        }
        self.insert(qname, qtype, CacheEntryKind::Records(records), ttl);
    }

    /// Caches a negative (NXDOMAIN/NODATA) upstream answer. Without this, a
    /// flood of queries for random non-existent subdomains ("water torture")
    /// never hits the cache and forces an upstream round-trip on every single
    /// packet — amplifying attacker traffic straight into the resolver pool.
    pub fn put_negative(&self, qname: String, qtype: u16, kind: NegativeKind, ttl: Duration) {
        self.insert(qname, qtype, CacheEntryKind::Negative(kind), ttl);
    }

    pub fn purge_expired(&self) {
        let now = Instant::now();
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, e| e.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{rdata::A, RData, RecordType};
    use std::net::Ipv4Addr;

    fn a_record(qname: &str, ip: Ipv4Addr) -> Record {
        let name: hickory_proto::rr::Name = qname.parse().unwrap();
        Record::from_rdata(name, 60, RData::A(A(ip)))
    }

    #[test]
    fn put_then_get_returns_records() {
        let cache = DnsCache::new(10);
        let rec = a_record("example.com", Ipv4Addr::new(1, 2, 3, 4));
        cache.put(
            "example.com".into(),
            u16::from(RecordType::A),
            vec![rec.clone()],
            Duration::from_secs(60),
        );
        match cache.get("example.com", u16::from(RecordType::A)) {
            Some(CacheLookup::Records(records)) => assert_eq!(records.len(), 1),
            other => panic!("expected a positive cache hit, got {}", other.is_some()),
        }
    }

    #[test]
    fn put_negative_then_get_returns_the_same_kind() {
        let cache = DnsCache::new(10);
        cache.put_negative(
            "doesnotexist.example".into(),
            u16::from(RecordType::A),
            NegativeKind::NxDomain,
            Duration::from_secs(60),
        );
        match cache.get("doesnotexist.example", u16::from(RecordType::A)) {
            Some(CacheLookup::Negative(NegativeKind::NxDomain)) => {}
            _ => panic!("expected a cached NXDOMAIN"),
        }
    }

    #[test]
    fn negative_cache_entry_expires() {
        let cache = DnsCache::new(10);
        cache.put_negative(
            "doesnotexist.example".into(),
            u16::from(RecordType::A),
            NegativeKind::NoData,
            Duration::from_millis(1),
        );
        std::thread::sleep(Duration::from_millis(10));
        assert!(cache.get("doesnotexist.example", u16::from(RecordType::A)).is_none());
    }

    #[test]
    fn different_qtypes_are_independent() {
        let cache = DnsCache::new(10);
        let rec = a_record("example.com", Ipv4Addr::new(1, 2, 3, 4));
        cache.put(
            "example.com".into(),
            u16::from(RecordType::A),
            vec![rec],
            Duration::from_secs(60),
        );
        // AAAA miss even though A is cached
        assert!(cache.get("example.com", u16::from(RecordType::AAAA)).is_none());
    }

    #[test]
    fn expired_entry_not_returned() {
        let cache = DnsCache::new(10);
        let rec = a_record("example.com", Ipv4Addr::new(1, 2, 3, 4));
        cache.put(
            "example.com".into(),
            u16::from(RecordType::A),
            vec![rec],
            Duration::from_millis(0),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.get("example.com", u16::from(RecordType::A)).is_none());
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let cache = DnsCache::new(10);
        let rec = a_record("Example.com", Ipv4Addr::new(1, 2, 3, 4));
        cache.put(
            "Example.com".into(),
            u16::from(RecordType::A),
            vec![rec],
            Duration::from_secs(60),
        );
        assert!(cache.get("example.com", u16::from(RecordType::A)).is_some());
        assert!(cache.get("EXAMPLE.COM", u16::from(RecordType::A)).is_some());
    }

    #[test]
    fn evicts_when_over_capacity() {
        let cache = DnsCache::new(2);
        let dummy = a_record("x.example", Ipv4Addr::LOCALHOST);
        cache.put("a.example".into(), 1, vec![dummy.clone()], Duration::from_secs(60));
        cache.put("b.example".into(), 1, vec![dummy.clone()], Duration::from_secs(60));
        cache.put("c.example".into(), 1, vec![dummy], Duration::from_secs(60));
        let map = cache.map.read().unwrap();
        assert!(map.len() <= 2);
    }
}
