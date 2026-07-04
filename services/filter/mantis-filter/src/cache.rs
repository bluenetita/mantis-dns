//! DNS record cache keyed by (qname, qtype). TTL + size-bounded.
//!
//! Generalised from the Sprint 4 A-only cache to store arbitrary record sets
//! so AAAA, MX, TXT, PTR, etc. are all cached independently per (name, type)
//! pair without collision.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use hickory_proto::rr::Record;

struct CacheEntry {
    records: Vec<Record>,
    expires_at: Instant,
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

    pub fn get(&self, qname: &str, qtype: u16) -> Option<Vec<Record>> {
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        let entry = map.get(&(qname.to_string(), qtype))?;
        if entry.expires_at <= Instant::now() {
            return None;
        }
        Some(entry.records.clone())
    }

    pub fn put(&self, qname: String, qtype: u16, records: Vec<Record>, ttl: Duration) {
        if ttl.is_zero() || records.is_empty() {
            return;
        }
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        let key = (qname, qtype);
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
                records,
                expires_at: Instant::now() + ttl,
            },
        );
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
        let hit = cache.get("example.com", u16::from(RecordType::A));
        assert_eq!(hit.unwrap().len(), 1);
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
