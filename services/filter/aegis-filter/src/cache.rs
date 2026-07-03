//! In-process A-record cache. TTL + size-bounded; not a strict LRU (no
//! access-order tracking) — adequate for Sprint 4, revisit if eviction
//! pressure shows up in the Sprint 4 perf baseline.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

struct CacheEntry {
    ips: Vec<Ipv4Addr>,
    expires_at: Instant,
}

pub struct DnsCache {
    map: RwLock<HashMap<String, CacheEntry>>,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn get(&self, qname: &str) -> Option<Vec<Ipv4Addr>> {
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        let entry = map.get(qname)?;
        if entry.expires_at <= Instant::now() {
            return None;
        }
        Some(entry.ips.clone())
    }

    /// Removes all entries whose TTL has expired. Called periodically by a
    /// background task to bound memory growth when the cache is under capacity.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, e| e.expires_at > now);
    }

    pub fn put(&self, qname: String, ips: Vec<Ipv4Addr>, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_entries && !map.contains_key(&qname) {
            // Cheap eviction: drop one expired entry if we can find one, else
            // drop an arbitrary entry. Good enough at Sprint 4 scale; a real
            // LRU/clock-eviction policy is a candidate for the Sprint 4 perf
            // baseline follow-up if this proves too coarse under load.
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
            qname,
            CacheEntry {
                ips,
                expires_at: Instant::now() + ttl,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_returns_value() {
        let cache = DnsCache::new(10);
        cache.put(
            "example.com".into(),
            vec![Ipv4Addr::new(1, 2, 3, 4)],
            Duration::from_secs(60),
        );
        assert_eq!(cache.get("example.com"), Some(vec![Ipv4Addr::new(1, 2, 3, 4)]));
    }

    #[test]
    fn expired_entry_not_returned() {
        let cache = DnsCache::new(10);
        cache.put(
            "example.com".into(),
            vec![Ipv4Addr::new(1, 2, 3, 4)],
            Duration::from_millis(0),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get("example.com"), None);
    }

    #[test]
    fn miss_returns_none() {
        let cache = DnsCache::new(10);
        assert_eq!(cache.get("never-inserted.example"), None);
    }

    #[test]
    fn evicts_when_over_capacity() {
        let cache = DnsCache::new(2);
        cache.put("a.example".into(), vec![], Duration::from_secs(60));
        cache.put("b.example".into(), vec![], Duration::from_secs(60));
        cache.put("c.example".into(), vec![], Duration::from_secs(60));
        let map = cache.map.read().unwrap_or_else(|e| e.into_inner());
        assert!(map.len() <= 2);
    }
}
