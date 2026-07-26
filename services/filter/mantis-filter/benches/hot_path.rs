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

//! Sprint 23 (design.md §26 R7) hot-path p99 baseline.
//!
//! No criterion: `harness = false` + `std::time::Instant` is enough for a
//! p50/p99 read on the three query shapes that actually run per-packet
//! (cache hit, cache miss, zone-blocked lookup) without a new dependency.
//! `cargo bench -p mantis-filter --bench hot_path` runs it; pass `--record`
//! to overwrite `benches/baseline.txt` instead of comparing against it.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use mantis_filter::zone_store::LocalZoneRecordDto;
use mantis_filter::{DnsCache, ZoneLookup, ZoneStore};

const ITERS: usize = 100_000;
/// A regression beyond this fraction of the recorded baseline fails the run
/// (design.md §26 R7's "10% p99 gate").
const REGRESSION_THRESHOLD: f64 = 0.10;

fn percentile(sorted_nanos: &[u64], pct: f64) -> u64 {
    let idx = ((sorted_nanos.len() - 1) as f64 * pct).round() as usize;
    sorted_nanos[idx]
}

/// Runs `f` `ITERS` times, returning (p50_ns, p99_ns).
fn measure(mut f: impl FnMut()) -> (u64, u64) {
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let start = Instant::now();
        f();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    (percentile(&samples, 0.50), percentile(&samples, 0.99))
}

fn a_record(qname: &str) -> Record {
    let name: Name = qname.parse().unwrap();
    Record::from_rdata(name, 60, RData::A(A(Ipv4Addr::new(93, 184, 216, 34))))
}

fn bench_cache_hit() -> (u64, u64) {
    let cache = DnsCache::new(10_000);
    cache.put(
        "example.com".into(),
        u16::from(RecordType::A),
        vec![a_record("example.com")],
        Duration::from_secs(300),
    );
    measure(|| {
        cache.get("example.com", u16::from(RecordType::A));
    })
}

fn bench_cache_miss() -> (u64, u64) {
    let cache = DnsCache::new(10_000);
    measure(|| {
        cache.get("neverseen.example", u16::from(RecordType::A));
    })
}

fn bench_zone_blocked_lookup() -> (u64, u64) {
    let store = ZoneStore::empty();
    store.publish(vec![LocalZoneRecordDto {
        name: "internal.bluenetworks.lab".into(),
        zone: "bluenetworks.lab".into(),
        record_type: "A".into(),
        ttl: 300,
        data: "10.0.0.5".into(),
        priority: None,
    }]);
    measure(|| match store.lookup("host.internal.bluenetworks.lab.", RecordType::A) {
        ZoneLookup::NotLocal | ZoneLookup::NxDomain | ZoneLookup::Answer(_) => {}
    })
}

#[derive(Clone, Copy)]
struct Baseline {
    // Kept for humans reading baseline.txt; the gate below only checks p99.
    #[allow(dead_code)]
    p50_ns: u64,
    p99_ns: u64,
}

fn parse_baseline_line(line: &str) -> Option<(String, Baseline)> {
    // Minimal hand-rolled "name p50_ns p99_ns" format — no serde_json dep
    // needed for a 3-line file.
    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_string();
    let p50_ns = parts.next()?.parse().ok()?;
    let p99_ns = parts.next()?.parse().ok()?;
    Some((name, Baseline { p50_ns, p99_ns }))
}

fn load_baseline(path: &std::path::Path) -> std::collections::HashMap<String, Baseline> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return std::collections::HashMap::new();
    };
    contents.lines().filter_map(parse_baseline_line).collect()
}

fn main() {
    let record = std::env::args().any(|a| a == "--record");
    let baseline_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/baseline.txt");

    let results: Vec<(&str, (u64, u64))> = vec![
        ("cache_hit", bench_cache_hit()),
        ("cache_miss", bench_cache_miss()),
        ("zone_blocked_lookup", bench_zone_blocked_lookup()),
    ];

    for (name, (p50, p99)) in &results {
        println!("{name} p50={p50}ns p99={p99}ns");
    }

    if record {
        let body: String = results
            .iter()
            .map(|(name, (p50, p99))| format!("{name} {p50} {p99}\n"))
            .collect();
        std::fs::write(&baseline_path, body).expect("write baseline.txt");
        println!("recorded baseline to {}", baseline_path.display());
        return;
    }

    let baseline = load_baseline(&baseline_path);
    if baseline.is_empty() {
        println!("no baseline recorded yet at {} — run with --record first", baseline_path.display());
        return;
    }

    let mut regressed = false;
    for (name, (_, p99)) in &results {
        let Some(base) = baseline.get(*name) else { continue };
        let allowed = (base.p99_ns as f64) * (1.0 + REGRESSION_THRESHOLD);
        if (*p99 as f64) > allowed {
            eprintln!(
                "REGRESSION: {name} p99 {p99}ns exceeds baseline {}ns + {:.0}% ({allowed:.0}ns)",
                base.p99_ns,
                REGRESSION_THRESHOLD * 100.0
            );
            regressed = true;
        }
    }

    if regressed {
        std::process::exit(1);
    }
}
