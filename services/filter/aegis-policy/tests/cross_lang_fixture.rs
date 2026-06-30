//! Cross-language regression gate: loads a bloom filter built by the Python
//! compiler (services/control/aegis_control/compiler/gen_bloom_fixture.py)
//! and checks Rust's `might_contain` agrees on every included/excluded domain.
//! If this test fails after touching either hashing implementation, the two
//! sides have drifted — fix the implementation, not the fixture.

use aegis_bundle::gen::BloomParams;
use aegis_bundle::CategorySet;
use aegis_policy::BloomFilter;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct FixtureMeta {
    num_hashes: u32,
    num_bits: u64,
    seed: u64,
    included: Vec<String>,
    excluded: Vec<String>,
}

#[test]
fn rust_agrees_with_python_built_filter() {
    let meta_json = fs::read_to_string("tests/fixtures/bloom_fixture.json")
        .expect("run `python -m aegis_control.compiler.gen_bloom_fixture` first");
    let meta: FixtureMeta = serde_json::from_str(&meta_json).unwrap();
    let bits = fs::read("tests/fixtures/bloom_fixture.bin").unwrap();

    let cat = CategorySet {
        category_id: "fixture".into(),
        source_feed_id: "".into(),
        feed_version: "".into(),
        license: "".into(),
        bloom: Some(BloomParams {
            num_hashes: meta.num_hashes,
            num_bits: meta.num_bits,
            seed: meta.seed,
        }),
        bloom_bits: bits,
        action: 0,
    };
    let bf = BloomFilter::from_category(&cat).unwrap();

    for domain in &meta.included {
        assert!(
            bf.might_contain(domain),
            "expected {domain} to be in the Python-built filter, but Rust says no — hashing scheme drift"
        );
    }
    for domain in &meta.excluded {
        assert!(
            !bf.might_contain(domain),
            "expected {domain} to be absent from the Python-built filter, but Rust says yes — hashing scheme drift"
        );
    }
}
