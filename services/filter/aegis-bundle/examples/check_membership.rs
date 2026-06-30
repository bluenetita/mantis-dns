//! Diagnostic: loads a bundle and checks whether a given domain matches any
//! category's bloom filter, bypassing the DNS layer entirely.
//! cargo run -p aegis-bundle --example check_membership -- bundle.bin domain.example

use aegis_bundle::Bundle;
use aegis_policy::BloomFilter;
use prost::Message;
use std::env;
use std::fs;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let bundle_bytes = fs::read(&args[1])?;
    let domain = &args[2];

    let bundle = Bundle::decode(bundle_bytes.as_slice())?;
    println!("categories: {}", bundle.categories.len());
    for cat in &bundle.categories {
        if let Some(p) = &cat.bloom {
            println!(
                "rust-side params: num_hashes={} num_bits={} seed={} bits_len={}",
                p.num_hashes,
                p.num_bits,
                p.seed,
                cat.bloom_bits.len()
            );
        }
        let bf = BloomFilter::from_category(cat);
        let hit = bf.as_ref().map(|b| b.might_contain(domain)).unwrap_or(false);
        println!(
            "category={} action={} bloom_present={} might_contain({domain})={hit}",
            cat.category_id,
            cat.action,
            bf.is_some()
        );
    }
    Ok(())
}
