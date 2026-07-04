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

//! Diagnostic: loads a bundle and checks whether a given domain matches any
//! category's bloom filter, bypassing the DNS layer entirely.
//! cargo run -p mantis-bundle --example check_membership -- bundle.bin domain.example

use mantis_bundle::Bundle;
use mantis_policy::BloomFilter;
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
