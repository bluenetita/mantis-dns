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

//! Bloom filter lookup for category domain sets.
//!
//! CROSS-LANGUAGE CONTRACT: the hashing scheme here MUST match the Python
//! policy compiler exactly (same two base hashes, same combination formula,
//! same seed handling) or every lookup silently mismatches. Sprint 2 fixture
//! tests (Python-built filter -> Rust-verified lookups) are the regression
//! gate for this file. Do not change the hash functions without updating
//! services/control/mantis_control/bloom.py in lockstep.
//!
//! Scheme: Kirsch-Mitzenmacher double hashing.
//!   h1 = fnv1a_64(seed_bytes ++ domain)
//!   h2 = fnv1a_64(domain ++ seed_bytes)   (note: operand order swapped vs h1)
//!   bit_i = (h1 + i * h2) % num_bits,  for i in 0..num_hashes

use mantis_bundle::CategorySet;

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

pub struct BloomFilter<'a> {
    num_hashes: u32,
    num_bits: u64,
    seed: u64,
    bits: &'a [u8],
}

impl<'a> BloomFilter<'a> {
    pub fn from_category(cat: &'a CategorySet) -> Option<Self> {
        let params = cat.bloom.as_ref()?;
        Some(Self {
            num_hashes: params.num_hashes,
            num_bits: params.num_bits,
            seed: params.seed,
            bits: &cat.bloom_bits,
        })
    }

    fn hash_pair(&self, domain: &str) -> (u64, u64) {
        let seed_bytes = self.seed.to_le_bytes();
        let domain_bytes = domain.as_bytes();

        let mut buf1 = Vec::with_capacity(seed_bytes.len() + domain_bytes.len());
        buf1.extend_from_slice(&seed_bytes);
        buf1.extend_from_slice(domain_bytes);

        let mut buf2 = Vec::with_capacity(seed_bytes.len() + domain_bytes.len());
        buf2.extend_from_slice(domain_bytes);
        buf2.extend_from_slice(&seed_bytes);

        (fnv1a(&buf1), fnv1a(&buf2))
    }

    /// Returns true if `domain` is *possibly* in the set (bloom semantics: no
    /// false negatives, possible false positives).
    pub fn might_contain(&self, domain: &str) -> bool {
        if self.num_bits == 0 || self.bits.is_empty() {
            return false;
        }
        let (h1, h2) = self.hash_pair(domain);
        for i in 0..self.num_hashes as u64 {
            let bit_index = h1.wrapping_add(i.wrapping_mul(h2)) % self.num_bits;
            let byte_index = (bit_index / 8) as usize;
            let bit_offset = (bit_index % 8) as u8;
            match self.bits.get(byte_index) {
                Some(byte) if byte & (1 << bit_offset) != 0 => continue,
                _ => return false,
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_contains_nothing() {
        let cat = CategorySet {
            category_id: "test".into(),
            source_feed_id: "".into(),
            feed_version: "".into(),
            license: "".into(),
            bloom: Some(mantis_bundle::gen::BloomParams {
                num_hashes: 3,
                num_bits: 1024,
                seed: 42,
            }),
            bloom_bits: vec![0u8; 128],
            action: 0,
        };
        let bf = BloomFilter::from_category(&cat).unwrap();
        assert!(!bf.might_contain("example.com"));
    }
}
