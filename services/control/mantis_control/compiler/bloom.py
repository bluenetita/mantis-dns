# Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Bloom filter builder for category domain sets.

CROSS-LANGUAGE CONTRACT: this hashing scheme MUST match
services/filter/mantis-policy/src/lib.rs exactly (same two base hashes, same
combination formula, same seed handling) or every lookup silently mismatches.
Sprint 2 fixture tests (filter built here, verified there) are the regression
gate. Do not change the hash functions without updating the Rust side in lockstep.

Scheme: Kirsch-Mitzenmacher double hashing.
  h1 = fnv1a_64(seed_bytes ++ domain)
  h2 = fnv1a_64(domain ++ seed_bytes)   (note: operand order swapped vs h1)
  bit_i = (h1 +(wrapping) i *(wrapping) h2) % num_bits,  for i in 0..num_hashes

IMPORTANT: `i * h2` and the subsequent `+ h1` must be truncated to 64 bits at
each step (mask with MASK_64), matching Rust's wrapping_mul/wrapping_add.
Python integers don't overflow, so without explicit masking this silently
diverges from the Rust side once `i * h2` exceeds 2**64 — which happens
routinely for real domain counts (e.g. num_hashes >= 5 on typical FNV
outputs). This bit it Sprint 5 in production: a 388-domain feed compiled
fine, verified fine structurally, but `might_contain` returned false for
every domain because of this exact divergence. The cross-language fixture
test (gen_bloom_fixture.py) didn't catch it because its small fixture
(4 hashes) didn't reliably trigger the overflow case.
"""

from __future__ import annotations

from dataclasses import dataclass

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK_64 = (1 << 64) - 1


def fnv1a(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK_64
    return h


@dataclass(frozen=True)
class BloomParams:
    num_hashes: int
    num_bits: int
    seed: int


def _hash_pair(domain: str, seed: int) -> tuple[int, int]:
    seed_bytes = seed.to_bytes(8, "little")
    domain_bytes = domain.encode("utf-8")
    h1 = fnv1a(seed_bytes + domain_bytes)
    h2 = fnv1a(domain_bytes + seed_bytes)
    return h1, h2


def _bit_index(h1: int, h2: int, i: int, num_bits: int) -> int:
    """Mirrors Rust's `h1.wrapping_add(i.wrapping_mul(h2)) % num_bits` exactly,
    including 64-bit truncation at each step. See module docstring."""
    step = (i * h2) & MASK_64
    combined = (h1 + step) & MASK_64
    return combined % num_bits


class BloomFilterBuilder:
    """Builds a bloom filter bitset from a domain set, matching the Rust reader."""

    def __init__(self, params: BloomParams) -> None:
        self.params = params
        self._bits = bytearray((params.num_bits + 7) // 8)

    def add(self, domain: str) -> None:
        h1, h2 = _hash_pair(domain, self.params.seed)
        for i in range(self.params.num_hashes):
            bit_index = _bit_index(h1, h2, i, self.params.num_bits)
            byte_index = bit_index // 8
            bit_offset = bit_index % 8
            self._bits[byte_index] |= 1 << bit_offset

    def might_contain(self, domain: str) -> bool:
        h1, h2 = _hash_pair(domain, self.params.seed)
        for i in range(self.params.num_hashes):
            bit_index = _bit_index(h1, h2, i, self.params.num_bits)
            byte_index = bit_index // 8
            bit_offset = bit_index % 8
            if not (self._bits[byte_index] & (1 << bit_offset)):
                return False
        return True

    def to_bytes(self) -> bytes:
        return bytes(self._bits)


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def _next_prime(n: int) -> int:
    """Smallest prime >= n. `bit_index = (h1 + i*h2) % num_bits` (see module
    docstring) is a Kirsch-Mitzenmacher double hash: whenever num_bits shares a
    small factor with h2, an item's own k probes collapse onto num_bits/gcd
    distinct positions instead of spreading across the full range, correlating
    which bits get set/checked and inflating the *real* false-positive rate far
    above the sizing formula's prediction. A composite num_bits (the formula's
    raw output almost always is — e.g. 13691130 = 2*3*5*41*11131) hits this
    routinely, since h2 mod {2,3,5,...} is uniform and so shares a factor with
    high probability. Measured impact on a 952k-domain category: 0.665%
    empirical FPR against a 0.1% target; rounding num_bits to the next prime
    (same size, +19 bits here) alone brought it back to 0.093%."""
    candidate = n if n % 2 else n + 1
    while not _is_prime(candidate):
        candidate += 2
    return candidate


def recommended_params(expected_items: int, false_positive_rate: float = 0.001, seed: int = 0) -> BloomParams:
    """Standard bloom sizing formulas, given an expected item count and target FP rate."""
    import math

    if expected_items <= 0:
        expected_items = 1
    num_bits = max(64, math.ceil(-(expected_items * math.log(false_positive_rate)) / (math.log(2) ** 2)))
    num_bits = _next_prime(num_bits)
    num_hashes = max(1, round((num_bits / expected_items) * math.log(2)))
    return BloomParams(num_hashes=num_hashes, num_bits=num_bits, seed=seed)
