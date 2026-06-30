"""Bloom filter builder for category domain sets.

CROSS-LANGUAGE CONTRACT: this hashing scheme MUST match
services/filter/aegis-policy/src/lib.rs exactly (same two base hashes, same
combination formula, same seed handling) or every lookup silently mismatches.
Sprint 2 fixture tests (filter built here, verified there) are the regression
gate. Do not change the hash functions without updating the Rust side in lockstep.

Scheme: Kirsch-Mitzenmacher double hashing.
  h1 = fnv1a_64(seed_bytes ++ domain)
  h2 = fnv1a_64(domain ++ seed_bytes)   (note: operand order swapped vs h1)
  bit_i = (h1 + i * h2) % num_bits,  for i in 0..num_hashes
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


class BloomFilterBuilder:
    """Builds a bloom filter bitset from a domain set, matching the Rust reader."""

    def __init__(self, params: BloomParams) -> None:
        self.params = params
        self._bits = bytearray((params.num_bits + 7) // 8)

    def add(self, domain: str) -> None:
        h1, h2 = _hash_pair(domain, self.params.seed)
        for i in range(self.params.num_hashes):
            bit_index = (h1 + i * h2) % self.params.num_bits
            byte_index = bit_index // 8
            bit_offset = bit_index % 8
            self._bits[byte_index] |= 1 << bit_offset

    def might_contain(self, domain: str) -> bool:
        h1, h2 = _hash_pair(domain, self.params.seed)
        for i in range(self.params.num_hashes):
            bit_index = (h1 + i * h2) % self.params.num_bits
            byte_index = bit_index // 8
            bit_offset = bit_index % 8
            if not (self._bits[byte_index] & (1 << bit_offset)):
                return False
        return True

    def to_bytes(self) -> bytes:
        return bytes(self._bits)


def recommended_params(expected_items: int, false_positive_rate: float = 0.001, seed: int = 0) -> BloomParams:
    """Standard bloom sizing formulas, given an expected item count and target FP rate."""
    import math

    if expected_items <= 0:
        expected_items = 1
    num_bits = max(64, math.ceil(-(expected_items * math.log(false_positive_rate)) / (math.log(2) ** 2)))
    num_hashes = max(1, round((num_bits / expected_items) * math.log(2)))
    return BloomParams(num_hashes=num_hashes, num_bits=num_bits, seed=seed)
