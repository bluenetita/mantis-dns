"""Generates the cross-language bloom filter fixture consumed by the Rust
aegis-policy test suite. Run after any change to bloom.py's hashing scheme:

    python -m aegis_control.compiler.gen_bloom_fixture

Writes to services/filter/aegis-policy/tests/fixtures/.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis_control.compiler.bloom import BloomFilterBuilder, BloomParams

FIXTURE_DIR = Path(__file__).resolve().parents[3] / "filter" / "aegis-policy" / "tests" / "fixtures"

PARAMS = BloomParams(num_hashes=4, num_bits=4096, seed=1234)
INCLUDED = ["ads.example.com", "tracker.test", "casino.example", "porn.example.net"]
EXCLUDED = ["totally-unrelated.org", "my-bank.example", "internal.corp.local"]


def main() -> None:
    bf = BloomFilterBuilder(PARAMS)
    for domain in INCLUDED:
        bf.add(domain)

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    (FIXTURE_DIR / "bloom_fixture.bin").write_bytes(bf.to_bytes())
    (FIXTURE_DIR / "bloom_fixture.json").write_text(
        json.dumps(
            {
                "num_hashes": PARAMS.num_hashes,
                "num_bits": PARAMS.num_bits,
                "seed": PARAMS.seed,
                "included": INCLUDED,
                "excluded": EXCLUDED,
            },
            indent=2,
        )
    )
    print(f"wrote fixture to {FIXTURE_DIR}")


if __name__ == "__main__":
    main()
