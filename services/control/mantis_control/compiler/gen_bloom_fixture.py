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

"""Generates the cross-language bloom filter fixture consumed by the Rust
mantis-policy test suite. Run after any change to bloom.py's hashing scheme:

    python -m mantis_control.compiler.gen_bloom_fixture

Writes to services/filter/mantis-policy/tests/fixtures/.
"""

from __future__ import annotations

import json
from pathlib import Path

from mantis_control.compiler.bloom import BloomFilterBuilder, BloomParams

FIXTURE_DIR = Path(__file__).resolve().parents[3] / "filter" / "mantis-policy" / "tests" / "fixtures"

# num_hashes=10 deliberately mirrors a real production sizing (recommended_params
# for ~400 items) — a smaller num_hashes (e.g. 4) failed to trigger the 64-bit
# wraparound bug that slipped through Sprint 5 (see bloom.py module docstring).
PARAMS = BloomParams(num_hashes=10, num_bits=5579, seed=1234)
INCLUDED = [f"included-{i}.example.test" for i in range(50)] + [
    "ads.example.com",
    "tracker.test",
    "casino.example",
    "porn.example.net",
]
EXCLUDED = [f"excluded-{i}.example.test" for i in range(50)] + [
    "totally-unrelated.org",
    "my-bank.example",
    "internal.corp.local",
]


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
