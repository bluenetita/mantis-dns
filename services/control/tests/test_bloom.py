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

from mantis_control.compiler.bloom import BloomFilterBuilder, BloomParams, fnv1a


def test_fnv1a_known_vector() -> None:
    # Standard FNV-1a 64-bit test vector for empty string and "a".
    assert fnv1a(b"") == 0xCBF29CE484222325
    assert fnv1a(b"a") == 0xAF63DC4C8601EC8C


def test_bloom_no_false_negatives() -> None:
    params = BloomParams(num_hashes=5, num_bits=4096, seed=42)
    bf = BloomFilterBuilder(params)
    domains = ["ads.example.com", "tracker.test", "porn.example", "casino.example"]
    for d in domains:
        bf.add(d)
    for d in domains:
        assert bf.might_contain(d)


def test_bloom_likely_rejects_unrelated_domain() -> None:
    params = BloomParams(num_hashes=5, num_bits=4096, seed=42)
    bf = BloomFilterBuilder(params)
    bf.add("ads.example.com")
    assert not bf.might_contain("totally-unrelated-domain.org")


def test_bloom_bytes_length_matches_params() -> None:
    params = BloomParams(num_hashes=3, num_bits=1024, seed=7)
    bf = BloomFilterBuilder(params)
    assert len(bf.to_bytes()) == 128  # 1024 bits / 8
