from aegis_control.compiler.bloom import BloomFilterBuilder, BloomParams, fnv1a


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
