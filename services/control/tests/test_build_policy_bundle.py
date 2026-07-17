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

"""Regression tests for `_category_bloom`: a category with SEVERAL enabled
feeds must compile the UNION of all their domains. The original code picked
one feed with an unordered `.first()`, so every other feed's domains were
silently missing from the wire — and, because the row order was
nondeterministic, "Test a domain" (same query) could consult a different
feed than the compiler and contradict live DNS answers in both directions.
Uses an in-memory sqlite DB (only the Feed table) since `_category_bloom`
runs a real ORM query.
"""
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.compiler import build_policy_bundle
from mantis_control.compiler.bloom import BloomFilterBuilder
from mantis_control.db.models import Base, Feed
from mantis_control.feeds.ingest import _feed_path


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    # Only the table under test — other models use postgres-only ARRAY
    # columns that sqlite's dialect can't compile.
    Base.metadata.create_all(engine, tables=[Feed.__table__])
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _write_feed(db, storage_dir, feed_id: str, domains: list[str], ingested: bool = True) -> None:
    db.add(
        Feed(
            id=feed_id,
            category_id="malware",
            url=f"https://example.test/{feed_id}",
            format="domain-list",
            enabled=True,
            last_domain_count=len(domains) if ingested else None,
        )
    )
    db.commit()
    _feed_path(storage_dir, feed_id).write_text("\n".join(domains))


def _contains(bloom_bytes: bytes, params, domain: str) -> bool:
    bf = BloomFilterBuilder(params)
    bf._bits = bytearray(bloom_bytes)
    return bf.might_contain(domain)


def test_category_bloom_unions_all_enabled_feeds(db, tmp_path):
    _write_feed(db, tmp_path, "feed-a", ["only-in-a.example"])
    _write_feed(db, tmp_path, "feed-b", ["only-in-b.example"])

    # Bloom seed is normally randomized per compile (see bloom.py); with only
    # two domains in a 67-bit filter, an unlucky seed has a small but real
    # chance of making "neither.example" a false positive, which flaked this
    # test in CI. Pin the seed so the negative-containment assertion below is
    # deterministic instead of probabilistic.
    with patch.object(build_policy_bundle, "_random_seed", return_value=0), patch.object(
        build_policy_bundle, "FEED_STORAGE_DIR", tmp_path
    ):
        bloom_bytes, params, feeds = build_policy_bundle._category_bloom(db, "malware")

    assert [f.id for f in feeds] == ["feed-a", "feed-b"]
    assert _contains(bloom_bytes, params, "only-in-a.example")
    assert _contains(bloom_bytes, params, "only-in-b.example")
    assert not _contains(bloom_bytes, params, "neither.example")


def test_category_bloom_skips_never_ingested_feeds(db, tmp_path):
    _write_feed(db, tmp_path, "feed-a", ["only-in-a.example"])
    _write_feed(db, tmp_path, "feed-b", ["only-in-b.example"], ingested=False)

    with patch.object(build_policy_bundle, "FEED_STORAGE_DIR", tmp_path):
        bloom_bytes, params, feeds = build_policy_bundle._category_bloom(db, "malware")

    assert [f.id for f in feeds] == ["feed-a"]
    assert _contains(bloom_bytes, params, "only-in-a.example")
    assert not _contains(bloom_bytes, params, "only-in-b.example")


def test_category_bloom_empty_when_no_feed_ingested(db, tmp_path):
    _write_feed(db, tmp_path, "feed-a", ["only-in-a.example"], ingested=False)

    with patch.object(build_policy_bundle, "FEED_STORAGE_DIR", tmp_path):
        bloom_bytes, params, feeds = build_policy_bundle._category_bloom(db, "malware")

    assert feeds == []
    assert not _contains(bloom_bytes, params, "only-in-a.example")
