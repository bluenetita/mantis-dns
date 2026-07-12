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

import httpx
import pytest
from unittest.mock import patch

import mantis_control.feeds.ingest as ingest_module
from mantis_control.db.models import Feed
from mantis_control.feeds.ingest import fetch_and_ingest, load_domains, _sanity_check
from mantis_control.feeds.parsers import parse_domain_list, parse_hostfile


def test_parse_hostfile_basic():
    text = """
    # comment
    0.0.0.0 ads.example.com
    127.0.0.1 tracker.example.net
    0.0.0.0 www.duplicate.example

    0.0.0.0 www.duplicate.example
    """
    domains = parse_hostfile(text)
    assert domains == {"ads.example.com", "tracker.example.net", "duplicate.example"}


def test_parse_hostfile_skips_localhost():
    text = "0.0.0.0 localhost\n0.0.0.0 real.example\n"
    assert parse_hostfile(text) == {"real.example"}


def test_parse_domain_list_basic():
    text = "ads.example.com\n# comment\n\ntracker.example.net\n"
    assert parse_domain_list(text) == {"ads.example.com", "tracker.example.net"}


def test_parse_domain_list_strips_inline_comment():
    text = "gore.example.com           #Gore\nclean.example.net\n"
    assert parse_domain_list(text) == {"gore.example.com", "clean.example.net"}


def test_sanity_check_rejects_must_never_block():
    new_domains = {"ads.example.com", "google.com"}
    reason = _sanity_check(new_domains, previous_count=None)
    assert reason is not None
    assert "must-never-block" in reason


def test_sanity_check_rejects_large_delta():
    new_domains = {f"domain{i}.example" for i in range(10)}
    reason = _sanity_check(new_domains, previous_count=1000)
    assert reason is not None
    assert "exceeds" in reason


def test_sanity_check_passes_normal_update():
    new_domains = {f"domain{i}.example" for i in range(100)}
    reason = _sanity_check(new_domains, previous_count=95)
    assert reason is None


@pytest.mark.asyncio
async def test_fetch_and_ingest_updates_and_stores(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="0.0.0.0 malicious.example\n0.0.0.0 bad.example\n")

    transport = httpx.MockTransport(handler)
    feed = Feed(id="test-feed", category_id="malware", url="https://example.test/feed", format="hostfile")

    with patch(
        "mantis_control.feeds.ingest.resolve_pinned_url",
        return_value=(feed.url, "example.test"),
    ):
        async with httpx.AsyncClient(transport=transport) as client:
            result = await fetch_and_ingest(feed, tmp_path, client)

    assert result.status == "updated"
    assert result.domain_count == 2
    assert load_domains(tmp_path, "test-feed") == {"malicious.example", "bad.example"}
    assert feed.last_domain_count == 2


@pytest.mark.asyncio
async def test_fetch_and_ingest_rejects_poisoned_feed(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="0.0.0.0 google.com\n")

    transport = httpx.MockTransport(handler)
    feed = Feed(id="test-feed", category_id="malware", url="https://example.test/feed", format="hostfile")

    with patch(
        "mantis_control.feeds.ingest.resolve_pinned_url",
        return_value=(feed.url, "example.test"),
    ):
        async with httpx.AsyncClient(transport=transport) as client:
            result = await fetch_and_ingest(feed, tmp_path, client)

    assert result.status == "rejected"
    assert load_domains(tmp_path, "test-feed") == set()  # nothing written on rejection


@pytest.mark.asyncio
async def test_fetch_and_ingest_rejects_oversized_body(tmp_path, monkeypatch):
    """A feed source returning an unbounded body must be aborted mid-stream,
    not fully buffered into memory before any sanity check runs."""
    monkeypatch.setattr(ingest_module, "MAX_FEED_BYTES", 100)

    def handler(request: httpx.Request) -> httpx.Response:
        oversized = "0.0.0.0 domain.example\n" * 20  # well over the 100-byte cap
        return httpx.Response(200, text=oversized)

    transport = httpx.MockTransport(handler)
    feed = Feed(id="test-feed", category_id="malware", url="https://example.test/feed", format="hostfile")

    with patch(
        "mantis_control.feeds.ingest.resolve_pinned_url",
        return_value=(feed.url, "example.test"),
    ):
        async with httpx.AsyncClient(transport=transport) as client:
            result = await fetch_and_ingest(feed, tmp_path, client)

    assert result.status == "error"
    assert "byte cap" in result.reason
    assert load_domains(tmp_path, "test-feed") == set()  # nothing written


@pytest.mark.asyncio
async def test_fetch_and_ingest_unchanged_on_304(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("If-None-Match") == "abc123"
        return httpx.Response(304)

    transport = httpx.MockTransport(handler)
    feed = Feed(
        id="test-feed",
        category_id="malware",
        url="https://example.test/feed",
        format="hostfile",
        last_etag="abc123",
        last_domain_count=42,
    )

    with patch(
        "mantis_control.feeds.ingest.resolve_pinned_url",
        return_value=(feed.url, "example.test"),
    ):
        async with httpx.AsyncClient(transport=transport) as client:
            result = await fetch_and_ingest(feed, tmp_path, client)

    assert result.status == "unchanged"
    assert result.domain_count == 42
