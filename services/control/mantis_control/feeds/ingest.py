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

"""Feed fetch -> validate -> normalize -> dedupe/diff -> sanity-gated store.

design.md §18.3 safeguards implemented here:
  - conditional fetch (ETag) to skip unchanged feeds
  - sanity gates: reject if domain count collapses/explodes beyond a
    threshold, or if any "must never block" domain shows up (poisoned feed
    protection)
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

from mantis_control.db.models import Feed
from mantis_control.feeds.parsers import PARSERS
from mantis_control.ssrf_guard import resolve_pinned_url

# One lock per feed_id, shared between the recurring scheduler job
# (scheduler.run_ingest) and the manual "sync now" endpoint
# (api/feed_routers.ingest_feed) — without it, both can fetch and write the
# same feed concurrently on independent DB sessions, leaving the on-disk
# file and the Feed row's last_etag/last_domain_count/last_version reflecting
# two different fetches.
_feed_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)


def feed_lock(feed_id: str) -> asyncio.Lock:
    return _feed_locks[feed_id]

# Domains that must never appear in a compiled category set. A feed proposing
# to block one of these is treated as poisoned/broken and rejected outright.
MUST_NEVER_BLOCK = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "cloudflare.com",
    "amazon.com",
    "github.com",
}

DEFAULT_MAX_DELTA_PCT = 50
DEFAULT_MIN_DOMAINS = 1

# Generous cap for any legitimate domain-list feed (largest public blocklists
# run a few hundred MB uncompressed at the extreme). Without a cap, a feed
# source (admin-configured, but often a public third-party list — or one
# compromised/MITM'd) returning an arbitrarily large body gets fully buffered
# into memory before _sanity_check ever runs, so the OOM already happens
# during the fetch, before any of the poisoned-feed protections apply.
MAX_FEED_BYTES = 64 * 1024 * 1024


@dataclass
class IngestResult:
    status: str  # "updated" | "unchanged" | "rejected" | "error"
    domain_count: int = 0
    reason: str = ""


def _feed_path(storage_dir: Path, feed_id: str) -> Path:
    return storage_dir / f"{feed_id}.domains.txt"


def load_domains(storage_dir: Path, feed_id: str) -> set[str]:
    path = _feed_path(storage_dir, feed_id)
    if not path.exists():
        return set()
    return set(path.read_text().splitlines())


def _sanity_check(new_domains: set[str], previous_count: int | None) -> str | None:
    """Returns a rejection reason, or None if the new set passes."""
    if len(new_domains) < DEFAULT_MIN_DOMAINS:
        return f"domain count {len(new_domains)} below minimum {DEFAULT_MIN_DOMAINS}"

    hit = MUST_NEVER_BLOCK & new_domains
    if hit:
        return f"feed contains must-never-block domains: {sorted(hit)}"

    if previous_count is not None and previous_count > 0:
        delta_pct = abs(len(new_domains) - previous_count) / previous_count * 100
        if delta_pct > DEFAULT_MAX_DELTA_PCT:
            return (
                f"domain count changed {delta_pct:.1f}% "
                f"({previous_count} -> {len(new_domains)}), exceeds {DEFAULT_MAX_DELTA_PCT}% threshold"
            )
    return None


async def fetch_and_ingest(
    feed: Feed, storage_dir: Path, client: httpx.AsyncClient
) -> IngestResult:
    """Callers MUST hold `feed_lock(feed.id)` for the duration of this call
    plus their own subsequent DB commit — see `_feed_locks` above. Not
    acquired internally because each caller commits the mutated `feed`
    (returned via side effect on the passed-in object) in a separate step
    right after this returns, and the lock has to cover that too."""
    parser = PARSERS.get(feed.format)
    if parser is None:
        return IngestResult(status="error", reason=f"unknown feed format '{feed.format}'")

    try:
        # resolve_pinned_url does a blocking socket.getaddrinfo() call — this
        # is a single-process app where one event loop also serves every
        # tenant's API requests, so run it off-thread rather than stalling
        # the whole control plane on a slow/black-holed feed hostname.
        pinned_url, original_host = await asyncio.to_thread(resolve_pinned_url, feed.url)
    except ValueError as e:
        return IngestResult(status="error", reason=f"SSRF guard rejected feed URL: {e}")

    # Fetch by pinned IP (not the hostname) so a DNS re-resolution at connect
    # time can't redirect this request somewhere the guard above didn't see.
    headers = {"Host": original_host}
    if feed.last_etag:
        headers["If-None-Match"] = feed.last_etag
    try:
        # Streamed (not client.get()) so the MAX_FEED_BYTES cap below can
        # abort mid-download instead of only checking after the whole body
        # is already buffered in memory.
        async with client.stream(
            "GET",
            pinned_url,
            headers=headers,
            timeout=30.0,
            follow_redirects=False,
            extensions={"sni_hostname": original_host},
        ) as resp:
            if resp.status_code == 304:
                return IngestResult(status="unchanged", domain_count=feed.last_domain_count or 0)
            if resp.status_code != 200:
                return IngestResult(status="error", reason=f"HTTP {resp.status_code}")

            etag = resp.headers.get("ETag")
            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_FEED_BYTES:
                    return IngestResult(
                        status="error",
                        reason=f"feed body exceeds {MAX_FEED_BYTES}-byte cap",
                    )
    except httpx.HTTPError as e:
        return IngestResult(status="error", reason=str(e))

    new_domains = parser(bytes(body).decode("utf-8", errors="replace"))
    rejection = _sanity_check(new_domains, feed.last_domain_count)
    if rejection:
        return IngestResult(status="rejected", domain_count=len(new_domains), reason=rejection)

    storage_dir.mkdir(parents=True, exist_ok=True)
    # Write via tempfile + atomic rename rather than truncating the target
    # in place — a reader (or a concurrent ingest for the same feed) must
    # never observe a half-written file.
    target = _feed_path(storage_dir, feed.id)
    fd, tmp_name = tempfile.mkstemp(dir=storage_dir, prefix=f".{feed.id}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(sorted(new_domains)))
        os.replace(tmp_name, target)
    except BaseException:
        os.unlink(tmp_name)
        raise

    feed.last_fetched_at = datetime.now(timezone.utc)
    feed.last_etag = etag
    feed.last_domain_count = len(new_domains)
    feed.last_version = hashlib.sha256("\n".join(sorted(new_domains)).encode()).hexdigest()[:16]

    return IngestResult(status="updated", domain_count=len(new_domains))
