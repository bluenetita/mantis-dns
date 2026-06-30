"""Feed fetch -> validate -> normalize -> dedupe/diff -> sanity-gated store.

design.md §18.3 safeguards implemented here:
  - conditional fetch (ETag) to skip unchanged feeds
  - sanity gates: reject if domain count collapses/explodes beyond a
    threshold, or if any "must never block" domain shows up (poisoned feed
    protection)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

from aegis_control.db.models import Feed
from aegis_control.feeds.parsers import PARSERS

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

    if previous_count and previous_count > 0:
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
    parser = PARSERS.get(feed.format)
    if parser is None:
        return IngestResult(status="error", reason=f"unknown feed format '{feed.format}'")

    headers = {"If-None-Match": feed.last_etag} if feed.last_etag else {}
    try:
        resp = await client.get(feed.url, headers=headers, timeout=30.0, follow_redirects=True)
    except httpx.HTTPError as e:
        return IngestResult(status="error", reason=str(e))

    if resp.status_code == 304:
        return IngestResult(status="unchanged", domain_count=feed.last_domain_count or 0)
    if resp.status_code != 200:
        return IngestResult(status="error", reason=f"HTTP {resp.status_code}")

    new_domains = parser(resp.text)
    rejection = _sanity_check(new_domains, feed.last_domain_count)
    if rejection:
        return IngestResult(status="rejected", domain_count=len(new_domains), reason=rejection)

    storage_dir.mkdir(parents=True, exist_ok=True)
    _feed_path(storage_dir, feed.id).write_text("\n".join(sorted(new_domains)))

    feed.last_fetched_at = datetime.now(timezone.utc)
    feed.last_etag = resp.headers.get("ETag")
    feed.last_domain_count = len(new_domains)
    feed.last_version = hashlib.sha256("\n".join(sorted(new_domains)).encode()).hexdigest()[:16]

    return IngestResult(status="updated", domain_count=len(new_domains))
