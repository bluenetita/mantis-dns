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

"""Compiles a DB Policy into a signed Bundle, ready for a filter node to load.

Sprint 2 scope: category sets get real bloom params but empty domain bits —
feed ingestion (Sprint 4-5) is what actually populates them. Allow/deny
overrides are wired end to end since they come straight from the DB.
"""

from __future__ import annotations

import hashlib
import os
import random
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from mantis_control.block_page import resolve_block_template
from mantis_control.compiler.bloom import BloomFilterBuilder, BloomParams, recommended_params
from mantis_control.compiler.signing import sign_bundle
from mantis_control.config import FEED_STORAGE_DIR
from mantis_control.db.models import Feed, Policy
from mantis_control.feeds.ingest import load_domains
from mantis_control.gen import bundle_pb2


def _random_seed() -> int:
    """A fixed seed (this used to be a hardcoded 1234, every category, every
    install) makes bloom false-positive collisions permanent and identical
    across every Mantis-DNS deployment: whichever real-world domains happen to
    hash-collide with a given category's bit pattern collide *forever*, since
    the pattern only changes when the underlying feed content changes. A fresh
    seed per compile turns that into transient noise that shifts on the next
    recompile instead of a standing, reproducible bug. bundle_pb2.BloomParams
    carries the seed per-category on the wire already — the reader
    (mantis-policy) needs no change, it already reads whatever seed ships."""
    return random.getrandbits(64)


# Target false-positive rate for every category's bloom filter. Bits scale
# with -ln(p), not 1/p, so tightening 0.001 -> 0.0001 (10x fewer false
# blocks per category) only costs ~1.33x the bits — on the current catalog
# (17 categories, ~4.4M domains total) that's 7.56 MB -> 10.08 MB combined,
# not the 10x a naive reading of "10x lower FPR" would suggest. Categories
# are checked independently and block on first hit (mantis-filter's decide()),
# so the per-category rate compounds across however many are enabled — this
# is what actually bounds the real-world false-block rate, not any single
# category's number in isolation.
_TARGET_FPR = 0.0001

# Sizing for a category with no ingested feed yet (empty bloom, matches behavior
# before Sprint 5's feed ingester existed). Bits are all-zero either way
# (nothing to insert), so the seed can't affect matching here — randomized
# anyway for consistency, not because it's load-bearing.
_EMPTY_CATEGORY_PARAMS = recommended_params(expected_items=1000, false_positive_rate=_TARGET_FPR, seed=_random_seed())

_FAILURE_POLICY_MAP = {
    "FAIL_OPEN": bundle_pb2.FAIL_OPEN,
    "FAIL_CLOSED": bundle_pb2.FAIL_CLOSED,
}
_ACTION_MAP = {
    "ACTION_BLOCK": bundle_pb2.ACTION_BLOCK,
    "ACTION_LOG_ONLY": bundle_pb2.ACTION_LOG_ONLY,
    "ACTION_ALLOW": bundle_pb2.ACTION_ALLOW,
}
_BLOCK_MODE_MAP = {
    "BLOCK_MODE_UNSPECIFIED": bundle_pb2.BLOCK_MODE_UNSPECIFIED,
    "BLOCK_MODE_NXDOMAIN": bundle_pb2.BLOCK_MODE_NXDOMAIN,
    "BLOCK_MODE_ZERO_IP": bundle_pb2.BLOCK_MODE_ZERO_IP,
    "BLOCK_MODE_REDIRECT": bundle_pb2.BLOCK_MODE_REDIRECT,
}


def _fetch_ingested_feeds(db: Session, category_id: str) -> list[Feed]:
    """Enabled feeds for a category that have actually been ingested at least
    once. Ordered by feed id so compiles are deterministic. DB-bound — must
    run in the calling process, never inside a worker (Session isn't
    fork/spawn-safe)."""
    feeds = db.execute(
        select(Feed)
        .where(Feed.category_id == category_id, Feed.enabled.is_(True))
        .order_by(Feed.id)
    ).scalars().all()
    return [f for f in feeds if f.last_domain_count is not None]


def _compile_bloom(feed_storage_dir: Path, feed_ids: list[str]) -> tuple[bytes, int, int, int]:
    """Pure CPU/IO work for one category: union the given feeds' domains and
    build the bloom filter. No DB access, no closures over module-level
    mutable state — this is the piece dispatched to worker processes, so it
    must be importable and picklable as a plain top-level function. Returns
    a plain tuple (not BloomParams) to keep the pickled result minimal."""
    domains: set[str] = set()
    for feed_id in feed_ids:
        domains |= load_domains(feed_storage_dir, feed_id)
    params = recommended_params(expected_items=max(len(domains), 1), false_positive_rate=_TARGET_FPR, seed=_random_seed())
    bf = BloomFilterBuilder(params)
    for domain in domains:
        bf.add(domain)
    return bf.to_bytes(), params.num_hashes, params.num_bits, params.seed


def _category_bloom(db: Session, category_id: str) -> tuple[bytes, BloomParams, list[Feed]]:
    """Builds a category's bloom filter as the UNION of every enabled,
    ingested feed for that category — a category may have several feeds
    (e.g. two ads lists), and consulting only one silently drops the rest
    from the wire. Falls back to an empty filter when no feed has been
    ingested yet. Returns the feeds that contributed domains (empty list
    if none). Sequential fetch + compute — used directly by callers that
    only need one category (tests, the diagnose script); build_bundle below
    fans the compute step for *all* of a policy's categories out to a
    process pool instead of calling this per category."""
    ingested = _fetch_ingested_feeds(db, category_id)
    if not ingested:
        bf = BloomFilterBuilder(_EMPTY_CATEGORY_PARAMS)
        return bf.to_bytes(), _EMPTY_CATEGORY_PARAMS, []

    bloom_bytes, num_hashes, num_bits, seed = _compile_bloom(FEED_STORAGE_DIR, [f.id for f in ingested])
    return bloom_bytes, BloomParams(num_hashes, num_bits, seed), ingested


_pool: ProcessPoolExecutor | None = None


def _get_pool() -> ProcessPoolExecutor:
    """Lazily-created, process-lifetime-reused pool. Bloom insertion is a
    pure-Python hash loop (bloom.py) — threads buy nothing there, the GIL
    serializes it regardless of thread count. A fresh ProcessPoolExecutor
    per compile would burn most of the win on interpreter startup (costly
    on Windows' spawn), so one pool is created on first use and kept
    around for the life of the server process."""
    global _pool
    if _pool is None:
        _pool = ProcessPoolExecutor(max_workers=os.cpu_count() or 1)
    return _pool


def build_bundle(policy: Policy, version: int, db: Session) -> bundle_pb2.Bundle:
    bundle = bundle_pb2.Bundle(
        tenant_id=policy.group.tenant_id,
        group_id=policy.group_id,
        version=version,
        built_at_unix=int(time.time()),
        on_load_failure=_FAILURE_POLICY_MAP.get(policy.on_load_failure, bundle_pb2.FAIL_OPEN),
    )

    # Phase 1: DB reads, sequential — the Session isn't fork/spawn-safe so
    # this can't be handed to worker processes.
    toggle_feeds = [(toggle, _fetch_ingested_feeds(db, toggle.category_id)) for toggle in policy.category_toggles]

    # Phase 2: the CPU-bound bloom build, fanned out across categories.
    # Categories are independent (no shared state), so this is where the
    # actual wall-clock win is — skip the pool for 0-1 categories needing
    # real work, since process spawn/pickling overhead would eat the gain.
    results: dict[int, tuple[bytes, BloomParams]] = {}
    needs_compute = [(i, feeds) for i, (_, feeds) in enumerate(toggle_feeds) if feeds]
    for i, (_, feeds) in enumerate(toggle_feeds):
        if not feeds:
            results[i] = (BloomFilterBuilder(_EMPTY_CATEGORY_PARAMS).to_bytes(), _EMPTY_CATEGORY_PARAMS)

    if len(needs_compute) > 1:
        pool = _get_pool()
        futures = {
            pool.submit(_compile_bloom, FEED_STORAGE_DIR, [f.id for f in feeds]): i
            for i, feeds in needs_compute
        }
        for future in as_completed(futures):
            i = futures[future]
            bloom_bytes, num_hashes, num_bits, seed = future.result()
            results[i] = (bloom_bytes, BloomParams(num_hashes, num_bits, seed))
    else:
        for i, feeds in needs_compute:
            bloom_bytes, num_hashes, num_bits, seed = _compile_bloom(FEED_STORAGE_DIR, [f.id for f in feeds])
            results[i] = (bloom_bytes, BloomParams(num_hashes, num_bits, seed))

    for i, (toggle, feeds) in enumerate(toggle_feeds):
        bloom_bytes, params = results[i]
        bundle.categories.append(
            bundle_pb2.CategorySet(
                category_id=toggle.category_id,
                source_feed_id=",".join(f.id for f in feeds),
                feed_version=",".join(f.last_version or "" for f in feeds),
                license=",".join(sorted({f.license for f in feeds if f.license})),
                bloom=bundle_pb2.BloomParams(
                    num_hashes=params.num_hashes,
                    num_bits=params.num_bits,
                    seed=params.seed,
                ),
                bloom_bits=bloom_bytes,
                action=_ACTION_MAP.get(toggle.action, bundle_pb2.ACTION_BLOCK),
            )
        )

    for override in policy.overrides:
        if override.kind == "allow":
            bundle.allow_overrides.append(override.domain)
        else:
            bundle.deny_overrides.append(override.domain)

    # Only the hot-path fields (mode + redirect IPs + ttl) go in the signed
    # bundle; branding is served separately to the block-page listener. When no
    # template is configured the field is left absent and the filter defaults to
    # NXDOMAIN (historical behavior).
    template = resolve_block_template(db, policy.group.tenant_id, policy.group_id)
    if template is not None and template.block_mode != "BLOCK_MODE_NXDOMAIN":
        bundle.block_response.CopyFrom(
            bundle_pb2.BlockResponse(
                mode=_BLOCK_MODE_MAP.get(template.block_mode, bundle_pb2.BLOCK_MODE_NXDOMAIN),
                redirect_ipv4=template.redirect_ipv4 or "",
                redirect_ipv6=template.redirect_ipv6 or "",
                ttl_seconds=template.ttl_seconds or 0,
            )
        )

    return bundle


def content_address(signed_bytes: bytes) -> str:
    return hashlib.sha256(signed_bytes).hexdigest()


def store_bundle(signed_bytes: bytes, storage_dir: Path, group_id: str) -> Path:
    """Content-addressed disk storage + a 'latest' pointer per group (Sprint 2 local-disk version
    of the object-store + etcd distribution described in design.md §5.2; swap the body of this
    function for an S3 put + etcd key write without touching callers)."""
    storage_dir.mkdir(parents=True, exist_ok=True)
    digest = content_address(signed_bytes)
    bundle_path = storage_dir / f"{digest}.bin"
    bundle_path.write_bytes(signed_bytes)

    latest_pointer = storage_dir / f"{group_id}.latest"
    latest_pointer.write_text(digest)
    return bundle_path


def compile_and_store(
    policy: Policy,
    version: int,
    private_key: Ed25519PrivateKey,
    key_id: str,
    storage_dir: Path,
    db: Session,
) -> Path:
    bundle = build_bundle(policy, version, db)
    signed_bytes = sign_bundle(bundle, private_key, key_id)
    return store_bundle(signed_bytes, storage_dir, policy.group_id)
