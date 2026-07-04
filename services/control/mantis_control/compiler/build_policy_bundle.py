"""Compiles a DB Policy into a signed Bundle, ready for a filter node to load.

Sprint 2 scope: category sets get real bloom params but empty domain bits —
feed ingestion (Sprint 4-5) is what actually populates them. Allow/deny
overrides are wired end to end since they come straight from the DB.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from mantis_control.compiler.bloom import BloomFilterBuilder, BloomParams, recommended_params
from mantis_control.compiler.signing import sign_bundle
from mantis_control.config import FEED_STORAGE_DIR
from mantis_control.db.models import Feed, Policy
from mantis_control.feeds.ingest import load_domains
from mantis_control.gen import bundle_pb2

# Sizing for a category with no ingested feed yet (empty bloom, matches behavior
# before Sprint 5's feed ingester existed).
_EMPTY_CATEGORY_PARAMS = recommended_params(expected_items=1000, seed=1234)

_FAILURE_POLICY_MAP = {
    "FAIL_OPEN": bundle_pb2.FAIL_OPEN,
    "FAIL_CLOSED": bundle_pb2.FAIL_CLOSED,
}
_ACTION_MAP = {
    "ACTION_BLOCK": bundle_pb2.ACTION_BLOCK,
    "ACTION_LOG_ONLY": bundle_pb2.ACTION_LOG_ONLY,
    "ACTION_ALLOW": bundle_pb2.ACTION_ALLOW,
}


def _category_bloom(db: Session, category_id: str) -> tuple[bytes, BloomParams, Feed | None]:
    """Builds a category's bloom filter from its ingested feed domains, if any
    feed has been ingested for this category yet. Falls back to an empty
    filter (pre-Sprint-5 behavior) when no feed has run."""
    feed = db.execute(
        select(Feed).where(Feed.category_id == category_id, Feed.enabled.is_(True))
    ).scalars().first()

    if feed is None or feed.last_domain_count is None:
        bf = BloomFilterBuilder(_EMPTY_CATEGORY_PARAMS)
        return bf.to_bytes(), _EMPTY_CATEGORY_PARAMS, feed

    domains = load_domains(FEED_STORAGE_DIR, feed.id)
    params = recommended_params(expected_items=max(len(domains), 1), seed=1234)
    bf = BloomFilterBuilder(params)
    for domain in domains:
        bf.add(domain)
    return bf.to_bytes(), params, feed


def build_bundle(policy: Policy, version: int, db: Session) -> bundle_pb2.Bundle:
    bundle = bundle_pb2.Bundle(
        tenant_id=policy.group.tenant_id,
        group_id=policy.group_id,
        version=version,
        built_at_unix=int(time.time()),
        on_load_failure=_FAILURE_POLICY_MAP.get(policy.on_load_failure, bundle_pb2.FAIL_OPEN),
    )

    for toggle in policy.category_toggles:
        bloom_bytes, params, feed = _category_bloom(db, toggle.category_id)
        bundle.categories.append(
            bundle_pb2.CategorySet(
                category_id=toggle.category_id,
                source_feed_id=feed.id if feed else "",
                feed_version=(feed.last_version or "") if feed else "",
                license=feed.license if feed else "",
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
