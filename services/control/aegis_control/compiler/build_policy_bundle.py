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

from aegis_control.compiler.bloom import BloomFilterBuilder, recommended_params
from aegis_control.compiler.signing import sign_bundle
from aegis_control.db.models import Policy
from aegis_control.gen import bundle_pb2

# Default sizing for a category with no known domain count yet (Sprint 2).
# Real counts come from the feed ingester (Sprint 4) and reuse recommended_params().
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


def build_bundle(policy: Policy, version: int) -> bundle_pb2.Bundle:
    bundle = bundle_pb2.Bundle(
        tenant_id=policy.group.tenant_id,
        group_id=policy.group_id,
        version=version,
        built_at_unix=int(time.time()),
        on_load_failure=_FAILURE_POLICY_MAP.get(policy.on_load_failure, bundle_pb2.FAIL_OPEN),
    )

    for toggle in policy.category_toggles:
        bf = BloomFilterBuilder(_EMPTY_CATEGORY_PARAMS)  # no domains yet — Sprint 4 ingester fills this in
        bundle.categories.append(
            bundle_pb2.CategorySet(
                category_id=toggle.category_id,
                source_feed_id="",
                feed_version="",
                license="",
                bloom=bundle_pb2.BloomParams(
                    num_hashes=_EMPTY_CATEGORY_PARAMS.num_hashes,
                    num_bits=_EMPTY_CATEGORY_PARAMS.num_bits,
                    seed=_EMPTY_CATEGORY_PARAMS.seed,
                ),
                bloom_bits=bf.to_bytes(),
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
    policy: Policy, version: int, private_key: Ed25519PrivateKey, key_id: str, storage_dir: Path
) -> Path:
    bundle = build_bundle(policy, version)
    signed_bytes = sign_bundle(bundle, private_key, key_id)
    return store_bundle(signed_bytes, storage_dir, policy.group_id)
