"""Shared storage paths. Sprint 2/5: local disk. Swap for S3 + etcd per
design.md §5.2 without touching callers — see build_policy_bundle.store_bundle."""

from pathlib import Path

BUNDLE_STORAGE_DIR = Path("bundles")
FEED_STORAGE_DIR = Path("feed_domains")
