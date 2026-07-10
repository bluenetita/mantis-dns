#!/usr/bin/env python
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

"""Diagnoses why a category that's BLOCK in the saved policy still lets
traffic through on the wire, by checking the one gate `_category_bloom()`
(mantis_control/compiler/build_policy_bundle.py) applies that the
"Test a domain" endpoint doesn't: `feed.last_domain_count is None`.

If a feed was created/enabled but never actually *ingested* (a separate,
explicit action - POST /feeds/{id}/ingest - not triggered by just toggling
it on), `last_domain_count` stays NULL forever and every compile embeds an
EMPTY bloom filter for that category: structurally valid, signature verifies
fine, filter node accepts it happily - it just never matches anything.

Connects directly to DATABASE_URL (same as the API process) - no running
control-plane server required. Read-only: issues no writes.

Usage:
    python scripts/diagnose_category_bloom.py --group-id b83222e0-a6ee-4c84-a134-4388c7b18bbf
    python scripts/diagnose_category_bloom.py --group-id <id> --domain pornhub.com
"""
from __future__ import annotations

import argparse
import sys

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from mantis_control.config import FEED_STORAGE_DIR
from mantis_control.db import models
from mantis_control.db.session import engine
from mantis_control.feeds.ingest import load_domains


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--group-id", required=True, help="Group whose policy to inspect")
    parser.add_argument("--domain", help="Domain to check against each blocked category's feed file (optional)")
    args = parser.parse_args()

    db = sessionmaker(bind=engine)()
    try:
        return _diagnose(db, args.group_id, args.domain)
    finally:
        db.close()


def _diagnose(db, group_id: str, domain: str | None) -> int:
    group = db.get(models.Group, group_id)
    if group is None:
        print(f"no group with id {group_id!r}", file=sys.stderr)
        return 2

    policy = db.query(models.Policy).filter(models.Policy.group_id == group_id).one_or_none()
    if policy is None:
        print(f"group {group.name!r} has no policy at all - nothing to compile.")
        return 1

    print(f"Group {group.name!r} (tenant_id={group.tenant_id}), bundle_version={policy.bundle_version}")
    print(f"{len(policy.category_toggles)} category toggle(s):\n")

    domain_norm = domain.strip().lower().rstrip(".") if domain else None
    any_block = False
    for toggle in policy.category_toggles:
        if toggle.action != "ACTION_BLOCK":
            print(f"  [{toggle.category_id}] action={toggle.action} (not a block - skipped by compiler same as here)")
            continue
        any_block = True

        feeds = db.execute(
            select(models.Feed).where(
                models.Feed.category_id == toggle.category_id,
                models.Feed.enabled.is_(True),
            ).order_by(models.Feed.id)
        ).scalars().all()

        if not feeds:
            print(f"  [{toggle.category_id}] action=ACTION_BLOCK but NO enabled feed for this category")
            print("      -> compiled bundle embeds an EMPTY bloom filter for it. Enable a feed.")
            continue

        for feed in feeds:
            if feed.last_domain_count is None:
                print(f"  [{toggle.category_id}] action=ACTION_BLOCK, feed={feed.id!r} enabled=True, last_domain_count=NULL")
                print("      -> feed has never been ingested (last_domain_count is NULL), so it")
                print("         contributes NO domains to the compiled bloom filter, no matter")
                print("         how many times you click 'Compile & publish bundle'.")
                print(f"      -> Fix: POST /api/v1/feeds/{feed.id}/ingest (or click 'Refresh' on the")
                print("         Feeds page for this feed), THEN Compile & publish bundle again.")
            else:
                on_disk = load_domains(FEED_STORAGE_DIR, feed.id)
                print(
                    f"  [{toggle.category_id}] action=ACTION_BLOCK, feed={feed.id!r} enabled=True, "
                    f"last_domain_count={feed.last_domain_count}, on-disk domains={len(on_disk)}"
                )
                if domain_norm:
                    hit = domain_norm in on_disk
                    print(f"      -> {domain_norm!r} {'IS' if hit else 'is NOT'} in this feed's domain file")

    if not any_block:
        print("\nNo category is set to ACTION_BLOCK in this policy at all - nothing should be blocked,")
        print("by design (not a bug).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
