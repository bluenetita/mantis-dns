"""Loads catalog.json — the pre-vetted default feed list (MISP-manifest
style: a declarative, version-controlled catalog of known-good sources) —
into the DB on startup. Idempotent: only inserts feeds whose id isn't
already present, so it never clobbers admin edits (enabled toggle, interval,
custom feeds) made via the UI after first boot.

Known gap: there's no good free, reliably-maintained public list for every
category in the taxonomy (mantis_control.categories.CATEGORY_REGISTRY) — see
each entry's has_bundled_feed flag. Those categories are left for an admin
to add manually via the UI (POST /api/v1/feeds) once they have a vetted
source.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from mantis_control.db.models import Feed

CATALOG_PATH = Path(__file__).parent / "catalog.json"


def seed_catalog(db: Session) -> int:
    catalog = json.loads(CATALOG_PATH.read_text())
    existing_ids = {f.id for f in db.query(Feed.id).all()}

    inserted = 0
    for entry in catalog:
        if entry["id"] in existing_ids:
            continue
        db.add(
            Feed(
                id=entry["id"],
                category_id=entry["category_id"],
                url=entry["url"],
                format=entry["format"],
                interval_seconds=entry.get("interval_seconds", 86400),
                license=entry.get("license", ""),
                provider=entry.get("provider", ""),
                from_catalog=True,
                enabled=True,
            )
        )
        inserted += 1
    db.commit()
    return inserted
