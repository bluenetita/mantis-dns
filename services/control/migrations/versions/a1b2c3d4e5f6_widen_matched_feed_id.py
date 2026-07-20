# Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""widen query_events.matched_feed_id

matched_feed_id carries a comma-joined list of every feed that contributed
to the matched category's bloom filter (source_feed_id in
build_policy_bundle.py's _category_bloom), not a single feed id — a category
backed by several feeds (e.g. "social": facebook/tiktok/twitter/whatsapp)
already produces a 100-char string, well past the old 64-char cap. Filter
nodes were silently losing every such block event: the control API rejected
the batch with 422 (string_too_long) and mantis-filter's telemetry flush
never checked the response status, so the drop was invisible in both sets
of logs. 512 gives headroom for a category backed by many more feeds before
this needs revisiting.

Revision ID: a1b2c3d4e5f6
Revises: e2c9a4f0b6d1
Create Date: 2026-07-20 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "e2c9a4f0b6d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column(
        "query_events",
        "matched_feed_id",
        existing_type=sa.String(length=64),
        type_=sa.String(length=512),
        existing_nullable=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column(
        "query_events",
        "matched_feed_id",
        existing_type=sa.String(length=512),
        type_=sa.String(length=64),
        existing_nullable=True,
    )
