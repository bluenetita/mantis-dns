# Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""user token version

Adds users.token_version, embedded in every issued JWT as the "tv" claim and
checked in auth.get_current_user — bumped on password change so a stolen
session cookie/bearer token is invalidated immediately instead of remaining
valid for its full 12h TTL (JWTs are otherwise stateless here).

Revision ID: e2c9a4f0b6d1
Revises: d4a1f6c2b8e7
Create Date: 2026-07-17 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e2c9a4f0b6d1"
down_revision: Union[str, Sequence[str], None] = "d4a1f6c2b8e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("users", "token_version")
