# Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""user tenant scope constraint

Revision ID: c7d8e9f0a123
Revises: fc7584542ce8
Create Date: 2026-07-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "c7d8e9f0a123"
down_revision: Union[str, Sequence[str], None] = "fc7584542ce8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_check_constraint(
        "ck_users_non_admin_requires_tenant",
        "users",
        "role = 'admin' OR tenant_id IS NOT NULL",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint("ck_users_non_admin_requires_tenant", "users", type_="check")
