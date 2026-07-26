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

"""drop siem_webhooks

The SIEM webhook push feature (HMAC-signed HTTP push, design.md §20.4) is
removed — the syslog sink (siem_syslogs) and the pull API cover SIEM export
going forward. This drops the table the baseline migration created; it is a
new migration rather than an edit to baseline so already-migrated
deployments have a clean upgrade path instead of a rewritten history.

Revision ID: e5f8b2c1a734
Revises: d7f2a9c6b1e4
Create Date: 2026-07-26 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f8b2c1a734"
down_revision: Union[str, Sequence[str], None] = "d7f2a9c6b1e4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_index(op.f("ix_siem_webhooks_tenant_id"), table_name="siem_webhooks")
    op.drop_table("siem_webhooks")


def downgrade() -> None:
    """Downgrade schema."""
    op.create_table(
        "siem_webhooks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("url", sa.String(length=1024), nullable=False),
        sa.Column("secret_encrypted", sa.String(length=1024), nullable=False),
        sa.Column("format", sa.String(length=10), nullable=False),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("flush_interval_s", sa.Integer(), nullable=False),
        sa.Column("filter_decision", sa.String(length=10), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_delivered_seq", sa.BigInteger(), nullable=False),
        sa.Column("last_delivered_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(length=2000), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("next_retry_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_siem_webhooks_tenant_id"), "siem_webhooks", ["tenant_id"], unique=False)
