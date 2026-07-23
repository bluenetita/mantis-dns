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

"""siem syslog export

Adds siem_syslogs, the RFC 5424 syslog sibling of siem_webhooks
(design.md §20.8, Sprint 17) — same cursor/backoff/auto-disable shape,
no secret column since syslog has no HMAC signing concept.

Revision ID: b8e4f1a9c3d7
Revises: a1b2c3d4e5f6
Create Date: 2026-07-23 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b8e4f1a9c3d7"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "siem_syslogs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("transport", sa.String(length=10), nullable=False),
        sa.Column("format", sa.String(length=10), nullable=False),
        sa.Column("facility", sa.Integer(), nullable=False),
        sa.Column("app_name", sa.String(length=48), nullable=False),
        sa.Column("filter_decision", sa.String(length=10), nullable=False),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("flush_interval_s", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_delivered_seq", sa.BigInteger(), nullable=False),
        sa.Column("last_delivered_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(length=2000), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("next_retry_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_siem_syslogs_tenant_id"), "siem_syslogs", ["tenant_id"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_siem_syslogs_tenant_id"), table_name="siem_syslogs")
    op.drop_table("siem_syslogs")
