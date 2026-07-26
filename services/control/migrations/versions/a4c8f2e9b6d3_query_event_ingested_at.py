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

"""query_event ingested_at

Adds QueryEvent.ingested_at: always server-set at INSERT, unlike
occurred_at (now optionally client-reported query time, see
QueryEventIn.occurred_at_ms in telemetry_routers.py). The SIEM delivery
cursor's DELIVERY_LAG_SECONDS safety window (siem_common.py) needs a
timestamp that actually correlates with QueryEvent.seq commit order —
occurred_at no longer reliably does once a filter node supplies its own
(client-clock) value for it.

server_default=now() backfills existing rows at the moment this migration
runs, so no historical row is left NULL.

Revision ID: a4c8f2e9b6d3
Revises: e5f8b2c1a734
Create Date: 2026-07-26 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a4c8f2e9b6d3"
down_revision: Union[str, Sequence[str], None] = "e5f8b2c1a734"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "query_events",
        sa.Column("ingested_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(op.f("ix_query_events_ingested_at"), "query_events", ["ingested_at"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_query_events_ingested_at"), table_name="query_events")
    op.drop_column("query_events", "ingested_at")
