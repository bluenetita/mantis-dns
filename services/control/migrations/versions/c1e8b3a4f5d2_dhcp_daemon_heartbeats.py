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

"""dhcp daemon heartbeats

mantis-dhcp/mantis-dhcp6 have no liveness signal reaching the control plane
or UI today -- if the daemon process crashes or can't bind its socket, the
lease/utilisation numbers on the Status tab just stop updating silently,
with nothing telling an operator the daemon itself is down (see design.md
§22.11). Each daemon instance now upserts its own row here on the same tick
as its existing config-refresh loop; `instance_id` is a fresh UUID generated
at process startup (not persisted anywhere else), so a restarted process is
a new row, not an update of the old one -- the daemon itself prunes its own
stale rows (same family, past a staleness threshold) on every tick, so this
table is self-cleaning without a separate sweep job.

Revision ID: c1e8b3a4f5d2
Revises: b6e2a814f9c3
Create Date: 2026-07-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1e8b3a4f5d2'
down_revision: Union[str, Sequence[str], None] = 'b6e2a814f9c3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'dhcp_daemon_heartbeats',
        sa.Column('instance_id', sa.String(length=36), nullable=False),
        sa.Column('family', sa.String(length=1), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('instance_id'),
    )
    op.create_index(op.f('ix_dhcp_daemon_heartbeats_family'), 'dhcp_daemon_heartbeats', ['family'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_dhcp_daemon_heartbeats_family'), table_name='dhcp_daemon_heartbeats')
    op.drop_table('dhcp_daemon_heartbeats')
