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

"""dhcp heartbeat host+family unique

c1e8b3a4f5d2 keyed each heartbeat row on a fresh UUID generated at process
startup -- meaning a daemon *restart* (the exact case an operator most wants
visibility into) left the old, now-dead instance's row sitting there going
stale forever instead of being replaced, so the same host would accumulate
one "Not responding" row per past restart alongside the current "Online"
one. Only one instance per host can ever run a given family anyway (host
networking, one process per bound port -- design.md §22.6), so (hostname,
family) is the real identity. Postgres treats NULL as never-equal in a
unique index, so a host whose hostname couldn't be determined still falls
back to accumulating one row per restart -- an accepted, rare edge case
rather than the common one.

Revision ID: d7f2a9c6b1e4
Revises: c1e8b3a4f5d2
Create Date: 2026-07-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'd7f2a9c6b1e4'
down_revision: Union[str, Sequence[str], None] = 'c1e8b3a4f5d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Collapse any pre-existing duplicate (hostname, family) rows down to the
    # most-recently-seen one before the constraint can be added, so upgrading
    # a host that already accumulated restart-churn rows doesn't fail.
    op.execute(
        """
        DELETE FROM dhcp_daemon_heartbeats a
        USING dhcp_daemon_heartbeats b
        WHERE a.hostname IS NOT NULL
          AND a.hostname = b.hostname
          AND a.family = b.family
          AND a.last_seen_at < b.last_seen_at
        """
    )
    op.create_unique_constraint(
        'uq_dhcp_daemon_heartbeat_host_family', 'dhcp_daemon_heartbeats', ['hostname', 'family']
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('uq_dhcp_daemon_heartbeat_host_family', 'dhcp_daemon_heartbeats', type_='unique')
