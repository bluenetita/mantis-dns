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

"""dhcp ddns retry queue

mantis-dhcp's own delivery-reliability table for /internal/dhcp-event POSTs
that failed (control plane down, network blip). Not part of the Python
domain model — no SQLAlchemy model or API surface — mantis-dhcp (Rust) is
the only reader/writer, same as it owns dhcp_leases. Still goes through
Alembic because every schema change does, per this project's convention.

Revision ID: a3d7e91c4f56
Revises: f4a9c1d3e8b2
Create Date: 2026-07-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3d7e91c4f56'
down_revision: Union[str, Sequence[str], None] = 'f4a9c1d3e8b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'dhcp_ddns_retries',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('event', sa.String(length=10), nullable=False),
        sa.Column('family', sa.String(length=1), nullable=False),
        sa.Column('scope_id', sa.String(length=36), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('mac', sa.String(length=17), nullable=True),
        sa.Column('duid', sa.String(length=255), nullable=True),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('next_attempt_at', sa.DateTime(), nullable=False),
        sa.Column('last_error', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_dhcp_ddns_retries_next_attempt_at'), 'dhcp_ddns_retries', ['next_attempt_at'], unique=False
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_dhcp_ddns_retries_next_attempt_at'), table_name='dhcp_ddns_retries')
    op.drop_table('dhcp_ddns_retries')
