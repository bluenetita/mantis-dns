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

"""baseline

Product has not shipped yet, so the prior 16-migration history (one per
schema change since the real baseline) carried no upgrade path anyone
depended on. Folded into a single migration that creates the schema
straight from the current ORM metadata instead of replaying history.

Revision ID: cc2a9802b8b7
Revises:
Create Date: 2026-07-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from mantis_control.db.models import Base

# revision identifiers, used by Alembic.
revision: str = 'cc2a9802b8b7'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    Base.metadata.create_all(bind=op.get_bind())
    # mantis-dhcp DDNS retry queue — owned by Rust service, not in ORM.
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
    Base.metadata.drop_all(bind=op.get_bind())
