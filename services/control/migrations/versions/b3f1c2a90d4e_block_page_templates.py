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

"""block_page_templates

Revision ID: b3f1c2a90d4e
Revises: 1200eeb54f99
Create Date: 2026-07-10 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b3f1c2a90d4e'
down_revision: Union[str, Sequence[str], None] = '1200eeb54f99'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'block_page_templates',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('group_id', sa.String(length=36), nullable=True),
        sa.Column('block_mode', sa.String(length=24), nullable=False, server_default='BLOCK_MODE_NXDOMAIN'),
        sa.Column('redirect_ipv4', sa.String(length=15), nullable=True),
        sa.Column('redirect_ipv6', sa.String(length=45), nullable=True),
        sa.Column('ttl_seconds', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('title', sa.String(length=255), nullable=True),
        sa.Column('message', sa.String(length=2000), nullable=True),
        sa.Column('logo_url', sa.String(length=1024), nullable=True),
        sa.Column('brand_color', sa.String(length=7), nullable=True),
        sa.Column('contact_url', sa.String(length=1024), nullable=True),
        sa.Column('show_domain', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('show_category', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'group_id', name='uq_block_page_tenant_group'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('block_page_templates')
