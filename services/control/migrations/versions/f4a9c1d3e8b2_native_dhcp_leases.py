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

"""native dhcp leases (drop Kea integration)

Kea is replaced by mantis-dhcp (services/dhcp, Rust): it reads dhcp_scopes/
dhcp_static_leases/dhcp_options/dhcp_relay_configs directly and writes its
own lease state here instead of a separate daemon's lease4/lease6 tables.
kea_subnet_id/last_pushed_at existed only to track a push to that daemon and
no longer mean anything; dhcp_ha_configs configured Kea's HA peer protocol,
which shared-DB allocation (a Postgres advisory transaction lock per scope,
pg_advisory_xact_lock) replaces with no config needed at all.

Revision ID: f4a9c1d3e8b2
Revises: b8e4f1a9c3d7
Create Date: 2026-07-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f4a9c1d3e8b2'
down_revision: Union[str, Sequence[str], None] = 'b8e4f1a9c3d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'dhcp_leases',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scope_id', sa.String(length=36), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('mac_address', sa.String(length=17), nullable=False),
        sa.Column('client_id', sa.String(length=255), nullable=True),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('state', sa.Integer(), nullable=False),
        sa.Column('allocated_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scope_id'], ['dhcp_scopes.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scope_id', 'ip_address', name='uq_dhcp_lease_ip'),
    )
    op.create_index(op.f('ix_dhcp_leases_scope_id'), 'dhcp_leases', ['scope_id'], unique=False)
    op.create_index(op.f('ix_dhcp_leases_ip_address'), 'dhcp_leases', ['ip_address'], unique=False)
    op.create_index(op.f('ix_dhcp_leases_expires_at'), 'dhcp_leases', ['expires_at'], unique=False)

    op.create_table(
        'dhcp_leases6',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scope_id', sa.String(length=36), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('duid', sa.String(length=255), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('lease_type', sa.Integer(), nullable=False),
        sa.Column('state', sa.Integer(), nullable=False),
        sa.Column('allocated_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scope_id'], ['dhcp_scopes6.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scope_id', 'ip_address', name='uq_dhcp_lease6_ip'),
    )
    op.create_index(op.f('ix_dhcp_leases6_scope_id'), 'dhcp_leases6', ['scope_id'], unique=False)
    op.create_index(op.f('ix_dhcp_leases6_ip_address'), 'dhcp_leases6', ['ip_address'], unique=False)
    op.create_index(op.f('ix_dhcp_leases6_expires_at'), 'dhcp_leases6', ['expires_at'], unique=False)

    op.drop_column('dhcp_scopes', 'kea_subnet_id')
    op.drop_column('dhcp_scopes', 'last_pushed_at')
    op.drop_column('dhcp_scopes6', 'kea_subnet_id')
    op.drop_column('dhcp_scopes6', 'last_pushed_at')

    op.drop_table('dhcp_ha_configs')


def downgrade() -> None:
    """Downgrade schema."""
    op.create_table(
        'dhcp_ha_configs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('mode', sa.String(length=32), nullable=False),
        sa.Column('this_server_name', sa.String(length=128), nullable=False),
        sa.Column('this_server_url', sa.String(length=255), nullable=False),
        sa.Column('peer_name', sa.String(length=128), nullable=False),
        sa.Column('peer_url', sa.String(length=255), nullable=False),
        sa.Column('peer_role', sa.String(length=32), nullable=False),
        sa.Column('max_unacked_clients', sa.Integer(), nullable=True),
        sa.Column('max_ack_delay_ms', sa.Integer(), nullable=True),
        sa.Column('heartbeat_delay_ms', sa.Integer(), nullable=True),
        sa.Column('retry_wait_time_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id'),
    )

    op.add_column('dhcp_scopes6', sa.Column('last_pushed_at', sa.DateTime(), nullable=True))
    op.add_column('dhcp_scopes6', sa.Column('kea_subnet_id', sa.Integer(), nullable=True))
    op.add_column('dhcp_scopes', sa.Column('last_pushed_at', sa.DateTime(), nullable=True))
    op.add_column('dhcp_scopes', sa.Column('kea_subnet_id', sa.Integer(), nullable=True))

    op.drop_index(op.f('ix_dhcp_leases6_expires_at'), table_name='dhcp_leases6')
    op.drop_index(op.f('ix_dhcp_leases6_ip_address'), table_name='dhcp_leases6')
    op.drop_index(op.f('ix_dhcp_leases6_scope_id'), table_name='dhcp_leases6')
    op.drop_table('dhcp_leases6')

    op.drop_index(op.f('ix_dhcp_leases_expires_at'), table_name='dhcp_leases')
    op.drop_index(op.f('ix_dhcp_leases_ip_address'), table_name='dhcp_leases')
    op.drop_index(op.f('ix_dhcp_leases_scope_id'), table_name='dhcp_leases')
    op.drop_table('dhcp_leases')
