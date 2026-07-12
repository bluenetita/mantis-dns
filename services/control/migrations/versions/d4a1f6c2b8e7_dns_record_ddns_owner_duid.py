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

"""dns_record ddns_owner_duid

Revision ID: d4a1f6c2b8e7
Revises: c7d8e9f0a123
Create Date: 2026-07-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4a1f6c2b8e7'
down_revision: Union[str, Sequence[str], None] = 'c7d8e9f0a123'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Mirrors ddns_owner_mac (v4) for DHCPv6 DDNS ownership — DUIDs don't fit
    # the 17-char MAC column, so this is a separate column rather than a
    # widened reuse of ddns_owner_mac.
    op.add_column('dns_records', sa.Column('ddns_owner_duid', sa.String(length=128), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('dns_records', 'ddns_owner_duid')
