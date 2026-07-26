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

"""add ca_cert_pem to SiemSyslog

Allows self-signed or internal CA certificates for TLS syslog collectors
on private networks.

Revision ID: 7343f2e97b7
Revises: cc2a9802b8b7
Create Date: 2026-07-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7343f2e97b7'
down_revision: Union[str, Sequence[str], None] = 'cc2a9802b8b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('siem_syslogs', sa.Column('ca_cert_pem', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('siem_syslogs', 'ca_cert_pem')
