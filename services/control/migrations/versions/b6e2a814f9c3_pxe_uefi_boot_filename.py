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

"""pxe uefi boot filename

Minimal PXE architecture-classing (design.md §22.8): a client's option 93
(Client System Architecture, RFC 4578) tells mantis-dhcp whether it's a
legacy BIOS or a UEFI PXE client. Rather than a full client-class system
(no other part of this schema has one), this adds a single alternate boot
filename per scope/reservation, used when option 93 indicates a UEFI
architecture (codes 6-10, 15-16 per RFC 4578) instead of `pxe_boot_filename`/
`boot_filename`, which stay the BIOS/default fallback.

Revision ID: b6e2a814f9c3
Revises: a3d7e91c4f56
Create Date: 2026-07-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b6e2a814f9c3'
down_revision: Union[str, Sequence[str], None] = 'a3d7e91c4f56'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('dhcp_scopes', sa.Column('pxe_uefi_boot_filename', sa.String(length=255), nullable=True))
    op.add_column('dhcp_static_leases', sa.Column('uefi_boot_filename', sa.String(length=255), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('dhcp_static_leases', 'uefi_boot_filename')
    op.drop_column('dhcp_scopes', 'pxe_uefi_boot_filename')
