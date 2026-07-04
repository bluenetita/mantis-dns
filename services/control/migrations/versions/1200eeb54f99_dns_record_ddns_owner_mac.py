"""dns_record ddns_owner_mac

Revision ID: 1200eeb54f99
Revises: a7263be2ad89
Create Date: 2026-07-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1200eeb54f99'
down_revision: Union[str, Sequence[str], None] = 'a7263be2ad89'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('dns_records', sa.Column('ddns_owner_mac', sa.String(length=17), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('dns_records', 'ddns_owner_mac')
