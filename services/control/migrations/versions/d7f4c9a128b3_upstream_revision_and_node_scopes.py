# Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""upstream revision and node scopes

Revision ID: d7f4c9a128b3
Revises: cc2a9802b8b7
Create Date: 2026-07-26 19:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "d7f4c9a128b3"
down_revision: Union[str, Sequence[str], None] = "cc2a9802b8b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The unshipped-product baseline intentionally calls
    # Base.metadata.create_all(), so a brand-new database may already contain
    # these objects from the current ORM. An existing database stamped at the
    # baseline does not. Support both paths.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "upstream_bundle_revision" not in tables:
        op.create_table(
            "upstream_bundle_revision",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("version", sa.BigInteger(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
    op.execute(
        "INSERT INTO upstream_bundle_revision (id, version) VALUES (1, 0) "
        "ON CONFLICT (id) DO NOTHING"
    )

    # Preserve connectivity for credentials issued before scopes existed.
    # Newly issued credentials default to least privilege in the ORM/API.
    node_columns = {
        column["name"] for column in inspector.get_columns("node_credentials")
    }
    if "allow_all" not in node_columns:
        op.add_column(
            "node_credentials",
            sa.Column("allow_all", sa.Boolean(), nullable=False, server_default=sa.true()),
        )
        op.alter_column("node_credentials", "allow_all", server_default=sa.false())
    if "allowed_tenant_ids" not in node_columns:
        op.add_column(
            "node_credentials",
            sa.Column(
                "allowed_tenant_ids",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'::json"),
            ),
        )
    if "allowed_group_ids" not in node_columns:
        op.add_column(
            "node_credentials",
            sa.Column(
                "allowed_group_ids",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'::json"),
            ),
        )


def downgrade() -> None:
    op.drop_column("node_credentials", "allowed_group_ids")
    op.drop_column("node_credentials", "allowed_tenant_ids")
    op.drop_column("node_credentials", "allow_all")
    op.drop_table("upstream_bundle_revision")
