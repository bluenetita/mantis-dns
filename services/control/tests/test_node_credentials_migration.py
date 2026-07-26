# Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Regression coverage for the post-baseline node-credential migration."""

from importlib import import_module
from unittest.mock import MagicMock

import pytest


migration = import_module(
    "migrations.versions.d7f4c9a128b3_upstream_revision_and_node_scopes"
)


def test_upgrade_creates_node_credentials_when_baseline_database_lacks_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = MagicMock()
    inspector.get_table_names.return_value = []
    monkeypatch.setattr(migration.sa, "inspect", lambda _bind: inspector)

    migration_op = MagicMock()
    monkeypatch.setattr(migration, "op", migration_op)

    migration.upgrade()

    node_create = next(
        call for call in migration_op.create_table.call_args_list
        if call.args[0] == "node_credentials"
    )
    column_names = {
        argument.name for argument in node_create.args[1:]
        if hasattr(argument, "name") and argument.name is not None
    }
    assert column_names == {
        "node_name",
        "token_hash",
        "created_at",
        "created_by",
        "revoked_at",
        "last_seen_at",
        "allow_all",
        "allowed_tenant_ids",
        "allowed_group_ids",
    }
    inspector.get_columns.assert_not_called()


def test_upgrade_adds_scopes_to_legacy_node_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = MagicMock()
    inspector.get_table_names.return_value = [
        "node_credentials",
        "upstream_bundle_revision",
    ]
    inspector.get_columns.return_value = [
        {"name": "node_name"},
        {"name": "token_hash"},
        {"name": "created_at"},
        {"name": "created_by"},
        {"name": "revoked_at"},
        {"name": "last_seen_at"},
    ]
    monkeypatch.setattr(migration.sa, "inspect", lambda _bind: inspector)

    migration_op = MagicMock()
    monkeypatch.setattr(migration, "op", migration_op)

    migration.upgrade()

    added_columns = {
        call.args[1].name for call in migration_op.add_column.call_args_list
    }
    assert added_columns == {
        "allow_all",
        "allowed_tenant_ids",
        "allowed_group_ids",
    }
