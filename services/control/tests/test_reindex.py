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

"""Regression tests for reindex.reindex_query_events. REINDEX CONCURRENTLY
isn't supported by sqlite, and can't run inside a transaction on Postgres
either, so this asserts against the connection mock rather than a real
engine: the AUTOCOMMIT isolation level and the exact statements issued are
the two ways this function can silently do the wrong thing.
"""
from unittest.mock import MagicMock

from mantis_control.reindex import _QUERY_EVENTS_INDEXES, reindex_query_events


def test_reindexes_every_query_events_index_concurrently():
    conn = MagicMock()
    conn.__enter__.return_value = conn
    engine = MagicMock()
    engine.connect.return_value.execution_options.return_value = conn

    reindex_query_events(engine)

    engine.connect.return_value.execution_options.assert_called_once_with(
        isolation_level="AUTOCOMMIT"
    )
    executed_sql = [c.args[0].text for c in conn.execute.call_args_list]
    assert executed_sql == [
        f"REINDEX INDEX CONCURRENTLY {name}" for name in _QUERY_EVENTS_INDEXES
    ]


def test_index_list_has_no_duplicates():
    assert len(_QUERY_EVENTS_INDEXES) == len(set(_QUERY_EVENTS_INDEXES))
