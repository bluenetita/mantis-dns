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

"""Periodic REINDEX for query_events — autovacuum reclaims dead-tuple space
in the table itself, but doesn't shrink B-tree index bloat. query_events is
the one table with steady delete churn (retention.py prunes it daily) against
an actively-inserted-into table, which is exactly the pattern that grows
index bloat unbounded over time.

Scheduled monthly via APScheduler in main.py, same pattern as retention.py.
"""
from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.engine import Engine

log = logging.getLogger(__name__)

# Every index on query_events (see migrations/versions/a7263be2ad89_baseline.py).
# Excludes the primary key (id) — Postgres doesn't let REINDEX CONCURRENTLY
# touch a constraint-backed index in the same statement form as a plain one,
# and the churn here is on the secondary lookup indexes, not the PK.
_QUERY_EVENTS_INDEXES = [
    "ix_query_events_client_ip",
    "ix_query_events_group_id",
    "ix_query_events_occurred_at",
    "ix_query_events_seq",
    "ix_query_events_tenant_id",
]


def reindex_query_events(engine: Engine) -> None:
    """REINDEXes each query_events index CONCURRENTLY, one at a time.

    CONCURRENTLY avoids taking the exclusive lock a plain REINDEX would —
    query-log reads and telemetry inserts keep working throughout. It can't
    run inside a transaction block, so this uses a raw AUTOCOMMIT connection
    rather than an ORM Session.
    """
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for index_name in _QUERY_EVENTS_INDEXES:
            log.info("reindexing %s", index_name)
            conn.execute(text(f"REINDEX INDEX CONCURRENTLY {index_name}"))
