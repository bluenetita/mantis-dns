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

"""query_events retention — without this, every DNS query on every filter
node becomes one row forever (see api/telemetry_routers.py's
ingest_query_events): a busy deployment accumulates millions of rows a day,
and every analytics/query-log endpoint does unindexed-aggregate scans over
an ever-growing table.

Scheduled daily via APScheduler in main.py, same pattern as the SIEM webhook
delivery cycle and DHCP lease sync.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from mantis_control.db import models

log = logging.getLogger(__name__)

# Deleted in batches rather than one giant DELETE — a single unbounded
# statement would hold a long-running transaction (and associated locks)
# against a table other requests (query-log reads, new query-event inserts)
# are actively hitting.
_BATCH_SIZE = 5_000


def prune_query_events(db: Session, retention_days: int) -> int:
    """Deletes QueryEvent rows older than `retention_days`, but never a row
    an *enabled* SIEM webhook (siem_delivery.py) or syslog sink
    (siem_syslog_delivery.py) hasn't delivered yet — `last_delivered_seq` is
    each sink's own cursor into QueryEvent.seq, so a row with seq <= every
    enabled sink's cursor has already been delivered everywhere it needs to
    be. A backlogged-but-still-enabled sink therefore delays pruning of the
    rows it hasn't caught up to, rather than silently losing them; a sink
    that's actually dead auto-disables itself after MAX_CONSECUTIVE_FAILURES
    (siem_common.py) and so stops blocking retention.

    This does NOT protect against the separate pull-based /api/v1/siem/events
    API, which has no server-tracked per-consumer cursor to check — same as
    any log-retention window, a puller is expected to keep up within
    `retention_days`.

    Returns the number of rows deleted.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    min_delivered_seqs = [
        db.query(func.min(models.SiemWebhook.last_delivered_seq))
        .filter(models.SiemWebhook.enabled.is_(True))
        .scalar(),
        db.query(func.min(models.SiemSyslog.last_delivered_seq))
        .filter(models.SiemSyslog.enabled.is_(True))
        .scalar(),
    ]
    min_delivered_seq = min((s for s in min_delivered_seqs if s is not None), default=None)

    total_deleted = 0
    while True:
        query = db.query(models.QueryEvent.id).filter(models.QueryEvent.occurred_at < cutoff)
        if min_delivered_seq is not None:
            query = query.filter(models.QueryEvent.seq <= min_delivered_seq)
        ids = [row[0] for row in query.limit(_BATCH_SIZE).all()]
        if not ids:
            break
        deleted = (
            db.query(models.QueryEvent)
            .filter(models.QueryEvent.id.in_(ids))
            .delete(synchronize_session=False)
        )
        db.commit()
        total_deleted += deleted
        if deleted < _BATCH_SIZE:
            break

    if total_deleted:
        log.info("query_events retention: pruned %d rows older than %d days", total_deleted, retention_days)
    return total_deleted
