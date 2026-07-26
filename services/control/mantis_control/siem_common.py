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

"""Shared plumbing for the SIEM export sinks (currently just syslog:
siem_syslog_delivery.py). Kept as a Protocol-based abstraction — rather than
folded directly into the syslog module — because it's designed to support
more than one sink type sharing the same cursor/backoff/CRUD shape.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Protocol, TypeVar, cast

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mantis_control.api.siem_routers import SiemEvent, build_siem_events
from mantis_control.audit import write_audit_log
from mantis_control.auth import check_tenant_access
from mantis_control.db import models
from mantis_control.db.session import SessionLocal

BACKOFF_SECONDS = [5, 30, 120, 600, 3600]
MAX_CONSECUTIVE_FAILURES = 6

# QueryEvent.seq is a Postgres IDENTITY column: a row's seq is allocated at
# INSERT, but two concurrent ingest transactions can commit out of seq order
# (e.g. seq=101 opened first but commits after seq=102). A sink polling in
# that window sees only 102, advances its cursor past it, and 101 becomes
# permanently unreachable to `seq > last_delivered_seq` — silently skipped
# and then pruned by retention as "already delivered". Excluding events
# younger than this lag gives any same-moment concurrent ingest transaction
# time to commit before a sink is allowed to consider its seq final.
DELIVERY_LAG_SECONDS = 5

# A backlogged-but-healthy sink would otherwise only ever send one
# batch_size batch per scheduler tick (every 10s, see main.py) — at the
# default batch_size=200 that's a 20/s delivery ceiling regardless of how
# far behind the sink is, which both starves the sink indefinitely under
# sustained load and blocks retention.prune_query_events (it won't prune
# past an enabled sink's cursor). Draining multiple batches per tick while
# backlog remains fixes this without changing the tick cadence itself.
#
# Bounded by wall-clock time, not just a batch count: MAX_BATCHES_PER_TICK
# batches at batch_size=10_000 with a per-batch connect timeout (10s, see
# _CONNECT_TIMEOUT_S in siem_syslog_delivery.py) could otherwise run for
# minutes on one sink, inside a job that's supposed to tick every 10s and
# processes sinks serially (run_delivery_cycle) — a single backlogged sink
# would starve every other sink's delivery for the duration.
MAX_BATCHES_PER_TICK = 20
DRAIN_DEADLINE_SECONDS = 5.0


class DeliverySink(Protocol):
    """The fields a delivery-sink model needs for the shared delivery/CRUD
    helpers below — currently only SiemSyslog implements this shape."""

    id: str
    tenant_id: str | None
    enabled: bool
    filter_decision: str
    batch_size: int
    flush_interval_s: int
    last_delivered_seq: int
    last_delivered_at: datetime | None
    next_retry_at: datetime | None
    consecutive_failures: int
    last_error: str | None


SinkT = TypeVar("SinkT", bound=DeliverySink)

log = logging.getLogger(__name__)


def as_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def describe_error(e: Exception) -> str:
    """`str(asyncio.TimeoutError())` (a common failure mode — a dead or
    firewalled receiver) is `""`, which would otherwise leave
    `last_error` blank and give an admin nothing to diagnose a stuck sink
    with. Falls back to the exception's type name whenever str() is empty."""
    return str(e) or type(e).__name__


def build_test_event(tenant_id: str | None) -> SiemEvent:
    """One synthetic event, used by the Settings UI's "send test event"
    button. Never touches a sink's real delivery cursor."""
    now = datetime.now(timezone.utc)
    return SiemEvent(
        id="00000000-0000-0000-0000-000000000000",
        seq=0,
        occurred_at=now,
        tenant_id=tenant_id,
        group_id="test",
        client_ip="203.0.113.1",
        client_name="test-client",
        qname="siem-test-event.mantis.local.",
        qtype="A",
        decision="block",
        matched_rule="category",
        matched_category="test",
        matched_feed_id="mantis-test",
        response_code="NXDomain",
        cache_hit=False,
        latency_us=1234,
    )


async def _deliver_one_batch(
    db: Session,
    sink: DeliverySink,
    *,
    send: Callable[[list[SiemEvent]], Awaitable[None]],
    resource_type: str,
    now: datetime,
) -> int:
    """Sends at most one batch. Returns the number of rows sent (0 means
    caught up — nothing left to drain this tick)."""
    safe_cutoff = now - timedelta(seconds=DELIVERY_LAG_SECONDS)

    query = select(models.QueryEvent).where(
        models.QueryEvent.seq > sink.last_delivered_seq,
        models.QueryEvent.ingested_at <= safe_cutoff,
    )
    if sink.tenant_id:
        query = query.where(models.QueryEvent.tenant_id == sink.tenant_id)
    if sink.filter_decision != "all":
        query = query.where(models.QueryEvent.decision == sink.filter_decision)
    query = query.order_by(models.QueryEvent.seq.asc()).limit(sink.batch_size)
    rows = list(db.execute(query).scalars().all())
    if not rows:
        # A filtered sink (e.g. filter_decision="block") on a mostly-allow
        # stream would otherwise never advance its cursor and rescan an
        # ever-growing span on every tick. Jump straight to the newest seq
        # this sink is scoped to see, even though none of it matched — but
        # only up to safe_cutoff, same reasoning as the row query above.
        max_query = select(func.max(models.QueryEvent.seq)).where(
            models.QueryEvent.ingested_at <= safe_cutoff
        )
        if sink.tenant_id:
            max_query = max_query.where(models.QueryEvent.tenant_id == sink.tenant_id)
        max_seq = db.execute(max_query).scalar_one_or_none()
        if max_seq is not None and max_seq > sink.last_delivered_seq:
            sink.last_delivered_seq = max_seq
            db.commit()
        return 0
    events = build_siem_events(db, rows)

    try:
        await send(events)
    except Exception as e:
        sink.consecutive_failures += 1
        sink.last_error = describe_error(e)[:2000]
        backoff_idx = min(sink.consecutive_failures - 1, len(BACKOFF_SECONDS) - 1)
        sink.next_retry_at = now + timedelta(seconds=BACKOFF_SECONDS[backoff_idx])
        if sink.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            sink.enabled = False
            write_audit_log(
                db,
                f"{resource_type}.disabled",
                resource_type,
                sink.id,
                detail=f"disabled after {sink.consecutive_failures} consecutive failures: {sink.last_error}",
                actor="system",
            )
        db.commit()
        raise

    sink.last_delivered_seq = events[-1].seq
    sink.last_delivered_at = now
    sink.consecutive_failures = 0
    sink.last_error = None
    sink.next_retry_at = None
    db.commit()
    return len(rows)


async def process_delivery_sink(
    db: Session,
    sink: DeliverySink,
    *,
    send: Callable[[list[SiemEvent]], Awaitable[None]],
    resource_type: str,
) -> None:
    """Runs one delivery attempt for *sink*. *send* does the actual
    transport; everything else (cadence gating, batching, cursor advance,
    backoff, auto-disable) is shared.

    Drains batches in a row while backlog remains, instead of a single
    batch_size batch per tick — otherwise a sink that falls behind (burst
    of traffic, brief outage) can never send faster than batch_size per
    flush_interval_s, no matter how large its backlog, and retention can't
    prune past its cursor in the meantime. Bounded by both a batch count
    (MAX_BATCHES_PER_TICK) and a wall-clock deadline (DRAIN_DEADLINE_SECONDS)
    so one backlogged sink can't starve every other sink's delivery for a
    whole scheduler tick.
    """
    now = datetime.now(timezone.utc)

    if sink.next_retry_at is not None:
        # In backoff after a failure — next_retry_at supersedes flush_interval_s.
        if as_aware(sink.next_retry_at) > now:
            return
    elif sink.last_delivered_at is not None:
        # Happy path: don't fire more often than the sink's configured cadence.
        elapsed = (now - as_aware(sink.last_delivered_at)).total_seconds()
        if elapsed < sink.flush_interval_s:
            return

    deadline = time.monotonic() + DRAIN_DEADLINE_SECONDS
    for _ in range(MAX_BATCHES_PER_TICK):
        try:
            sent = await _deliver_one_batch(db, sink, send=send, resource_type=resource_type, now=now)
        except Exception:
            return  # error already recorded on the sink by _deliver_one_batch
        if sent < sink.batch_size:
            return  # caught up (or no rows at all) — nothing more to drain
        if time.monotonic() >= deadline:
            return  # more backlog remains; picked up again next tick


async def run_delivery_cycle(
    model: type[SinkT],
    process_one: Callable[[Session, SinkT], Awaitable[None]],
) -> None:
    """Scheduler-tick shape: list enabled rows on their own short-lived
    session, then process each on its own fresh session so
    one sink's failure/rollback can't affect another's, holding a DB
    connection only for the duration of that sink's work."""
    db = SessionLocal()
    try:
        # `model` is typed by DeliverySink (an instance-shape Protocol) for
        # the sake of process_one's parameter; SQLAlchemy's class-level
        # `.enabled` (an InstrumentedAttribute, not a plain bool) needs the
        # escape hatch here.
        ids = [r.id for r in db.query(model).filter(cast(Any, model).enabled.is_(True)).all()]
    finally:
        db.close()
    if not ids:
        return

    for row_id in ids:
        db = SessionLocal()
        try:
            row = db.get(model, row_id)
            if row is None or not row.enabled:
                continue
            await process_one(db, row)
        except Exception:
            # A failure here is one process_one didn't already record on the
            # sink (send() failures are caught and logged to sink.last_error
            # inside _deliver_one_batch) — e.g. a bug in build_siem_events.
            # Log it so the sink doesn't silently stop delivering with no
            # trace anywhere, on top of rolling back its half-done session.
            log.exception("SIEM delivery cycle failed for %s %s", model.__name__, row_id)
            db.rollback()
        finally:
            db.close()


def get_sink_or_404(
    db: Session, model: type[SinkT], sink_id: str, admin: models.User, *, not_found_msg: str
) -> SinkT:
    """CRUD-route lookup: 404 if missing, tenant-scope check otherwise."""
    sink = db.get(model, sink_id)
    if sink is None:
        raise HTTPException(404, not_found_msg)
    if sink.tenant_id is not None:
        check_tenant_access(admin, sink.tenant_id)
    return sink
