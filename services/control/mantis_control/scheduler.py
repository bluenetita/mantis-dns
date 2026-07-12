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

"""Shared APScheduler instance + feed job (re)scheduling.

Split out from main.py so feed_routers.py can add/remove/reschedule jobs
immediately on create/update/delete — without this, toggling a feed's
`enabled` flag in the UI would silently do nothing until the next restart.
"""

from __future__ import annotations

import asyncio
import logging

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from mantis_control.config import FEED_STORAGE_DIR
from mantis_control.db.models import Feed
from mantis_control.db.session import SessionLocal
from mantis_control.feeds.ingest import feed_lock, fetch_and_ingest

scheduler = AsyncIOScheduler()


_shutting_down = False


def mark_shutting_down() -> None:
    """Call right before scheduler.shutdown() — see _DropCancelledJobErrors
    below for why this flag exists rather than dropping CancelledError
    unconditionally."""
    global _shutting_down
    _shutting_down = True


class _DropCancelledJobErrors(logging.Filter):
    """AsyncIOExecutor.shutdown() (scheduler.shutdown()) cancels every
    pending job future outright — including ones submitted moments
    earlier by kick_feed_now() that haven't had a chance to start
    running yet, *and* ones that are already mid-run (AsyncIOExecutor
    keeps a future in `_pending_futures`, and therefore cancellable,
    until it's done — verified against the installed apscheduler
    source). APScheduler's executor logs the resulting CancelledError
    as `ERROR ... Error running job ...` unconditionally (see
    BaseExecutor._run_job_error / run_coroutine_job), even though it's
    an expected side effect of shutdown (e.g. the install/update
    startup check, which enters and immediately exits the app's
    lifespan) rather than a real failure.

    Only suppress those records while we're actually inside
    scheduler.shutdown() (see `mark_shutting_down`) — a CancelledError
    logged at any other time is a genuine mid-run job failure/interruption
    and must stay visible, not be silently dropped forever."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not _shutting_down:
            return True
        exc = record.exc_info[1] if record.exc_info else None
        return not isinstance(exc, asyncio.CancelledError)


logging.getLogger("apscheduler.executors.default").addFilter(_DropCancelledJobErrors())


def _job_id(feed_id: str) -> str:
    return f"ingest-{feed_id}"


async def run_ingest(feed_id: str) -> None:
    # Look up the feed and release the connection *before* the (slow,
    # possibly hanging) outbound fetch below — holding a pooled connection
    # for the duration of an httpx call starves the pool (5+10 conns) when
    # several feeds are in flight at once, which then starves API requests
    # like bundle-compile that need a connection too.
    db = SessionLocal()
    try:
        feed = db.get(Feed, feed_id)
        if feed is None or not feed.enabled:
            return
        db.expunge(feed)
    finally:
        db.close()

    # See feed_lock's docstring — serializes this run against a concurrent
    # manual "sync now" call for the same feed, held across the fetch and
    # the commit below.
    async with feed_lock(feed_id):
        async with httpx.AsyncClient() as client:
            result = await fetch_and_ingest(feed, FEED_STORAGE_DIR, client)

        if result.status == "updated":
            db = SessionLocal()
            try:
                db.merge(feed)
                db.commit()
            finally:
                db.close()


def schedule_feed(feed: Feed) -> None:
    """(Re)schedules a feed's ingest job. Safe to call on create, on update
    (interval change), or to pick a feed back up after re-enabling."""
    scheduler.add_job(
        run_ingest,
        "interval",
        seconds=feed.interval_seconds,
        args=[feed.id],
        id=_job_id(feed.id),
        replace_existing=True,
    )


def unschedule_feed(feed_id: str) -> None:
    job_id = _job_id(feed_id)
    if scheduler.get_job(job_id) is not None:
        scheduler.remove_job(job_id)


def sync_feed_schedule(feed: Feed) -> None:
    """Call after any create/update to a feed: schedules it if enabled,
    unschedules it otherwise. Idempotent."""
    if feed.enabled:
        schedule_feed(feed)
    else:
        unschedule_feed(feed.id)


def kick_feed_now(feed_id: str) -> None:
    """Schedules a one-off immediate ingest for a feed, independent of (and
    in addition to) its recurring interval job. `add_job` with no trigger
    defaults to a `DateTrigger` at `now`, so this fires as soon as the
    scheduler starts rather than waiting up to a full `interval_seconds`
    (default 24h) for the feed's first run — the gap a never-ingested feed
    would otherwise sit in, silently contributing nothing to compiled
    bundles. Distinct job id so it can't collide with/replace the recurring
    `ingest-{feed_id}` job."""
    scheduler.add_job(
        run_ingest,
        args=[feed_id],
        id=f"startup-kick-{feed_id}",
        replace_existing=True,
        # The default 1s misfire grace time can skip this run if the event
        # loop is busy (e.g. many feeds queued at once) between this call
        # and the scheduler actually picking it up — this run must always
        # happen regardless of how late.
        misfire_grace_time=None,
    )
