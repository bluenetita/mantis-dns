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

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from mantis_control.config import FEED_STORAGE_DIR
from mantis_control.db.models import Feed
from mantis_control.db.session import SessionLocal
from mantis_control.feeds.ingest import fetch_and_ingest

scheduler = AsyncIOScheduler()


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
