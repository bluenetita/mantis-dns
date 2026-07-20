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

"""Regression tests: scheduler.run_ingest and feed_routers.ingest_feed must
read the Feed row (last_etag/last_domain_count) *while holding* feed_lock,
not before it. Reading before the lock let a losing racer fetch against a
stale snapshot and then commit that stale data back over whatever the
winning racer had just committed — this simulates two concurrent callers for
the same feed_id and asserts the second one observes the first one's already-
committed state rather than the value both would have seen if the read
happened before acquiring the lock.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mantis_control import scheduler
from mantis_control.feeds.ingest import IngestResult


class _FakeAsyncClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeHttpxModule:
    AsyncClient = staticmethod(lambda *a, **kw: _FakeAsyncClient())


class _FeedStore:
    """Stand-in for the Feed row's persisted state, shared across 'sessions'."""

    def __init__(self):
        self.last_domain_count = 10
        self.enabled = True


class _FakeSession:
    def __init__(self, store: _FeedStore):
        self._store = store

    def get(self, _model, _feed_id):
        # A fresh snapshot reflecting whatever is currently committed —
        # exactly what a real SQLAlchemy session issuing a new SELECT under
        # Postgres's default READ COMMITTED isolation would return.
        return SimpleNamespace(enabled=self._store.enabled, last_domain_count=self._store.last_domain_count)

    def expunge(self, _obj):
        pass

    def merge(self, obj):
        self._store.last_domain_count = obj.last_domain_count

    def commit(self):
        pass

    def close(self):
        pass


@pytest.mark.asyncio
async def test_run_ingest_holds_lock_across_the_db_read():
    store = _FeedStore()
    seen_counts: list[int] = []

    async def fake_fetch_and_ingest(feed, _storage_dir, _client):
        seen_counts.append(feed.last_domain_count)
        await asyncio.sleep(0.01)  # let the other racer attempt to interleave
        feed.last_domain_count += 10
        return IngestResult(status="updated", domain_count=feed.last_domain_count)

    with patch.object(scheduler, "SessionLocal", lambda: _FakeSession(store)), \
         patch.object(scheduler, "fetch_and_ingest", fake_fetch_and_ingest), \
         patch.object(scheduler, "httpx", _FakeHttpxModule()):
        await asyncio.gather(
            scheduler.run_ingest("feed-1"),
            scheduler.run_ingest("feed-1"),
        )

    # If the read happened before the lock (the bug), both racers would read
    # the original count (10) and the loser's later commit would overwrite
    # the winner's — final count would be 20 with seen_counts == [10, 10].
    # With the lock held across the read, the second racer must observe the
    # first racer's already-committed value.
    assert sorted(seen_counts) == [10, 20]
    assert store.last_domain_count == 30
