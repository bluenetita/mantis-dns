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

"""Regression tests for retention.prune_query_events: query_events had no
retention policy at all before this — every DNS query became a row forever.
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.db.models import Base, QueryEvent, SiemSyslog, SiemWebhook
from mantis_control.retention import prune_query_events

_TABLES = [QueryEvent.__table__, SiemWebhook.__table__, SiemSyslog.__table__]


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=_TABLES)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _event(db, seq: int, age_days: int) -> QueryEvent:
    occurred_at = datetime.now(timezone.utc) - timedelta(days=age_days)
    e = QueryEvent(seq=seq, group_id="g1", qname=f"q{seq}.example", decision="allow", occurred_at=occurred_at)
    db.add(e)
    return e


def _webhook(db, last_delivered_seq: int, enabled: bool = True) -> SiemWebhook:
    w = SiemWebhook(
        name="test-webhook", url="https://siem.example/ingest", secret_encrypted="enc",
        enabled=enabled, last_delivered_seq=last_delivered_seq,
    )
    db.add(w)
    return w


def test_prune_deletes_only_rows_older_than_retention_window(db):
    _event(db, seq=1, age_days=200)
    _event(db, seq=2, age_days=5)
    db.commit()

    deleted = prune_query_events(db, retention_days=90)

    assert deleted == 1
    remaining = {e.seq for e in db.query(QueryEvent).all()}
    assert remaining == {2}


def test_prune_does_nothing_when_nothing_is_old_enough(db):
    _event(db, seq=1, age_days=10)
    db.commit()

    assert prune_query_events(db, retention_days=90) == 0
    assert db.query(QueryEvent).count() == 1


def test_prune_never_deletes_a_row_an_enabled_webhook_has_not_delivered_yet(db):
    """An old row past the age cutoff must still survive if an enabled SIEM
    webhook's cursor hasn't reached it yet — otherwise a webhook that's
    merely backlogged (not dead) would silently lose events it never got to
    deliver."""
    _event(db, seq=1, age_days=200)  # old, but...
    _event(db, seq=2, age_days=200)
    _webhook(db, last_delivered_seq=1, enabled=True)  # ...only delivered through seq=1
    db.commit()

    deleted = prune_query_events(db, retention_days=90)

    assert deleted == 1
    remaining = {e.seq for e in db.query(QueryEvent).all()}
    assert remaining == {2}, "seq=2 hasn't been delivered by the enabled webhook yet"


def test_prune_ignores_a_disabled_webhooks_cursor(db):
    """A disabled webhook (e.g. auto-disabled after repeated failures) must
    not block retention forever — only enabled webhooks' cursors count."""
    _event(db, seq=1, age_days=200)
    _webhook(db, last_delivered_seq=0, enabled=False)
    db.commit()

    assert prune_query_events(db, retention_days=90) == 1
    assert db.query(QueryEvent).count() == 0


def _syslog_sink(db, last_delivered_seq: int, enabled: bool = True) -> SiemSyslog:
    s = SiemSyslog(
        name="test-syslog", host="10.8.1.20", port=1514, transport="tcp",
        enabled=enabled, last_delivered_seq=last_delivered_seq,
    )
    db.add(s)
    return s


def test_prune_never_deletes_a_row_an_enabled_syslog_sink_has_not_delivered_yet(db):
    """Same safety bound as the webhook cursor, for the syslog sink's own
    independent cursor — see SiemSyslog.last_delivered_seq."""
    _event(db, seq=1, age_days=200)
    _event(db, seq=2, age_days=200)
    _syslog_sink(db, last_delivered_seq=1, enabled=True)
    db.commit()

    deleted = prune_query_events(db, retention_days=90)

    assert deleted == 1
    remaining = {e.seq for e in db.query(QueryEvent).all()}
    assert remaining == {2}, "seq=2 hasn't been delivered by the enabled syslog sink yet"


def test_prune_ignores_a_disabled_syslog_sinks_cursor(db):
    _event(db, seq=1, age_days=200)
    _syslog_sink(db, last_delivered_seq=0, enabled=False)
    db.commit()

    assert prune_query_events(db, retention_days=90) == 1
    assert db.query(QueryEvent).count() == 0


def test_prune_uses_the_slowest_across_both_webhook_and_syslog_sinks(db):
    """The safety bound must be the minimum enabled cursor across *both*
    sink types, not just whichever one happens to be slower within its own
    type — a fast webhook must not let a backlogged syslog sink's rows (or
    vice versa) get pruned out from under it."""
    _event(db, seq=1, age_days=200)
    _event(db, seq=2, age_days=200)
    _event(db, seq=3, age_days=200)
    _webhook(db, last_delivered_seq=3, enabled=True)  # fast webhook
    _syslog_sink(db, last_delivered_seq=1, enabled=True)  # slow syslog sink
    db.commit()

    deleted = prune_query_events(db, retention_days=90)

    assert deleted == 1
    remaining = {e.seq for e in db.query(QueryEvent).all()}
    assert remaining == {2, 3}


def test_prune_uses_the_slowest_enabled_webhook_as_the_safety_bound(db):
    _event(db, seq=1, age_days=200)
    _event(db, seq=2, age_days=200)
    _event(db, seq=3, age_days=200)
    _webhook(db, last_delivered_seq=3, enabled=True)  # fast webhook
    _webhook(db, last_delivered_seq=1, enabled=True)  # slow webhook
    db.commit()

    deleted = prune_query_events(db, retention_days=90)

    assert deleted == 1
    remaining = {e.seq for e in db.query(QueryEvent).all()}
    assert remaining == {2, 3}
