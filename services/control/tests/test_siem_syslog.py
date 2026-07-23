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

"""SIEM syslog: RFC 5424 framing, delivery cursor/backoff, and config CRUD
validation (design.md §20.8, Sprint 17)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api.siem_routers import SiemEvent
from mantis_control.api.siem_syslog_routers import (
    SiemSyslogCreate,
    SiemSyslogUpdate,
    create_syslog,
    update_syslog,
)
from mantis_control.db.models import AuditLog, Base, QueryEvent, SiemSyslog
from mantis_control.siem_syslog_delivery import (
    _process_syslog,
    _to_syslog_line,
    describe_error,
)


def _event(**overrides) -> SiemEvent:
    defaults = dict(
        id="018f4a00-0000-0000-0000-000000000000",
        seq=1,
        occurred_at=datetime(2026, 7, 23, 14, 32, 1, 123456, tzinfo=timezone.utc),
        tenant_id="t1",
        group_id="g1",
        client_ip="10.8.1.47",
        client_name=None,
        qname="casino.example.",
        qtype="A",
        decision="block",
        matched_rule="category",
        matched_category="gambling",
        matched_feed_id="oisd-gambling",
        response_code="NXDOMAIN",
        cache_hit=False,
        latency_us=1240,
    )
    defaults.update(overrides)
    return SiemEvent(**defaults)


def _sink(**overrides) -> SiemSyslog:
    defaults = dict(
        name="test-sink", host="10.8.1.20", port=1514, transport="tcp", format="cef",
        facility=16, app_name="mantis-dns",
    )
    defaults.update(overrides)
    return SiemSyslog(**defaults)


# ─── RFC 5424 framing ──────────────────────────────────────────────────────


def test_to_syslog_line_block_uses_warning_severity():
    sink = _sink(facility=16, format="cef")
    line = _to_syslog_line(sink, _event(decision="block"))
    # facility 16 * 8 + severity 4 (Warning) = 132
    assert line.startswith("<132>1 ")


def test_to_syslog_line_allow_uses_informational_severity():
    sink = _sink(facility=16, format="cef")
    line = _to_syslog_line(sink, _event(decision="allow"))
    # facility 16 * 8 + severity 6 (Informational) = 134
    assert line.startswith("<134>1 ")


def test_to_syslog_line_timestamp_is_rfc3339_utc_with_microseconds():
    sink = _sink()
    line = _to_syslog_line(sink, _event())
    assert "2026-07-23T14:32:01.123456Z" in line


def test_to_syslog_line_nilvalues_for_hostname_procid_msgid_structured_data():
    sink = _sink(app_name="mantis-dns")
    line = _to_syslog_line(sink, _event())
    # <PRI>VERSION TIMESTAMP HOSTNAME(-) APP-NAME PROCID(-) MSGID(-) SD(-) MSG
    header, _, msg = line.partition(" CEF:0")
    parts = header.split(" ")
    assert parts[2] == "-"  # HOSTNAME
    assert parts[3] == "mantis-dns"  # APP-NAME
    assert parts[4:7] == ["-", "-", "-"]  # PROCID, MSGID, STRUCTURED-DATA


def test_to_syslog_line_cef_format_embeds_cef_message():
    sink = _sink(format="cef")
    line = _to_syslog_line(sink, _event())
    assert "CEF:0|MantisDNS|mantis-filter|1.0|DNS_QUERY" in line
    assert "dhost=casino.example." in line


def test_to_syslog_line_json_format_embeds_json_message():
    sink = _sink(format="json")
    line = _to_syslog_line(sink, _event())
    assert '"qname":"casino.example."' in line


# ─── describe_error ────────────────────────────────────────────────────────


def test_describe_error_falls_back_to_type_name_when_str_is_empty():
    """asyncio.TimeoutError() (the common failure — a dead/firewalled
    collector) stringifies to '', which would otherwise leave a sink's
    last_error blank and undiagnosable."""
    assert describe_error(TimeoutError()) == "TimeoutError"


def test_describe_error_keeps_a_real_message():
    assert describe_error(ValueError("host unreachable")) == "host unreachable"


# ─── delivery cursor / backoff ─────────────────────────────────────────────


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[QueryEvent.__table__, SiemSyslog.__table__, AuditLog.__table__])
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _query_event(db, seq: int, decision: str = "block") -> QueryEvent:
    e = QueryEvent(seq=seq, group_id="g1", qname=f"q{seq}.example", decision=decision)
    db.add(e)
    return e


async def test_process_syslog_advances_cursor_on_success(db, monkeypatch):
    _query_event(db, seq=1)
    _query_event(db, seq=2)
    sink = _sink()
    db.add(sink)
    db.commit()

    sent = []
    monkeypatch.setattr(
        "mantis_control.siem_syslog_delivery._send",
        AsyncMock(side_effect=lambda s, events: sent.append(events)),
    )

    await _process_syslog(db, sink)

    assert sink.last_delivered_seq == 2
    assert sink.consecutive_failures == 0
    assert sink.last_error is None
    assert len(sent[0]) == 2


async def test_process_syslog_backs_off_and_records_error_on_failure(db, monkeypatch):
    _query_event(db, seq=1)
    sink = _sink()
    db.add(sink)
    db.commit()

    monkeypatch.setattr(
        "mantis_control.siem_syslog_delivery._send",
        AsyncMock(side_effect=TimeoutError()),
    )

    await _process_syslog(db, sink)

    assert sink.last_delivered_seq == 0  # cursor must not advance on failure
    assert sink.consecutive_failures == 1
    assert sink.last_error == "TimeoutError"  # not blank, see describe_error
    assert sink.next_retry_at is not None


async def test_process_syslog_auto_disables_after_max_consecutive_failures(db, monkeypatch):
    _query_event(db, seq=1)
    sink = _sink(consecutive_failures=5)  # one more failure hits MAX_CONSECUTIVE_FAILURES=6
    db.add(sink)
    db.commit()

    monkeypatch.setattr(
        "mantis_control.siem_syslog_delivery._send",
        AsyncMock(side_effect=ConnectionRefusedError("refused")),
    )

    await _process_syslog(db, sink)

    assert sink.consecutive_failures == 6
    assert sink.enabled is False


async def test_process_syslog_skips_when_no_new_events(db, monkeypatch):
    sink = _sink()
    db.add(sink)
    db.commit()

    send_mock = AsyncMock()
    monkeypatch.setattr("mantis_control.siem_syslog_delivery._send", send_mock)

    await _process_syslog(db, sink)

    send_mock.assert_not_called()


async def test_process_syslog_respects_flush_interval(db, monkeypatch):
    _query_event(db, seq=1)
    sink = _sink(last_delivered_at=datetime.now(timezone.utc), flush_interval_s=3600)
    db.add(sink)
    db.commit()

    send_mock = AsyncMock()
    monkeypatch.setattr("mantis_control.siem_syslog_delivery._send", send_mock)

    await _process_syslog(db, sink)

    send_mock.assert_not_called()


async def test_process_syslog_respects_next_retry_at_backoff(db, monkeypatch):
    _query_event(db, seq=1)
    sink = _sink(next_retry_at=datetime.now(timezone.utc) + timedelta(minutes=5))
    db.add(sink)
    db.commit()

    send_mock = AsyncMock()
    monkeypatch.setattr("mantis_control.siem_syslog_delivery._send", send_mock)

    await _process_syslog(db, sink)

    send_mock.assert_not_called()


async def test_process_syslog_filters_by_decision(db, monkeypatch):
    _query_event(db, seq=1, decision="allow")
    _query_event(db, seq=2, decision="block")
    sink = _sink(filter_decision="block")
    db.add(sink)
    db.commit()

    sent = []
    monkeypatch.setattr(
        "mantis_control.siem_syslog_delivery._send",
        AsyncMock(side_effect=lambda s, events: sent.append(events)),
    )

    await _process_syslog(db, sink)

    assert sink.last_delivered_seq == 2
    assert len(sent[0]) == 1


# ─── router validation ─────────────────────────────────────────────────────


class _Admin:
    email = "admin@example.test"
    role = "admin"
    tenant_id = None


def test_create_syslog_rejects_loopback_host(db):
    payload = SiemSyslogCreate(name="bad", host="127.0.0.1")
    with pytest.raises(HTTPException) as exc_info:
        create_syslog(payload, db, _Admin())
    assert exc_info.value.status_code == 422


def test_create_syslog_allows_private_address(db):
    payload = SiemSyslogCreate(name="wazuh", host="10.8.1.20", port=1514)
    sink = create_syslog(payload, db, _Admin())
    assert sink.host == "10.8.1.20"
    assert db.get(SiemSyslog, sink.id) is not None


def test_update_syslog_rejects_loopback_host(db):
    sink = create_syslog(SiemSyslogCreate(name="wazuh", host="10.8.1.20"), db, _Admin())
    with pytest.raises(HTTPException) as exc_info:
        update_syslog(sink.id, SiemSyslogUpdate(host="169.254.169.254"), db, _Admin())
    assert exc_info.value.status_code == 422


def test_update_syslog_reenable_clears_backoff_state(db):
    sink = create_syslog(SiemSyslogCreate(name="wazuh", host="10.8.1.20"), db, _Admin())
    sink.enabled = False
    sink.consecutive_failures = 6
    sink.next_retry_at = datetime.now(timezone.utc) + timedelta(hours=1)
    db.commit()

    updated = update_syslog(sink.id, SiemSyslogUpdate(enabled=True), db, _Admin())

    assert updated.consecutive_failures == 0
    assert updated.next_retry_at is None
