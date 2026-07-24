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

"""SIEM webhook: HMAC signing, serialization, delivery cursor/backoff, and
config CRUD validation (design.md §20.4, Sprint 15). Mirrors
test_siem_syslog.py's coverage for the other export sink."""

from __future__ import annotations

import hashlib
import hmac
import json as jsonlib
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api.siem_routers import SiemEvent
from mantis_control.api.siem_webhook_routers import (
    SiemWebhookCreate,
    SiemWebhookUpdate,
    create_webhook,
    update_webhook,
)
from mantis_control.crypto import encrypt_secret
from mantis_control.db.models import AuditLog, Base, QueryEvent, SiemWebhook
from mantis_control.siem_delivery import _process_webhook, _serialize_events, _sign


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


def _webhook(**overrides) -> SiemWebhook:
    defaults = dict(
        name="test-webhook",
        url="https://10.8.1.20:9200/mantis-events",
        secret_encrypted=encrypt_secret("s3kr3t"),
        format="json",
        batch_size=200,
        flush_interval_s=30,
        filter_decision="all",
    )
    defaults.update(overrides)
    return SiemWebhook(**defaults)


# ─── serialization / signing ───────────────────────────────────────────────


def test_serialize_events_json_format_embeds_events_and_cursor():
    webhook = _webhook(format="json")
    body, content_type = _serialize_events(webhook, [_event(seq=5)], "delivery-1")
    assert content_type == "application/json"
    payload = jsonlib.loads(body)
    assert payload["delivery_id"] == "delivery-1"
    assert payload["cursor"] == "5"
    assert payload["events"][0]["qname"] == "casino.example."


def test_serialize_events_cef_format_joins_lines_as_plain_text():
    webhook = _webhook(format="cef")
    body, content_type = _serialize_events(
        webhook, [_event(seq=1), _event(seq=2)], "delivery-2"
    )
    assert content_type == "text/plain"
    lines = body.decode().split("\n")
    assert len(lines) == 2
    assert all(line.startswith("CEF:0|MantisDNS|mantis-filter|1.0|DNS_QUERY") for line in lines)


def test_sign_is_hmac_sha256_of_raw_body():
    body = b'{"events":[]}'
    expected = hmac.new(b"s3kr3t", body, hashlib.sha256).hexdigest()
    assert _sign("s3kr3t", body) == expected


# ─── delivery cursor / backoff ─────────────────────────────────────────────


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[QueryEvent.__table__, SiemWebhook.__table__, AuditLog.__table__])
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _query_event(db, seq: int, decision: str = "block") -> QueryEvent:
    e = QueryEvent(seq=seq, group_id="g1", qname=f"q{seq}.example", decision=decision)
    db.add(e)
    return e


async def test_process_webhook_advances_cursor_on_success(db, monkeypatch):
    _query_event(db, seq=1)
    _query_event(db, seq=2)
    webhook = _webhook()
    db.add(webhook)
    db.commit()

    sent = []
    monkeypatch.setattr(
        "mantis_control.siem_delivery._post",
        AsyncMock(side_effect=lambda w, body, content_type, client, delivery_id: sent.append(body) or 200),
    )

    await _process_webhook(db, webhook, client=None)

    assert webhook.last_delivered_seq == 2
    assert webhook.consecutive_failures == 0
    assert webhook.last_error is None
    assert len(sent) == 1


async def test_process_webhook_backs_off_and_records_error_on_failure(db, monkeypatch):
    _query_event(db, seq=1)
    webhook = _webhook()
    db.add(webhook)
    db.commit()

    monkeypatch.setattr(
        "mantis_control.siem_delivery._post",
        AsyncMock(side_effect=TimeoutError()),
    )

    await _process_webhook(db, webhook, client=None)

    assert webhook.last_delivered_seq == 0  # cursor must not advance on failure
    assert webhook.consecutive_failures == 1
    assert webhook.last_error == "TimeoutError"  # not blank, see describe_error
    assert webhook.next_retry_at is not None


async def test_process_webhook_auto_disables_after_max_consecutive_failures(db, monkeypatch):
    _query_event(db, seq=1)
    webhook = _webhook(consecutive_failures=5)  # one more failure hits MAX_CONSECUTIVE_FAILURES=6
    db.add(webhook)
    db.commit()

    monkeypatch.setattr(
        "mantis_control.siem_delivery._post",
        AsyncMock(side_effect=ConnectionRefusedError("refused")),
    )

    await _process_webhook(db, webhook, client=None)

    assert webhook.consecutive_failures == 6
    assert webhook.enabled is False


async def test_process_webhook_skips_when_no_new_events(db, monkeypatch):
    webhook = _webhook()
    db.add(webhook)
    db.commit()

    post_mock = AsyncMock()
    monkeypatch.setattr("mantis_control.siem_delivery._post", post_mock)

    await _process_webhook(db, webhook, client=None)

    post_mock.assert_not_called()


async def test_process_webhook_respects_flush_interval(db, monkeypatch):
    _query_event(db, seq=1)
    webhook = _webhook(last_delivered_at=datetime.now(timezone.utc), flush_interval_s=3600)
    db.add(webhook)
    db.commit()

    post_mock = AsyncMock()
    monkeypatch.setattr("mantis_control.siem_delivery._post", post_mock)

    await _process_webhook(db, webhook, client=None)

    post_mock.assert_not_called()


async def test_process_webhook_respects_next_retry_at_backoff(db, monkeypatch):
    _query_event(db, seq=1)
    webhook = _webhook(next_retry_at=datetime.now(timezone.utc) + timedelta(minutes=5))
    db.add(webhook)
    db.commit()

    post_mock = AsyncMock()
    monkeypatch.setattr("mantis_control.siem_delivery._post", post_mock)

    await _process_webhook(db, webhook, client=None)

    post_mock.assert_not_called()


async def test_process_webhook_filters_by_decision(db, monkeypatch):
    _query_event(db, seq=1, decision="allow")
    _query_event(db, seq=2, decision="block")
    webhook = _webhook(filter_decision="block")
    db.add(webhook)
    db.commit()

    sent = []
    monkeypatch.setattr(
        "mantis_control.siem_delivery._post",
        AsyncMock(side_effect=lambda w, body, content_type, client, delivery_id: sent.append(body) or 200),
    )

    await _process_webhook(db, webhook, client=None)

    assert webhook.last_delivered_seq == 2
    assert len(sent) == 1


async def test_process_webhook_filtered_no_matches_still_advances_cursor(db, monkeypatch):
    """A filter_decision="block" webhook on an allow-only window must not
    rescan the same growing span forever — the cursor should jump to the
    newest seq even though nothing matched (regression: previously `return`ed
    with the cursor untouched)."""
    _query_event(db, seq=1, decision="allow")
    _query_event(db, seq=2, decision="allow")
    webhook = _webhook(filter_decision="block")
    db.add(webhook)
    db.commit()

    post_mock = AsyncMock()
    monkeypatch.setattr("mantis_control.siem_delivery._post", post_mock)

    await _process_webhook(db, webhook, client=None)

    post_mock.assert_not_called()
    assert webhook.last_delivered_seq == 2


# ─── router validation ─────────────────────────────────────────────────────


class _Admin:
    email = "admin@example.test"
    role = "admin"
    tenant_id = None


def test_create_webhook_rejects_loopback_url(db):
    payload = SiemWebhookCreate(name="bad", url="http://127.0.0.1/hook", secret="x")
    with pytest.raises(HTTPException) as exc_info:
        create_webhook(payload, db, _Admin())
    assert exc_info.value.status_code == 422


def test_create_webhook_allows_private_url(db):
    payload = SiemWebhookCreate(name="wazuh", url="https://10.8.1.20:9200/mantis-events", secret="x")
    webhook = create_webhook(payload, db, _Admin())
    assert webhook.url == "https://10.8.1.20:9200/mantis-events"
    assert db.get(SiemWebhook, webhook.id) is not None


def test_update_webhook_rejects_loopback_url(db):
    webhook = create_webhook(
        SiemWebhookCreate(name="wazuh", url="https://10.8.1.20:9200/mantis-events", secret="x"), db, _Admin()
    )
    with pytest.raises(HTTPException) as exc_info:
        update_webhook(webhook.id, SiemWebhookUpdate(url="http://169.254.169.254/hook"), db, _Admin())
    assert exc_info.value.status_code == 422


def test_update_webhook_reenable_clears_backoff_state(db):
    webhook = create_webhook(
        SiemWebhookCreate(name="wazuh", url="https://10.8.1.20:9200/mantis-events", secret="x"), db, _Admin()
    )
    webhook.enabled = False
    webhook.consecutive_failures = 6
    webhook.next_retry_at = datetime.now(timezone.utc) + timedelta(hours=1)
    db.commit()

    updated = update_webhook(webhook.id, SiemWebhookUpdate(enabled=True), db, _Admin())

    assert updated.consecutive_failures == 0
    assert updated.next_retry_at is None
