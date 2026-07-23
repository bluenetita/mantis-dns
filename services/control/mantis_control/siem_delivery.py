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

"""SIEM webhook delivery engine (design.md §20.4, Sprint 15).

Runs on a fixed scheduler tick (see main.py), independent of each webhook's
own `flush_interval_s` (that field governs how much a webhook batches
before considering itself "caught up" — not how often this loop checks).
HMAC-signed, retried with exponential backoff, auto-disables after too many
consecutive failures so a dead SIEM endpoint can't accumulate silently.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json as jsonlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from mantis_control.api.siem_routers import SiemEvent, _to_cef, build_siem_events
from mantis_control.audit import write_audit_log
from mantis_control.crypto import decrypt_secret
from mantis_control.db import models
from mantis_control.db.session import SessionLocal
from mantis_control.siem_common import BACKOFF_SECONDS, MAX_CONSECUTIVE_FAILURES, as_aware
from mantis_control.ssrf_guard import resolve_pinned_webhook_url


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _serialize_events(webhook: models.SiemWebhook, events: list[SiemEvent], delivery_id: str) -> tuple[bytes, str]:
    if webhook.format == "cef":
        return "\n".join(_to_cef(e) for e in events).encode(), "text/plain"
    payload = {
        "events": [jsonlib.loads(e.model_dump_json()) for e in events],
        "delivery_id": delivery_id,
        "cursor": str(events[-1].seq) if events else None,
    }
    return jsonlib.dumps(payload).encode(), "application/json"


async def _post(webhook: models.SiemWebhook, body: bytes, content_type: str, client: httpx.AsyncClient, delivery_id: str) -> int:
    # raises ValueError -> caught by caller as delivery failure. Fetch by
    # pinned IP (not the hostname) so a DNS re-resolution at connect time
    # can't redirect this request somewhere the guard didn't see.
    # resolve_pinned_webhook_url blocks on socket.getaddrinfo() — offload it
    # so a slow/black-holed webhook host doesn't stall the shared event loop
    # (this runs on every ~10s SIEM delivery tick, not just admin actions).
    pinned_url, original_host = await asyncio.to_thread(resolve_pinned_webhook_url, webhook.url)
    secret = decrypt_secret(webhook.secret_encrypted)
    signature = _sign(secret, body)
    headers = {
        "Host": original_host,
        "Content-Type": content_type,
        "X-Mantis-Signature": f"sha256={signature}",
        "X-Mantis-Delivery-Id": delivery_id,
        "X-Mantis-Timestamp": str(int(datetime.now(timezone.utc).timestamp() * 1000)),
    }
    resp = await client.post(
        pinned_url,
        content=body,
        headers=headers,
        timeout=10.0,
        extensions={"sni_hostname": original_host},
    )
    resp.raise_for_status()
    return resp.status_code


async def deliver_test_event(webhook: models.SiemWebhook, client: httpx.AsyncClient) -> int:
    """One synthetic event, used by the Settings UI's "send test event"
    button. Never touches the webhook's real delivery cursor or the client
    registry — deliberately not a real ClientEntry lookup."""
    now = datetime.now(timezone.utc)
    fake = SiemEvent(
        id="00000000-0000-0000-0000-000000000000",
        seq=0,
        occurred_at=now,
        tenant_id=webhook.tenant_id,
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
    delivery_id = str(uuid4())
    body, content_type = _serialize_events(webhook, [fake], delivery_id)
    return await _post(webhook, body, content_type, client, delivery_id)


async def _process_webhook(db: Session, webhook: models.SiemWebhook, client: httpx.AsyncClient) -> None:
    now = datetime.now(timezone.utc)

    if webhook.next_retry_at is not None:
        # In backoff after a failure — next_retry_at supersedes flush_interval_s.
        if as_aware(webhook.next_retry_at) > now:
            return
    elif webhook.last_delivered_at is not None:
        # Happy path: don't fire more often than the webhook's configured cadence.
        elapsed = (now - as_aware(webhook.last_delivered_at)).total_seconds()
        if elapsed < webhook.flush_interval_s:
            return

    query = select(models.QueryEvent).where(models.QueryEvent.seq > webhook.last_delivered_seq)
    if webhook.tenant_id:
        query = query.where(models.QueryEvent.tenant_id == webhook.tenant_id)
    if webhook.filter_decision != "all":
        query = query.where(models.QueryEvent.decision == webhook.filter_decision)
    query = query.order_by(models.QueryEvent.seq.asc()).limit(webhook.batch_size)
    rows = list(db.execute(query).scalars().all())
    if not rows:
        return
    events = build_siem_events(db, rows)

    try:
        delivery_id = str(uuid4())
        body, content_type = _serialize_events(webhook, events, delivery_id)
        await _post(webhook, body, content_type, client, delivery_id)
    except Exception as e:
        webhook.consecutive_failures += 1
        webhook.last_error = str(e)[:2000]
        backoff_idx = min(webhook.consecutive_failures - 1, len(BACKOFF_SECONDS) - 1)
        webhook.next_retry_at = now + timedelta(seconds=BACKOFF_SECONDS[backoff_idx])
        if webhook.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            webhook.enabled = False
            write_audit_log(
                db,
                "siem_webhook.disabled",
                "siem_webhook",
                webhook.id,
                detail=f"disabled after {webhook.consecutive_failures} consecutive failures: {webhook.last_error}",
                actor="system",
            )
        db.commit()
        return

    webhook.last_delivered_seq = events[-1].seq
    webhook.last_delivered_at = now
    webhook.consecutive_failures = 0
    webhook.last_error = None
    webhook.next_retry_at = None
    db.commit()


async def run_webhook_delivery_cycle() -> None:
    db = SessionLocal()
    try:
        webhook_ids = [
            w.id for w in db.query(models.SiemWebhook).filter(models.SiemWebhook.enabled.is_(True)).all()
        ]
    finally:
        db.close()
    if not webhook_ids:
        return

    # One connection per webhook, held only for that webhook's read + POST +
    # write — not one connection pinned across every webhook's HTTP call.
    # A shared connection here would sit checked-out from the pool for the
    # combined duration of all deliveries (up to 10s each), starving other
    # requests (e.g. bundle-compile) of pool connections.
    async with httpx.AsyncClient() as client:
        for webhook_id in webhook_ids:
            db = SessionLocal()
            try:
                webhook = db.get(models.SiemWebhook, webhook_id)
                if webhook is None or not webhook.enabled:
                    continue
                await _process_webhook(db, webhook, client)
            except Exception:
                db.rollback()
            finally:
                db.close()
