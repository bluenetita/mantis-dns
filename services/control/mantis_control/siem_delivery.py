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

Cursor/backoff/auto-disable bookkeeping is shared with the syslog sink in
siem_common.py — this module only supplies the "how to send a batch" part.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json as jsonlib
from datetime import datetime, timezone
from uuid import uuid4

import httpx
from sqlalchemy.orm import Session

from mantis_control.api.siem_routers import SiemEvent, _to_cef
from mantis_control.crypto import decrypt_secret
from mantis_control.db import models
from mantis_control.siem_common import build_test_event, process_delivery_sink, run_delivery_cycle
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
    fake = build_test_event(webhook.tenant_id)
    delivery_id = str(uuid4())
    body, content_type = _serialize_events(webhook, [fake], delivery_id)
    return await _post(webhook, body, content_type, client, delivery_id)


async def _process_webhook(db: Session, webhook: models.SiemWebhook, client: httpx.AsyncClient) -> None:
    async def send(events: list[SiemEvent]) -> None:
        delivery_id = str(uuid4())
        body, content_type = _serialize_events(webhook, events, delivery_id)
        await _post(webhook, body, content_type, client, delivery_id)

    await process_delivery_sink(db, webhook, send=send, resource_type="siem_webhook")


async def run_webhook_delivery_cycle() -> None:
    # One shared client for the whole cycle (its own internal connection
    # pooling) — separate from the DB session, which run_delivery_cycle
    # opens fresh per webhook so one slow delivery can't hold a pooled DB
    # connection for the combined duration of every webhook in this tick.
    async with httpx.AsyncClient() as client:
        await run_delivery_cycle(models.SiemWebhook, lambda db, webhook: _process_webhook(db, webhook, client))
