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

"""SIEM syslog delivery engine (design.md §20.8, Sprint 17).

RFC 5424 messages carrying the same enriched event payload (CEF or JSON)
that the webhook path sends — this is a transport swap, not a new event
model. TCP/TLS use RFC 6587 octet-counting framing so a stream receiver can
split messages without a trailer scan; UDP sends one message per datagram
(no framing prefix, per convention).

Same cursor/backoff/auto-disable shape as siem_delivery.py, run on its own
scheduler tick (see main.py) so a stalled syslog collector can't affect
webhook delivery or vice versa.

Delivery guarantee note: TCP/TLS write success only means the collector's
kernel accepted the bytes — syslog has no application-layer acknowledgment,
so "delivered" here means "sent successfully to an open, writable socket",
same as any fire-and-forget syslog client. UDP is additionally lossy at the
network layer with no delivery signal at all. The cursor still only advances
on a successful send, so a *closed* connection or refused datagram is
retried like any other failure; a receiver that silently drops accepted
bytes is outside what this protocol can detect.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from mantis_control.api.siem_routers import SiemEvent, _to_cef, build_siem_events
from mantis_control.audit import write_audit_log
from mantis_control.db import models
from mantis_control.db.session import SessionLocal
from mantis_control.siem_common import BACKOFF_SECONDS, MAX_CONSECUTIVE_FAILURES, as_aware
from mantis_control.ssrf_guard import resolve_pinned_syslog_host

_CONNECT_TIMEOUT_S = 10.0

# RFC 5424 severity — block is a security-relevant decision worth flagging
# but not a system failure, so Warning rather than Error; allow is routine.
_SEVERITY = {"block": 4, "allow": 6}  # Warning / Informational
_DEFAULT_SEVERITY = 6


def describe_error(e: Exception) -> str:
    """`str(asyncio.TimeoutError())` (the common failure mode here — a dead
    or firewalled collector) is `""`, which would otherwise leave
    `last_error` blank and give an admin nothing to diagnose a stuck sink
    with. Falls back to the exception's type name whenever str() is empty."""
    return str(e) or type(e).__name__


def _to_syslog_line(sink: models.SiemSyslog, e: SiemEvent) -> str:
    """RFC 5424 message: `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID
    MSGID STRUCTURED-DATA MSG`. HOSTNAME/PROCID/MSGID/STRUCTURED-DATA are
    NILVALUE ("-") — the enriched event itself (in MSG) already carries
    tenant/group/client identity, which is what those fields would otherwise
    encode."""
    severity = _SEVERITY.get(e.decision, _DEFAULT_SEVERITY)
    pri = sink.facility * 8 + severity
    timestamp = e.occurred_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    msg = _to_cef(e) if sink.format == "cef" else e.model_dump_json()
    app_name = sink.app_name or "mantis-dns"
    return f"<{pri}>1 {timestamp} - {app_name} - - - {msg}"


async def _send_tcp(ip: str, port: int, lines: list[str], *, tls: bool, original_host: str) -> None:
    ssl_ctx = ssl.create_default_context() if tls else None
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            ip, port, ssl=ssl_ctx, server_hostname=original_host if tls else None
        ),
        timeout=_CONNECT_TIMEOUT_S,
    )
    del reader
    try:
        for line in lines:
            data = line.encode("utf-8")
            # RFC 6587 octet-counting framing: "<byte-length> <message>".
            writer.write(f"{len(data)} ".encode("ascii"))
            writer.write(data)
        await asyncio.wait_for(writer.drain(), timeout=_CONNECT_TIMEOUT_S)
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=_CONNECT_TIMEOUT_S)
        except Exception:
            pass  # best-effort close; the batch was already written above


async def _send_udp(ip: str, port: int, family: socket.AddressFamily, lines: list[str]) -> None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for line in lines:
            await asyncio.wait_for(
                loop.sock_sendto(sock, line.encode("utf-8"), (ip, port)), timeout=_CONNECT_TIMEOUT_S
            )
    finally:
        sock.close()


async def _send(sink: models.SiemSyslog, events: list[SiemEvent]) -> None:
    # Resolve once and connect to the IP literal, not the hostname — closes
    # the DNS-rebinding TOCTOU gap between validation and connect, same
    # reasoning as the webhook path's resolve_pinned_webhook_url.
    ip, family, original_host = await asyncio.to_thread(resolve_pinned_syslog_host, sink.host)
    lines = [_to_syslog_line(sink, e) for e in events]
    if sink.transport == "udp":
        await _send_udp(ip, sink.port, family, lines)
    else:
        await _send_tcp(ip, sink.port, lines, tls=(sink.transport == "tls"), original_host=original_host)


async def deliver_test_event(sink: models.SiemSyslog) -> None:
    """One synthetic event, used by the Settings UI's "send test event"
    button. Never touches the sink's real delivery cursor."""
    now = datetime.now(timezone.utc)
    fake = SiemEvent(
        id="00000000-0000-0000-0000-000000000000",
        seq=0,
        occurred_at=now,
        tenant_id=sink.tenant_id,
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
    await _send(sink, [fake])


async def _process_syslog(db: Session, sink: models.SiemSyslog) -> None:
    now = datetime.now(timezone.utc)

    if sink.next_retry_at is not None:
        if as_aware(sink.next_retry_at) > now:
            return
    elif sink.last_delivered_at is not None:
        elapsed = (now - as_aware(sink.last_delivered_at)).total_seconds()
        if elapsed < sink.flush_interval_s:
            return

    query = select(models.QueryEvent).where(models.QueryEvent.seq > sink.last_delivered_seq)
    if sink.tenant_id:
        query = query.where(models.QueryEvent.tenant_id == sink.tenant_id)
    if sink.filter_decision != "all":
        query = query.where(models.QueryEvent.decision == sink.filter_decision)
    query = query.order_by(models.QueryEvent.seq.asc()).limit(sink.batch_size)
    rows = list(db.execute(query).scalars().all())
    if not rows:
        return
    events = build_siem_events(db, rows)

    try:
        await _send(sink, events)
    except Exception as e:
        sink.consecutive_failures += 1
        sink.last_error = describe_error(e)[:2000]
        backoff_idx = min(sink.consecutive_failures - 1, len(BACKOFF_SECONDS) - 1)
        sink.next_retry_at = now + timedelta(seconds=BACKOFF_SECONDS[backoff_idx])
        if sink.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            sink.enabled = False
            write_audit_log(
                db,
                "siem_syslog.disabled",
                "siem_syslog",
                sink.id,
                detail=f"disabled after {sink.consecutive_failures} consecutive failures: {sink.last_error}",
                actor="system",
            )
        db.commit()
        return

    sink.last_delivered_seq = events[-1].seq
    sink.last_delivered_at = now
    sink.consecutive_failures = 0
    sink.last_error = None
    sink.next_retry_at = None
    db.commit()


async def run_syslog_delivery_cycle() -> None:
    db = SessionLocal()
    try:
        sink_ids = [
            s.id for s in db.query(models.SiemSyslog).filter(models.SiemSyslog.enabled.is_(True)).all()
        ]
    finally:
        db.close()
    if not sink_ids:
        return

    for sink_id in sink_ids:
        db = SessionLocal()
        try:
            sink = db.get(models.SiemSyslog, sink_id)
            if sink is None or not sink.enabled:
                continue
            await _process_syslog(db, sink)
        except Exception:
            db.rollback()
        finally:
            db.close()
