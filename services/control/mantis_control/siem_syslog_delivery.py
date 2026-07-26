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
that the pull API (siem_routers.py) serves — this is a transport/push
adapter, not a new event model. TCP/TLS use RFC 6587 octet-counting framing
so a stream receiver can split messages without a trailer scan; UDP sends
one message per datagram (no framing prefix, per convention).

Cursor/backoff/auto-disable bookkeeping is run on its own scheduler tick
(see main.py).

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
import logging
import socket
import ssl
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mantis_control.api.siem_routers import SiemEvent, _to_cef, build_siem_events
from mantis_control.audit import write_audit_log
from mantis_control.db import models
from mantis_control.db.session import SessionLocal
from mantis_control.ssrf_guard import resolve_pinned_syslog_host

log = logging.getLogger(__name__)

BACKOFF_SECONDS = [5, 30, 120, 600, 3600]
MAX_CONSECUTIVE_FAILURES = 6
DELIVERY_LAG_SECONDS = 5
MAX_BATCHES_PER_TICK = 20
DRAIN_DEADLINE_SECONDS = 5.0

_CONNECT_TIMEOUT_S = 10.0


def describe_error(e: Exception) -> str:
    return str(e) or type(e).__name__


def _describe_error(e: Exception) -> str:
    return describe_error(e)


def _build_test_event(tenant_id: str | None) -> SiemEvent:
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
    sink: models.SiemSyslog,
    *,
    send: Callable[[list[SiemEvent]], Awaitable[None]],
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
        sink.last_error = _describe_error(e)[:2000]
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
        raise

    sink.last_delivered_seq = events[-1].seq
    sink.last_delivered_at = now
    sink.consecutive_failures = 0
    sink.last_error = None
    sink.next_retry_at = None
    db.commit()
    return len(rows)


async def _process_delivery_sink(
    db: Session,
    sink: models.SiemSyslog,
    *,
    send: Callable[[list[SiemEvent]], Awaitable[None]],
) -> None:
    """Runs one delivery attempt for the sink. Drains batches in a row while
    backlog remains, bounded by both a batch count (MAX_BATCHES_PER_TICK) and
    a wall-clock deadline (DRAIN_DEADLINE_SECONDS)."""
    now = datetime.now(timezone.utc)

    if sink.next_retry_at is not None:
        if sink.next_retry_at.tzinfo is None:
            sink.next_retry_at = sink.next_retry_at.replace(tzinfo=timezone.utc)
        if sink.next_retry_at > now:
            return
    elif sink.last_delivered_at is not None:
        last_at = sink.last_delivered_at
        if last_at.tzinfo is None:
            last_at = last_at.replace(tzinfo=timezone.utc)
        elapsed = (now - last_at).total_seconds()
        if elapsed < sink.flush_interval_s:
            return

    deadline = time.monotonic() + DRAIN_DEADLINE_SECONDS
    for _ in range(MAX_BATCHES_PER_TICK):
        try:
            sent = await _deliver_one_batch(db, sink, send=send, now=now)
        except Exception:
            return
        if sent < sink.batch_size:
            return
        if time.monotonic() >= deadline:
            return


async def _run_delivery_cycle() -> None:
    """Scheduler-tick shape: list enabled sinks on their own short-lived
    session, then process each on its own fresh session so one sink's
    failure/rollback can't affect another's."""
    db = SessionLocal()
    try:
        ids = [r.id for r in db.query(models.SiemSyslog).filter(models.SiemSyslog.enabled.is_(True)).all()]
    finally:
        db.close()
    if not ids:
        return

    for row_id in ids:
        db = SessionLocal()
        try:
            sink = db.get(models.SiemSyslog, row_id)
            if sink is None or not sink.enabled:
                continue
            await _process_delivery_sink(db, sink, send=lambda events: _send(sink, events))
        except Exception:
            log.exception("SIEM syslog delivery cycle failed for sink %s", row_id)
            db.rollback()
        finally:
            db.close()

# RFC 5424 severity — block is a security-relevant decision worth flagging
# but not a system failure, so Warning rather than Error; allow is routine.
_SEVERITY = {"block": 4, "allow": 6}  # Warning / Informational
_DEFAULT_SEVERITY = 6

# A single oversized event (e.g. an operator-set client tags list, or any
# future unbounded field) would otherwise wedge a sink forever: the cursor
# only advances on whole-batch success, so a batch containing one message
# too large for the collector (rsyslog's default maxMessageSize is 8KB;
# UDP's hard ceiling is 65507 bytes) fails every retry, backs off, and
# auto-disables — re-enabling replays the exact same poison message. This is
# a conservative shared cap well under typical collector limits — truncating
# the offending message (with a marker) keeps the batch, and every message
# after it, flowing instead of retrying the same line forever.
_MAX_LINE_BYTES = 32_768
_TRUNCATION_SUFFIX = b"...[truncated]"


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
    header = f"<{pri}>1 {timestamp} - {app_name} - - - "

    msg_bytes = msg.encode("utf-8")
    header_bytes = header.encode("utf-8")
    if len(header_bytes) + len(msg_bytes) > _MAX_LINE_BYTES:
        keep = max(_MAX_LINE_BYTES - len(header_bytes) - len(_TRUNCATION_SUFFIX), 0)
        # errors="ignore" drops a multi-byte UTF-8 char split by the cut.
        msg = msg_bytes[:keep].decode("utf-8", errors="ignore") + _TRUNCATION_SUFFIX.decode()

    return header + msg


async def _send_tcp(ip: str, port: int, lines: list[str], *, tls: bool, original_host: str) -> None:
    ssl_ctx = ssl.create_default_context() if tls else None
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            ip, port, ssl=ssl_ctx, server_hostname=original_host if tls else None
        ),
        timeout=_CONNECT_TIMEOUT_S,
    )
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
    # the DNS-rebinding TOCTOU gap between validation and connect.
    ip, family, original_host = await asyncio.to_thread(resolve_pinned_syslog_host, sink.host)
    lines = [_to_syslog_line(sink, e) for e in events]
    if sink.transport == "udp":
        await _send_udp(ip, sink.port, family, lines)
    else:
        await _send_tcp(ip, sink.port, lines, tls=(sink.transport == "tls"), original_host=original_host)


async def _process_syslog(db: Session, sink: models.SiemSyslog) -> None:
    """Test helper wrapper."""
    await _process_delivery_sink(db, sink, send=lambda events: _send(sink, events))


async def deliver_test_event(sink: models.SiemSyslog) -> None:
    fake = _build_test_event(sink.tenant_id)
    await _send(sink, [fake])


async def run_syslog_delivery_cycle() -> None:
    await _run_delivery_cycle()
