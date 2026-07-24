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

Cursor/backoff/auto-disable bookkeeping is shared with the webhook sink in
siem_common.py, run on its own scheduler tick (see main.py) so a stalled
syslog collector can't affect webhook delivery or vice versa.

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
from datetime import timezone

from sqlalchemy.orm import Session

from mantis_control.api.siem_routers import SiemEvent, _to_cef
from mantis_control.db import models
from mantis_control.siem_common import build_test_event, process_delivery_sink, run_delivery_cycle
from mantis_control.ssrf_guard import resolve_pinned_syslog_host

_CONNECT_TIMEOUT_S = 10.0

# RFC 5424 severity — block is a security-relevant decision worth flagging
# but not a system failure, so Warning rather than Error; allow is routine.
_SEVERITY = {"block": 4, "allow": 6}  # Warning / Informational
_DEFAULT_SEVERITY = 6


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
    fake = build_test_event(sink.tenant_id)
    await _send(sink, [fake])


async def _process_syslog(db: Session, sink: models.SiemSyslog) -> None:
    await process_delivery_sink(db, sink, send=lambda events: _send(sink, events), resource_type="siem_syslog")


async def run_syslog_delivery_cycle() -> None:
    await run_delivery_cycle(models.SiemSyslog, _process_syslog)
