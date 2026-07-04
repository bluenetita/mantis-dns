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

"""SIEM export — pull API (design.md §20.3). Cursor-based, JSON or CEF.

Sprint 16 (§20.6): events are enriched with client registry data
(client_name/owner/device_type/tags) where the client IP has been
registered — this is what turns a raw client IP into an actionable SIEM
alert. `build_siem_events` is shared with the webhook delivery engine
(siem_delivery.py) so both export paths enrich identically.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from mantis_control.auth import check_tenant_access, require_role, user_tenant_filter
from mantis_control.db import models
from mantis_control.db.session import get_db

router = APIRouter()


class SiemEvent(BaseModel):
    id: str
    seq: int
    occurred_at: datetime
    tenant_id: str | None
    group_id: str
    client_ip: str | None
    client_name: str | None = None
    owner: str | None = None
    device_type: str | None = None
    tags: list[str] = []
    qname: str
    qtype: str | None
    decision: str
    matched_rule: str | None
    matched_category: str | None
    matched_feed_id: str | None
    response_code: str | None
    cache_hit: bool | None
    latency_us: int | None

    class Config:
        from_attributes = True


class SiemEventsPage(BaseModel):
    events: list[SiemEvent]
    next_cursor: str | None
    total_in_window: int


def build_siem_events(db: Session, rows: list[models.QueryEvent]) -> list[SiemEvent]:
    """Batch-enriches QueryEvent rows with client registry data (one query
    for the whole batch, not one per row)."""
    pairs = {(r.tenant_id, r.client_ip) for r in rows if r.tenant_id and r.client_ip}
    clients: dict[tuple[str, str], models.ClientEntry] = {}
    if pairs:
        tenant_ids = {p[0] for p in pairs}
        ips = {p[1] for p in pairs}
        for entry in (
            db.query(models.ClientEntry)
            .filter(models.ClientEntry.tenant_id.in_(tenant_ids), models.ClientEntry.ip.in_(ips))
            .all()
        ):
            clients[(entry.tenant_id, entry.ip)] = entry

    events = []
    for r in rows:
        c = clients.get((r.tenant_id, r.client_ip)) if r.tenant_id and r.client_ip else None
        events.append(
            SiemEvent(
                id=r.id,
                seq=r.seq,
                occurred_at=r.occurred_at,
                tenant_id=r.tenant_id,
                group_id=r.group_id,
                client_ip=r.client_ip,
                client_name=c.hostname if c else None,
                owner=c.owner if c else None,
                device_type=c.device_type if c else None,
                tags=c.tags if c else [],
                qname=r.qname,
                qtype=r.qtype,
                decision=r.decision,
                matched_rule=r.matched_rule,
                matched_category=r.matched_category,
                matched_feed_id=r.matched_feed_id,
                response_code=r.response_code,
                cache_hit=r.cache_hit,
                latency_us=r.latency_us,
            )
        )
    return events


def _cef_ext(value: str) -> str:
    """Escape a CEF extension field value per the CEF 0 spec."""
    return (
        value
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace(" ", "\\s")   # Unicode LINE SEPARATOR — some parsers split on it
        .replace(" ", "\\s")   # Unicode PARAGRAPH SEPARATOR
    )


def _to_cef(e: SiemEvent) -> str:
    """Maps an enriched SiemEvent to a CEF:0 line per design.md §20.5."""
    severity = 7 if e.decision == "block" else 3
    parts = [f"start={int(e.occurred_at.timestamp() * 1_000)}"]
    if e.client_ip:
        parts.append(f"src={_cef_ext(e.client_ip)}")
    if e.client_name:
        parts.append(f"shost={_cef_ext(e.client_name)}")
    parts.append(f"dhost={_cef_ext(e.qname)}")
    if e.matched_category:
        parts.append(f"cs1={_cef_ext(e.matched_category)} cs1Label=matchedCategory")
    if e.matched_feed_id:
        parts.append(f"cs2={_cef_ext(e.matched_feed_id)} cs2Label=matchedFeed")
    if e.qtype:
        parts.append(f"cs3={_cef_ext(e.qtype)} cs3Label=queryType")
    if e.latency_us is not None:
        parts.append(f"cn1={e.latency_us} cn1Label=latencyMicros")
    if e.cache_hit is not None:
        parts.append(f"cn2={int(e.cache_hit)} cn2Label=cacheHit")
    parts.append(f"act={_cef_ext(e.decision)}")
    if e.response_code:
        parts.append(f"outcome={_cef_ext(e.response_code)}")
    parts.append(f"deviceExternalId={_cef_ext(e.id)}")
    if e.tenant_id:
        parts.append(f"tenantId={_cef_ext(e.tenant_id)}")
    parts.append(f"grp={_cef_ext(e.group_id)}")

    extension = " ".join(parts)
    return f"CEF:0|MantisDNS|mantis-filter|1.0|DNS_QUERY|DNS query event|{severity}|{extension}"


@router.get("/siem/events", response_model=None)
def list_siem_events(
    after_id: str | None = None,
    limit: int = Query(500, ge=1, le=10_000),
    tenant_id: str | None = None,
    group_id: str | None = None,
    decision: Literal["allow", "block"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    format: Literal["json", "cef"] = "json",
    db: Session = Depends(get_db),
    _user: models.User = Depends(require_role("admin", "operator")),
) -> SiemEventsPage | PlainTextResponse:
    if tenant_id:
        check_tenant_access(_user, tenant_id)
    scope = user_tenant_filter(_user)
    effective_tenant_id = tenant_id or scope

    query = select(models.QueryEvent)

    if after_id is not None:
        try:
            after_seq = int(after_id)
        except ValueError as e:
            raise HTTPException(422, "after_id must be a cursor previously returned as next_cursor") from e
        query = query.where(models.QueryEvent.seq > after_seq)
    if effective_tenant_id:
        query = query.where(models.QueryEvent.tenant_id == effective_tenant_id)
    if group_id:
        query = query.where(models.QueryEvent.group_id == group_id)
    if decision:
        query = query.where(models.QueryEvent.decision == decision)
    if since:
        query = query.where(models.QueryEvent.occurred_at >= since)
    if until:
        query = query.where(models.QueryEvent.occurred_at <= until)

    query = query.order_by(models.QueryEvent.seq.asc()).limit(limit + 1)
    rows = list(db.execute(query).scalars().all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    events = build_siem_events(db, rows)

    if format == "cef":
        return PlainTextResponse("\n".join(_to_cef(e) for e in events), media_type="text/plain")

    return SiemEventsPage(
        events=events,
        next_cursor=str(rows[-1].seq) if has_more else None,
        total_in_window=len(rows),
    )
