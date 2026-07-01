"""SIEM export — pull API (design.md §20.3). Cursor-based, JSON or CEF.

Webhook push (§20.4) and the client registry (§20.6) are later Sprint-15/16
items; this module is the Sprint-14 foundation both depend on.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis_control.auth import require_role
from aegis_control.db import models
from aegis_control.db.session import get_db

router = APIRouter()


class SiemEvent(BaseModel):
    id: str
    seq: int
    occurred_at: datetime
    tenant_id: str | None
    group_id: str
    client_ip: str | None
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


def _to_cef(e: models.QueryEvent) -> str:
    """Maps an enriched QueryEvent to a CEF:0 line per design.md §20.5."""
    severity = 7 if e.decision == "block" else 3
    parts = [f"start={int(e.occurred_at.timestamp() * 1_000_000)}"]
    if e.client_ip:
        parts.append(f"src={e.client_ip}")
    parts.append(f"dhost={e.qname}")
    if e.matched_category:
        parts.append(f"cs1={e.matched_category} cs1Label=matchedCategory")
    if e.matched_feed_id:
        parts.append(f"cs2={e.matched_feed_id} cs2Label=matchedFeed")
    if e.qtype:
        parts.append(f"cs3={e.qtype} cs3Label=queryType")
    if e.latency_us is not None:
        parts.append(f"cn1={e.latency_us} cn1Label=latencyMicros")
    if e.cache_hit is not None:
        parts.append(f"cn2={int(e.cache_hit)} cn2Label=cacheHit")
    parts.append(f"act={e.decision}")
    if e.response_code:
        parts.append(f"outcome={e.response_code}")
    parts.append(f"deviceExternalId={e.id}")
    if e.tenant_id:
        parts.append(f"tenantId={e.tenant_id}")
    parts.append(f"grp={e.group_id}")

    extension = " ".join(parts)
    return f"CEF:0|AegisDNS|aegis-filter|1.0|DNS_QUERY|DNS query event|{severity}|{extension}"


@router.get("/siem/events")
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
):
    query = select(models.QueryEvent)

    if after_id is not None:
        try:
            after_seq = int(after_id)
        except ValueError as e:
            raise HTTPException(422, "after_id must be a cursor previously returned as next_cursor") from e
        query = query.where(models.QueryEvent.seq > after_seq)
    if tenant_id:
        query = query.where(models.QueryEvent.tenant_id == tenant_id)
    if group_id:
        query = query.where(models.QueryEvent.group_id == group_id)
    if decision:
        query = query.where(models.QueryEvent.decision == decision)
    if since:
        query = query.where(models.QueryEvent.occurred_at >= since)
    if until:
        query = query.where(models.QueryEvent.occurred_at <= until)

    query = query.order_by(models.QueryEvent.seq.asc()).limit(limit)
    rows = list(db.execute(query).scalars().all())

    if format == "cef":
        return PlainTextResponse("\n".join(_to_cef(r) for r in rows), media_type="text/plain")

    return SiemEventsPage(
        events=[SiemEvent.model_validate(r) for r in rows],
        next_cursor=str(rows[-1].seq) if len(rows) == limit else None,
        total_in_window=len(rows),
    )
