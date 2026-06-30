from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis_control.db import models
from aegis_control.db.session import get_db

router = APIRouter()


class QueryEventIn(BaseModel):
    group_id: str
    qname: str
    decision: str


class QueryEventBatch(BaseModel):
    events: list[QueryEventIn]


class TopDomain(BaseModel):
    qname: str
    decision: str
    count: int


@router.post("/query-events", status_code=202)
def ingest_query_events(payload: QueryEventBatch, db: Session = Depends(get_db)) -> dict[str, int]:
    """Fire-and-forget sink for filter-node query telemetry. Best-effort by
    design — the hot DNS path never blocks on this succeeding."""
    for event in payload.events:
        db.add(
            models.QueryEvent(
                group_id=event.group_id, qname=event.qname, decision=event.decision
            )
        )
    db.commit()
    return {"accepted": len(payload.events)}


@router.get("/groups/{group_id}/top-domains", response_model=list[TopDomain])
def top_domains(group_id: str, limit: int = 20, db: Session = Depends(get_db)) -> list[TopDomain]:
    rows = db.execute(
        select(
            models.QueryEvent.qname,
            models.QueryEvent.decision,
            func.count().label("count"),
        )
        .where(models.QueryEvent.group_id == group_id)
        .group_by(models.QueryEvent.qname, models.QueryEvent.decision)
        .order_by(func.count().desc())
        .limit(limit)
    ).all()
    return [TopDomain(qname=r.qname, decision=r.decision, count=r.count) for r in rows]
