from __future__ import annotations

from datetime import datetime, timedelta, timezone

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


class AnalyticsSummary(BaseModel):
    total_queries: int
    blocked_queries: int
    allowed_queries: int
    block_ratio: float
    tenant_count: int
    group_count: int
    feed_count: int
    top_blocked_domains: list[TopDomain]


class TimeseriesPoint(BaseModel):
    bucket: datetime
    total: int
    blocked: int
    allowed: int


class GroupBreakdown(BaseModel):
    group_id: str
    group_name: str
    tenant_name: str
    total: int
    blocked: int
    block_ratio: float


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


@router.get("/analytics/summary", response_model=AnalyticsSummary)
def analytics_summary(db: Session = Depends(get_db)) -> AnalyticsSummary:
    """Org-wide rollup across all tenants/groups. Postgres for now (design.md
    §6: Kafka -> ClickHouse is the at-scale target); fine at current volumes."""
    total = db.query(func.count(models.QueryEvent.id)).scalar() or 0
    blocked = (
        db.query(func.count(models.QueryEvent.id))
        .filter(models.QueryEvent.decision == "block")
        .scalar()
        or 0
    )
    allowed = total - blocked

    top_blocked_rows = db.execute(
        select(
            models.QueryEvent.qname,
            models.QueryEvent.decision,
            func.count().label("count"),
        )
        .where(models.QueryEvent.decision == "block")
        .group_by(models.QueryEvent.qname, models.QueryEvent.decision)
        .order_by(func.count().desc())
        .limit(10)
    ).all()

    return AnalyticsSummary(
        total_queries=total,
        blocked_queries=blocked,
        allowed_queries=allowed,
        block_ratio=(blocked / total) if total else 0.0,
        tenant_count=db.query(func.count(models.Tenant.id)).scalar() or 0,
        group_count=db.query(func.count(models.Group.id)).scalar() or 0,
        feed_count=db.query(func.count(models.Feed.id)).scalar() or 0,
        top_blocked_domains=[
            TopDomain(qname=r.qname, decision=r.decision, count=r.count) for r in top_blocked_rows
        ],
    )


@router.get("/analytics/timeseries", response_model=list[TimeseriesPoint])
def analytics_timeseries(hours: int = 24, db: Session = Depends(get_db)) -> list[TimeseriesPoint]:
    """Hourly query volume for the last `hours` hours, org-wide. Buckets with
    zero queries are included (not just present-in-DB rows) so charts don't
    show misleading gaps."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    bucket = func.date_trunc("hour", models.QueryEvent.occurred_at)

    raw_rows = db.execute(
        select(bucket.label("bucket"), models.QueryEvent.decision, func.count().label("count"))
        .where(models.QueryEvent.occurred_at >= since)
        .group_by(bucket, models.QueryEvent.decision)
    ).all()

    by_bucket: dict[datetime, dict[str, int]] = {}
    for r in raw_rows:
        b = r.bucket if r.bucket.tzinfo else r.bucket.replace(tzinfo=timezone.utc)
        by_bucket.setdefault(b, {"block": 0, "allow": 0})
        by_bucket[b][r.decision] = r.count

    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    points: list[TimeseriesPoint] = []
    for i in range(hours - 1, -1, -1):
        b = now - timedelta(hours=i)
        counts = by_bucket.get(b, {"block": 0, "allow": 0})
        points.append(
            TimeseriesPoint(
                bucket=b,
                total=counts["block"] + counts["allow"],
                blocked=counts["block"],
                allowed=counts["allow"],
            )
        )
    return points


@router.get("/analytics/by-group", response_model=list[GroupBreakdown])
def analytics_by_group(db: Session = Depends(get_db)) -> list[GroupBreakdown]:
    rows = db.execute(
        select(
            models.QueryEvent.group_id,
            models.Group.name.label("group_name"),
            models.Tenant.name.label("tenant_name"),
            models.QueryEvent.decision,
            func.count().label("count"),
        )
        .select_from(models.QueryEvent)
        .join(models.Group, models.Group.id == models.QueryEvent.group_id)
        .join(models.Tenant, models.Tenant.id == models.Group.tenant_id)
        .group_by(models.QueryEvent.group_id, models.Group.name, models.Tenant.name, models.QueryEvent.decision)
    ).all()

    by_group: dict[str, dict] = {}
    for r in rows:
        g = by_group.setdefault(
            r.group_id,
            {"group_name": r.group_name, "tenant_name": r.tenant_name, "block": 0, "allow": 0},
        )
        g[r.decision] = r.count

    return [
        GroupBreakdown(
            group_id=group_id,
            group_name=g["group_name"],
            tenant_name=g["tenant_name"],
            total=g["block"] + g["allow"],
            blocked=g["block"],
            block_ratio=(g["block"] / (g["block"] + g["allow"])) if (g["block"] + g["allow"]) else 0.0,
        )
        for group_id, g in by_group.items()
    ]
