from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sqlalchemy.dialects.postgresql import insert as pg_insert

from aegis_control.auth import get_current_user
from aegis_control.db import models
from aegis_control.db.session import get_db

router = APIRouter()


class QueryEventIn(BaseModel):
    group_id: str
    qname: str
    decision: str
    # Sprint 14 (design.md §20) enrichment — all optional so older filter
    # node builds can still post the pre-enrichment shape without breaking.
    client_ip: str | None = None
    qtype: str | None = None
    matched_rule: str | None = None
    matched_category: str | None = None
    matched_feed_id: str | None = None
    response_code: str | None = None
    cache_hit: bool | None = None
    latency_us: int | None = None


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
    design — the hot DNS path never blocks on this succeeding. Unauthenticated
    like /routing-table and /public-key: this is filter-node-to-control-plane
    traffic, not a user-facing endpoint."""
    group_ids = {event.group_id for event in payload.events}
    tenant_by_group: dict[str, str] = dict(
        db.execute(
            select(models.Group.id, models.Group.tenant_id).where(models.Group.id.in_(group_ids))
        ).all()
    ) if group_ids else {}

    for event in payload.events:
        db.add(
            models.QueryEvent(
                group_id=event.group_id,
                tenant_id=tenant_by_group.get(event.group_id),
                qname=event.qname,
                decision=event.decision,
                client_ip=event.client_ip,
                qtype=event.qtype,
                matched_rule=event.matched_rule,
                matched_category=event.matched_category,
                matched_feed_id=event.matched_feed_id,
                response_code=event.response_code,
                cache_hit=event.cache_hit,
                latency_us=event.latency_us,
            )
        )
    # Sprint 16 (design.md §20.6) auto-discovery: touch/create a stub
    # ClientEntry for every unique (tenant_id, ip) seen in this batch, so
    # unregistered clients surface in the UI without the DNS hot path ever
    # having to know about the registry.
    seen: dict[tuple[str, str], str] = {}
    for event in payload.events:
        tenant_id = tenant_by_group.get(event.group_id)
        if event.client_ip and tenant_id:
            seen[(tenant_id, event.client_ip)] = event.group_id
    now = datetime.now(timezone.utc)
    for (tenant_id, ip), group_id in seen.items():
        stmt = (
            pg_insert(models.ClientEntry)
            .values(tenant_id=tenant_id, ip=ip, group_id=group_id, last_seen=now)
            .on_conflict_do_update(
                index_elements=["tenant_id", "ip"],
                set_={"last_seen": now, "group_id": group_id},
            )
        )
        db.execute(stmt)

    db.commit()
    return {"accepted": len(payload.events)}


@router.get("/groups/{group_id}/top-domains", response_model=list[TopDomain])
def top_domains(
    group_id: str, limit: int = 20, db: Session = Depends(get_db), _user: models.User = Depends(get_current_user)
) -> list[TopDomain]:
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
def analytics_summary(db: Session = Depends(get_db), _user: models.User = Depends(get_current_user)) -> AnalyticsSummary:
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
def analytics_timeseries(
    hours: int = 24, db: Session = Depends(get_db), _user: models.User = Depends(get_current_user)
) -> list[TimeseriesPoint]:
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
def analytics_by_group(db: Session = Depends(get_db), _user: models.User = Depends(get_current_user)) -> list[GroupBreakdown]:
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
