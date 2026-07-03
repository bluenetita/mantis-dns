from __future__ import annotations

from datetime import datetime, timedelta, timezone

from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from sqlalchemy.dialects.postgresql import insert as pg_insert

from aegis_control.auth import get_current_user, get_group_or_403, require_service_token, user_tenant_filter
from aegis_control.db import models
from aegis_control.db.session import get_db

router = APIRouter()


class QueryEventIn(BaseModel):
    group_id: str = Field(max_length=64)
    qname: str = Field(max_length=255)
    decision: str = Field(max_length=16)
    # Sprint 14 (design.md §20) enrichment — all optional so older filter
    # node builds can still post the pre-enrichment shape without breaking.
    client_ip: str | None = Field(None, max_length=45)   # max IPv6 length
    qtype: str | None = Field(None, max_length=16)
    matched_rule: str | None = Field(None, max_length=64)
    matched_category: str | None = Field(None, max_length=64)
    matched_feed_id: str | None = Field(None, max_length=64)
    response_code: str | None = Field(None, max_length=16)
    cache_hit: bool | None = None
    latency_us: int | None = None


class QueryEventBatch(BaseModel):
    events: list[QueryEventIn] = Field(default_factory=list, max_length=10_000)


class TopDomain(BaseModel):
    qname: str
    decision: str
    count: int


class AnalyticsSummary(BaseModel):
    total_queries: int
    blocked_queries: int
    allowed_queries: int
    block_ratio: float
    cache_hit_ratio: float = 0.0
    unique_clients: int = 0
    tenant_count: int
    group_count: int
    feed_count: int
    top_blocked_domains: list[TopDomain]


class TopClient(BaseModel):
    client_ip: str
    hostname: str | None
    owner: str | None
    group_name: str | None
    total: int
    blocked: int
    block_ratio: float


class CategoryBreakdown(BaseModel):
    category: str
    count: int
    pct: float


class RecentEvent(BaseModel):
    id: str
    occurred_at: datetime
    client_ip: str | None
    client_name: str | None
    qname: str
    decision: str
    matched_category: str | None
    matched_feed_id: str | None
    group_name: str | None
    latency_us: int | None


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
def ingest_query_events(
    payload: QueryEventBatch,
    db: Session = Depends(get_db),
    _: None = Depends(require_service_token),
) -> dict[str, int]:
    """Fire-and-forget sink for filter-node query telemetry. Best-effort by
    design — the hot DNS path never blocks on this succeeding. Guarded by
    AEGIS_SERVICE_TOKEN like /routing-table and /public-key: this is
    filter-node-to-control-plane traffic, not a user-facing endpoint."""
    group_ids = {event.group_id for event in payload.events}
    tenant_by_group: dict[str, str] = (
        {str(r[0]): str(r[1]) for r in db.execute(
            select(models.Group.id, models.Group.tenant_id).where(models.Group.id.in_(group_ids))
        ).all()}
        if group_ids else {}
    )

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
    group_id: str, limit: int = Query(20, ge=1, le=1000), db: Session = Depends(get_db), user: models.User = Depends(get_current_user)
) -> list[TopDomain]:
    get_group_or_403(db, group_id, user)
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
    return [TopDomain(qname=r.qname, decision=r.decision, count=r.count) for r in rows]  # type: ignore[arg-type]


@router.get("/analytics/summary", response_model=AnalyticsSummary)
def analytics_summary(
    hours: int | None = Query(None, ge=1, le=8760),
    db: Session = Depends(get_db),
    _user: models.User = Depends(get_current_user),
) -> AnalyticsSummary:
    """Org-wide rollup. Optional `hours` window (None = all time)."""
    scope = user_tenant_filter(_user)
    base_filters: list[Any] = []
    if hours:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        base_filters.append(models.QueryEvent.occurred_at >= since)
    if scope is not None:
        base_filters.append(models.QueryEvent.tenant_id == scope)

    def _count(*extra_filters: Any) -> int:
        q = db.query(func.count(models.QueryEvent.id))
        for f in (*base_filters, *extra_filters):
            q = q.filter(f)
        return int(q.scalar() or 0)

    total = _count()
    blocked = _count(models.QueryEvent.decision == "block")
    allowed = total - blocked

    total_with_cache = _count(models.QueryEvent.cache_hit.isnot(None))
    cache_hits = _count(models.QueryEvent.cache_hit.is_(True))
    cache_hit_ratio = (cache_hits / total_with_cache) if total_with_cache else 0.0

    unique_clients = (
        db.query(func.count(func.distinct(models.QueryEvent.client_ip)))
        .filter(models.QueryEvent.client_ip.isnot(None), *base_filters)
        .scalar()
        or 0
    )

    top_q = (
        select(models.QueryEvent.qname, models.QueryEvent.decision, func.count().label("count"))
        .where(models.QueryEvent.decision == "block", *base_filters)
        .group_by(models.QueryEvent.qname, models.QueryEvent.decision)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_blocked_rows = db.execute(top_q).all()

    if scope is not None:
        tenant_count = 1 if db.get(models.Tenant, scope) else 0
        group_count = db.query(func.count(models.Group.id)).filter(models.Group.tenant_id == scope).scalar() or 0
    else:
        tenant_count = db.query(func.count(models.Tenant.id)).scalar() or 0
        group_count = db.query(func.count(models.Group.id)).scalar() or 0

    return AnalyticsSummary(
        total_queries=total,
        blocked_queries=blocked,
        allowed_queries=allowed,
        block_ratio=(blocked / total) if total else 0.0,
        cache_hit_ratio=round(cache_hit_ratio, 4),
        unique_clients=unique_clients,
        tenant_count=tenant_count,
        group_count=group_count,
        feed_count=db.query(func.count(models.Feed.id)).scalar() or 0,
        top_blocked_domains=[
            TopDomain(qname=r.qname, decision=r.decision, count=r.count) for r in top_blocked_rows  # type: ignore[arg-type]
        ],
    )


@router.get("/analytics/timeseries", response_model=list[TimeseriesPoint])
def analytics_timeseries(
    hours: int = Query(24, ge=1, le=8760), db: Session = Depends(get_db), _user: models.User = Depends(get_current_user)
) -> list[TimeseriesPoint]:
    """Hourly query volume for the last `hours` hours, org-wide. Buckets with
    zero queries are included (not just present-in-DB rows) so charts don't
    show misleading gaps."""
    scope = user_tenant_filter(_user)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    bucket = func.date_trunc("hour", models.QueryEvent.occurred_at)

    ts_filters: list[Any] = [models.QueryEvent.occurred_at >= since]
    if scope is not None:
        ts_filters.append(models.QueryEvent.tenant_id == scope)

    raw_rows = db.execute(
        select(bucket.label("bucket"), models.QueryEvent.decision, func.count().label("count"))
        .where(*ts_filters)
        .group_by(bucket, models.QueryEvent.decision)
    ).all()

    by_bucket: dict[datetime, dict[str, int]] = {}
    for r in raw_rows:
        b = r.bucket if r.bucket.tzinfo else r.bucket.replace(tzinfo=timezone.utc)
        by_bucket.setdefault(b, {"block": 0, "allow": 0})
        by_bucket[b][r.decision] = r.count  # type: ignore[assignment]

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
def analytics_by_group(
    hours: int | None = Query(None, ge=1, le=8760),
    db: Session = Depends(get_db),
    _user: models.User = Depends(get_current_user),
) -> list[GroupBreakdown]:
    scope = user_tenant_filter(_user)
    bg_filters: list[Any] = []
    if hours:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        bg_filters.append(models.QueryEvent.occurred_at >= since)
    if scope is not None:
        bg_filters.append(models.QueryEvent.tenant_id == scope)
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
        .where(*bg_filters)
        .group_by(models.QueryEvent.group_id, models.Group.name, models.Tenant.name, models.QueryEvent.decision)
    ).all()

    by_group: dict[str, dict[str, Any]] = {}
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


@router.get("/analytics/top-clients", response_model=list[TopClient])
def top_clients_analytics(
    hours: int = Query(24, ge=1, le=8760),
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    _user: models.User = Depends(get_current_user),
) -> list[TopClient]:
    scope = user_tenant_filter(_user)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    tc_filters: list[Any] = [models.QueryEvent.client_ip.isnot(None), models.QueryEvent.occurred_at >= since]
    if scope is not None:
        tc_filters.append(models.QueryEvent.tenant_id == scope)
    rows = db.execute(
        select(
            models.QueryEvent.client_ip,
            models.QueryEvent.tenant_id,
            models.Group.name.label("group_name"),
            func.count().label("total"),
            func.sum(case((models.QueryEvent.decision == "block", 1), else_=0)).label("blocked"),
        )
        .select_from(models.QueryEvent)
        .outerjoin(models.Group, models.Group.id == models.QueryEvent.group_id)
        .where(*tc_filters)
        .group_by(models.QueryEvent.client_ip, models.QueryEvent.tenant_id, models.Group.name)
        .order_by(func.count().desc())
        .limit(limit)
    ).all()

    if not rows:
        return []

    tenant_ids = {r.tenant_id for r in rows if r.tenant_id}
    ips = {r.client_ip for r in rows}
    clients: dict[tuple[str, str], models.ClientEntry] = {}
    if tenant_ids and ips:
        for entry in (
            db.query(models.ClientEntry)
            .filter(models.ClientEntry.tenant_id.in_(tenant_ids), models.ClientEntry.ip.in_(ips))
            .all()
        ):
            clients[(entry.tenant_id, entry.ip)] = entry

    result = []
    for r in rows:
        c: models.ClientEntry | None = clients.get((r.tenant_id, r.client_ip)) if r.tenant_id else None
        total = r.total or 0
        blocked = r.blocked or 0
        result.append(TopClient(
            client_ip=r.client_ip,
            hostname=c.hostname if c else None,
            owner=c.owner if c else None,
            group_name=r.group_name,
            total=total,
            blocked=blocked,
            block_ratio=round(blocked / total, 4) if total else 0.0,
        ))
    return result


@router.get("/analytics/top-categories", response_model=list[CategoryBreakdown])
def top_categories_analytics(
    hours: int = Query(24, ge=1, le=8760),
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    _user: models.User = Depends(get_current_user),
) -> list[CategoryBreakdown]:
    scope = user_tenant_filter(_user)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    cat_filters: list[Any] = [
        models.QueryEvent.decision == "block",
        models.QueryEvent.matched_category.isnot(None),
        models.QueryEvent.occurred_at >= since,
    ]
    if scope is not None:
        cat_filters.append(models.QueryEvent.tenant_id == scope)
    rows = db.execute(
        select(
            models.QueryEvent.matched_category,
            func.count().label("count"),
        )
        .where(*cat_filters)
        .group_by(models.QueryEvent.matched_category)
        .order_by(func.count().desc())
        .limit(limit)
    ).all()
    total = sum(r.count for r in rows)  # type: ignore[misc]
    return [
        CategoryBreakdown(
            category=r.matched_category,
            count=r.count,  # type: ignore[arg-type]
            pct=round((r.count / total) * 100, 1) if total else 0.0,  # type: ignore[operator]
        )
        for r in rows
    ]


@router.get("/analytics/recent-events", response_model=list[RecentEvent])
def recent_events_analytics(
    limit: int = Query(25, ge=1, le=100),
    decision: Literal["allow", "block"] | None = None,
    db: Session = Depends(get_db),
    _user: models.User = Depends(get_current_user),
) -> list[RecentEvent]:
    scope = user_tenant_filter(_user)
    q = select(models.QueryEvent)
    if decision:
        q = q.where(models.QueryEvent.decision == decision)
    if scope is not None:
        q = q.where(models.QueryEvent.tenant_id == scope)
    q = q.order_by(models.QueryEvent.occurred_at.desc()).limit(limit)
    qevents = list(db.execute(q).scalars().all())

    if not qevents:
        return []

    group_ids = {qe.group_id for qe in qevents}
    groups: dict[str, str] = {
        g.id: g.name
        for g in db.query(models.Group).filter(models.Group.id.in_(group_ids)).all()
    }

    pairs = {(qe.tenant_id, qe.client_ip) for qe in qevents if qe.tenant_id and qe.client_ip}
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

    result = []
    for qe in qevents:
        c: models.ClientEntry | None = clients.get((qe.tenant_id, qe.client_ip)) if qe.tenant_id and qe.client_ip else None
        result.append(RecentEvent(
            id=qe.id,
            occurred_at=qe.occurred_at,
            client_ip=qe.client_ip,
            client_name=c.hostname if c else None,
            qname=qe.qname,
            decision=qe.decision,
            matched_category=qe.matched_category,
            matched_feed_id=qe.matched_feed_id,
            group_name=groups.get(qe.group_id),
            latency_us=qe.latency_us,
        ))
    return result
