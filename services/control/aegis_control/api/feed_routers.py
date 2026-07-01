from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis_control.audit import write_audit_log
from aegis_control.auth import get_current_user, require_role
from aegis_control.config import FEED_STORAGE_DIR
from aegis_control.db import models
from aegis_control.db.session import get_db
from aegis_control.feeds.ingest import fetch_and_ingest
from aegis_control.scheduler import sync_feed_schedule, unschedule_feed

router = APIRouter()


class FeedCreate(BaseModel):
    id: str
    category_id: str
    url: str
    format: str
    interval_seconds: int = 86400
    license: str = ""
    provider: str = ""
    enabled: bool = True


class FeedUpdate(BaseModel):
    """All fields optional — PATCH semantics. Used by the UI's feed toggle
    and edit controls; takes effect immediately (reschedules the live
    APScheduler job), no restart needed."""

    category_id: str | None = None
    url: str | None = None
    format: str | None = None
    interval_seconds: int | None = None
    license: str | None = None
    provider: str | None = None
    enabled: bool | None = None


class FeedOut(BaseModel):
    id: str
    category_id: str
    url: str
    format: str
    interval_seconds: int
    license: str
    provider: str
    from_catalog: bool
    enabled: bool
    last_domain_count: int | None
    last_version: str | None

    class Config:
        from_attributes = True


class IngestOut(BaseModel):
    status: str
    domain_count: int
    reason: str


@router.post("/feeds", response_model=FeedOut, status_code=201)
def create_feed(
    payload: FeedCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> models.Feed:
    if db.get(models.Feed, payload.id) is not None:
        raise HTTPException(409, "feed with this id already exists")
    feed = models.Feed(**payload.model_dump(), from_catalog=False)
    db.add(feed)
    db.flush()
    write_audit_log(db, "feed.create", "feed", feed.id, detail=f"category_id={feed.category_id} url={feed.url}", actor=user.email)
    db.commit()
    db.refresh(feed)
    sync_feed_schedule(feed)
    return feed


@router.get("/feeds", response_model=list[FeedOut])
def list_feeds(db: Session = Depends(get_db), _user: models.User = Depends(get_current_user)) -> list[models.Feed]:
    return list(db.query(models.Feed).all())


@router.patch("/feeds/{feed_id}", response_model=FeedOut)
def update_feed(
    feed_id: str,
    payload: FeedUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> models.Feed:
    """Toggle enabled, change interval/url/etc — the UI's main feed-config
    surface. Catalog feeds can be edited/disabled here too; only their
    initial seeding is special-cased, not ongoing management."""
    feed = db.get(models.Feed, feed_id)
    if feed is None:
        raise HTTPException(404, "feed not found")

    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(feed, field, value)

    write_audit_log(db, "feed.update", "feed", feed.id, detail=str(changes), actor=user.email)
    db.commit()
    db.refresh(feed)
    sync_feed_schedule(feed)
    return feed


@router.delete("/feeds/{feed_id}", status_code=204)
def delete_feed(
    feed_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> None:
    feed = db.get(models.Feed, feed_id)
    if feed is None:
        raise HTTPException(404, "feed not found")
    unschedule_feed(feed_id)
    write_audit_log(db, "feed.delete", "feed", feed.id, detail=f"category_id={feed.category_id}", actor=user.email)
    db.delete(feed)
    db.commit()


@router.post("/feeds/{feed_id}/ingest", response_model=IngestOut)
async def ingest_feed(
    feed_id: str,
    db: Session = Depends(get_db),
    _user: models.User = Depends(require_role("admin", "operator")),
) -> IngestOut:
    feed = db.get(models.Feed, feed_id)
    if feed is None:
        raise HTTPException(404, "feed not found")

    async with httpx.AsyncClient() as client:
        result = await fetch_and_ingest(feed, FEED_STORAGE_DIR, client)

    if result.status == "updated":
        db.commit()
    else:
        db.rollback()

    return IngestOut(status=result.status, domain_count=result.domain_count, reason=result.reason)
