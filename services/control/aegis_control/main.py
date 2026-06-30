"""Aegis-DNS control plane API entrypoint."""

import os

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis_control.api.feed_routers import router as feed_router
from aegis_control.api.routers import router as api_router
from aegis_control.api.telemetry_routers import router as telemetry_router
from aegis_control.config import FEED_STORAGE_DIR
from aegis_control.db.models import Base, Feed
from aegis_control.db.session import SessionLocal, engine
from aegis_control.feeds.ingest import fetch_and_ingest

app = FastAPI(title="Aegis-DNS Control Plane", version="0.1.0")

# Dev default: UI runs on a different origin/port (Vite on :5173, API on
# :8000). Tighten to specific origins before any non-dev deployment.
_cors_origins = os.environ.get("CORS_ALLOW_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")
app.include_router(feed_router, prefix="/api/v1")
app.include_router(telemetry_router, prefix="/api/v1")

scheduler = AsyncIOScheduler()


async def _scheduled_ingest(feed_id: str) -> None:
    db = SessionLocal()
    try:
        feed = db.get(Feed, feed_id)
        if feed is None or not feed.enabled:
            return
        async with httpx.AsyncClient() as client:
            result = await fetch_and_ingest(feed, FEED_STORAGE_DIR, client)
        if result.status == "updated":
            db.commit()
    finally:
        db.close()


@app.on_event("startup")
def on_startup() -> None:
    # Sprint 1: create-all is fine for dev. Replace with Alembic migrations before Sprint 7.
    Base.metadata.create_all(bind=engine)

    # Reads the feed list once at startup; feeds added afterward need a
    # restart to get scheduled. Fine for Sprint 5 — revisit if/when feeds
    # become a frequently-edited resource.
    db = SessionLocal()
    try:
        for feed in db.query(Feed).filter(Feed.enabled.is_(True)).all():
            scheduler.add_job(
                _scheduled_ingest,
                "interval",
                seconds=feed.interval_seconds,
                args=[feed.id],
                id=f"ingest-{feed.id}",
                replace_existing=True,
            )
    finally:
        db.close()
    scheduler.start()


@app.on_event("shutdown")
def on_shutdown() -> None:
    scheduler.shutdown(wait=False)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
