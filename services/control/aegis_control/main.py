"""Aegis-DNS control plane API entrypoint."""

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis_control.api.feed_routers import router as feed_router
from aegis_control.api.routers import router as api_router
from aegis_control.api.telemetry_routers import router as telemetry_router
from aegis_control.db.models import Base, Feed
from aegis_control.db.session import SessionLocal, engine
from aegis_control.feeds.seed import seed_catalog
from aegis_control.scheduler import schedule_feed, scheduler

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


@app.on_event("startup")
def on_startup() -> None:
    # Sprint 1: create-all is fine for dev. Replace with Alembic migrations before Sprint 7.
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        inserted = seed_catalog(db)
        if inserted:
            logging.getLogger(__name__).info(f"seeded {inserted} feeds from catalog.json")

        for feed in db.query(Feed).filter(Feed.enabled.is_(True)).all():
            schedule_feed(feed)
    finally:
        db.close()
    scheduler.start()


@app.on_event("shutdown")
def on_shutdown() -> None:
    scheduler.shutdown(wait=False)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
