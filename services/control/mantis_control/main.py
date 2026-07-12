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

"""Mantis-DNS control plane API entrypoint."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from mantis_control.api.audit_routers import router as audit_router
from mantis_control.api.auth_routers import router as auth_router
from mantis_control.api.client_routers import router as client_router
from mantis_control.api.zone_routers import router as zone_router
from mantis_control.api.upstream_routers import router as upstream_router
from mantis_control.api.dhcp_routers import router as dhcp_router
from mantis_control.api.dhcp_internal_routers import router as dhcp_internal_router
from mantis_control.api.dhcp6_routers import router as dhcp6_router
from mantis_control.api.feed_routers import router as feed_router
from mantis_control.api.routers import router as api_router
from mantis_control.api.siem_routers import router as siem_router
from mantis_control.api.siem_webhook_routers import router as siem_webhook_router
from mantis_control.api.telemetry_routers import router as telemetry_router
from mantis_control.auth import CsrfMiddleware, hash_password
from mantis_control.compiler.keys import load_or_create_signing_key
from mantis_control.config import settings

from mantis_control.db.models import Feed, User
from mantis_control.db.session import SessionLocal
from mantis_control.feeds.seed import seed_catalog
from mantis_control.scheduler import kick_feed_now, mark_shutting_down, schedule_feed, scheduler
from mantis_control.siem_delivery import run_webhook_delivery_cycle
from mantis_control.dhcp.lease_sync import sync_dhcp_leases


_SERVICE_ROOT = Path(__file__).resolve().parent.parent  # services/control/
_ALEMBIC_INI = _SERVICE_ROOT / "alembic.ini"


def _run_migrations() -> None:
    """Applies all pending Alembic migrations (migrations/versions/).

    This docker-compose deployment runs exactly one `control` replica, so
    it's safe to migrate at process startup; a multi-replica deployment
    should instead run `alembic upgrade head` as a separate pre-start step
    to avoid concurrent instances racing on the same migration.
    """
    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_SERVICE_ROOT / "migrations"))
    alembic_command.upgrade(cfg, "head")


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    _run_migrations()

    # Load (or create) the signing key sequentially, before the app accepts
    # any requests: a corrupt/unreadable key file must fail boot loudly
    # rather than surface as 500s on /public-key and compile later, and
    # doing it here — instead of lazily on first request — avoids two
    # concurrent first requests racing to generate and persist different keys.
    load_or_create_signing_key()

    db = SessionLocal()
    try:
        inserted = seed_catalog(db)
        if inserted:
            logging.getLogger(__name__).info(f"seeded {inserted} feeds from catalog.json")

        enabled_feed_ids = []
        for feed in db.query(Feed).filter(Feed.enabled.is_(True)).all():
            schedule_feed(feed)
            enabled_feed_ids.append(feed.id)

        if db.query(User).count() == 0:
            db.add(User(
                email=settings.ADMIN_EMAIL,
                password_hash=hash_password(settings.ADMIN_PASSWORD),
                role="admin",
            ))
            db.commit()
            logging.getLogger(__name__).warning(
                f"seeded initial admin user {settings.ADMIN_EMAIL!r} — "
                "change ADMIN_PASSWORD / log in and rotate it"
            )
    finally:
        db.close()

    scheduler.add_job(
        run_webhook_delivery_cycle,
        "interval",
        seconds=10,
        id="siem-webhook-delivery",
        replace_existing=True,
    )

    def _lease_sync_job() -> None:
        db = SessionLocal()
        try:
            n = sync_dhcp_leases(db)
            if n:
                logging.getLogger(__name__).debug("dhcp lease sync: %d entries updated", n)
        finally:
            db.close()

    scheduler.add_job(
        _lease_sync_job,
        "interval",
        seconds=settings.DHCP_LEASE_SYNC_INTERVAL_S,
        id="dhcp-lease-sync",
        replace_existing=True,
    )

    scheduler.start()

    # Kick every enabled feed's ingest immediately, in addition to its
    # recurring interval job: an interval job's first tick is up to a full
    # `interval_seconds` (default 24h) away, so without this a never-ingested
    # feed contributes nothing to compiled bundles for up to a day after
    # every control-plane restart (see _category_bloom in
    # compiler/build_policy_bundle.py). Called after scheduler.start() so
    # each job's `date` trigger fires immediately with no misfire risk.
    for feed_id in enabled_feed_ids:
        kick_feed_now(feed_id)

    try:
        yield
    finally:
        mark_shutting_down()
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="Mantis-DNS Control Plane",
    version="0.1.0",
    lifespan=_lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)

# CSRF check runs inside the CORS layer so its 403 responses still get CORS
# headers attached (added first == innermost; see Starlette middleware order).
app.add_middleware(CsrfMiddleware)

# Dev default: UI runs on a different origin/port (Vite on :5173, API on
# :8000). Tighten to specific origins before any non-dev deployment.
# allow_credentials is required for the httpOnly session cookie to be sent
# on cross-origin fetches; it's only valid with an explicit origin list
# (never "*"), which CORS_ALLOW_ORIGINS already enforces.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Mantis-CSRF-Token"],
)

app.include_router(api_router, prefix="/api/v1")
app.include_router(feed_router, prefix="/api/v1")
app.include_router(telemetry_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(siem_router, prefix="/api/v1")
app.include_router(siem_webhook_router, prefix="/api/v1")
app.include_router(client_router, prefix="/api/v1")
app.include_router(zone_router, prefix="/api/v1")
app.include_router(upstream_router, prefix="/api/v1")
app.include_router(dhcp_router, prefix="/api/v1")
app.include_router(dhcp_internal_router, prefix="/api/v1")
app.include_router(dhcp6_router, prefix="/api/v1")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
