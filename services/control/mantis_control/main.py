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
from mantis_control.config import (
    ADMIN_PASSWORD_DEV_DEFAULT,
    INTERNAL_TOKEN_DEV_DEFAULT,
    JWT_DEV_SECRET,
    settings,
)

from mantis_control.db.models import Feed, User
from mantis_control.db.session import SessionLocal
from mantis_control.feeds.seed import seed_catalog
from mantis_control.scheduler import schedule_feed, scheduler
from mantis_control.siem_delivery import run_webhook_delivery_cycle
from mantis_control.dhcp.lease_sync import sync_dhcp_leases

def _check_production_secrets() -> None:
    """Refuse to start when MANTIS_ENV=production but dev-default secrets are in use."""
    if not settings.is_production:
        return
    errors: list[str] = []
    if settings.MANTIS_JWT_SECRET == JWT_DEV_SECRET:
        errors.append("MANTIS_JWT_SECRET is the insecure dev default — set a strong random value")
    elif len(settings.MANTIS_JWT_SECRET) < 32:
        errors.append("MANTIS_JWT_SECRET is too short — minimum 32 characters required")
    if not settings.MANTIS_WEBHOOK_SECRET_KEY:
        errors.append("MANTIS_WEBHOOK_SECRET_KEY is not set")
    if settings.MANTIS_INTERNAL_TOKEN == INTERNAL_TOKEN_DEV_DEFAULT:
        errors.append("MANTIS_INTERNAL_TOKEN is the insecure dev default — set a strong random value")
    if not settings.MANTIS_SERVICE_TOKEN:
        errors.append("MANTIS_SERVICE_TOKEN is not set — filter-node M2M endpoints would be unauthenticated")
    if settings.ADMIN_PASSWORD == ADMIN_PASSWORD_DEV_DEFAULT:
        errors.append("ADMIN_PASSWORD is the insecure dev default — set it before first boot")
    if errors:
        raise RuntimeError(
            "Refusing to start: MANTIS_ENV=production but insecure secrets detected: "
            + "; ".join(errors)
        )

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
    _check_production_secrets()
    _run_migrations()

    db = SessionLocal()
    try:
        inserted = seed_catalog(db)
        if inserted:
            logging.getLogger(__name__).info(f"seeded {inserted} feeds from catalog.json")

        for feed in db.query(Feed).filter(Feed.enabled.is_(True)).all():
            schedule_feed(feed)

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
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)


app = FastAPI(title="Mantis-DNS Control Plane", version="0.1.0", lifespan=_lifespan)

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
