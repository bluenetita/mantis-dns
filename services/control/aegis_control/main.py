"""Aegis-DNS control plane API entrypoint."""

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis_control.api.audit_routers import router as audit_router
from aegis_control.api.auth_routers import router as auth_router
from aegis_control.api.client_routers import router as client_router
from aegis_control.api.zone_routers import router as zone_router
from aegis_control.api.upstream_routers import router as upstream_router
from aegis_control.api.dhcp_routers import router as dhcp_router
from aegis_control.api.dhcp_internal_routers import router as dhcp_internal_router
from aegis_control.api.dhcp6_routers import router as dhcp6_router
from aegis_control.api.feed_routers import router as feed_router
from aegis_control.api.routers import router as api_router
from aegis_control.api.siem_routers import router as siem_router
from aegis_control.api.siem_webhook_routers import router as siem_webhook_router
from aegis_control.api.telemetry_routers import router as telemetry_router
from aegis_control.auth import hash_password
from sqlalchemy import text

from aegis_control.db.models import Base, Feed, User
from aegis_control.db.session import SessionLocal, engine
from aegis_control.feeds.seed import seed_catalog
from aegis_control.scheduler import schedule_feed, scheduler
from aegis_control.siem_delivery import run_webhook_delivery_cycle
from aegis_control.dhcp.lease_sync import sync_dhcp_leases

app = FastAPI(title="Aegis-DNS Control Plane", version="0.1.0")

_JWT_DEV_SECRET = "dev-insecure-secret-change-me"
_WEBHOOK_DEV_KEY_MATERIAL = "dev-insecure-webhook-key-change-me"
_INTERNAL_TOKEN_DEV_DEFAULT = "dev-insecure-internal-token"


def _check_production_secrets() -> None:
    """Refuse to start when AEGIS_ENV=production but dev-default secrets are in use."""
    if os.environ.get("AEGIS_ENV", "").lower() != "production":
        return
    errors: list[str] = []
    jwt_secret = os.environ.get("AEGIS_JWT_SECRET", _JWT_DEV_SECRET)
    if jwt_secret == _JWT_DEV_SECRET:
        errors.append("AEGIS_JWT_SECRET is the insecure dev default — set a strong random value")
    elif len(jwt_secret) < 32:
        errors.append("AEGIS_JWT_SECRET is too short — minimum 32 characters required")
    if not os.environ.get("AEGIS_WEBHOOK_SECRET_KEY"):
        errors.append("AEGIS_WEBHOOK_SECRET_KEY is not set")
    internal_token = os.environ.get("AEGIS_INTERNAL_TOKEN", _INTERNAL_TOKEN_DEV_DEFAULT)
    if internal_token == _INTERNAL_TOKEN_DEV_DEFAULT:
        errors.append("AEGIS_INTERNAL_TOKEN is the insecure dev default — set a strong random value")
    if not os.environ.get("AEGIS_SERVICE_TOKEN"):
        errors.append("AEGIS_SERVICE_TOKEN is not set — filter-node M2M endpoints would be unauthenticated")
    admin_password = os.environ.get("ADMIN_PASSWORD", "change-me-now")
    if admin_password == "change-me-now":
        errors.append("ADMIN_PASSWORD is the insecure dev default — set it before first boot")
    if errors:
        raise RuntimeError(
            "Refusing to start: AEGIS_ENV=production but insecure secrets detected: "
            + "; ".join(errors)
        )

# Dev default: UI runs on a different origin/port (Vite on :5173, API on
# :8000). Tighten to specific origins before any non-dev deployment.
_cors_origins = os.environ.get("CORS_ALLOW_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
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


@app.on_event("startup")
def on_startup() -> None:
    _check_production_secrets()
    # create_all is fine for dev. Replace with Alembic migrations before Sprint 7.
    Base.metadata.create_all(bind=engine)
    # Additive column migrations: safe to run on every startup (IF NOT EXISTS).
    with engine.connect() as _conn:
        _conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36)"
        ))
        # Sprint 20: additive columns on existing DHCP tables.
        for stmt in (
            "ALTER TABLE dhcp_scopes ADD COLUMN IF NOT EXISTS pxe_next_server VARCHAR(45)",
            "ALTER TABLE dhcp_scopes ADD COLUMN IF NOT EXISTS pxe_boot_filename VARCHAR(255)",
            "ALTER TABLE dhcp_relay_configs ADD COLUMN IF NOT EXISTS circuit_id_hex VARCHAR(255)",
            "ALTER TABLE dhcp_relay_configs ADD COLUMN IF NOT EXISTS remote_id_hex VARCHAR(255)",
        ):
            _conn.execute(text(stmt))
        _conn.commit()

    db = SessionLocal()
    try:
        inserted = seed_catalog(db)
        if inserted:
            logging.getLogger(__name__).info(f"seeded {inserted} feeds from catalog.json")

        for feed in db.query(Feed).filter(Feed.enabled.is_(True)).all():
            schedule_feed(feed)

        if db.query(User).count() == 0:
            admin_email = os.environ.get("ADMIN_EMAIL", "admin@aegis.local")
            admin_password = os.environ.get("ADMIN_PASSWORD", "change-me-now")
            db.add(User(email=admin_email, password_hash=hash_password(admin_password), role="admin"))
            db.commit()
            logging.getLogger(__name__).warning(
                f"seeded initial admin user {admin_email!r} — change ADMIN_PASSWORD / log in and rotate it"
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

    lease_sync_interval = int(os.environ.get("DHCP_LEASE_SYNC_INTERVAL_S", "60"))
    scheduler.add_job(
        _lease_sync_job,
        "interval",
        seconds=lease_sync_interval,
        id="dhcp-lease-sync",
        replace_existing=True,
    )

    scheduler.start()


@app.on_event("shutdown")
def on_shutdown() -> None:
    scheduler.shutdown(wait=False)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
