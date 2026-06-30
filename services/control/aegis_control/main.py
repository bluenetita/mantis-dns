"""Aegis-DNS control plane API entrypoint."""

from fastapi import FastAPI

from aegis_control.api.routers import router as api_router
from aegis_control.db.models import Base
from aegis_control.db.session import engine

app = FastAPI(title="Aegis-DNS Control Plane", version="0.1.0")
app.include_router(api_router, prefix="/api/v1")


@app.on_event("startup")
def on_startup() -> None:
    # Sprint 1: create-all is fine for dev. Replace with Alembic migrations before Sprint 7.
    Base.metadata.create_all(bind=engine)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


# TODO(sprint 2): policy compiler -> bundle emission wired to PUT /groups/{id}/policy
# TODO(sprint 4): feed registry + ingestion scheduler
