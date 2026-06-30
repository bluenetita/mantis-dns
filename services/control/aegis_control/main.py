"""Aegis-DNS control plane API entrypoint (Sprint 1 skeleton)."""

from fastapi import FastAPI

app = FastAPI(title="Aegis-DNS Control Plane", version="0.1.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


# TODO(sprint 1): tenant/group/policy CRUD routers
# TODO(sprint 2): policy compiler -> bundle emission
# TODO(sprint 4): feed registry + ingestion scheduler
