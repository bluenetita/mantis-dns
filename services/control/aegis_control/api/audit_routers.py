from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import desc
from sqlalchemy.orm import Session

from aegis_control.auth import require_role
from aegis_control.db import models
from aegis_control.db.session import get_db

router = APIRouter()


class AuditLogEntry(BaseModel):
    id: str
    occurred_at: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str
    detail: str

    class Config:
        from_attributes = True


@router.get("/audit-log", response_model=list[AuditLogEntry])
def list_audit_log(
    limit: int = 100,
    resource_type: str | None = None,
    db: Session = Depends(get_db),
    _user: models.User = Depends(require_role("admin", "operator")),
) -> list[models.AuditLog]:
    query = db.query(models.AuditLog)
    if resource_type:
        query = query.filter(models.AuditLog.resource_type == resource_type)
    return list(query.order_by(desc(models.AuditLog.occurred_at)).limit(min(limit, 1000)).all())
