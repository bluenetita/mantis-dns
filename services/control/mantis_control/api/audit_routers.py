from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import desc
from sqlalchemy.orm import Session

from mantis_control.auth import require_role, user_tenant_filter
from mantis_control.db import models
from mantis_control.db.session import get_db

router = APIRouter()


class AuditLogEntry(BaseModel):
    id: str
    occurred_at: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str
    detail: str
    tenant_id: str | None = None

    class Config:
        from_attributes = True


@router.get("/audit-log", response_model=list[AuditLogEntry])
def list_audit_log(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    resource_type: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> list[models.AuditLog]:
    scope = user_tenant_filter(user)
    query = db.query(models.AuditLog)
    if resource_type:
        query = query.filter(models.AuditLog.resource_type == resource_type)
    if scope is not None:
        # Tenant-scoped: only entries for their own tenant. Global/system
        # entries (tenant_id IS NULL — feed/upstream-resolver management,
        # unscoped pushes) are admin-only.
        query = query.filter(models.AuditLog.tenant_id == scope)
    return list(query.order_by(desc(models.AuditLog.occurred_at)).offset(offset).limit(limit).all())
