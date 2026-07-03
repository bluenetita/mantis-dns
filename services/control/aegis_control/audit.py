"""Append-only audit log helper.

No auth/OIDC exists yet (design.md §9, sprint-plan.md Sprint 8 backend item),
so `actor` is always "unauthenticated" for now — wire this to the
authenticated principal once that lands. Logging now rather than waiting
means the audit trail has history from day one instead of a gap before
auth ships.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from aegis_control.db.models import AuditLog


def write_audit_log(
    db: Session,
    action: str,
    resource_type: str,
    resource_id: str,
    detail: str = "",
    actor: str = "unauthenticated",
    tenant_id: str | None = None,
) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=detail,
            tenant_id=tenant_id,
        )
    )
