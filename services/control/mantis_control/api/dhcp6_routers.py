"""DHCPv6 management API (Sprint 22).

Scopes and host reservations for kea-dhcp6.  Mirrors dhcp_routers.py structure.
Every mutating operation calls try_push6() to keep kea-dhcp6 in sync.
Lease reads query Kea's lease6 table directly (shared Postgres DB).
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from mantis_control.audit import write_audit_log
from mantis_control.auth import check_tenant_access, require_role, user_tenant_filter
from mantis_control.db.models import DhcpScope6, DhcpStaticLease6
from mantis_control.db.session import get_db
from mantis_control.dhcp.kea_config6 import try_push6

router = APIRouter(prefix="/dhcp6", tags=["dhcp6"])
log = logging.getLogger(__name__)


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class Scope6Create(BaseModel):
    tenant_id: str
    name: str
    description: str | None = None
    subnet: str
    pool_start: str
    pool_end: str
    pd_prefix: str | None = None
    pd_prefix_len: int | None = Field(None, ge=1, le=128)
    dns_servers: list[str] = []
    domain_name: str | None = None
    interface: str | None = None
    preferred_lifetime_s: int = Field(3000, ge=60)
    valid_lifetime_s: int = Field(4000, ge=60)
    renew_time_s: int | None = None
    rebind_time_s: int | None = None
    ddns_enabled: bool = False
    ddns_zone_id: str | None = None
    ddns_ttl_s: int = 300
    enabled: bool = True


class Scope6Update(BaseModel):
    name: str | None = None
    description: str | None = None
    pool_start: str | None = None
    pool_end: str | None = None
    pd_prefix: str | None = None
    pd_prefix_len: int | None = Field(None, ge=1, le=128)
    dns_servers: list[str] | None = None
    domain_name: str | None = None
    interface: str | None = None
    preferred_lifetime_s: int | None = Field(None, ge=60)
    valid_lifetime_s: int | None = Field(None, ge=60)
    renew_time_s: int | None = None
    rebind_time_s: int | None = None
    ddns_enabled: bool | None = None
    ddns_zone_id: str | None = None
    ddns_ttl_s: int | None = None
    enabled: bool | None = None


class Scope6Out(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: str | None
    subnet: str
    pool_start: str
    pool_end: str
    pd_prefix: str | None
    pd_prefix_len: int | None
    dns_servers: list[str]
    domain_name: str | None
    interface: str | None
    preferred_lifetime_s: int
    valid_lifetime_s: int
    renew_time_s: int | None
    rebind_time_s: int | None
    ddns_enabled: bool
    ddns_zone_id: str | None
    ddns_ttl_s: int
    kea_subnet_id: int | None
    last_pushed_at: datetime | None
    enabled: bool
    created_at: datetime
    updated_at: datetime
    kea_push_error: str | None = None

    class Config:
        from_attributes = True


class Reservation6Create(BaseModel):
    duid: str
    ip_address: str
    hostname: str | None = None
    description: str | None = None
    enabled: bool = True


class Reservation6Update(BaseModel):
    duid: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    description: str | None = None
    enabled: bool | None = None


class Reservation6Out(BaseModel):
    id: str
    scope_id: str
    tenant_id: str
    duid: str
    ip_address: str
    hostname: str | None
    description: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime
    kea_push_error: str | None = None

    class Config:
        from_attributes = True


class Lease6Out(BaseModel):
    ip_address: str
    duid: str | None
    hostname: str
    subnet_id: int
    expire: datetime | None
    state: int
    lease_type: int  # 0=IA_NA, 2=IA_PD


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_scope6_or_404(db: Session, scope_id: str) -> DhcpScope6:
    scope = db.get(DhcpScope6, scope_id)
    if scope is None:
        raise HTTPException(404, "DHCPv6 scope not found")
    return scope


def _get_reservation6_or_404(db: Session, scope_id: str, reservation_id: str) -> DhcpStaticLease6:
    r = db.get(DhcpStaticLease6, reservation_id)
    if r is None or r.scope_id != scope_id:
        raise HTTPException(404, "DHCPv6 reservation not found")
    return r


# ── Scope endpoints ────────────────────────────────────────────────────────────

@router.get("/scopes", response_model=list[Scope6Out])
def list_scopes6(
    tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[DhcpScope6]:
    if tenant_id:
        check_tenant_access(user, tenant_id)
    q = db.query(DhcpScope6)
    tid = tenant_id or user_tenant_filter(user)
    if tid:
        q = q.filter(DhcpScope6.tenant_id == tid)
    return q.order_by(DhcpScope6.created_at).all()


@router.post("/scopes", response_model=Scope6Out, status_code=201)
async def create_scope6(
    body: Scope6Create,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> Scope6Out:
    check_tenant_access(user, body.tenant_id)
    scope = DhcpScope6(**body.model_dump())
    db.add(scope)
    db.commit()
    db.refresh(scope)
    write_audit_log(db, "dhcp6_scope.create", "dhcp_scope6", scope.id, actor=user.email, tenant_id=scope.tenant_id)
    err = await try_push6(db)
    out = Scope6Out.model_validate(scope)
    out.kea_push_error = err
    return out


@router.get("/scopes/{scope_id}", response_model=Scope6Out)
def get_scope6(
    scope_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> DhcpScope6:
    scope = _get_scope6_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    return scope


@router.patch("/scopes/{scope_id}", response_model=Scope6Out)
async def update_scope6(
    scope_id: str,
    body: Scope6Update,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> Scope6Out:
    scope = _get_scope6_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(scope, field, val)
    db.commit()
    db.refresh(scope)
    write_audit_log(db, "dhcp6_scope.update", "dhcp_scope6", scope_id, actor=user.email, tenant_id=scope.tenant_id)
    err = await try_push6(db)
    out = Scope6Out.model_validate(scope)
    out.kea_push_error = err
    return out


@router.delete("/scopes/{scope_id}", status_code=204)
async def delete_scope6(
    scope_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> None:
    scope = _get_scope6_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    db.delete(scope)
    db.commit()
    write_audit_log(db, "dhcp6_scope.delete", "dhcp_scope6", scope_id, actor=user.email, tenant_id=scope.tenant_id)
    await try_push6(db)


# ── Reservation endpoints ──────────────────────────────────────────────────────

@router.get("/scopes/{scope_id}/reservations", response_model=list[Reservation6Out])
def list_reservations6(
    scope_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[DhcpStaticLease6]:
    scope = _get_scope6_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    return (
        db.query(DhcpStaticLease6)
        .filter(DhcpStaticLease6.scope_id == scope_id)
        .order_by(DhcpStaticLease6.ip_address)
        .all()
    )


@router.post("/scopes/{scope_id}/reservations", response_model=Reservation6Out, status_code=201)
async def create_reservation6(
    scope_id: str,
    body: Reservation6Create,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> Reservation6Out:
    scope = _get_scope6_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    r = DhcpStaticLease6(scope_id=scope_id, tenant_id=scope.tenant_id, **body.model_dump())
    db.add(r)
    db.commit()
    db.refresh(r)
    write_audit_log(db, "dhcp6_reservation.create", "dhcp_static_lease6", r.id, actor=user.email, tenant_id=scope.tenant_id)
    err = await try_push6(db)
    out = Reservation6Out.model_validate(r)
    out.kea_push_error = err
    return out


@router.patch("/scopes/{scope_id}/reservations/{reservation_id}", response_model=Reservation6Out)
async def update_reservation6(
    scope_id: str,
    reservation_id: str,
    body: Reservation6Update,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> Reservation6Out:
    scope = _get_scope6_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    r = _get_reservation6_or_404(db, scope_id, reservation_id)
    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(r, field, val)
    db.commit()
    db.refresh(r)
    write_audit_log(db, "dhcp6_reservation.update", "dhcp_static_lease6", reservation_id, actor=user.email, tenant_id=scope.tenant_id)
    err = await try_push6(db)
    out = Reservation6Out.model_validate(r)
    out.kea_push_error = err
    return out


@router.delete("/scopes/{scope_id}/reservations/{reservation_id}", status_code=204)
async def delete_reservation6(
    scope_id: str,
    reservation_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> None:
    scope = _get_scope6_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    r = _get_reservation6_or_404(db, scope_id, reservation_id)
    db.delete(r)
    db.commit()
    write_audit_log(db, "dhcp6_reservation.delete", "dhcp_static_lease6", reservation_id, actor=user.email, tenant_id=scope.tenant_id)
    await try_push6(db)


# ── Lease read ─────────────────────────────────────────────────────────────────

@router.get("/leases", response_model=list[Lease6Out])
def list_leases6(
    scope_id: str | None = None,
    tenant_id: str | None = None,
    state: int = 0,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[Lease6Out]:
    """Read active IPv6 leases from Kea's lease6 table."""
    if tenant_id:
        check_tenant_access(user, tenant_id)
    tid = tenant_id or user_tenant_filter(user)

    q = db.query(DhcpScope6)
    if scope_id:
        q = q.filter(DhcpScope6.id == scope_id)
        scope = q.first()
        if scope:
            check_tenant_access(user, scope.tenant_id)
    elif tid:
        q = q.filter(DhcpScope6.tenant_id == tid)

    scopes = q.filter(DhcpScope6.kea_subnet_id.isnot(None)).all()
    if not scopes:
        return []

    subnet_ids = [s.kea_subnet_id for s in scopes]

    try:
        rows = db.execute(
            text("""
                SELECT
                    address                           AS ip_address,
                    encode(duid, 'hex')               AS duid,
                    COALESCE(hostname, '')             AS hostname,
                    subnet_id,
                    expire,
                    state,
                    lease_type
                FROM lease6
                WHERE subnet_id = ANY(:sids)
                  AND state = :state
                ORDER BY subnet_id, address
                LIMIT 1000
            """),
            {"sids": subnet_ids, "state": state},
        ).mappings().all()
    except Exception as exc:
        log.warning("Could not query lease6: %s", exc)
        return []

    return [Lease6Out(**dict(r)) for r in rows]


# ── Manual push ────────────────────────────────────────────────────────────────

@router.post("/push", status_code=200)
async def manual_push6(
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> dict:
    """Re-push the full Kea DHCPv6 config from DB."""
    err = await try_push6(db)
    if err:
        return {"ok": False, "error": err}
    write_audit_log(db, "dhcp6.push", "kea6", "full-config", actor=user.email)
    return {"ok": True}
