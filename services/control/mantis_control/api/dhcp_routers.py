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

"""DHCP management API (design.md §22).

Scopes, host reservations, custom options, and relay config are managed here.
mantis-dhcp (services/dhcp, Rust) reads this same DB directly — there is no
push/sync step; a change is live as soon as it's committed.

Lease reads query the native `dhcp_leases` table (mantis-dhcp's own
allocation state), not a separate daemon's schema.
"""
from __future__ import annotations

import logging
import socket
from datetime import datetime
from ipaddress import ip_address
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from mantis_control.audit import write_audit_log
from mantis_control.auth import check_tenant_access, require_role, user_tenant_filter
from mantis_control.db.models import DhcpLease, DhcpOption, DhcpRelayConfig, DhcpScope, DhcpStaticLease
from mantis_control.db.session import get_db

router = APIRouter(prefix="/dhcp", tags=["dhcp"])
log = logging.getLogger(__name__)

# ── Pydantic schemas ───────────────────────────────────────────────────────────

class ScopeCreate(BaseModel):
    tenant_id: str
    name: str
    description: str | None = None
    subnet: str                         # CIDR, e.g. "10.8.1.0/24"
    range_start: str
    range_end: str
    router_ip: str | None = None
    dns_servers: list[str] = []
    ntp_server: str | None = None
    domain_name: str | None = None
    interface: str | None = None
    vlan_id: int | None = None
    lease_time_s: int = Field(86400, ge=60)
    max_lease_time_s: int = Field(604800, ge=60)
    renew_time_s: int | None = None
    rebind_time_s: int | None = None
    ddns_enabled: bool = False
    ddns_zone_id: str | None = None
    ddns_ttl_s: int = 300
    pxe_next_server: str | None = None
    pxe_boot_filename: str | None = None
    pxe_uefi_boot_filename: str | None = None
    enabled: bool = True


class ScopeUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    range_start: str | None = None
    range_end: str | None = None
    router_ip: str | None = None
    dns_servers: list[str] | None = None
    ntp_server: str | None = None
    domain_name: str | None = None
    interface: str | None = None
    vlan_id: int | None = None
    lease_time_s: int | None = Field(None, ge=60)
    max_lease_time_s: int | None = Field(None, ge=60)
    renew_time_s: int | None = None
    rebind_time_s: int | None = None
    ddns_enabled: bool | None = None
    ddns_zone_id: str | None = None
    ddns_ttl_s: int | None = None
    pxe_next_server: str | None = None
    pxe_boot_filename: str | None = None
    pxe_uefi_boot_filename: str | None = None
    enabled: bool | None = None


class ScopeOut(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: str | None
    subnet: str
    range_start: str
    range_end: str
    router_ip: str | None
    dns_servers: list[str]
    ntp_server: str | None
    domain_name: str | None
    interface: str | None
    vlan_id: int | None
    lease_time_s: int
    max_lease_time_s: int
    renew_time_s: int | None
    rebind_time_s: int | None
    ddns_enabled: bool
    ddns_zone_id: str | None
    ddns_ttl_s: int
    pxe_next_server: str | None
    pxe_boot_filename: str | None
    pxe_uefi_boot_filename: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReservationCreate(BaseModel):
    mac_address: str
    ip_address: str
    hostname: str | None = None
    description: str | None = None
    client_id: str | None = None
    next_server: str | None = None
    boot_filename: str | None = None
    uefi_boot_filename: str | None = None
    enabled: bool = True


class ReservationUpdate(BaseModel):
    mac_address: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    description: str | None = None
    client_id: str | None = None
    next_server: str | None = None
    boot_filename: str | None = None
    uefi_boot_filename: str | None = None
    enabled: bool | None = None


class ReservationOut(BaseModel):
    id: str
    scope_id: str
    tenant_id: str
    mac_address: str
    ip_address: str
    hostname: str | None
    description: str | None
    client_id: str | None
    next_server: str | None
    boot_filename: str | None
    uefi_boot_filename: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OptionCreate(BaseModel):
    option_code: int = Field(..., ge=1, le=254)
    option_space: str = "dhcp4"
    value: str
    always_send: bool = False


class OptionOut(BaseModel):
    id: str
    scope_id: str | None
    static_lease_id: str | None
    option_code: int
    option_space: str
    value: str
    always_send: bool

    model_config = ConfigDict(from_attributes=True)


class RelayCreate(BaseModel):
    relay_ip: str
    description: str | None = None
    circuit_id_hex: str | None = None   # Option 82 sub-option 1 (hex, e.g. "0x0102")
    remote_id_hex: str | None = None    # Option 82 sub-option 2


class RelayOut(BaseModel):
    id: str
    scope_id: str
    relay_ip: str
    description: str | None
    circuit_id_hex: str | None
    remote_id_hex: str | None

    model_config = ConfigDict(from_attributes=True)


class LeaseOut(BaseModel):
    ip_address: str
    mac_address: str
    hostname: str | None
    scope_id: str
    expires_at: datetime
    state: int   # 0=active, 1=declined, 2=expired-reclaimed

    model_config = ConfigDict(from_attributes=True)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_scope_or_404(db: Session, scope_id: str) -> DhcpScope:
    scope = db.get(DhcpScope, scope_id)
    if scope is None:
        raise HTTPException(404, "DHCP scope not found")
    return scope


def _get_reservation_or_404(db: Session, scope_id: str, reservation_id: str) -> DhcpStaticLease:
    sl = db.get(DhcpStaticLease, reservation_id)
    if sl is None or sl.scope_id != scope_id:
        raise HTTPException(404, "Reservation not found")
    return sl


# ── Scope endpoints ────────────────────────────────────────────────────────────

@router.get("/scopes", response_model=list[ScopeOut])
def list_scopes(
    tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[DhcpScope]:
    if tenant_id:
        check_tenant_access(user, tenant_id)
    q = db.query(DhcpScope)
    tid = tenant_id or user_tenant_filter(user)
    if tid:
        q = q.filter(DhcpScope.tenant_id == tid)
    return q.order_by(DhcpScope.created_at).all()


@router.post("/scopes", response_model=ScopeOut, status_code=201)
def create_scope(
    body: ScopeCreate,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> DhcpScope:
    check_tenant_access(user, body.tenant_id)
    scope = DhcpScope(**body.model_dump())
    db.add(scope)
    db.commit()
    db.refresh(scope)
    write_audit_log(db, "dhcp_scope.create", "dhcp_scope", scope.id, actor=user.email, tenant_id=scope.tenant_id)
    return scope


@router.get("/scopes/{scope_id}", response_model=ScopeOut)
def get_scope(
    scope_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> DhcpScope:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    return scope


@router.patch("/scopes/{scope_id}", response_model=ScopeOut)
def update_scope(
    scope_id: str,
    body: ScopeUpdate,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> DhcpScope:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(scope, field, val)
    db.commit()
    db.refresh(scope)
    write_audit_log(db, "dhcp_scope.update", "dhcp_scope", scope_id, actor=user.email, tenant_id=scope.tenant_id)
    return scope


@router.delete("/scopes/{scope_id}", status_code=204)
def delete_scope(
    scope_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> None:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    db.delete(scope)
    db.commit()
    write_audit_log(db, "dhcp_scope.delete", "dhcp_scope", scope_id, actor=user.email, tenant_id=scope.tenant_id)


# ── Reservation endpoints ──────────────────────────────────────────────────────

@router.get("/scopes/{scope_id}/reservations", response_model=list[ReservationOut])
def list_reservations(
    scope_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[DhcpStaticLease]:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    return (
        db.query(DhcpStaticLease)
        .filter(DhcpStaticLease.scope_id == scope_id)
        .order_by(DhcpStaticLease.ip_address)
        .all()
    )


@router.post("/scopes/{scope_id}/reservations", response_model=ReservationOut, status_code=201)
def create_reservation(
    scope_id: str,
    body: ReservationCreate,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> DhcpStaticLease:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    sl = DhcpStaticLease(scope_id=scope_id, tenant_id=scope.tenant_id, **body.model_dump())
    db.add(sl)
    db.commit()
    db.refresh(sl)
    write_audit_log(db, "dhcp_reservation.create", "dhcp_static_lease", sl.id, actor=user.email, tenant_id=scope.tenant_id)
    return sl


@router.patch("/scopes/{scope_id}/reservations/{reservation_id}", response_model=ReservationOut)
def update_reservation(
    scope_id: str,
    reservation_id: str,
    body: ReservationUpdate,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> DhcpStaticLease:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    sl = _get_reservation_or_404(db, scope_id, reservation_id)
    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(sl, field, val)
    db.commit()
    db.refresh(sl)
    write_audit_log(db, "dhcp_reservation.update", "dhcp_static_lease", reservation_id, actor=user.email, tenant_id=scope.tenant_id)
    return sl


@router.delete("/scopes/{scope_id}/reservations/{reservation_id}", status_code=204)
def delete_reservation(
    scope_id: str,
    reservation_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> None:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    sl = _get_reservation_or_404(db, scope_id, reservation_id)
    db.delete(sl)
    db.commit()
    write_audit_log(db, "dhcp_reservation.delete", "dhcp_static_lease", reservation_id, actor=user.email, tenant_id=scope.tenant_id)


# ── Option endpoints ───────────────────────────────────────────────────────────

@router.get("/scopes/{scope_id}/options", response_model=list[OptionOut])
def list_options(
    scope_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[DhcpOption]:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    return db.query(DhcpOption).filter(DhcpOption.scope_id == scope_id).all()


@router.post("/scopes/{scope_id}/options", response_model=OptionOut, status_code=201)
def create_option(
    scope_id: str,
    body: OptionCreate,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> DhcpOption:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    opt = DhcpOption(scope_id=scope_id, **body.model_dump())
    db.add(opt)
    db.commit()
    db.refresh(opt)
    return opt


@router.delete("/scopes/{scope_id}/options/{option_id}", status_code=204)
def delete_option(
    scope_id: str,
    option_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> None:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    opt = db.get(DhcpOption, option_id)
    if opt is None or opt.scope_id != scope_id:
        raise HTTPException(404, "Option not found")
    db.delete(opt)
    db.commit()


# ── Relay endpoints ────────────────────────────────────────────────────────────

@router.get("/scopes/{scope_id}/relays", response_model=list[RelayOut])
def list_relays(
    scope_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[DhcpRelayConfig]:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    return db.query(DhcpRelayConfig).filter(DhcpRelayConfig.scope_id == scope_id).all()


@router.post("/scopes/{scope_id}/relays", response_model=RelayOut, status_code=201)
def create_relay(
    scope_id: str,
    body: RelayCreate,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> DhcpRelayConfig:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    relay = DhcpRelayConfig(scope_id=scope_id, **body.model_dump())
    db.add(relay)
    db.commit()
    db.refresh(relay)
    return relay


@router.delete("/scopes/{scope_id}/relays/{relay_id}", status_code=204)
def delete_relay(
    scope_id: str,
    relay_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> None:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    relay = db.get(DhcpRelayConfig, relay_id)
    if relay is None or relay.scope_id != scope_id:
        raise HTTPException(404, "Relay config not found")
    db.delete(relay)
    db.commit()


# ── Lease read (native dhcp_leases table — mantis-dhcp's own state) ──────────

@router.get("/leases", response_model=list[LeaseOut])
def list_leases(
    scope_id: str | None = None,
    tenant_id: str | None = None,
    state: int = 0,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[DhcpLease]:
    """Read active leases mantis-dhcp allocated, filtered by scope and/or
    tenant (all scopes for that tenant)."""
    if tenant_id:
        check_tenant_access(user, tenant_id)
    tid = tenant_id or user_tenant_filter(user)

    q = db.query(DhcpScope)
    if scope_id:
        q = q.filter(DhcpScope.id == scope_id)
        scope = q.first()
        if scope:
            check_tenant_access(user, scope.tenant_id)
    elif tid:
        q = q.filter(DhcpScope.tenant_id == tid)

    scope_ids = [s.id for s in q.all()]
    if not scope_ids:
        return []

    return (
        db.query(DhcpLease)
        .filter(DhcpLease.scope_id.in_(scope_ids), DhcpLease.state == state)
        .order_by(DhcpLease.scope_id, DhcpLease.ip_address)
        .limit(1000)
        .all()
    )


# ── Utilisation stats ──────────────────────────────────────────────────────────

class SubnetStatOut(BaseModel):
    scope_id: str
    scope_name: str
    subnet: str
    total_addresses: int
    assigned_addresses: int
    declined_addresses: int


@router.get("/stats", response_model=list[SubnetStatOut])
def dhcp_stats(
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[SubnetStatOut]:
    """Per-subnet utilisation stats computed from the native dhcp_leases table."""
    tid = user_tenant_filter(user)
    q = db.query(DhcpScope).filter(DhcpScope.enabled.is_(True))
    if tid:
        q = q.filter(DhcpScope.tenant_id == tid)
    scopes = q.all()
    if not scopes:
        return []

    scope_ids = [s.id for s in scopes]
    rows = (
        db.query(
            DhcpLease.scope_id,
            func.count().filter(DhcpLease.state == 0).label("assigned"),
            func.count().filter(DhcpLease.state == 1).label("declined"),
        )
        .filter(DhcpLease.scope_id.in_(scope_ids))
        .group_by(DhcpLease.scope_id)
        .all()
    )
    counts = {r.scope_id: r for r in rows}

    result = []
    for scope in scopes:
        try:
            # The allocatable pool is range_start..range_end, not the whole
            # subnet — a scope's dynamic range is normally much smaller than
            # its subnet, so subnet size wildly understated utilisation %.
            total = int(ip_address(scope.range_end)) - int(ip_address(scope.range_start)) + 1
        except ValueError:
            total = 0
        c = counts.get(scope.id)
        result.append(SubnetStatOut(
            scope_id=scope.id,
            scope_name=scope.name,
            subnet=scope.subnet,
            total_addresses=max(total, 0),
            assigned_addresses=c.assigned if c else 0,
            declined_addresses=c.declined if c else 0,
        ))
    return result


# ── Network interfaces (for the scope form's `interface` picker) ──────────────

@router.get("/interfaces", response_model=list[str])
def list_interfaces(user: Any = Depends(require_role("viewer"))) -> list[str]:
    """Interface names on *this* (the control plane's) host, for the scope
    form's `interface` dropdown -- shared by both the v4 and v6 forms, since
    a scope's `interface` value is just the name mantis-dhcp passes straight
    to SO_BINDTODEVICE (v4) at startup.

    This only reflects the control plane's own host. In the common
    single-host deployment that's also where mantis-dhcp runs, so the list
    is accurate; a scope pointed at a second, separate mantis-dhcp host's
    interface (design.md §22.6's multi-host HA) won't show up here -- the
    field still accepts free text typed directly for that case, this
    endpoint only supplies the convenience list.
    """
    return sorted(name for _, name in socket.if_nameindex())
