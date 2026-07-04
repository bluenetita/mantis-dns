"""DHCP management API (design.md §22, Sprint 19).

Scopes, host reservations, custom options, and relay config are managed here.
Every mutating operation calls `try_push()` to keep Kea in sync; failures are
returned as a non-fatal warning so DB state is never rolled back due to a
transient Kea outage.  Operators can re-sync manually via POST /dhcp/push.

Lease read queries go directly to Kea's `lease4` table (shared Postgres DB).
"""
from __future__ import annotations

import logging
from datetime import datetime
from ipaddress import ip_network
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from mantis_control.audit import write_audit_log
from mantis_control.auth import check_tenant_access, require_role, user_tenant_filter
from mantis_control.db.models import DhcpHaConfig, DhcpOption, DhcpRelayConfig, DhcpScope, DhcpStaticLease
from mantis_control.db.session import get_db
from mantis_control.dhcp.kea_config import kea_command, try_push

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
    kea_subnet_id: int | None
    last_pushed_at: datetime | None
    enabled: bool
    created_at: datetime
    updated_at: datetime
    kea_push_error: str | None = None

    class Config:
        from_attributes = True


class ReservationCreate(BaseModel):
    mac_address: str
    ip_address: str
    hostname: str | None = None
    description: str | None = None
    client_id: str | None = None
    next_server: str | None = None
    boot_filename: str | None = None
    enabled: bool = True


class ReservationUpdate(BaseModel):
    mac_address: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    description: str | None = None
    client_id: str | None = None
    next_server: str | None = None
    boot_filename: str | None = None
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
    enabled: bool
    created_at: datetime
    updated_at: datetime
    kea_push_error: str | None = None

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True


class LeaseOut(BaseModel):
    ip_address: str
    mac_address: str | None
    hostname: str
    subnet_id: int
    expire: datetime | None
    state: int   # 0=active, 1=declined, 2=expired-reclaimed


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
async def create_scope(
    body: ScopeCreate,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> ScopeOut:
    check_tenant_access(user, body.tenant_id)
    scope = DhcpScope(**body.model_dump())
    db.add(scope)
    db.commit()
    db.refresh(scope)
    write_audit_log(db, "dhcp_scope.create", "dhcp_scope", scope.id, actor=user.email, tenant_id=scope.tenant_id)
    err = await try_push(db)
    out = ScopeOut.model_validate(scope)
    out.kea_push_error = err
    return out


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
async def update_scope(
    scope_id: str,
    body: ScopeUpdate,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> ScopeOut:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(scope, field, val)
    db.commit()
    db.refresh(scope)
    write_audit_log(db, "dhcp_scope.update", "dhcp_scope", scope_id, actor=user.email, tenant_id=scope.tenant_id)
    err = await try_push(db)
    out = ScopeOut.model_validate(scope)
    out.kea_push_error = err
    return out


@router.delete("/scopes/{scope_id}", status_code=204)
async def delete_scope(
    scope_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> None:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    db.delete(scope)
    db.commit()
    write_audit_log(db, "dhcp_scope.delete", "dhcp_scope", scope_id, actor=user.email, tenant_id=scope.tenant_id)
    await try_push(db)


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
async def create_reservation(
    scope_id: str,
    body: ReservationCreate,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> ReservationOut:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    sl = DhcpStaticLease(scope_id=scope_id, tenant_id=scope.tenant_id, **body.model_dump())
    db.add(sl)
    db.commit()
    db.refresh(sl)
    write_audit_log(db, "dhcp_reservation.create", "dhcp_static_lease", sl.id, actor=user.email, tenant_id=scope.tenant_id)
    err = await try_push(db)
    out = ReservationOut.model_validate(sl)
    out.kea_push_error = err
    return out


@router.patch("/scopes/{scope_id}/reservations/{reservation_id}", response_model=ReservationOut)
async def update_reservation(
    scope_id: str,
    reservation_id: str,
    body: ReservationUpdate,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> ReservationOut:
    scope = _get_scope_or_404(db, scope_id)
    check_tenant_access(user, scope.tenant_id)
    sl = _get_reservation_or_404(db, scope_id, reservation_id)
    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(sl, field, val)
    db.commit()
    db.refresh(sl)
    write_audit_log(db, "dhcp_reservation.update", "dhcp_static_lease", reservation_id, actor=user.email, tenant_id=scope.tenant_id)
    err = await try_push(db)
    out = ReservationOut.model_validate(sl)
    out.kea_push_error = err
    return out


@router.delete("/scopes/{scope_id}/reservations/{reservation_id}", status_code=204)
async def delete_reservation(
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
    await try_push(db)


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
async def create_option(
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
    await try_push(db)
    return opt


@router.delete("/scopes/{scope_id}/options/{option_id}", status_code=204)
async def delete_option(
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
    await try_push(db)


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
async def create_relay(
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
    await try_push(db)
    return relay


@router.delete("/scopes/{scope_id}/relays/{relay_id}", status_code=204)
async def delete_relay(
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
    await try_push(db)


# ── Lease read (queries Kea's lease4 table directly) ─────────────────────────

@router.get("/leases", response_model=list[LeaseOut])
def list_leases(
    scope_id: str | None = None,
    tenant_id: str | None = None,
    state: int = 0,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[LeaseOut]:
    """Read active leases from Kea's lease4 table.

    Filters by scope (via kea_subnet_id) and/or tenant (all scopes for that tenant).
    Falls back gracefully if the lease4 table doesn't exist yet (Kea not started).
    """
    if tenant_id:
        check_tenant_access(user, tenant_id)
    tid = tenant_id or user_tenant_filter(user)

    # Collect kea_subnet_ids in scope
    q = db.query(DhcpScope)
    if scope_id:
        q = q.filter(DhcpScope.id == scope_id)
        scope = q.first()
        if scope:
            check_tenant_access(user, scope.tenant_id)
    elif tid:
        q = q.filter(DhcpScope.tenant_id == tid)

    scopes = q.filter(DhcpScope.kea_subnet_id.isnot(None)).all()
    if not scopes:
        return []

    subnet_ids = [s.kea_subnet_id for s in scopes]

    try:
        rows = db.execute(
            text("""
                SELECT
                    ((address >> 24) & 255)::text || '.' ||
                    ((address >> 16) & 255)::text || '.' ||
                    ((address >>  8) & 255)::text || '.' ||
                    (address & 255)::text            AS ip_address,
                    encode(hwaddr, 'hex')             AS mac_address,
                    COALESCE(hostname, '')            AS hostname,
                    subnet_id,
                    expire,
                    state
                FROM lease4
                WHERE subnet_id = ANY(:sids)
                  AND state = :state
                ORDER BY subnet_id, address
                LIMIT 1000
            """),
            {"sids": subnet_ids, "state": state},
        ).mappings().all()
    except Exception as exc:
        # lease4 table absent means Kea hasn't initialised yet — return empty
        log.warning("Could not query lease4: %s", exc)
        return []

    return [LeaseOut(**dict(r)) for r in rows]


# ── Manual push ────────────────────────────────────────────────────────────────

@router.post("/push", status_code=200)
async def manual_push(
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> dict:
    """Re-push the full Kea DHCPv4 config from DB. Use after Kea restarts."""
    err = await try_push(db)
    if err:
        return {"ok": False, "error": err}
    write_audit_log(db, "dhcp.push", "kea", "full-config", actor=user.email)
    return {"ok": True}


# ── Kea version / status ───────────────────────────────────────────────────────

class SubnetStatOut(BaseModel):
    scope_id: str
    scope_name: str
    subnet: str
    kea_subnet_id: int
    total_addresses: int
    assigned_addresses: int
    declined_addresses: int


@router.get("/stats", response_model=list[SubnetStatOut])
def dhcp_stats(
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("viewer")),
) -> list[SubnetStatOut]:
    """Per-subnet utilisation stats computed from the lease4 table."""
    tid = user_tenant_filter(user)
    q = db.query(DhcpScope).filter(
        DhcpScope.kea_subnet_id.isnot(None),
        DhcpScope.enabled.is_(True),
    )
    if tid:
        q = q.filter(DhcpScope.tenant_id == tid)
    scopes = q.all()
    if not scopes:
        return []

    subnet_map = {s.kea_subnet_id: s for s in scopes}
    subnet_ids = list(subnet_map.keys())

    try:
        rows = db.execute(
            text("""
                SELECT subnet_id,
                       COUNT(*) FILTER (WHERE state = 0) AS assigned,
                       COUNT(*) FILTER (WHERE state = 1) AS declined
                FROM lease4
                WHERE subnet_id = ANY(:sids)
                GROUP BY subnet_id
            """),
            {"sids": subnet_ids},
        ).mappings().all()
    except Exception as exc:
        log.warning("Could not query lease4 for stats: %s", exc)
        rows = []

    counts: dict[int, dict] = {r["subnet_id"]: dict(r) for r in rows}

    result = []
    for sid, scope in subnet_map.items():
        try:
            total = ip_network(scope.subnet, strict=False).num_addresses - 2
        except ValueError:
            total = 0
        c = counts.get(sid, {})
        result.append(SubnetStatOut(
            scope_id=scope.id,
            scope_name=scope.name,
            subnet=scope.subnet,
            kea_subnet_id=sid,
            total_addresses=max(total, 0),
            assigned_addresses=c.get("assigned", 0),
            declined_addresses=c.get("declined", 0),
        ))
    return result


@router.get("/kea/status")
async def kea_status(user: Any = Depends(require_role("viewer"))) -> dict:
    """Query Kea daemon status via Control Agent."""
    try:
        result = await kea_command("version-get", service=["dhcp4"])
        return {"ok": True, "version": result.get("text"), "result": result.get("result")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ── HA configuration ───────────────────────────────────────────────────────────

class HaConfigIn(BaseModel):
    enabled: bool = False
    mode: str = "hot-standby"
    this_server_name: str = "primary"
    this_server_url: str = "http://kea-primary:8080/"
    peer_name: str = "secondary"
    peer_url: str = "http://kea-secondary:8080/"
    peer_role: str = "standby"
    max_unacked_clients: int | None = 10
    max_ack_delay_ms: int | None = 10000
    heartbeat_delay_ms: int | None = 10000
    retry_wait_time_ms: int | None = 5000


class HaConfigOut(BaseModel):
    id: str
    tenant_id: str
    enabled: bool
    mode: str
    this_server_name: str
    this_server_url: str
    peer_name: str
    peer_url: str
    peer_role: str
    max_unacked_clients: int | None
    max_ack_delay_ms: int | None
    heartbeat_delay_ms: int | None
    retry_wait_time_ms: int | None
    created_at: datetime
    updated_at: datetime
    kea_push_error: str | None = None

    class Config:
        from_attributes = True


@router.get("/ha/{tenant_id}", response_model=HaConfigOut)
def get_ha_config(
    tenant_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("operator")),
) -> HaConfigOut:
    check_tenant_access(user, tenant_id)
    ha = db.query(DhcpHaConfig).filter(DhcpHaConfig.tenant_id == tenant_id).first()
    if ha is None:
        raise HTTPException(404, "No HA config for this tenant")
    return HaConfigOut.model_validate(ha)


@router.put("/ha/{tenant_id}", response_model=HaConfigOut)
async def upsert_ha_config(
    tenant_id: str,
    body: HaConfigIn,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("admin")),
) -> HaConfigOut:
    """Create or replace the HA config for a tenant (idempotent PUT)."""
    check_tenant_access(user, tenant_id)
    ha = db.query(DhcpHaConfig).filter(DhcpHaConfig.tenant_id == tenant_id).first()
    if ha is None:
        ha = DhcpHaConfig(tenant_id=tenant_id, **body.model_dump())
        db.add(ha)
    else:
        for field, val in body.model_dump().items():
            setattr(ha, field, val)
    db.commit()
    db.refresh(ha)
    write_audit_log(db, "dhcp_ha.upsert", "dhcp_ha_config", ha.id, actor=user.email, tenant_id=tenant_id)
    err = await try_push(db)
    out = HaConfigOut.model_validate(ha)
    out.kea_push_error = err
    return out


@router.delete("/ha/{tenant_id}", status_code=204)
async def delete_ha_config(
    tenant_id: str,
    db: Session = Depends(get_db),
    user: Any = Depends(require_role("admin")),
) -> None:
    check_tenant_access(user, tenant_id)
    ha = db.query(DhcpHaConfig).filter(DhcpHaConfig.tenant_id == tenant_id).first()
    if ha is None:
        raise HTTPException(404, "No HA config for this tenant")
    db.delete(ha)
    db.commit()
    write_audit_log(db, "dhcp_ha.delete", "dhcp_ha_config", tenant_id, actor=user.email, tenant_id=tenant_id)
    await try_push(db)
