from __future__ import annotations

import ipaddress
from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from aegis_control.audit import write_audit_log
from aegis_control.auth import check_tenant_access, get_current_user, require_role, user_tenant_filter
from aegis_control.db import models
from aegis_control.db.session import get_db

router = APIRouter(tags=["dns-zones"])

_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "CAA"}
_ZONE_TYPES = {"local", "forward", "passthrough"}


# ── Schemas ───────────────────────────────────────────────────────────────────

class ZoneCreate(BaseModel):
    tenant_id: str
    name: str
    zone_type: str
    description: str = ""
    enabled: bool = True
    ttl_default: int = 300
    forwarder: str | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        if not v:
            raise ValueError("Zone name must not be empty")
        return v

    @field_validator("zone_type")
    @classmethod
    def _zone_type(cls, v: str) -> str:
        if v not in _ZONE_TYPES:
            raise ValueError(f"zone_type must be one of {sorted(_ZONE_TYPES)}")
        return v

    @field_validator("ttl_default")
    @classmethod
    def _ttl(cls, v: int) -> int:
        if v < 0:
            raise ValueError("TTL must be non-negative")
        return v


class ZoneUpdate(BaseModel):
    name: str | None = None
    zone_type: str | None = None
    description: str | None = None
    enabled: bool | None = None
    ttl_default: int | None = None
    forwarder: str | None = None


class ZoneOut(BaseModel):
    id: str
    tenant_id: str | None
    name: str
    zone_type: str
    description: str
    enabled: bool
    ttl_default: int
    forwarder: str | None
    record_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RecordIn(BaseModel):
    name: str
    record_type: str
    data: str
    ttl: int | None = None
    priority: int | None = None
    enabled: bool = True

    @field_validator("record_type")
    @classmethod
    def _rtype(cls, v: str) -> str:
        v = v.upper()
        if v not in _RECORD_TYPES:
            raise ValueError(f"record_type must be one of {sorted(_RECORD_TYPES)}")
        return v

    @field_validator("name")
    @classmethod
    def _rname(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Record name must not be empty")
        return v

    @field_validator("data")
    @classmethod
    def _rdata(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Record data must not be empty")
        return v


class RecordUpdate(BaseModel):
    name: str | None = None
    record_type: str | None = None
    data: str | None = None
    ttl: int | None = None
    priority: int | None = None
    enabled: bool | None = None


class RecordOut(BaseModel):
    id: str
    zone_id: str
    name: str
    record_type: str
    data: str
    ttl: int | None
    priority: int | None
    enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _zone_out(z: models.DnsZone) -> ZoneOut:
    return ZoneOut(
        id=z.id, tenant_id=z.tenant_id, name=z.name, zone_type=z.zone_type, description=z.description,
        enabled=z.enabled, ttl_default=z.ttl_default, forwarder=z.forwarder,
        record_count=len(z.records), created_at=z.created_at, updated_at=z.updated_at,
    )


def _get_zone_or_403(zone_id: str, db: Session, user: models.User) -> models.DnsZone:
    z = db.query(models.DnsZone).filter_by(id=zone_id).first()
    if not z:
        raise HTTPException(404, "Zone not found")
    if z.tenant_id is None:
        # Pre-migration/legacy zone with no tenant assigned yet — admin-only
        # until reassigned (see main.py's additive tenant_id migration).
        if user.role != "admin":
            raise HTTPException(403, "access denied — this zone has no tenant assigned")
    else:
        check_tenant_access(user, z.tenant_id)
    return z


# ── Zone endpoints ────────────────────────────────────────────────────────────

@router.get("/dns-zones", response_model=list[ZoneOut])
def list_zones(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[ZoneOut]:
    scope = user_tenant_filter(user)
    query = db.query(models.DnsZone)
    if scope is not None:
        query = query.filter(models.DnsZone.tenant_id == scope)
    zones = query.order_by(models.DnsZone.name).all()
    return [_zone_out(z) for z in zones]


@router.post("/dns-zones", response_model=ZoneOut, status_code=201)
def create_zone(
    body: ZoneCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("operator")),
) -> ZoneOut:
    check_tenant_access(user, body.tenant_id)
    if db.get(models.Tenant, body.tenant_id) is None:
        raise HTTPException(404, "tenant not found")
    if db.query(models.DnsZone).filter_by(tenant_id=body.tenant_id, name=body.name).first():
        raise HTTPException(409, f"Zone {body.name!r} already exists for this tenant")
    if body.zone_type == "forward" and not body.forwarder:
        raise HTTPException(422, "forward zones require a forwarder IP address")
    if body.forwarder:
        try:
            ipaddress.ip_address(body.forwarder)
        except ValueError:
            raise HTTPException(422, f"invalid forwarder IP address: {body.forwarder!r}")
    z = models.DnsZone(**body.model_dump())
    db.add(z)
    db.flush()
    write_audit_log(db, "dns_zone.create", "dns_zone", z.id, detail=f"name={z.name} type={z.zone_type}",
                     actor=user.email, tenant_id=z.tenant_id)
    db.commit()
    db.refresh(z)
    return _zone_out(z)


@router.get("/dns-zones/{zone_id}", response_model=ZoneOut)
def get_zone(
    zone_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ZoneOut:
    return _zone_out(_get_zone_or_403(zone_id, db, user))


@router.patch("/dns-zones/{zone_id}", response_model=ZoneOut)
def update_zone(
    zone_id: str,
    body: ZoneUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("operator")),
) -> ZoneOut:
    z = _get_zone_or_403(zone_id, db, user)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(z, k, v)
    if z.zone_type == "forward" and not z.forwarder:
        raise HTTPException(422, "forward zones require a forwarder IP address")
    if z.forwarder:
        try:
            ipaddress.ip_address(z.forwarder)
        except ValueError:
            raise HTTPException(422, f"invalid forwarder IP address: {z.forwarder!r}")
    write_audit_log(db, "dns_zone.update", "dns_zone", z.id, detail=str(changes),
                     actor=user.email, tenant_id=z.tenant_id)
    db.commit()
    db.refresh(z)
    return _zone_out(z)


@router.delete("/dns-zones/{zone_id}", status_code=204)
def delete_zone(
    zone_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("operator")),
) -> None:
    z = _get_zone_or_403(zone_id, db, user)
    write_audit_log(db, "dns_zone.delete", "dns_zone", z.id, detail=f"name={z.name}",
                     actor=user.email, tenant_id=z.tenant_id)
    db.delete(z)
    db.commit()


@router.get("/dns-zones/{zone_id}/export")
def export_zone(
    zone_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> Response:
    z = _get_zone_or_403(zone_id, db, user)
    serial = date.today().strftime("%Y%m%d") + "01"
    lines = [
        f"; Zone file for {z.name} — exported by Aegis-DNS",
        f"$ORIGIN {z.name}.",
        f"$TTL {z.ttl_default}",
        f"@\tIN\tSOA\tns1.{z.name}. hostmaster.{z.name}. (",
        f"\t\t{serial}\t; serial",
        f"\t\t3600\t\t; refresh",
        f"\t\t900\t\t; retry",
        f"\t\t604800\t\t; expire",
        f"\t\t{z.ttl_default}\t\t; minimum",
        f")",
        f"@\tIN\tNS\tns1.{z.name}.",
        "",
    ]
    for rec in sorted(z.records, key=lambda r: (r.record_type, r.name)):
        if not rec.enabled:
            continue
        ttl_part = f"\t{rec.ttl}" if rec.ttl is not None else ""
        prio_part = f"\t{rec.priority}" if rec.priority is not None else ""
        name = rec.name.replace("\n", " ").replace("\r", "")
        data = rec.data.replace("\n", " ").replace("\r", "")
        lines.append(f"{name}{ttl_part}\tIN\t{rec.record_type}{prio_part}\t{data}")
    content = "\n".join(lines) + "\n"
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{z.name}.zone"'},
    )


# ── Record endpoints ──────────────────────────────────────────────────────────

@router.get("/dns-zones/{zone_id}/records", response_model=list[RecordOut])
def list_records(
    zone_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[models.DnsRecord]:
    _get_zone_or_403(zone_id, db, user)
    return (
        db.query(models.DnsRecord)
        .filter_by(zone_id=zone_id)
        .order_by(models.DnsRecord.record_type, models.DnsRecord.name)
        .all()
    )


@router.post("/dns-zones/{zone_id}/records", response_model=RecordOut, status_code=201)
def create_record(
    zone_id: str,
    body: RecordIn,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("operator")),
) -> RecordOut:
    _get_zone_or_403(zone_id, db, user)
    rec = models.DnsRecord(zone_id=zone_id, **body.model_dump())
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec  # type: ignore[return-value]


@router.patch("/dns-zones/{zone_id}/records/{record_id}", response_model=RecordOut)
def update_record(
    zone_id: str,
    record_id: str,
    body: RecordUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("operator")),
) -> RecordOut:
    _get_zone_or_403(zone_id, db, user)
    rec = db.query(models.DnsRecord).filter_by(id=record_id, zone_id=zone_id).first()
    if not rec:
        raise HTTPException(404, "Record not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(rec, k, v)
    db.commit()
    db.refresh(rec)
    return rec  # type: ignore[return-value]


@router.delete("/dns-zones/{zone_id}/records/{record_id}", status_code=204)
def delete_record(
    zone_id: str,
    record_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("operator")),
) -> None:
    _get_zone_or_403(zone_id, db, user)
    rec = db.query(models.DnsRecord).filter_by(id=record_id, zone_id=zone_id).first()
    if not rec:
        raise HTTPException(404, "Record not found")
    db.delete(rec)
    db.commit()
