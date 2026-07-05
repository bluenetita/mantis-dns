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

"""Client registry (design.md §20.6, Sprint 16). Bridges a raw client IP
seen in query telemetry to a human identity — the piece that turns a SIEM
alert on `10.8.1.47 queried casino.com` into `fabio-laptop / fabio@corp
queried casino.com`.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from mantis_control.audit import write_audit_log
from mantis_control.auth import check_tenant_access, get_current_user, require_role
from mantis_control.db import models
from mantis_control.db.session import get_db

router = APIRouter()


class ClientOut(BaseModel):
    id: str
    tenant_id: str
    group_id: str | None
    ip: str
    hostname: str | None
    owner: str | None
    device_type: str | None
    tags: list[str]
    last_seen: datetime
    registered_at: datetime | None
    registered_by: str | None

    model_config = ConfigDict(from_attributes=True)


class ClientUpsert(BaseModel):
    hostname: str | None = None
    owner: str | None = None
    device_type: str | None = None
    tags: list[str] = []


@router.get("/tenants/{tenant_id}/clients", response_model=list[ClientOut])
def list_clients(
    tenant_id: str,
    unregistered_only: bool = False,
    db: Session = Depends(get_db),
    _user: models.User = Depends(get_current_user),
) -> list[models.ClientEntry]:
    check_tenant_access(_user, tenant_id)
    query = db.query(models.ClientEntry).filter(models.ClientEntry.tenant_id == tenant_id)
    if unregistered_only:
        query = query.filter(models.ClientEntry.registered_at.is_(None))
    return list(query.order_by(models.ClientEntry.last_seen.desc()).all())


@router.put("/tenants/{tenant_id}/clients/{ip}", response_model=ClientOut)
def register_client(
    tenant_id: str,
    ip: str,
    payload: ClientUpsert,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> models.ClientEntry:
    """Upsert: registers a not-yet-seen IP directly (rather than requiring a
    query event first) or edits an already-auto-discovered stub."""
    check_tenant_access(user, tenant_id)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, f"invalid IP address: {ip!r}")
    client = (
        db.query(models.ClientEntry)
        .filter(models.ClientEntry.tenant_id == tenant_id, models.ClientEntry.ip == ip)
        .one_or_none()
    )
    if client is None:
        client = models.ClientEntry(tenant_id=tenant_id, ip=ip, last_seen=datetime.now(timezone.utc))
        db.add(client)
        db.flush()

    client.hostname = payload.hostname
    client.owner = payload.owner
    client.device_type = payload.device_type
    client.tags = payload.tags
    if client.registered_at is None:
        client.registered_at = datetime.now(timezone.utc)
    client.registered_by = user.email

    write_audit_log(db, "client.register", "client", client.id, detail=f"ip={ip} hostname={payload.hostname}", actor=user.email, tenant_id=tenant_id)
    db.commit()
    db.refresh(client)
    return client


@router.delete("/tenants/{tenant_id}/clients/{ip}", status_code=204)
def delete_client(
    tenant_id: str,
    ip: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> None:
    check_tenant_access(user, tenant_id)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, f"invalid IP address: {ip!r}")
    client = (
        db.query(models.ClientEntry)
        .filter(models.ClientEntry.tenant_id == tenant_id, models.ClientEntry.ip == ip)
        .one_or_none()
    )
    if client is None:
        raise HTTPException(404, "client not found")
    write_audit_log(db, "client.delete", "client", client.id, detail=f"ip={ip}", actor=user.email, tenant_id=tenant_id)
    db.delete(client)
    db.commit()
