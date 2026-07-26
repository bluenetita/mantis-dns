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

"""SIEM syslog config CRUD + on-demand test delivery (design.md §20.8, Sprint 17).

Admin-only: these configs name a network target the control plane will
connect out to on a schedule, the same trust tier as user management, not
operator-level policy edits.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from mantis_control.audit import write_audit_log
from mantis_control.auth import require_role, user_tenant_filter
from mantis_control.db import models
from mantis_control.db.session import get_db
from mantis_control.siem_common import describe_error, get_sink_or_404
from mantis_control.siem_syslog_delivery import deliver_test_event
from mantis_control.ssrf_guard import check_probe_target_safe

router = APIRouter()


class SiemSyslogCreate(BaseModel):
    tenant_id: str | None = None
    name: str
    host: str
    port: int = Field(514, ge=1, le=65_535)
    transport: Literal["tcp", "tls", "udp"] = "tls"
    format: Literal["json", "cef"] = "cef"
    facility: int = Field(16, ge=0, le=23)
    # RFC 5424 APP-NAME is PRINTUSASCII (no space, no control chars) — a
    # value outside that shifts every header field after it for the
    # receiver (see _to_syslog_line's fixed "- APP-NAME - - -" framing).
    app_name: str = Field("mantis-dns", max_length=48, pattern=r"^[!-~]+$")
    batch_size: int = Field(200, ge=1, le=10_000)
    flush_interval_s: int = Field(30, ge=10, le=86_400)
    filter_decision: Literal["all", "block", "allow"] = "all"
    enabled: bool = True


class SiemSyslogUpdate(BaseModel):
    name: str | None = None
    host: str | None = None
    port: int | None = Field(None, ge=1, le=65_535)
    transport: Literal["tcp", "tls", "udp"] | None = None
    format: Literal["json", "cef"] | None = None
    facility: int | None = Field(None, ge=0, le=23)
    app_name: str | None = Field(None, max_length=48, pattern=r"^[!-~]+$")
    batch_size: int | None = Field(None, ge=1, le=10_000)
    flush_interval_s: int | None = Field(None, ge=10, le=86_400)
    filter_decision: Literal["all", "block", "allow"] | None = None
    enabled: bool | None = None


class SiemSyslogOut(BaseModel):
    id: str
    tenant_id: str | None
    name: str
    host: str
    port: int
    transport: str
    format: str
    facility: int
    app_name: str
    batch_size: int
    flush_interval_s: int
    filter_decision: str
    enabled: bool
    last_delivered_at: datetime | None
    last_error: str | None
    consecutive_failures: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SyslogTestResult(BaseModel):
    success: bool
    error: str | None


@router.post("/siem/syslog", response_model=SiemSyslogOut, status_code=201)
def create_syslog(
    payload: SiemSyslogCreate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.SiemSyslog:
    try:
        check_probe_target_safe(payload.host)
    except ValueError as e:
        raise HTTPException(422, f"syslog host rejected: {e}") from e
    sink = models.SiemSyslog(
        tenant_id=payload.tenant_id,
        name=payload.name,
        host=payload.host,
        port=payload.port,
        transport=payload.transport,
        format=payload.format,
        facility=payload.facility,
        app_name=payload.app_name,
        batch_size=payload.batch_size,
        flush_interval_s=payload.flush_interval_s,
        filter_decision=payload.filter_decision,
        enabled=payload.enabled,
    )
    db.add(sink)
    db.flush()
    write_audit_log(db, "siem_syslog.create", "siem_syslog", sink.id, detail=f"name={sink.name} host={sink.host}:{sink.port}/{sink.transport}", actor=admin.email, tenant_id=sink.tenant_id)
    db.commit()
    db.refresh(sink)
    return sink


@router.get("/siem/syslog", response_model=list[SiemSyslogOut])
def list_syslog(db: Session = Depends(get_db), _admin: models.User = Depends(require_role("admin"))) -> list[models.SiemSyslog]:
    scope = user_tenant_filter(_admin)
    q = db.query(models.SiemSyslog)
    if scope is not None:
        q = q.filter(models.SiemSyslog.tenant_id == scope)
    return list(q.all())


@router.patch("/siem/syslog/{syslog_id}", response_model=SiemSyslogOut)
def update_syslog(
    syslog_id: str,
    payload: SiemSyslogUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.SiemSyslog:
    sink = get_sink_or_404(db, models.SiemSyslog, syslog_id, admin, not_found_msg="syslog sink not found")

    changes = payload.model_dump(exclude_unset=True)
    if "host" in changes:
        try:
            check_probe_target_safe(changes["host"])
        except ValueError as e:
            raise HTTPException(422, f"syslog host rejected: {e}") from e
    for field, value in changes.items():
        setattr(sink, field, value)
    if payload.enabled is True or ("host" in changes and sink.enabled):
        # Re-enabling or fixing the host clears the failure backoff so delivery resumes immediately.
        sink.consecutive_failures = 0
        sink.next_retry_at = None

    write_audit_log(db, "siem_syslog.update", "siem_syslog", sink.id, detail=str(changes), actor=admin.email, tenant_id=sink.tenant_id)
    db.commit()
    db.refresh(sink)
    return sink


@router.delete("/siem/syslog/{syslog_id}", status_code=204)
def delete_syslog(
    syslog_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> None:
    sink = get_sink_or_404(db, models.SiemSyslog, syslog_id, admin, not_found_msg="syslog sink not found")
    write_audit_log(db, "siem_syslog.delete", "siem_syslog", sink.id, detail=f"name={sink.name}", actor=admin.email, tenant_id=sink.tenant_id)
    db.delete(sink)
    db.commit()


@router.post("/siem/syslog/{syslog_id}/test", response_model=SyslogTestResult)
async def test_syslog(
    syslog_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> SyslogTestResult:
    """Sends one synthetic event to the configured host, framed the same way
    real batches are, without touching the sink's delivery cursor."""
    sink = get_sink_or_404(db, models.SiemSyslog, syslog_id, admin, not_found_msg="syslog sink not found")

    try:
        await deliver_test_event(sink)
        write_audit_log(db, "siem_syslog.test", "siem_syslog", sink.id, detail="status=sent", actor=admin.email, tenant_id=sink.tenant_id)
        db.commit()
        return SyslogTestResult(success=True, error=None)
    except Exception as e:
        error = describe_error(e)
        write_audit_log(db, "siem_syslog.test", "siem_syslog", sink.id, detail=f"failed: {error}", actor=admin.email, tenant_id=sink.tenant_id)
        db.commit()
        return SyslogTestResult(success=False, error=error)
