"""SIEM webhook config CRUD + on-demand test delivery (design.md §20.4, Sprint 15).

Admin-only: these configs hold a signing secret and can point at any URL,
so they get the same trust level as user management, not operator-level
policy edits.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis_control.audit import write_audit_log
from aegis_control.auth import require_role
from aegis_control.crypto import encrypt_secret
from aegis_control.db import models
from aegis_control.db.session import get_db
from aegis_control.siem_delivery import deliver_test_event

router = APIRouter()


class SiemWebhookCreate(BaseModel):
    tenant_id: str | None = None
    name: str
    url: str
    secret: str
    format: Literal["json", "cef"] = "json"
    batch_size: int = 200
    flush_interval_s: int = 30
    filter_decision: Literal["all", "block", "allow"] = "all"
    enabled: bool = True


class SiemWebhookUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    secret: str | None = None
    format: Literal["json", "cef"] | None = None
    batch_size: int | None = None
    flush_interval_s: int | None = None
    filter_decision: Literal["all", "block", "allow"] | None = None
    enabled: bool | None = None


class SiemWebhookOut(BaseModel):
    id: str
    tenant_id: str | None
    name: str
    url: str
    format: str
    batch_size: int
    flush_interval_s: int
    filter_decision: str
    enabled: bool
    last_delivered_at: datetime | None
    last_error: str | None
    consecutive_failures: int
    created_at: datetime

    class Config:
        from_attributes = True


class TestDeliveryResult(BaseModel):
    success: bool
    status_code: int | None
    error: str | None


@router.post("/siem/webhooks", response_model=SiemWebhookOut, status_code=201)
def create_webhook(
    payload: SiemWebhookCreate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.SiemWebhook:
    webhook = models.SiemWebhook(
        tenant_id=payload.tenant_id,
        name=payload.name,
        url=payload.url,
        secret_encrypted=encrypt_secret(payload.secret),
        format=payload.format,
        batch_size=payload.batch_size,
        flush_interval_s=payload.flush_interval_s,
        filter_decision=payload.filter_decision,
        enabled=payload.enabled,
    )
    db.add(webhook)
    db.flush()
    write_audit_log(db, "siem_webhook.create", "siem_webhook", webhook.id, detail=f"name={webhook.name} url={webhook.url}", actor=admin.email)
    db.commit()
    db.refresh(webhook)
    return webhook


@router.get("/siem/webhooks", response_model=list[SiemWebhookOut])
def list_webhooks(db: Session = Depends(get_db), _admin: models.User = Depends(require_role("admin"))) -> list[models.SiemWebhook]:
    return list(db.query(models.SiemWebhook).all())


@router.patch("/siem/webhooks/{webhook_id}", response_model=SiemWebhookOut)
def update_webhook(
    webhook_id: str,
    payload: SiemWebhookUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.SiemWebhook:
    webhook = db.get(models.SiemWebhook, webhook_id)
    if webhook is None:
        raise HTTPException(404, "webhook not found")

    changes = payload.model_dump(exclude_unset=True, exclude={"secret"})
    for field, value in changes.items():
        setattr(webhook, field, value)
    if payload.secret is not None:
        webhook.secret_encrypted = encrypt_secret(payload.secret)
    if payload.enabled is True:
        # Re-enabling clears the failure backoff so delivery resumes immediately.
        webhook.consecutive_failures = 0
        webhook.next_retry_at = None

    write_audit_log(db, "siem_webhook.update", "siem_webhook", webhook.id, detail=str(changes), actor=admin.email)
    db.commit()
    db.refresh(webhook)
    return webhook


@router.delete("/siem/webhooks/{webhook_id}", status_code=204)
def delete_webhook(
    webhook_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> None:
    webhook = db.get(models.SiemWebhook, webhook_id)
    if webhook is None:
        raise HTTPException(404, "webhook not found")
    write_audit_log(db, "siem_webhook.delete", "siem_webhook", webhook.id, detail=f"name={webhook.name}", actor=admin.email)
    db.delete(webhook)
    db.commit()


@router.post("/siem/webhooks/{webhook_id}/test", response_model=TestDeliveryResult)
async def test_webhook(
    webhook_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> TestDeliveryResult:
    """Sends one synthetic event to the configured URL, signed the same way
    real batches are, without touching the webhook's delivery cursor."""
    webhook = db.get(models.SiemWebhook, webhook_id)
    if webhook is None:
        raise HTTPException(404, "webhook not found")

    async with httpx.AsyncClient() as client:
        try:
            status_code = await deliver_test_event(webhook, client)
            write_audit_log(db, "siem_webhook.test", "siem_webhook", webhook.id, detail=f"status={status_code}", actor=admin.email)
            db.commit()
            return TestDeliveryResult(success=True, status_code=status_code, error=None)
        except httpx.HTTPStatusError as e:
            write_audit_log(db, "siem_webhook.test", "siem_webhook", webhook.id, detail=f"failed status={e.response.status_code}", actor=admin.email)
            db.commit()
            return TestDeliveryResult(success=False, status_code=e.response.status_code, error=str(e))
        except Exception as e:
            write_audit_log(db, "siem_webhook.test", "siem_webhook", webhook.id, detail=f"failed: {e}", actor=admin.email)
            db.commit()
            return TestDeliveryResult(success=False, status_code=None, error=str(e))
