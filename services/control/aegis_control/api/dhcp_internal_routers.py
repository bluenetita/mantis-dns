"""Internal DHCP event endpoint — called by the Kea run_script hook via
aegis-ddns-bridge.sh (design.md §22, Sprint 20).

Authentication: X-Internal-Token header (AEGIS_INTERNAL_TOKEN env var).
Not exposed in the public API docs and never reaches user-facing clients.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi import Depends

from aegis_control.db.models import ClientEntry, DhcpScope, DnsRecord, DnsZone
from aegis_control.db.session import get_db

router = APIRouter(prefix="/internal", tags=["internal"])
log = logging.getLogger(__name__)

_INTERNAL_TOKEN = os.getenv("AEGIS_INTERNAL_TOKEN", "dev-insecure-internal-token")


def _verify_internal(x_internal_token: str | None = Header(None)) -> None:
    if not x_internal_token or x_internal_token != _INTERNAL_TOKEN:
        raise HTTPException(403, "invalid internal token")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Schema ─────────────────────────────────────────────────────────────────────

class DhcpEvent(BaseModel):
    event: str          # "add" | "expire"
    ip: str
    hostname: str
    mac: str = ""
    subnet_id: int = 0


# ── Helpers ────────────────────────────────────────────────────────────────────

def _rel_hostname(hostname: str, zone_name: str) -> str:
    """Strip zone suffix from hostname to get the relative record name."""
    # "mydevice.internal.example.com" with zone "internal.example.com" → "mydevice"
    # "mydevice" → "mydevice"
    h = hostname.rstrip(".")
    suffix = "." + zone_name.rstrip(".")
    if h.endswith(suffix):
        return h[: -len(suffix)]
    if h == zone_name.rstrip("."):
        return "@"
    return h


def _mac_fmt(raw: str) -> str | None:
    """Normalise MAC to aa:bb:cc:dd:ee:ff from aabbccddeeff."""
    if not raw:
        return None
    h = raw.replace(":", "").replace("-", "").lower()
    if len(h) != 12:
        return raw
    return ":".join(h[i: i + 2] for i in range(0, 12, 2))


def _upsert_client_entry(
    db: Session, tenant_id: str, ip: str, hostname: str | None, mac: str | None
) -> None:
    entry = (
        db.query(ClientEntry)
        .filter(ClientEntry.tenant_id == tenant_id, ClientEntry.ip == ip)
        .first()
    )
    now = _now()
    if entry:
        if hostname:
            entry.hostname = hostname
        if mac:
            pass  # ClientEntry has no mac field; leave for Sprint 21 extension
        entry.last_seen = now
    else:
        db.add(ClientEntry(tenant_id=tenant_id, ip=ip, hostname=hostname, last_seen=now))


def _upsert_a_record(db: Session, scope: DhcpScope, hostname: str, ip: str) -> None:
    zone = db.get(DnsZone, scope.ddns_zone_id)
    if zone is None or not zone.enabled:
        return
    name = _rel_hostname(hostname, zone.name)
    if not name:
        return

    existing = (
        db.query(DnsRecord)
        .filter(
            DnsRecord.zone_id == zone.id,
            DnsRecord.name == name,
            DnsRecord.record_type == "A",
        )
        .first()
    )
    now = _now()
    if existing:
        existing.data = ip
        existing.updated_at = now
    else:
        db.add(DnsRecord(
            zone_id=zone.id,
            name=name,
            record_type="A",
            data=ip,
            ttl=scope.ddns_ttl_s,
            enabled=True,
        ))
    zone.updated_at = now  # signal filter to refresh zone


def _delete_a_record(db: Session, scope: DhcpScope, hostname: str, ip: str) -> None:
    zone = db.get(DnsZone, scope.ddns_zone_id)
    if zone is None:
        return
    name = _rel_hostname(hostname, zone.name)
    if not name:
        return

    deleted = (
        db.query(DnsRecord)
        .filter(
            DnsRecord.zone_id == zone.id,
            DnsRecord.name == name,
            DnsRecord.record_type == "A",
            DnsRecord.data == ip,
        )
        .delete()
    )
    if deleted:
        zone.updated_at = _now()


# ── Endpoint ───────────────────────────────────────────────────────────────────

@router.post("/dhcp-event", status_code=204)
def dhcp_event(
    body: DhcpEvent,
    db: Session = Depends(get_db),
    _: None = Depends(_verify_internal),
) -> None:
    """Receives lease add/expire events from the Kea run_script hook.

    For each event:
    - Always upserts ClientEntry (client registry)
    - If the scope has ddns_enabled + ddns_zone_id, creates/removes A record
    """
    scope = (
        db.query(DhcpScope)
        .filter(DhcpScope.kea_subnet_id == body.subnet_id)
        .first()
    )
    if scope is None:
        # Subnet not managed by Aegis (shouldn't happen; log and ignore)
        log.debug("dhcp-event: subnet_id=%d not found in dhcp_scopes", body.subnet_id)
        return

    mac = _mac_fmt(body.mac) if body.mac else None
    hostname = body.hostname.strip() or None

    if body.event == "add":
        _upsert_client_entry(db, scope.tenant_id, body.ip, hostname, mac)
        if scope.ddns_enabled and scope.ddns_zone_id and hostname:
            _upsert_a_record(db, scope, hostname, body.ip)

    elif body.event in ("expire", "delete"):
        if scope.ddns_enabled and scope.ddns_zone_id and hostname:
            _delete_a_record(db, scope, hostname, body.ip)

    db.commit()
