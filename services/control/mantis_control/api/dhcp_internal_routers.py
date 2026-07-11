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

"""Internal DHCP event endpoint — called by the Kea run_script hook via
mantis-ddns-bridge.sh (design.md §22, Sprint 20).

Authentication: X-Internal-Token header (MANTIS_INTERNAL_TOKEN env var).
Not exposed in the public API docs and never reaches user-facing clients.
"""
from __future__ import annotations

import hmac
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi import Depends

from mantis_control.config import settings
from mantis_control.db.models import ClientEntry, DhcpScope, DnsRecord, DnsZone
from mantis_control.db.session import get_db

router = APIRouter(prefix="/internal", tags=["internal"])
log = logging.getLogger(__name__)

def _verify_internal(x_internal_token: str | None = Header(None)) -> None:
    if not x_internal_token or not hmac.compare_digest(x_internal_token, settings.MANTIS_INTERNAL_TOKEN):
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


def _upsert_a_record(db: Session, scope: DhcpScope, hostname: str, ip: str, mac: str | None) -> None:
    """Creates/updates the A record for `hostname`, refusing to clobber a
    name owned by a *different* client. Without this, a DHCP client could set
    its hostname option to an existing name (another host's "printer", or a
    name an admin created by hand through the zone API) and hijack that
    name's A record — every event here comes straight from a client-supplied
    DHCP hostname, unauthenticated beyond the DHCP handshake itself.
    """
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
        if existing.ddns_owner_mac is None:
            log.info("DDNS update for %s/%s ignored: record was not created via DDNS", zone.name, name)
            return
        if existing.ddns_owner_mac != mac:
            log.warning(
                "DDNS update for %s/%s ignored: owned by a different client (%s != %s)",
                zone.name, name, existing.ddns_owner_mac, mac,
            )
            return
        existing.data = ip
        existing.updated_at = now
        if mac:
            existing.ddns_owner_mac = mac
    else:
        db.add(DnsRecord(
            zone_id=zone.id,
            name=name,
            record_type="A",
            data=ip,
            ttl=scope.ddns_ttl_s,
            enabled=True,
            ddns_owner_mac=mac,
        ))
    zone.updated_at = now  # signal filter to refresh zone


def _delete_a_record(db: Session, scope: DhcpScope, hostname: str, ip: str, mac: str | None) -> None:
    zone = db.get(DnsZone, scope.ddns_zone_id)
    if zone is None:
        return
    name = _rel_hostname(hostname, zone.name)
    if not name:
        return

    if not mac:
        # Without a mac we can't verify ownership at all — refuse to delete
        # anything rather than matching on zone/name/ip alone, which would
        # let a blank-mac expire event remove another client's DDNS record,
        # or even a record created by hand through the zone API (ip reuse
        # across clients is common enough on DHCP networks).
        return

    filters = [
        DnsRecord.zone_id == zone.id,
        DnsRecord.name == name,
        DnsRecord.record_type == "A",
        DnsRecord.data == ip,
        # Don't let a different client's expire/delete event remove a record
        # it doesn't own even if it somehow supplied the matching ip.
        DnsRecord.ddns_owner_mac == mac,
    ]

    deleted = db.query(DnsRecord).filter(*filters).delete()
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
        # Subnet not managed by Mantis (shouldn't happen; log and ignore)
        log.debug("dhcp-event: subnet_id=%d not found in dhcp_scopes", body.subnet_id)
        return

    mac = _mac_fmt(body.mac) if body.mac else None
    hostname = body.hostname.strip() or None

    if body.event == "add":
        _upsert_client_entry(db, scope.tenant_id, body.ip, hostname, mac)
        if scope.ddns_enabled and scope.ddns_zone_id and hostname:
            _upsert_a_record(db, scope, hostname, body.ip, mac)

    elif body.event in ("expire", "delete"):
        if scope.ddns_enabled and scope.ddns_zone_id and hostname:
            _delete_a_record(db, scope, hostname, body.ip, mac)

    db.commit()
