"""DhcpLeaseSyncLoop — periodically reads Kea's lease4 table and upserts
ClientEntry rows so the client registry stays current without relying solely
on the DDNS bridge (which only fires on new leases, not pre-existing ones).

Scheduled via APScheduler in main.py (default interval: 60 s).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from mantis_control.db.models import ClientEntry, DhcpScope

log = logging.getLogger(__name__)


def _bigint_to_ip(n: int) -> str:
    return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def _mac_fmt(raw_bytes: bytes | None) -> str | None:
    if not raw_bytes:
        return None
    return ":".join(f"{b:02x}" for b in raw_bytes)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def sync_dhcp_leases(db: Session) -> int:
    """Read active leases from Kea's lease4 table; upsert ClientEntry rows.

    Returns count of entries touched.  Silently returns 0 if the lease4 table
    does not yet exist (Kea not started or schema not initialised).
    """
    scopes = (
        db.query(DhcpScope)
        .filter(DhcpScope.kea_subnet_id.isnot(None), DhcpScope.enabled.is_(True))
        .all()
    )
    if not scopes:
        return 0

    subnet_id_map: dict[int, DhcpScope] = {s.kea_subnet_id: s for s in scopes}  # type: ignore[misc]

    try:
        rows = db.execute(
            text("""
                SELECT address, hwaddr, hostname, subnet_id
                FROM lease4
                WHERE state = 0
                  AND expire > now()
                  AND subnet_id = ANY(:sids)
            """),
            {"sids": list(subnet_id_map.keys())},
        ).mappings().all()
    except Exception as exc:
        log.debug("lease_sync: lease4 query failed (Kea not running?): %s", exc)
        return 0

    now = _now()
    touched = 0

    for row in rows:
        scope = subnet_id_map.get(row["subnet_id"])
        if scope is None:
            continue

        ip = _bigint_to_ip(row["address"])
        hostname = row["hostname"] or None

        entry = (
            db.query(ClientEntry)
            .filter(ClientEntry.tenant_id == scope.tenant_id, ClientEntry.ip == ip)
            .first()
        )
        if entry:
            if hostname and not entry.hostname:
                entry.hostname = hostname
            entry.last_seen = now
        else:
            db.add(ClientEntry(
                tenant_id=scope.tenant_id,
                ip=ip,
                hostname=hostname,
                last_seen=now,
            ))

        touched += 1

    if touched:
        db.commit()

    return touched
