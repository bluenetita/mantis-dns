"""ISC Kea DHCPv6 configuration generator (Sprint 22).

Mirrors kea_config.py for DHCPv4 but targets kea-dhcp6 via the same Control
Agent (service=["dhcp6"]).  `build_dhcp6_config()` translates `DhcpScope6`
rows to a full Kea Dhcp6 JSON and `push_full_config6()` ships it atomically.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from mantis_control.dhcp.kea_config import kea_command
from mantis_control.db.models import DhcpScope6

log = logging.getLogger(__name__)

_PG_CFG = {
    "name": os.getenv("POSTGRES_DB", "mantis"),
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "user": os.getenv("POSTGRES_USER", "mantis"),
    "password": os.getenv("POSTGRES_PASSWORD", "mantis"),
}


def _scope_kea_id6(scope_uuid: str) -> int:
    """Stable Kea subnet6.id from UUID — same algo as v4, different namespace."""
    return int(scope_uuid.replace("-", "")[7:14], 16) % (2 ** 30)


def _assign_unique_kea_ids6(scopes: list[DhcpScope6]) -> dict[str, int]:
    """Resolves collisions from `_scope_kea_id6`'s truncated hash by linear-
    probing to the next free slot — see kea_config.py's `_assign_unique_kea_ids`
    for why an unresolved collision is a real problem (Kea rejects duplicate
    subnet ids; lease-read queries key on kea_subnet_id)."""
    assigned: dict[str, int] = {}
    used: set[int] = set()
    modulus = 2 ** 30
    for scope in scopes:
        candidate = _scope_kea_id6(scope.id)
        while candidate in used:
            candidate = (candidate + 1) % modulus
        used.add(candidate)
        assigned[scope.id] = candidate
    return assigned


def _build_option_data6(scope: DhcpScope6, filter_node_ip: str) -> list[dict[str, Any]]:
    opts: list[dict[str, Any]] = []
    dns = list(scope.dns_servers or [])
    if not dns and filter_node_ip:
        dns = [filter_node_ip]
    if dns:
        opts.append({"name": "dns-servers", "data": ", ".join(dns)})
    if scope.domain_name:
        opts.append({"name": "domain-search", "data": scope.domain_name})
    return opts


def _build_reservations6(scope: DhcpScope6) -> list[dict[str, Any]]:
    result = []
    for r in scope.reservations6:
        if not r.enabled:
            continue
        entry: dict[str, Any] = {"duid": r.duid, "ip-addresses": [r.ip_address]}
        if r.hostname:
            entry["hostname"] = r.hostname
        result.append(entry)
    return result


def build_dhcp6_config(db: Session, filter_node_ip: str = "") -> dict[str, Any]:
    """Build the full Kea Dhcp6 config dict from Mantis DB state."""
    scopes = db.query(DhcpScope6).filter(DhcpScope6.enabled.is_(True)).all()

    kea_ids = _assign_unique_kea_ids6(scopes)
    subnet6 = []
    for scope in scopes:
        kea_id = kea_ids[scope.id]
        pools = [{"pool": f"{scope.pool_start} - {scope.pool_end}"}]

        pd_pools = []
        if scope.pd_prefix and scope.pd_prefix_len is not None:
            pd_pools.append({
                "prefix": scope.pd_prefix,
                "prefix-len": scope.pd_prefix_len,
                "delegated-len": scope.pd_prefix_len,
            })

        sn: dict[str, Any] = {
            "id": kea_id,
            "subnet": scope.subnet,
            "pools": pools,
            "preferred-lifetime": scope.preferred_lifetime_s,
            "valid-lifetime": scope.valid_lifetime_s,
            "option-data": _build_option_data6(scope, filter_node_ip),
            "reservations": _build_reservations6(scope),
        }
        if pd_pools:
            sn["pd-pools"] = pd_pools
        if scope.renew_time_s is not None:
            sn["renew-timer"] = scope.renew_time_s
        if scope.rebind_time_s is not None:
            sn["rebind-timer"] = scope.rebind_time_s
        if scope.interface:
            sn["interface"] = scope.interface

        subnet6.append(sn)
        scope.kea_subnet_id = kea_id

    db.commit()

    return {
        "Dhcp6": {
            "interfaces-config": {"interfaces": ["*"]},
            "lease-database": {"type": "postgresql", **_PG_CFG},
            "control-socket": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea6-ctrl-socket",
            },
            "expired-leases-processing": {
                "reclaim-timer-wait-time": 10,
                "flush-reclaimed-timer-wait-time": 25,
                "hold-reclaimed-time": 3600,
                "max-reclaim-leases": 100,
                "max-reclaim-time": 250,
            },
            "preferred-lifetime": 3000,
            "valid-lifetime": 4000,
            "renew-timer": 1000,
            "rebind-timer": 2000,
            "subnet6": subnet6,
            "loggers": [{
                "name": "kea-dhcp6",
                "output_options": [{"output": "stdout", "pattern": "%-5p %m\n"}],
                "severity": "INFO",
            }],
        }
    }


async def push_full_config6(db: Session) -> None:
    """Push the complete Kea DHCPv6 config atomically via config-set."""
    filter_ip = os.getenv("MANTIS_FILTER_NODE_IP", "")
    config = build_dhcp6_config(db, filter_ip)

    result = await kea_command("config-set", service=["dhcp6"], arguments=config)
    if result.get("result") != 0:
        raise RuntimeError(f"Kea DHCPv6 config-set rejected: {result.get('text', result)}")

    now = datetime.now(timezone.utc)
    db.query(DhcpScope6).filter(DhcpScope6.enabled.is_(True)).update(
        {"last_pushed_at": now}, synchronize_session=False
    )
    db.commit()
    log.info("Kea DHCPv6 config pushed (%d subnets)", len(config["Dhcp6"]["subnet6"]))


async def try_push6(db: Session) -> str | None:
    """Push DHCPv6 config to Kea; return error string on failure."""
    try:
        await push_full_config6(db)
        return None
    except Exception as exc:
        log.warning("Kea DHCPv6 config push failed: %s", exc)
        return str(exc)
