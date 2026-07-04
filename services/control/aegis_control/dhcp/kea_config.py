"""ISC Kea DHCP configuration generator and Control Agent client (design.md §22).

`build_dhcp4_config()` translates Aegis shadow DB state to a full Kea Dhcp4
JSON structure.  `push_full_config()` ships it via the Control Agent REST API
using the `config-set` command, which replaces the running config atomically.

Every write operation (create/update/delete scope or reservation) calls
`push_full_config()` so Kea always mirrors the DB.  A manual
POST /api/v1/dhcp/push endpoint allows operators to re-sync after a Kea
restart without touching data.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from ipaddress import ip_network

import httpx
from sqlalchemy.orm import Session

from aegis_control.db.models import DhcpHaConfig, DhcpScope

log = logging.getLogger(__name__)

KEA_CTRL_URL = os.getenv("KEA_CTRL_URL", "http://kea:8080/")

_PG_CFG = {
    "name": os.getenv("POSTGRES_DB", "aegis"),
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "user": os.getenv("POSTGRES_USER", "aegis"),
    "password": os.getenv("POSTGRES_PASSWORD", "aegis"),
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _scope_kea_id(scope_uuid: str) -> int:
    """Stable positive integer Kea subnet4.id derived deterministically from UUID."""
    return int(scope_uuid.replace("-", "")[:7], 16) % (2 ** 30)


def _assign_unique_kea_ids(scopes: list[DhcpScope]) -> dict[str, int]:
    """Maps scope.id -> kea_subnet_id, resolving collisions from `_scope_kea_id`'s
    truncated hash (28 bits — a real collision risk once there are thousands of
    scopes) by linear-probing to the next free slot. Without this, two scopes
    (possibly different tenants) could be pushed to Kea with the same
    subnet4.id, which Kea would reject outright, or worse, would cause
    /dhcp/leases and lease-sync queries (which key on kea_subnet_id) to
    mis-attribute one tenant's leases to another."""
    assigned: dict[str, int] = {}
    used: set[int] = set()
    modulus = 2 ** 30
    for scope in scopes:
        candidate = _scope_kea_id(scope.id)
        while candidate in used:
            candidate = (candidate + 1) % modulus
        used.add(candidate)
        assigned[scope.id] = candidate
    return assigned


def _build_option_data(scope: DhcpScope, filter_node_ip: str) -> list[dict]:
    opts: list[dict] = []

    if scope.router_ip:
        opts.append({"name": "routers", "data": scope.router_ip})

    dns = list(scope.dns_servers or [])
    if not dns and filter_node_ip:
        dns = [filter_node_ip]
    if dns:
        opts.append({"name": "domain-name-servers", "data": ", ".join(dns)})

    if scope.ntp_server:
        opts.append({"name": "ntp-servers", "data": scope.ntp_server})

    if scope.domain_name:
        opts.append({"name": "domain-name", "data": scope.domain_name})

    for o in scope.options:
        opts.append({
            "code": o.option_code,
            "space": o.option_space,
            "data": o.value,
            "always-send": o.always_send,
        })

    return opts


def _build_reservations(scope: DhcpScope) -> list[dict]:
    result = []
    for sl in scope.static_leases:
        if not sl.enabled:
            continue
        r: dict = {"hw-address": sl.mac_address, "ip-address": sl.ip_address}
        if sl.hostname:
            r["hostname"] = sl.hostname
        if sl.client_id:
            r["client-id"] = sl.client_id
        if sl.next_server:
            r["next-server"] = sl.next_server

        per_res_opts: list[dict] = []
        if sl.boot_filename:
            per_res_opts.append({"name": "boot-file-name", "data": sl.boot_filename})
        for o in sl.options:
            per_res_opts.append({"code": o.option_code, "space": o.option_space, "data": o.value})
        if per_res_opts:
            r["option-data"] = per_res_opts

        result.append(r)
    return result


# ── HA hooks block builder ─────────────────────────────────────────────────────

def _build_ha_hooks(ha: "DhcpHaConfig") -> list[dict]:
    """Return the two Kea hook library entries needed for HA (lease_cmds + ha)."""
    return [
        {"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"},
        {
            "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
            "parameters": {
                "high-availability": [{
                    "this-server-name": ha.this_server_name,
                    "mode": ha.mode,
                    "heartbeat-delay": ha.heartbeat_delay_ms if ha.heartbeat_delay_ms is not None else 10000,
                    "max-response-delay": (ha.max_ack_delay_ms if ha.max_ack_delay_ms is not None else 10000) * 2,
                    "max-ack-delay": ha.max_ack_delay_ms if ha.max_ack_delay_ms is not None else 10000,
                    "max-unacked-clients": ha.max_unacked_clients if ha.max_unacked_clients is not None else 10,
                    "peers": [
                        {
                            "name": ha.this_server_name,
                            "url": ha.this_server_url,
                            "role": "primary" if ha.peer_role == "standby" else "standby",
                        },
                        {
                            "name": ha.peer_name,
                            "url": ha.peer_url,
                            "role": ha.peer_role,
                        },
                    ],
                }]
            },
        },
    ]


# ── Config builder ─────────────────────────────────────────────────────────────

def build_dhcp4_config(db: Session, filter_node_ip: str = "") -> dict:
    """Build the full Kea Dhcp4 config dict from Aegis DB state."""
    scopes = db.query(DhcpScope).filter(DhcpScope.enabled.is_(True)).all()

    # Collect enabled HA configs across all tenants represented in active scopes
    ha_hooks: list[dict] = []
    if scopes:
        tenant_ids = list({s.tenant_id for s in scopes})
        ha_cfg = (
            db.query(DhcpHaConfig)
            .filter(
                DhcpHaConfig.tenant_id.in_(tenant_ids),
                DhcpHaConfig.enabled.is_(True),
            )
            .first()
        )
        if ha_cfg:
            ha_hooks = _build_ha_hooks(ha_cfg)

    kea_ids = _assign_unique_kea_ids(scopes)
    subnet4 = []
    for scope in scopes:
        kea_id = kea_ids[scope.id]
        subnet: dict = {
            "id": kea_id,
            "subnet": scope.subnet,
            "pools": [{"pool": f"{scope.range_start} - {scope.range_end}"}],
            "valid-lifetime": scope.lease_time_s,
            "max-valid-lifetime": scope.max_lease_time_s,
            "option-data": _build_option_data(scope, filter_node_ip),
            "reservations": _build_reservations(scope),
        }
        if scope.renew_time_s is not None:
            subnet["renew-timer"] = scope.renew_time_s
        if scope.rebind_time_s is not None:
            subnet["rebind-timer"] = scope.rebind_time_s
        if scope.interface:
            subnet["interface"] = scope.interface
        if scope.pxe_next_server:
            subnet["next-server"] = scope.pxe_next_server
        if scope.pxe_boot_filename:
            subnet["boot-file-name"] = scope.pxe_boot_filename

        relay_ips = [r.relay_ip for r in scope.relay_configs]
        if relay_ips:
            subnet["relay"] = {"ip-addresses": relay_ips}

        subnet4.append(subnet)
        scope.kea_subnet_id = kea_id

    db.commit()

    return {
        "Dhcp4": {
            "interfaces-config": {"interfaces": ["*"], "dhcp-socket-type": "udp"},
            "hooks-libraries": ha_hooks,
            "lease-database": {"type": "postgresql", **_PG_CFG},
            "control-socket": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea4-ctrl-socket",
            },
            "expired-leases-processing": {
                "reclaim-timer-wait-time": 10,
                "flush-reclaimed-timer-wait-time": 25,
                "hold-reclaimed-time": 3600,
                "max-reclaim-leases": 100,
                "max-reclaim-time": 250,
            },
            "valid-lifetime": 86400,
            "renew-timer": 43200,
            "rebind-timer": 75600,
            "subnet4": subnet4,
            "loggers": [{
                "name": "kea-dhcp4",
                "output_options": [{"output": "stdout", "pattern": "%-5p %m\n"}],
                "severity": "INFO",
            }],
        }
    }


# ── Control Agent client ───────────────────────────────────────────────────────

async def kea_command(
    command: str,
    service: list[str] | None = None,
    arguments: dict | None = None,
) -> dict:
    """Send a command to the Kea Control Agent and return the first result."""
    payload: dict = {"command": command}
    if service is not None:
        payload["service"] = service
    if arguments is not None:
        payload["arguments"] = arguments
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(KEA_CTRL_URL, json=payload)
        resp.raise_for_status()
        results = resp.json()
        return results[0] if isinstance(results, list) else results


async def push_full_config(db: Session) -> None:
    """Push the complete Kea DHCPv4 config atomically via config-set."""
    filter_ip = os.getenv("AEGIS_FILTER_NODE_IP", "")
    config = build_dhcp4_config(db, filter_ip)

    result = await kea_command("config-set", service=["dhcp4"], arguments=config)
    if result.get("result") != 0:
        raise RuntimeError(f"Kea config-set rejected: {result.get('text', result)}")

    now = datetime.now(timezone.utc)
    db.query(DhcpScope).filter(DhcpScope.enabled.is_(True)).update(
        {"last_pushed_at": now}, synchronize_session=False
    )
    db.commit()
    log.info("Kea DHCPv4 config pushed successfully (%d subnets)", len(config["Dhcp4"]["subnet4"]))


async def try_push(db: Session) -> str | None:
    """Push to Kea; return error string on failure (caller decides how to surface it)."""
    try:
        await push_full_config(db)
        return None
    except Exception as exc:
        log.warning("Kea config push failed: %s", exc)
        return str(exc)
