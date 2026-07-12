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

"""ISC Kea DHCP configuration generator and management API client (design.md §22).

`push_full_config()` mirrors Mantis DB state into kea-dhcp4's live subnet4
list using the `subnet_cmds` hook's incremental commands (subnet4-add /
subnet4-update / subnet4-del), diffed against subnet4-list.

This deliberately avoids `config-set`: config-set replaces the *entire*
Dhcp4 config, including control-sockets, and Kea validates a new
control-sockets entry by binding it before releasing the one carrying the
very config-set request that's reconfiguring it. When the address/port is
unchanged (the normal case here — it never changes), that bind always
collides with the listener still serving the current request, so config-set
deterministically fails with "unable to setup TCP acceptor ... Address
already in use" — every push, every time, regardless of threading settings.
subnet_cmds commands never touch control-sockets or hooks-libraries, so this
failure mode doesn't apply to them.

One consequence: hooks-libraries (and therefore HA, which needs libdhcp_ha.so
loaded) can no longer be changed live through this path. Loading a new hook
library still requires updating the static kea-dhcp4.conf and restarting
Kea; toggling `DhcpHaConfig.enabled` updates Mantis's own DB immediately but
does not yet make Kea load/unload the ha hook.

Every write operation (create/update/delete scope or reservation) calls
`push_full_config()` so Kea always mirrors the DB.  A manual
POST /api/v1/dhcp/push endpoint allows operators to re-sync after a Kea
restart without touching data.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, cast

import httpx
from sqlalchemy.orm import Session

from mantis_control.db.models import DhcpScope

log = logging.getLogger(__name__)

KEA_CTRL_URL = os.getenv("KEA_CTRL_URL", "http://kea:8004/")
KEA4_CTRL_URL = os.getenv("KEA4_CTRL_URL", KEA_CTRL_URL)
KEA6_CTRL_URL = os.getenv("KEA6_CTRL_URL", "http://kea:8006/")


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


def _build_option_data(scope: DhcpScope, filter_node_ip: str) -> list[dict[str, Any]]:
    opts: list[dict[str, Any]] = []

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


def _build_reservations(scope: DhcpScope) -> list[dict[str, Any]]:
    result = []
    for sl in scope.static_leases:
        if not sl.enabled:
            continue
        r: dict[str, Any] = {"hw-address": sl.mac_address, "ip-address": sl.ip_address}
        if sl.hostname:
            r["hostname"] = sl.hostname
        if sl.client_id:
            r["client-id"] = sl.client_id
        if sl.next_server:
            r["next-server"] = sl.next_server

        per_res_opts: list[dict[str, Any]] = []
        if sl.boot_filename:
            per_res_opts.append({"name": "boot-file-name", "data": sl.boot_filename})
        for o in sl.options:
            per_res_opts.append({"code": o.option_code, "space": o.option_space, "data": o.value})
        if per_res_opts:
            r["option-data"] = per_res_opts

        result.append(r)
    return result


def _build_subnet4(scope: DhcpScope, kea_id: int, filter_node_ip: str) -> dict[str, Any]:
    """Build a single subnet4 entry, the unit subnet4-add/-update operate on."""
    subnet: dict[str, Any] = {
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

    return subnet


# ── Kea management API client ──────────────────────────────────────────────────

def _command_url(service: list[str] | None) -> str:
    if service and service[0] == "dhcp6":
        return KEA6_CTRL_URL
    return KEA4_CTRL_URL

async def kea_command(
    command: str,
    service: list[str] | None = None,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send a command to Kea and return the first result."""
    url = _command_url(service)
    if not url:
        target = "DHCPv6" if service and service[0] == "dhcp6" else "DHCPv4"
        raise RuntimeError(f"Kea {target} management URL is not configured")

    payload: dict[str, Any] = {"command": command}
    if arguments is not None:
        payload["arguments"] = arguments
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        results: Any = resp.json()
        return cast(dict[str, Any], results[0] if isinstance(results, list) else results)


async def _synced_kea_subnet_ids(service: list[str]) -> set[int]:
    """Kea's live subnet4/subnet6 ids, per subnet-list — the source of truth
    for diffing, since deleted DhcpScope rows leave no local trace of the
    kea_subnet_id they used to occupy."""
    command = "subnet6-list" if service[0] == "dhcp6" else "subnet4-list"
    result = await kea_command(command, service=service)
    if result.get("result") not in (0, 3):  # 3 == CONTROL_RESULT_EMPTY
        raise RuntimeError(f"Kea {command} failed: {result.get('text', result)}")
    subnets = (result.get("arguments") or {}).get("subnets", [])
    return {s["id"] for s in subnets}


async def push_full_config(db: Session) -> None:
    """Sync kea-dhcp4's live subnet4 list to Mantis DB state via subnet_cmds
    (subnet4-add/-update/-del), diffed against subnet4-list. See module
    docstring for why this replaced a config-set-based full push."""
    filter_ip = os.getenv("MANTIS_FILTER_NODE_IP", "")
    scopes = db.query(DhcpScope).filter(DhcpScope.enabled.is_(True)).all()
    kea_ids = _assign_unique_kea_ids(scopes)

    desired: dict[int, dict[str, Any]] = {}
    for scope in scopes:
        kea_id = kea_ids[scope.id]
        desired[kea_id] = _build_subnet4(scope, kea_id, filter_ip)
        scope.kea_subnet_id = kea_id
    db.commit()

    existing_ids = await _synced_kea_subnet_ids(["dhcp4"])

    for kea_id in existing_ids - desired.keys():
        result = await kea_command("subnet4-del", service=["dhcp4"], arguments={"id": kea_id})
        if result.get("result") != 0:
            raise RuntimeError(f"Kea subnet4-del rejected (id={kea_id}): {result.get('text', result)}")

    for kea_id, subnet in desired.items():
        command = "subnet4-update" if kea_id in existing_ids else "subnet4-add"
        result = await kea_command(command, service=["dhcp4"], arguments={"subnet4": [subnet]})
        if result.get("result") != 0:
            raise RuntimeError(f"Kea {command} rejected (id={kea_id}): {result.get('text', result)}")

    now = datetime.now(timezone.utc)
    db.query(DhcpScope).filter(DhcpScope.enabled.is_(True)).update(
        {"last_pushed_at": now}, synchronize_session=False
    )
    db.commit()
    log.info("Kea DHCPv4 subnets synced (%d subnets)", len(desired))


async def try_push(db: Session) -> str | None:
    """Push to Kea; return error string on failure (caller decides how to surface it)."""
    try:
        await push_full_config(db)
        return None
    except Exception as exc:
        log.warning("Kea config push failed: %s", exc)
        return str(exc)
