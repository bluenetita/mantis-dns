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

"""ISC Kea DHCPv6 configuration generator (Sprint 22).

Mirrors kea_config.py for DHCPv4 but targets kea-dhcp6: `push_full_config6()`
syncs kea-dhcp6's live subnet6 list to `DhcpScope6` rows via the
`subnet_cmds` hook's incremental commands (subnet6-add/-update/-del) rather
than a config-set full replace — see kea_config.py's module docstring for
why config-set can't be used here.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from mantis_control.dhcp.kea_config import _synced_kea_subnet_ids, kea_command
from mantis_control.db.models import DhcpScope6

log = logging.getLogger(__name__)


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


def _build_subnet6(scope: DhcpScope6, kea_id: int, filter_node_ip: str) -> dict[str, Any]:
    """Build a single subnet6 entry, the unit subnet6-add/-update operate on."""
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
        "pools": [{"pool": f"{scope.pool_start} - {scope.pool_end}"}],
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

    return sn


async def push_full_config6(db: Session) -> None:
    """Sync kea-dhcp6's live subnet6 list to Mantis DB state via subnet_cmds
    (subnet6-add/-update/-del), diffed against subnet6-list."""
    filter_ip = os.getenv("MANTIS_FILTER_NODE_IP", "")
    scopes = db.query(DhcpScope6).filter(DhcpScope6.enabled.is_(True)).all()
    kea_ids = _assign_unique_kea_ids6(scopes)

    desired: dict[int, dict[str, Any]] = {}
    for scope in scopes:
        kea_id = kea_ids[scope.id]
        desired[kea_id] = _build_subnet6(scope, kea_id, filter_ip)
        scope.kea_subnet_id = kea_id
    db.commit()

    existing_ids = await _synced_kea_subnet_ids(["dhcp6"])

    for kea_id in existing_ids - desired.keys():
        result = await kea_command("subnet6-del", service=["dhcp6"], arguments={"id": kea_id})
        if result.get("result") != 0:
            raise RuntimeError(f"Kea subnet6-del rejected (id={kea_id}): {result.get('text', result)}")

    for kea_id, subnet in desired.items():
        command = "subnet6-update" if kea_id in existing_ids else "subnet6-add"
        result = await kea_command(command, service=["dhcp6"], arguments={"subnet6": [subnet]})
        if result.get("result") != 0:
            raise RuntimeError(f"Kea {command} rejected (id={kea_id}): {result.get('text', result)}")

    now = datetime.now(timezone.utc)
    db.query(DhcpScope6).filter(DhcpScope6.enabled.is_(True)).update(
        {"last_pushed_at": now}, synchronize_session=False
    )
    db.commit()
    log.info("Kea DHCPv6 subnets synced (%d subnets)", len(desired))


async def try_push6(db: Session) -> str | None:
    """Push DHCPv6 config to Kea; return error string on failure."""
    try:
        await push_full_config6(db)
        return None
    except Exception as exc:
        log.warning("Kea DHCPv6 config push failed: %s", exc)
        return str(exc)
