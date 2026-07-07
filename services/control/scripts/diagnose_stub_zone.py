#!/usr/bin/env python
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

"""Diagnoses why a stub-zone record isn't (or would/wouldn't be) served by a
mantis-filter node, by walking the exact chain the filter node relies on:

    client source IP -> Group (vpn_subnet contains it) -> Group.tenant_id
      -> DnsZone (tenant_id matches, zone_type="local", enabled)
      -> DnsRecord (enabled) -> what GET /api/v1/local-zones would return

Connects directly to DATABASE_URL (same as the API process) - no running
control-plane server required. Read-only: issues no writes.

Usage:
    python scripts/diagnose_stub_zone.py --client-ip 10.8.1.42 --qname passbolt.bluenetworks.lab
    python scripts/diagnose_stub_zone.py --client-ip 10.8.1.42   # list all local records for the matched group
"""
from __future__ import annotations

import argparse
import ipaddress
import sys

from sqlalchemy.orm import sessionmaker

from mantis_control.api.routers import get_local_zone_records
from mantis_control.db import models
from mantis_control.db.session import engine


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--client-ip", required=True, help="Source IP of the querying client (e.g. the OpenVPN peer address)")
    parser.add_argument("--qname", help="FQDN to check, e.g. passbolt.bluenetworks.lab (optional)")
    args = parser.parse_args()

    try:
        client_ip = ipaddress.ip_address(args.client_ip)
    except ValueError as e:
        print(f"invalid --client-ip: {e}", file=sys.stderr)
        return 2

    db = sessionmaker(bind=engine)()
    try:
        return _diagnose(db, client_ip, args.qname)
    finally:
        db.close()


def _diagnose(db, client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, qname: str | None) -> int:
    print(f"1. Matching groups by vpn_subnet containing {client_ip}...")
    groups = db.query(models.Group).filter(models.Group.vpn_subnet.is_not(None)).all()
    matches = []
    for g in groups:
        try:
            net = ipaddress.ip_network(g.vpn_subnet, strict=False)
        except ValueError:
            continue
        if client_ip in net:
            matches.append(g)

    if not matches:
        print(f"   NO GROUP matches. {len(groups)} group(s) have a vpn_subnet set:")
        for g in groups:
            print(f"     - group={g.name!r} id={g.id} tenant_id={g.tenant_id} vpn_subnet={g.vpn_subnet}")
        print("   -> the filter node's routing table (GET /routing-table) will not route this")
        print("      client to ANY group's BundleStore/ZoneStore. Fix: set the group's vpn_subnet")
        print("      to a CIDR that actually covers this client IP.")
        return 1

    if len(matches) > 1:
        print(f"   WARNING: {len(matches)} groups match - longest-prefix wins on the filter node:")
        for g in matches:
            print(f"     - group={g.name!r} id={g.id} vpn_subnet={g.vpn_subnet}")

    group = max(matches, key=lambda g: ipaddress.ip_network(g.vpn_subnet, strict=False).prefixlen)
    print(f"   -> matched group={group.name!r} id={group.id} tenant_id={group.tenant_id} vpn_subnet={group.vpn_subnet}")

    print(f"\n2. Local zones for tenant_id={group.tenant_id}...")
    all_zones = db.query(models.DnsZone).filter(models.DnsZone.tenant_id == group.tenant_id).all()
    if not all_zones:
        print("   NO ZONES at all for this tenant. Create one (zone_type='local') first.")
        return 1
    for z in all_zones:
        flag = "OK" if (z.zone_type == "local" and z.enabled) else "SKIPPED"
        print(f"   [{flag}] zone={z.name!r} zone_type={z.zone_type} enabled={z.enabled} records={len(z.records)}")

    print("\n3. What GET /api/v1/local-zones would actually return for this group:")
    served = get_local_zone_records(group_id=group.id, db=db)
    if not served:
        print("   EMPTY - no local/enabled zone has any enabled record. This is why the filter")
        print("   node's ZoneStore is empty and queries fall through to NXDOMAIN upstream.")
        return 1
    for rec in served:
        print(f"   {rec.name:<40} {rec.record_type:<6} ttl={rec.ttl:<6} {rec.data}")

    if qname:
        qname_norm = qname.rstrip(".").lower()
        hit = [r for r in served if r.name.lower() == qname_norm]
        print(f"\n4. Lookup for {qname!r}:")
        if hit:
            print("   FOUND - the filter node's ZoneStore should answer this authoritatively.")
            for r in hit:
                print(f"     {r.record_type} {r.data}")
        else:
            under_zone = any(qname_norm == z.name or qname_norm.endswith(f".{z.name}") for z in all_zones if z.zone_type == "local" and z.enabled)
            if under_zone:
                print("   NOT FOUND, but qname falls under a local zone -> filter node answers")
                print("   authoritative NXDOMAIN (by design - add the missing record).")
            else:
                print("   NOT FOUND and outside every local zone -> filter node forwards upstream")
                print("   as normal (this is not a stub-zone case at all).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
