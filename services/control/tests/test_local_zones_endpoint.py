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

"""Regression tests for GET /api/v1/local-zones (mantis_control.api.routers.
get_local_zone_records) — the flattened zone-record feed the mantis-filter
stub-zone store polls. Uses an in-memory sqlite DB (only the tables under
test) since the endpoint runs real ORM queries and relationship loads."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api.routers import get_local_zone_records
from mantis_control.db.models import Base, DnsRecord, DnsZone, Group, NodeCredential, Tenant


def _node() -> NodeCredential:
    return NodeCredential(
        node_name="test",
        token_hash="x",
        created_by="test",
        allow_all=True,
    )


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(
        engine, tables=[Tenant.__table__, Group.__table__, DnsZone.__table__, DnsRecord.__table__]
    )
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def tenant_and_group(db) -> Group:
    t = Tenant(name="acme")
    db.add(t)
    db.flush()
    g = Group(tenant_id=t.id, name="default")
    db.add(g)
    db.commit()
    return g


def test_returns_records_for_apex_and_subdomain(db, tenant_and_group):
    zone = DnsZone(tenant_id=tenant_and_group.tenant_id, name="bluenetworks.lab", zone_type="local", enabled=True)
    db.add(zone)
    db.flush()
    db.add(DnsRecord(zone_id=zone.id, name="@", record_type="A", data="10.0.0.1", enabled=True))
    db.add(DnsRecord(zone_id=zone.id, name="passbolt", record_type="A", data="10.0.0.2", enabled=True))
    db.commit()

    out = get_local_zone_records(group_id=tenant_and_group.id, db=db, node=_node())

    names = {r.name for r in out}
    assert names == {"bluenetworks.lab", "passbolt.bluenetworks.lab"}


def test_zone_gets_a_synthesized_apex_soa_and_ns(db, tenant_and_group):
    """A4/B9 (docs/rfc-compliance.md): every zone needs an authoritative SOA
    so mantis-filter can put one in a negative answer's authority section —
    synthesized here since there's no admin-facing way to author one
    ("SOA" isn't in zone_routers._RECORD_TYPES)."""
    zone = DnsZone(tenant_id=tenant_and_group.tenant_id, name="bluenetworks.lab", zone_type="local", enabled=True)
    db.add(zone)
    db.commit()

    out = get_local_zone_records(group_id=tenant_and_group.id, db=db, node=_node())
    by_type = {r.record_type: r for r in out}

    assert set(by_type) == {"SOA", "NS"}
    assert by_type["SOA"].name == "bluenetworks.lab"
    assert by_type["SOA"].data.startswith("ns1.bluenetworks.lab. hostmaster.bluenetworks.lab. ")
    assert by_type["NS"].data == "ns1.bluenetworks.lab."


def test_explicit_apex_ns_record_suppresses_the_synthesized_one(db, tenant_and_group):
    zone = DnsZone(tenant_id=tenant_and_group.tenant_id, name="bluenetworks.lab", zone_type="local", enabled=True)
    db.add(zone)
    db.flush()
    db.add(DnsRecord(zone_id=zone.id, name="@", record_type="NS", data="ns.elsewhere.example.", enabled=True))
    db.commit()

    out = get_local_zone_records(group_id=tenant_and_group.id, db=db, node=_node())
    ns_records = [r for r in out if r.record_type == "NS"]
    assert len(ns_records) == 1
    assert ns_records[0].data == "ns.elsewhere.example."


def test_disabled_record_is_excluded(db, tenant_and_group):
    zone = DnsZone(tenant_id=tenant_and_group.tenant_id, name="bluenetworks.lab", zone_type="local", enabled=True)
    db.add(zone)
    db.flush()
    db.add(DnsRecord(zone_id=zone.id, name="old", record_type="A", data="10.0.0.9", enabled=False))
    db.commit()

    out = get_local_zone_records(group_id=tenant_and_group.id, db=db, node=_node())
    # The disabled record itself must not appear — but the zone still gets
    # its synthesized apex SOA/NS (A4/B9) regardless of whether any of its
    # explicit records are enabled, so the feed isn't empty outright.
    assert "old.bluenetworks.lab" not in {r.name for r in out}
    assert {r.record_type for r in out} == {"SOA", "NS"}


def test_disabled_zone_is_excluded(db, tenant_and_group):
    zone = DnsZone(tenant_id=tenant_and_group.tenant_id, name="bluenetworks.lab", zone_type="local", enabled=False)
    db.add(zone)
    db.flush()
    db.add(DnsRecord(zone_id=zone.id, name="www", record_type="A", data="10.0.0.9", enabled=True))
    db.commit()

    assert get_local_zone_records(group_id=tenant_and_group.id, db=db, node=_node()) == []


def test_forward_and_passthrough_zones_are_excluded(db, tenant_and_group):
    """Only 'local' zones are hosted authoritatively by the filter node —
    'forward'/'passthrough' zones route to an external server instead."""
    zone = DnsZone(tenant_id=tenant_and_group.tenant_id, name="corp.example.com", zone_type="forward", enabled=True)
    db.add(zone)
    db.flush()
    db.add(DnsRecord(zone_id=zone.id, name="www", record_type="A", data="10.0.0.9", enabled=True))
    db.commit()

    assert get_local_zone_records(group_id=tenant_and_group.id, db=db, node=_node()) == []


def test_record_ttl_falls_back_to_zone_default(db, tenant_and_group):
    zone = DnsZone(
        tenant_id=tenant_and_group.tenant_id, name="lab", zone_type="local", enabled=True, ttl_default=600
    )
    db.add(zone)
    db.flush()
    db.add(DnsRecord(zone_id=zone.id, name="a", record_type="A", data="10.0.0.1", ttl=None, enabled=True))
    db.add(DnsRecord(zone_id=zone.id, name="b", record_type="A", data="10.0.0.2", ttl=60, enabled=True))
    db.commit()

    out = {
        r.name: r.ttl
        for r in get_local_zone_records(
            group_id=tenant_and_group.id, db=db, node=_node()
        )
    }
    assert out["a.lab"] == 600
    assert out["b.lab"] == 60


def test_unknown_group_returns_404(db):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        get_local_zone_records(group_id="does-not-exist", db=db, node=_node())
    assert exc.value.status_code == 404


def test_zones_from_other_tenant_are_excluded(db, tenant_and_group):
    other = Tenant(name="other-co")
    db.add(other)
    db.flush()
    zone = DnsZone(tenant_id=other.id, name="other.example.com", zone_type="local", enabled=True)
    db.add(zone)
    db.flush()
    db.add(DnsRecord(zone_id=zone.id, name="www", record_type="A", data="10.0.0.9", enabled=True))
    db.commit()

    assert get_local_zone_records(group_id=tenant_and_group.id, db=db, node=_node()) == []
