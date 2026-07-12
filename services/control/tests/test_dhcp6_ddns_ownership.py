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

"""Regression tests for DHCPv6 DDNS record-ownership enforcement
(dhcp_internal_routers._upsert_aaaa_record / _delete_aaaa_record) — the
DUID-keyed counterpart of test_dhcp_ddns_ownership.py's MAC-keyed v4 tests.
"""
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api.dhcp_internal_routers import _delete_aaaa_record, _upsert_aaaa_record
from mantis_control.db.models import Base, DnsRecord, DnsZone

DUID_A = "00:01:00:01:2a:3b:4c:5d:aa:bb:cc:dd:ee:01"
DUID_B = "00:01:00:01:2a:3b:4c:5d:aa:bb:cc:dd:ee:02"


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[DnsZone.__table__, DnsRecord.__table__])
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def zone(db) -> DnsZone:
    z = DnsZone(name="corp.example.com", zone_type="local", enabled=True)
    db.add(z)
    db.commit()
    return z


def _scope(zone_id: str) -> SimpleNamespace:
    return SimpleNamespace(ddns_zone_id=zone_id, ddns_ttl_s=300)


def _get_record(db, zone_id: str, name: str = "laptop") -> DnsRecord | None:
    return (
        db.query(DnsRecord)
        .filter(DnsRecord.zone_id == zone_id, DnsRecord.name == name, DnsRecord.record_type == "AAAA")
        .one_or_none()
    )


def test_upsert_creates_new_record_owned_by_requesting_client(db, zone):
    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::5", DUID_A)
    db.commit()

    rec = _get_record(db, zone.id)
    assert rec is not None
    assert rec.data == "2001:db8::5"
    assert rec.ddns_owner_duid == DUID_A


def test_upsert_allows_owning_client_to_update_ip(db, zone):
    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::5", DUID_A)
    db.commit()

    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::9", DUID_A)
    db.commit()

    rec = _get_record(db, zone.id)
    assert rec.data == "2001:db8::9"


def test_upsert_rejects_hijack_by_different_client(db, zone):
    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::5", DUID_A)
    db.commit()

    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::66", DUID_B)
    db.commit()

    rec = _get_record(db, zone.id)
    assert rec.data == "2001:db8::5"           # untouched
    assert rec.ddns_owner_duid == DUID_A       # ownership unchanged


def test_upsert_never_overwrites_a_record_with_no_ddns_owner(db, zone):
    db.add(DnsRecord(zone_id=zone.id, name="laptop", record_type="AAAA", data="2001:db8::1", enabled=True))
    db.commit()

    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::99", DUID_A)
    db.commit()

    rec = _get_record(db, zone.id)
    assert rec.data == "2001:db8::1"
    assert rec.ddns_owner_duid is None


def test_delete_removes_record_owned_by_requesting_client(db, zone):
    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::5", DUID_A)
    db.commit()

    _delete_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::5", DUID_A)
    db.commit()

    assert _get_record(db, zone.id) is None


def test_delete_does_not_remove_record_owned_by_a_different_client(db, zone):
    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::5", DUID_A)
    db.commit()

    _delete_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::5", DUID_B)
    db.commit()

    assert _get_record(db, zone.id) is not None


def test_upsert_with_blank_duid_does_not_repoint_owned_record(db, zone):
    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::5", DUID_A)
    db.commit()

    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::66", None)
    db.commit()

    rec = _get_record(db, zone.id)
    assert rec.data == "2001:db8::5"           # untouched
    assert rec.ddns_owner_duid == DUID_A       # ownership unchanged


def test_delete_with_blank_duid_does_not_remove_any_record(db, zone):
    _upsert_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::5", DUID_A)
    db.commit()

    _delete_aaaa_record(db, _scope(zone.id), "laptop", "2001:db8::5", None)
    db.commit()

    assert _get_record(db, zone.id) is not None
