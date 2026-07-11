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

"""Regression tests for DDNS record-ownership enforcement
(dhcp_internal_routers._upsert_a_record / _delete_a_record).

Without ownership tracking, any DHCP client can set its hostname option to
an existing name and hijack that name's A record — these events come
straight from a client-supplied DHCP hostname with no authentication beyond
the DHCP handshake itself. Uses an in-memory sqlite DB (only the two tables
under test) rather than mocks, since the functions run real ORM queries
including a bulk `.delete()`.
"""
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api.dhcp_internal_routers import _delete_a_record, _upsert_a_record
from mantis_control.db.models import Base, DnsRecord, DnsZone

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    # Only create the tables under test — other models use postgres-only
    # ARRAY columns that sqlite's dialect can't compile.
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


def _get_record(db, zone_id: str, name: str = "printer") -> DnsRecord | None:
    return (
        db.query(DnsRecord)
        .filter(DnsRecord.zone_id == zone_id, DnsRecord.name == name, DnsRecord.record_type == "A")
        .one_or_none()
    )


def test_upsert_creates_new_record_owned_by_requesting_client(db, zone):
    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.5", MAC_A)
    db.commit()

    rec = _get_record(db, zone.id)
    assert rec is not None
    assert rec.data == "10.0.0.5"
    assert rec.ddns_owner_mac == MAC_A


def test_upsert_allows_owning_client_to_update_ip(db, zone):
    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.5", MAC_A)
    db.commit()

    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.9", MAC_A)
    db.commit()

    rec = _get_record(db, zone.id)
    assert rec.data == "10.0.0.9"


def test_upsert_rejects_hijack_by_different_client(db, zone):
    """A second DHCP client claiming the same hostname must not be able to
    repoint the name to its own IP."""
    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.5", MAC_A)
    db.commit()

    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.66", MAC_B)
    db.commit()

    rec = _get_record(db, zone.id)
    assert rec.data == "10.0.0.5"          # untouched
    assert rec.ddns_owner_mac == MAC_A     # ownership unchanged


def test_upsert_never_overwrites_a_record_with_no_ddns_owner(db, zone):
    """A record created through the normal zone-editing API (ddns_owner_mac
    is NULL) must never be silently repointed by a DHCP client claiming the
    same name."""
    db.add(DnsRecord(zone_id=zone.id, name="printer", record_type="A", data="10.0.0.1", enabled=True))
    db.commit()

    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.99", MAC_A)
    db.commit()

    rec = _get_record(db, zone.id)
    assert rec.data == "10.0.0.1"
    assert rec.ddns_owner_mac is None


def test_delete_removes_record_owned_by_requesting_client(db, zone):
    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.5", MAC_A)
    db.commit()

    _delete_a_record(db, _scope(zone.id), "printer", "10.0.0.5", MAC_A)
    db.commit()

    assert _get_record(db, zone.id) is None


def test_delete_does_not_remove_record_owned_by_a_different_client(db, zone):
    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.5", MAC_A)
    db.commit()

    # Even if a different client's expire event somehow carried the same ip,
    # it must not be able to delete a record it doesn't own.
    _delete_a_record(db, _scope(zone.id), "printer", "10.0.0.5", MAC_B)
    db.commit()

    assert _get_record(db, zone.id) is not None


def test_upsert_with_blank_mac_does_not_repoint_owned_record(db, zone):
    """A lease event missing HWADDR (blank mac) must be treated as an
    unverifiable, different owner — not as "skip the ownership check"."""
    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.5", MAC_A)
    db.commit()

    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.66", None)
    db.commit()

    rec = _get_record(db, zone.id)
    assert rec.data == "10.0.0.5"          # untouched
    assert rec.ddns_owner_mac == MAC_A     # ownership unchanged


def test_delete_with_blank_mac_does_not_remove_any_record(db, zone):
    """An expire/delete event without a mac can't prove ownership, so it must
    not delete anything — not a DDNS-owned record, and not a record created
    by hand through the zone API (ddns_owner_mac NULL) either."""
    _upsert_a_record(db, _scope(zone.id), "printer", "10.0.0.5", MAC_A)
    db.commit()

    _delete_a_record(db, _scope(zone.id), "printer", "10.0.0.5", None)
    db.commit()

    assert _get_record(db, zone.id) is not None
