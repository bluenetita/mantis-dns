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

"""Tenant delete endpoint. In-memory sqlite with FK enforcement turned on
(off by default in sqlite) so this actually reproduces the IntegrityError a
real Postgres deployment raises when a tenant still owns a DnsZone — mirrors
test_group_crud.py's pattern otherwise.
"""
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from mantis_control.api.routers import delete_tenant
from mantis_control.db.models import (
    AuditLog,
    Base,
    DhcpScope,
    DhcpScope6,
    DnsRecord,
    DnsZone,
    Group,
    Tenant,
)

# delete_tenant queries DhcpScope/DhcpScope6 too — those tables must exist
# even though this test never populates them. Both use postgres's ARRAY type
# for dns_servers, which sqlite's DDL compiler can't render at all; teach it
# to fall back to a plain column since no test here round-trips array data.
@compiles(ARRAY, "sqlite")
def _compile_array_sqlite(element, compiler, **kw):
    return "JSON"


_TABLES = [
    Tenant.__table__,
    Group.__table__,
    DnsZone.__table__,
    DnsRecord.__table__,
    DhcpScope.__table__,
    DhcpScope6.__table__,
    AuditLog.__table__,
]


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_fk(dbapi_connection, _connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine, tables=_TABLES)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def tenant(db) -> Tenant:
    t = Tenant(name="acme")
    db.add(t)
    db.commit()
    return t


class _Admin:
    email = "admin@example.test"
    role = "admin"
    tenant_id = None


def test_delete_tenant_with_no_dependents_succeeds(db, tenant):
    tenant_id = tenant.id
    delete_tenant(tenant_id, db, _Admin())
    assert db.get(Tenant, tenant_id) is None


def test_delete_tenant_owning_a_dns_zone_does_not_500(db, tenant):
    """Regression test: dns_zones.tenant_id is a plain FK with no ON DELETE
    CASCADE and Tenant has no relationship to DnsZone — deleting a tenant
    that still owned a zone used to raise an unhandled IntegrityError."""
    zone = DnsZone(tenant_id=tenant.id, name="corp.example.com", zone_type="local")
    db.add(zone)
    db.commit()
    tenant_id = tenant.id
    zone_id = zone.id

    delete_tenant(tenant_id, db, _Admin())

    assert db.get(Tenant, tenant_id) is None
    assert db.get(DnsZone, zone_id) is None


def test_delete_tenant_cascades_zone_records(db, tenant):
    zone = DnsZone(tenant_id=tenant.id, name="corp.example.com", zone_type="local")
    db.add(zone)
    db.flush()
    record = DnsRecord(zone_id=zone.id, name="www", record_type="A", data="10.0.0.1")
    db.add(record)
    db.commit()
    record_id = record.id

    delete_tenant(tenant.id, db, _Admin())

    assert db.get(DnsRecord, record_id) is None


# No populated-DhcpScope/DhcpScope6 regression test: both carry a postgres
# ARRAY column (dns_servers) that sqlite can bind on write only via
# dialect-specific processors this test harness doesn't stub out. The delete
# loop `delete_tenant` runs for them is mechanically identical to the DnsZone
# loop exercised above (same `db.query(Model).filter(Model.tenant_id ==
# tenant_id).all()` + `db.delete()` pattern) — `test_delete_tenant_with_no_
# dependents_succeeds` already proves both tables are queried without error
# in the (unpopulated) common case.
