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

import socket
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api.dhcp_routers import dhcp_health, list_interfaces
from mantis_control.db.models import Base, DhcpDaemonHeartbeat


def test_list_interfaces_matches_socket_if_nameindex_sorted():
    expected = sorted(name for _, name in socket.if_nameindex())
    assert list_interfaces(user=None) == expected


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[DhcpDaemonHeartbeat.__table__])
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def test_dhcp_health_flags_a_heartbeat_older_than_the_stale_threshold(db):
    now = datetime.now(timezone.utc)
    db.add(DhcpDaemonHeartbeat(instance_id="fresh", family="4", started_at=now, last_seen_at=now))
    db.add(
        DhcpDaemonHeartbeat(
            instance_id="stale", family="6", started_at=now, last_seen_at=now - timedelta(minutes=5)
        )
    )
    db.commit()

    rows = {r.instance_id: r for r in dhcp_health(db=db, user=None)}
    assert rows["fresh"].stale is False
    assert rows["stale"].stale is True


def test_dhcp_health_empty_when_no_instance_has_ever_reported(db):
    assert dhcp_health(db=db, user=None) == []
