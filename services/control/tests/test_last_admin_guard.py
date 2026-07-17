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

"""update_user must refuse to demote the last remaining admin — otherwise a
deployment can end up with zero admin users and no way back in short of a
direct DB edit. In-memory sqlite, mirroring test_group_crud.py."""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api.auth_routers import UserUpdate, update_user
from mantis_control.db.models import AuditLog, Base, User

_TABLES = [User.__table__, AuditLog.__table__]


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=_TABLES)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _make_user(db, *, email: str, role: str, tenant_id: str | None = None) -> User:
    u = User(email=email, password_hash="x", role=role, tenant_id=tenant_id)
    db.add(u)
    db.commit()
    return u


def test_demoting_sole_admin_by_self_is_rejected(db):
    admin = _make_user(db, email="admin@example.test", role="admin")

    with pytest.raises(HTTPException) as exc_info:
        update_user(admin.id, UserUpdate(role="operator", tenant_id="t1"), db, admin)
    assert exc_info.value.status_code == 400

    db.refresh(admin)
    assert admin.role == "admin"


class _NonPersistedAdmin:
    """Stands in for a *different* admin actor without adding a second row to
    the users table — see test_group_crud.py's `_User` for the same pattern.
    Only the target row (persisted below) counts toward the admin tally, so
    this exercises "the only admin *row* is being demoted", regardless of
    who the caller is."""

    id = "not-the-target-row"
    email = "actor@example.test"
    role = "admin"
    tenant_id = None


def test_demoting_sole_admin_by_a_different_actor_is_rejected(db):
    """Same guard applies even when a *different* admin performs the
    demotion — the invariant is "at least one admin row exists", not
    "an admin can't touch their own account" (that's delete_user's
    self-delete guard, a separate check)."""
    sole_admin = _make_user(db, email="admin@example.test", role="admin")

    with pytest.raises(HTTPException) as exc_info:
        update_user(sole_admin.id, UserUpdate(role="viewer", tenant_id="t1"), db, _NonPersistedAdmin())
    assert exc_info.value.status_code == 400


def test_demoting_one_of_several_admins_is_allowed(db):
    admin_a = _make_user(db, email="a@example.test", role="admin")
    _make_user(db, email="b@example.test", role="admin")

    result = update_user(admin_a.id, UserUpdate(role="viewer", tenant_id="t1"), db, admin_a)
    assert result.role == "viewer"


def test_promoting_or_updating_a_non_admin_is_unaffected(db):
    admin = _make_user(db, email="admin@example.test", role="admin")
    viewer = _make_user(db, email="viewer@example.test", role="viewer", tenant_id="t1")

    result = update_user(viewer.id, UserUpdate(role="operator", tenant_id="t1"), db, admin)
    assert result.role == "operator"
