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

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control import auth
from mantis_control.api.auth_routers import (
    ChangePasswordRequest,
    UserCreate,
    UserUpdate,
    change_password,
    create_user,
    update_user,
)
from mantis_control.db import models
from mantis_control.db.models import Base, NodeCredential


@pytest.fixture
def node_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[NodeCredential.__table__])
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _add_node(db, node_name="filter-1", token="s3cret", revoked=False):
    db.add(
        NodeCredential(
            node_name=node_name,
            token_hash=auth.hash_node_token(token),
            created_by="admin@mantis.local",
            revoked_at=datetime.now(timezone.utc) if revoked else None,
        )
    )
    db.commit()


def test_require_node_token_rejects_missing_header(node_db):
    """design.md §26 R3: per-node credential replacing the old fleet-wide
    MANTIS_SERVICE_TOKEN — these M2M endpoints (bundle/routing-table/
    public-key/query-events) must fail closed with no header at all."""
    with pytest.raises(HTTPException) as exc:
        auth.require_node_token(authorization=None, x_mantis_node=None, db=node_db)
    assert exc.value.status_code == 403


def test_require_node_token_rejects_unknown_node(node_db):
    with pytest.raises(HTTPException) as exc:
        auth.require_node_token(authorization="Bearer whatever", x_mantis_node="ghost", db=node_db)
    assert exc.value.status_code == 403


def test_require_node_token_rejects_wrong_token(node_db):
    _add_node(node_db)
    with pytest.raises(HTTPException) as exc:
        auth.require_node_token(authorization="Bearer wrong", x_mantis_node="filter-1", db=node_db)
    assert exc.value.status_code == 403


def test_require_node_token_rejects_revoked_credential(node_db):
    """Revoking one node must not require touching any other node's row —
    the whole point of per-node credentials over one shared secret."""
    _add_node(node_db, revoked=True)
    with pytest.raises(HTTPException) as exc:
        auth.require_node_token(authorization="Bearer s3cret", x_mantis_node="filter-1", db=node_db)
    assert exc.value.status_code == 403


def test_require_node_token_accepts_correct_token_and_bumps_last_seen(node_db):
    _add_node(node_db)
    auth.require_node_token(authorization="Bearer s3cret", x_mantis_node="filter-1", db=node_db)
    node = node_db.get(NodeCredential, "filter-1")
    assert node.last_seen_at is not None


def test_require_node_token_rejects_a_different_nodes_token(node_db):
    """A leaked token for one node must not authenticate as another node —
    this is the specific fleet-wide-forgery gap per-node credentials close."""
    _add_node(node_db, node_name="filter-1", token="s3cret-1")
    _add_node(node_db, node_name="filter-2", token="s3cret-2")
    with pytest.raises(HTTPException) as exc:
        auth.require_node_token(authorization="Bearer s3cret-1", x_mantis_node="filter-2", db=node_db)
    assert exc.value.status_code == 403


def test_check_tenant_access_admin_unrestricted():
    admin = _fake_user(role="admin", tenant_id=None)
    auth.check_tenant_access(admin, "some-other-tenant")  # must not raise


def test_check_tenant_access_scoped_user_blocked_on_foreign_tenant():
    user = _fake_user(role="operator", tenant_id="tenant-a")
    with pytest.raises(HTTPException) as exc:
        auth.check_tenant_access(user, "tenant-b")
    assert exc.value.status_code == 403


def test_check_tenant_access_scoped_user_allowed_on_own_tenant():
    user = _fake_user(role="viewer", tenant_id="tenant-a")
    auth.check_tenant_access(user, "tenant-a")  # must not raise


def _fake_user(role: str, tenant_id: str | None):
    class _U:
        pass

    u = _U()
    u.role = role  # type: ignore[attr-defined]
    u.tenant_id = tenant_id  # type: ignore[attr-defined]
    return u


def test_verify_password_correct():
    h = auth.hash_password("a-normal-password-123")
    assert auth.verify_password("a-normal-password-123", h) is True
    assert auth.verify_password("wrong-password", h) is False


def test_verify_password_over_72_bytes_returns_false_not_raise():
    """bcrypt raises ValueError for passwords >72 bytes rather than
    truncating (this bcrypt version) — verify_password must swallow that
    and report "wrong password", not crash the request."""
    h = auth.hash_password("a-normal-password-123")
    too_long = "x" * 100
    assert auth.verify_password(too_long, h) is False


def test_user_create_rejects_password_over_72_bytes():
    with pytest.raises(ValidationError):
        UserCreate(email="a@b.com", password="x" * 100)


def test_user_create_accepts_password_at_72_bytes():
    UserCreate(email="a@b.com", password="x" * 72)  # must not raise


def test_user_create_rejects_password_under_12_chars():
    with pytest.raises(ValidationError):
        UserCreate(email="a@b.com", password="short")


def _fake_admin() -> models.User:
    u = models.User(email="admin@x.com", password_hash="x", role="admin", tenant_id=None)
    u.id = "admin-1"
    return u


def _db_with_no_existing_user() -> MagicMock:
    db = MagicMock()
    db.query.return_value.filter.return_value.one_or_none.return_value = None
    return db


def test_create_user_rejects_non_admin_without_tenant():
    """A non-admin user with tenant_id=None is treated as globally
    unrestricted by check_tenant_access/user_tenant_filter — creation must
    require an explicit tenant for operator/viewer roles."""
    payload = UserCreate(email="viewer@x.com", password="a-strong-password-1", role="viewer", tenant_id=None)
    with pytest.raises(HTTPException) as exc:
        create_user(payload, _db_with_no_existing_user(), _fake_admin())
    assert exc.value.status_code == 422


def test_create_user_allows_non_admin_with_tenant():
    payload = UserCreate(email="viewer@x.com", password="a-strong-password-1", role="viewer", tenant_id="tenant-a")
    user = create_user(payload, _db_with_no_existing_user(), _fake_admin())
    assert user.tenant_id == "tenant-a"


def test_create_user_allows_admin_without_tenant():
    payload = UserCreate(email="admin2@x.com", password="a-strong-password-1", role="admin", tenant_id=None)
    user = create_user(payload, _db_with_no_existing_user(), _fake_admin())
    assert user.tenant_id is None


def test_update_user_rejects_non_admin_without_tenant():
    payload = UserUpdate(role="operator", tenant_id=None)
    db = MagicMock()
    db.get.return_value = models.User(email="x@y.com", password_hash="x", role="viewer", tenant_id="tenant-a")
    with pytest.raises(HTTPException) as exc:
        update_user("user-1", payload, db, _fake_admin())
    assert exc.value.status_code == 422


def test_update_user_allows_admin_without_tenant():
    payload = UserUpdate(role="admin", tenant_id=None)
    db = MagicMock()
    db.get.return_value = models.User(email="x@y.com", password_hash="x", role="viewer", tenant_id="tenant-a")
    updated = update_user("user-1", payload, db, _fake_admin())
    assert updated.role == "admin"


def test_change_password_rejects_too_short():
    with pytest.raises(ValidationError):
        ChangePasswordRequest(current_password="old-password-1", new_password="short")


def test_change_password_rejects_over_72_bytes():
    with pytest.raises(ValidationError):
        ChangePasswordRequest(current_password="old-password-1", new_password="x" * 100)


def test_change_password_accepts_at_72_bytes():
    ChangePasswordRequest(current_password="old-password-1", new_password="x" * 72)  # must not raise


def _fake_user_with_password(password: str) -> models.User:
    u = models.User(email="user@x.com", password_hash=auth.hash_password(password), role="viewer", tenant_id="tenant-a")
    u.id = "user-1"
    return u


def test_change_password_success_updates_hash():
    user = _fake_user_with_password("old-password-123")
    payload = ChangePasswordRequest(current_password="old-password-123", new_password="new-password-456")
    db = MagicMock()
    response = MagicMock()

    change_password(payload, response, db, user)

    assert auth.verify_password("new-password-456", user.password_hash) is True
    assert auth.verify_password("old-password-123", user.password_hash) is False
    db.commit.assert_called_once()


def test_change_password_rejects_wrong_current_password():
    user = _fake_user_with_password("old-password-123")
    payload = ChangePasswordRequest(current_password="totally-wrong-pw", new_password="new-password-456")
    with pytest.raises(HTTPException) as exc:
        change_password(payload, MagicMock(), MagicMock(), user)
    assert exc.value.status_code == 401


def test_change_password_rejects_same_as_current():
    user = _fake_user_with_password("old-password-123")
    payload = ChangePasswordRequest(current_password="old-password-123", new_password="old-password-123")
    with pytest.raises(HTTPException) as exc:
        change_password(payload, MagicMock(), MagicMock(), user)
    assert exc.value.status_code == 400
