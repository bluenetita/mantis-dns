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

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

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


def test_require_service_token_rejects_everything_when_unset(monkeypatch):
    """An unconfigured MANTIS_SERVICE_TOKEN must fail closed, not open — these
    M2M endpoints (bundle/routing-table/public-key/query-events) would
    otherwise be reachable by anyone on the network in any deployment that
    forgot to set the token."""
    monkeypatch.setattr(auth.settings, "MANTIS_SERVICE_TOKEN", "")
    with pytest.raises(HTTPException) as exc:
        auth.require_service_token(authorization=None)
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException) as exc:
        auth.require_service_token(authorization="Bearer anything")
    assert exc.value.status_code == 403


def test_require_service_token_rejects_missing_header(monkeypatch):
    monkeypatch.setattr(auth.settings, "MANTIS_SERVICE_TOKEN", "s3cret")
    with pytest.raises(HTTPException) as exc:
        auth.require_service_token(authorization=None)
    assert exc.value.status_code == 403


def test_require_service_token_rejects_wrong_token(monkeypatch):
    monkeypatch.setattr(auth.settings, "MANTIS_SERVICE_TOKEN", "s3cret")
    with pytest.raises(HTTPException) as exc:
        auth.require_service_token(authorization="Bearer wrong")
    assert exc.value.status_code == 403


def test_require_service_token_accepts_correct_token(monkeypatch):
    monkeypatch.setattr(auth.settings, "MANTIS_SERVICE_TOKEN", "s3cret")
    auth.require_service_token(authorization="Bearer s3cret")


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
