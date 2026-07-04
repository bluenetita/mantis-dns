from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from aegis_control import auth
from aegis_control.api.auth_routers import UserCreate, UserUpdate, create_user, update_user
from aegis_control.db import models


def test_require_service_token_open_when_unset(monkeypatch):
    """Dev default: no AEGIS_SERVICE_TOKEN configured -> endpoint stays open."""
    monkeypatch.setattr(auth, "_SERVICE_TOKEN", "")
    auth.require_service_token(x_aegis_service_token=None)
    auth.require_service_token(x_aegis_service_token="anything")


def test_require_service_token_rejects_missing_header(monkeypatch):
    monkeypatch.setattr(auth, "_SERVICE_TOKEN", "s3cret")
    with pytest.raises(HTTPException) as exc:
        auth.require_service_token(x_aegis_service_token=None)
    assert exc.value.status_code == 403


def test_require_service_token_rejects_wrong_token(monkeypatch):
    monkeypatch.setattr(auth, "_SERVICE_TOKEN", "s3cret")
    with pytest.raises(HTTPException) as exc:
        auth.require_service_token(x_aegis_service_token="wrong")
    assert exc.value.status_code == 403


def test_require_service_token_accepts_correct_token(monkeypatch):
    monkeypatch.setattr(auth, "_SERVICE_TOKEN", "s3cret")
    auth.require_service_token(x_aegis_service_token="s3cret")


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
