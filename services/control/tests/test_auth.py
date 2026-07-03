import pytest
from fastapi import HTTPException

from aegis_control import auth


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
