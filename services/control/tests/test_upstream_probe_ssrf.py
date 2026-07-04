from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from aegis_control.api import upstream_routers
from aegis_control.api.upstream_routers import ProbeResult, probe_resolver


def _fake_admin() -> SimpleNamespace:
    return SimpleNamespace(id="admin-1", email="admin@x.com", role="admin", tenant_id=None)


def _resolver(**overrides) -> SimpleNamespace:
    base = dict(
        protocol="doh", address="8.8.8.8", tls_hostname=None,
        port=443, doh_path="/dns-query", doh_method="post", timeout_ms=200,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _ok_result() -> ProbeResult:
    return ProbeResult(ok=True, latency_ms=1.0, response_code="NOERROR", dnssec_ad=False, tls_subject=None, error=None)


async def test_probe_rejects_doh_when_address_safe_but_tls_hostname_is_metadata(monkeypatch):
    """_probe_doh dials `tls_hostname or address`, not `address` — a resolver
    with a public `address` but tls_hostname pointed at the cloud metadata
    endpoint must still be rejected, or check_probe_target_safe(address)
    alone would rubber-stamp an SSRF to 169.254.169.254."""
    dialed = []

    async def fake_probe_doh(*args, **kwargs):
        dialed.append(args)
        return _ok_result()

    monkeypatch.setattr(upstream_routers, "_probe_doh", fake_probe_doh)
    db = MagicMock()
    db.get.return_value = _resolver(tls_hostname="169.254.169.254")

    with pytest.raises(HTTPException) as exc:
        await probe_resolver("resolver-1", db, _fake_admin())
    assert exc.value.status_code == 422
    assert dialed == []  # guard must reject before ever dialing out


async def test_probe_rejects_doh_when_tls_hostname_is_loopback(monkeypatch):
    async def fake_probe_doh(*args, **kwargs):
        return _ok_result()

    monkeypatch.setattr(upstream_routers, "_probe_doh", fake_probe_doh)
    db = MagicMock()
    db.get.return_value = _resolver(tls_hostname="127.0.0.1")

    with pytest.raises(HTTPException) as exc:
        await probe_resolver("resolver-1", db, _fake_admin())
    assert exc.value.status_code == 422


async def test_probe_allows_doh_with_no_tls_hostname_override(monkeypatch):
    """No tls_hostname set -> _probe_doh dials `address` itself, already
    covered by check_probe_target_safe(address); must not spuriously reject."""
    async def fake_probe_doh(*args, **kwargs):
        return _ok_result()

    monkeypatch.setattr(upstream_routers, "_probe_doh", fake_probe_doh)
    db = MagicMock()
    db.get.return_value = _resolver(tls_hostname=None)

    result = await probe_resolver("resolver-1", db, _fake_admin())
    assert result.ok is True


async def test_probe_do53_is_unaffected_by_tls_hostname_check(monkeypatch):
    """do53 has no tls_hostname concept — the extra check must only fire for
    protocol == 'doh'."""
    async def fake_probe_do53(*args, **kwargs):
        return _ok_result()

    monkeypatch.setattr(upstream_routers, "_probe_do53", fake_probe_do53)
    db = MagicMock()
    db.get.return_value = _resolver(protocol="do53", address="8.8.8.8", tls_hostname=None, port=53)

    result = await probe_resolver("resolver-1", db, _fake_admin())
    assert result.ok is True
