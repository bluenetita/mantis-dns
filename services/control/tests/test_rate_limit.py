from unittest.mock import MagicMock

from aegis_control import rate_limit


def _make_request(client_host: str, xff: str | None) -> MagicMock:
    req = MagicMock()
    req.client.host = client_host
    req.headers = {"X-Forwarded-For": xff} if xff else {}
    return req


def test_untrusted_peer_xff_is_ignored(monkeypatch):
    """A direct peer that isn't a configured trusted proxy can't spoof its
    rate-limit key via X-Forwarded-For."""
    monkeypatch.setattr(rate_limit, "_TRUSTED_PROXY_IPS", set())
    calls: list[str] = []
    monkeypatch.setattr(rate_limit._login_limiter, "check", lambda key: calls.append(key))

    req = _make_request(client_host="203.0.113.9", xff="1.2.3.4")
    rate_limit.login_rate_limit(req)

    assert calls == ["203.0.113.9"]


def test_trusted_proxy_xff_is_honored(monkeypatch):
    monkeypatch.setattr(rate_limit, "_TRUSTED_PROXY_IPS", {"10.0.0.1"})
    calls: list[str] = []
    monkeypatch.setattr(rate_limit._login_limiter, "check", lambda key: calls.append(key))

    req = _make_request(client_host="10.0.0.1", xff="203.0.113.9, 10.0.0.1")
    rate_limit.login_rate_limit(req)

    assert calls == ["203.0.113.9"]


def test_no_xff_header_uses_direct_peer(monkeypatch):
    monkeypatch.setattr(rate_limit, "_TRUSTED_PROXY_IPS", {"10.0.0.1"})
    calls: list[str] = []
    monkeypatch.setattr(rate_limit._login_limiter, "check", lambda key: calls.append(key))

    req = _make_request(client_host="203.0.113.9", xff=None)
    rate_limit.login_rate_limit(req)

    assert calls == ["203.0.113.9"]
