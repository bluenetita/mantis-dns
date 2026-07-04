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


def test_idle_ip_entries_are_swept_after_threshold(monkeypatch):
    """A defaultdict entry only gets pruned when *that same key* calls
    check() again — an IP that attacks once and never returns would leave a
    dead dict entry forever otherwise. The periodic sweep must clear idle
    keys once enough total calls have accumulated."""
    monkeypatch.setattr(rate_limit, "_SWEEP_EVERY_N_CALLS", 3)
    limiter = rate_limit._SlidingWindowLimiter(max_requests=100, window_secs=0)

    limiter.check("ip-1")
    assert "ip-1" in limiter._timestamps

    limiter.check("ip-2")
    limiter.check("ip-3")  # 3rd call since start -> sweep threshold reached

    assert "ip-1" not in limiter._timestamps
    assert "ip-2" not in limiter._timestamps
    assert "ip-3" in limiter._timestamps  # the call that triggered the sweep survives


def test_sweep_does_not_remove_keys_still_inside_the_window(monkeypatch):
    monkeypatch.setattr(rate_limit, "_SWEEP_EVERY_N_CALLS", 2)
    limiter = rate_limit._SlidingWindowLimiter(max_requests=100, window_secs=3600)

    limiter.check("ip-1")
    limiter.check("ip-2")  # triggers sweep, but ip-1's timestamp is well inside the 1h window

    assert "ip-1" in limiter._timestamps
    assert "ip-2" in limiter._timestamps
