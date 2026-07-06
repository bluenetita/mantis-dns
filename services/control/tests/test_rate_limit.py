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

from mantis_control import rate_limit


def _make_request(client_host: str, xff: str | None) -> MagicMock:
    req = MagicMock()
    req.client.host = client_host
    req.headers = {"X-Forwarded-For": xff} if xff else {}
    return req


def test_untrusted_peer_xff_is_ignored(monkeypatch):
    """A direct peer that isn't a configured trusted proxy can't spoof its
    rate-limit key via X-Forwarded-For."""
    monkeypatch.setattr(rate_limit.settings, "MANTIS_TRUSTED_PROXY_IPS", "")
    calls: list[str] = []
    monkeypatch.setattr(rate_limit._login_limiter, "check", lambda key: calls.append(key))

    req = _make_request(client_host="203.0.113.9", xff="1.2.3.4")
    rate_limit.login_rate_limit(req)

    assert calls == ["203.0.113.9"]


def test_trusted_proxy_xff_is_honored(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "MANTIS_TRUSTED_PROXY_IPS", "10.0.0.1")
    calls: list[str] = []
    monkeypatch.setattr(rate_limit._login_limiter, "check", lambda key: calls.append(key))

    req = _make_request(client_host="10.0.0.1", xff="203.0.113.9, 10.0.0.1")
    rate_limit.login_rate_limit(req)

    assert calls == ["203.0.113.9"]


def test_no_xff_header_uses_direct_peer(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "MANTIS_TRUSTED_PROXY_IPS", "10.0.0.1")
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
