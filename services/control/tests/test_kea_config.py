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

from types import SimpleNamespace

from mantis_control.dhcp import kea_config, kea_config6


class _FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return [{"result": 0, "text": "ok"}]


class _FakeAsyncClient:
    calls = []

    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def post(self, url, json):
        self.calls.append({"url": url, "json": json})
        return _FakeResponse()


def test_assign_unique_kea_ids_resolves_hash_collision(monkeypatch):
    """Two scopes whose truncated-hash subnet id collides (28 bits — a real
    risk at scale) must still get distinct ids, or Kea would reject the
    duplicate subnet4.id and lease queries keyed on kea_subnet_id would
    mis-attribute one scope's leases to the other."""
    scopes = [SimpleNamespace(id="scope-a"), SimpleNamespace(id="scope-b"), SimpleNamespace(id="scope-c")]
    monkeypatch.setattr(kea_config, "_scope_kea_id", lambda uuid: 42)

    assigned = kea_config._assign_unique_kea_ids(scopes)

    assert len(set(assigned.values())) == 3
    assert assigned["scope-a"] == 42
    assert assigned["scope-b"] == 43
    assert assigned["scope-c"] == 44


def test_assign_unique_kea_ids_no_collision_uses_hash_directly():
    scope = SimpleNamespace(id="11111111-2222-3333-4444-555555555555")
    assigned = kea_config._assign_unique_kea_ids([scope])
    assert assigned[scope.id] == kea_config._scope_kea_id(scope.id)


def test_assign_unique_kea_ids6_resolves_hash_collision(monkeypatch):
    scopes = [SimpleNamespace(id="scope-a"), SimpleNamespace(id="scope-b")]
    monkeypatch.setattr(kea_config6, "_scope_kea_id6", lambda uuid: 7)

    assigned = kea_config6._assign_unique_kea_ids6(scopes)

    assert len(set(assigned.values())) == 2
    assert assigned["scope-a"] == 7
    assert assigned["scope-b"] == 8


async def test_direct_kea_command_routes_to_dhcp6_without_service(monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(kea_config.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(kea_config, "KEA6_CTRL_URL", "http://kea:8006/")

    result = await kea_config.kea_command("version-get", service=["dhcp6"])

    assert result == {"result": 0, "text": "ok"}
    assert _FakeAsyncClient.calls == [
        {"url": "http://kea:8006/", "json": {"command": "version-get"}}
    ]


async def test_dhcp4_command_routes_without_service_wrapper(monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(kea_config.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(kea_config, "KEA4_CTRL_URL", "http://kea:8004/")

    await kea_config.kea_command("version-get", service=["dhcp4"])

    assert _FakeAsyncClient.calls == [
        {"url": "http://kea:8004/", "json": {"command": "version-get"}}
    ]


async def test_blank_kea_url_is_reported_before_http_call(monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(kea_config.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(kea_config, "KEA4_CTRL_URL", "")

    try:
        await kea_config.kea_command("version-get", service=["dhcp4"])
    except RuntimeError as exc:
        assert str(exc) == "Kea DHCPv4 management URL is not configured"
    else:
        raise AssertionError("expected RuntimeError")

    assert _FakeAsyncClient.calls == []
