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
from unittest.mock import MagicMock

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


async def test_list_kea_interfaces_parses_list_shape(monkeypatch):
    async def fake_kea_command(command, service=None, arguments=None):
        assert command == "interface-list"
        return {
            "result": 0,
            "arguments": {
                "interfaces": [
                    {"name": "eth0", "addresses": [{"address": "10.0.0.2"}], "flags": ["BROADCAST", "UP"]},
                    {"name": "eth1", "addresses": ["192.0.2.10"], "flags": []},
                ]
            },
        }

    monkeypatch.setattr(kea_config, "kea_command", fake_kea_command)

    assert await kea_config.list_kea_interfaces(["dhcp4"]) == [
        {"name": "eth0", "addresses": ["10.0.0.2"], "up": True},
        {"name": "eth1", "addresses": ["192.0.2.10"], "up": False},
    ]


async def test_list_kea_interfaces_parses_mapping_shape(monkeypatch):
    async def fake_kea_command(command, service=None, arguments=None):
        assert command == "interface-list"
        return {
            "result": 0,
            "arguments": {
                "interfaces": {
                    "ens18": {"addrs": {"primary": {"ip": "172.16.0.2"}}, "up": True},
                    "vlan20": {"addresses": [], "flag-up": False},
                }
            },
        }

    monkeypatch.setattr(kea_config, "kea_command", fake_kea_command)

    assert await kea_config.list_kea_interfaces(["dhcp4"]) == [
        {"name": "ens18", "addresses": ["172.16.0.2"], "up": True},
        {"name": "vlan20", "addresses": [], "up": False},
    ]


def _scope(scope_id: str, subnet: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=scope_id,
        tenant_id="tenant-1",
        subnet=subnet,
        range_start="10.0.0.10",
        range_end="10.0.0.200",
        lease_time_s=86400,
        max_lease_time_s=604800,
        renew_time_s=None,
        rebind_time_s=None,
        interface=None,
        pxe_next_server=None,
        pxe_boot_filename=None,
        router_ip=None,
        dns_servers=[],
        ntp_server=None,
        domain_name=None,
        options=[],
        static_leases=[],
        relay_configs=[],
        kea_subnet_id=None,
    )


def _fake_db(scopes):
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = scopes
    return db


async def test_push_full_config_adds_updates_and_deletes_subnets(monkeypatch):
    """push_full_config must diff against Kea's live subnet4-list (not just
    push everything as subnet4-add) so an already-known subnet is updated in
    place and a subnet no longer in the DB (deleted/disabled scope) is
    actually removed from Kea, rather than lingering forever."""
    kept = _scope("11111111-2222-3333-4444-555555555555", "10.0.0.0/24")
    added = _scope("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "10.0.1.0/24")
    kept_id = kea_config._scope_kea_id(kept.id)
    added_id = kea_config._scope_kea_id(added.id)
    stale_id = 999999

    db = _fake_db([kept, added])
    calls = []

    async def fake_kea_command(command, service=None, arguments=None):
        calls.append((command, service, arguments))
        if command == "subnet4-list":
            return {"result": 0, "arguments": {"subnets": [
                {"id": kept_id, "subnet": kept.subnet},
                {"id": stale_id, "subnet": "192.0.2.0/24"},
            ]}}
        return {"result": 0}

    monkeypatch.setattr(kea_config, "kea_command", fake_kea_command)

    await kea_config.push_full_config(db)

    commands = {c[0] for c in calls}
    assert commands == {"subnet4-list", "subnet4-del", "subnet4-update", "subnet4-add", "reservation-get-all"}

    del_call = next(c for c in calls if c[0] == "subnet4-del")
    assert del_call[2] == {"id": stale_id}

    update_call = next(c for c in calls if c[0] == "subnet4-update")
    assert update_call[2]["subnet4"][0]["id"] == kept_id
    assert update_call[2]["subnet4"][0]["subnet"] == kept.subnet

    add_call = next(c for c in calls if c[0] == "subnet4-add")
    assert add_call[2]["subnet4"][0]["id"] == added_id
    assert add_call[2]["subnet4"][0]["subnet"] == added.subnet

    # subnet_cmds rejects inline "reservations" on subnet4-add/-update.
    assert "reservations" not in update_call[2]["subnet4"][0]
    assert "reservations" not in add_call[2]["subnet4"][0]

    assert kept.kea_subnet_id == kept_id
    assert added.kea_subnet_id == added_id


def _static_lease(mac: str, ip: str, enabled: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        enabled=enabled, mac_address=mac, ip_address=ip,
        hostname=None, client_id=None, next_server=None, boot_filename=None, options=[],
    )


async def test_push_full_config_syncs_reservations_via_host_cmds(monkeypatch):
    """Reservations must go through reservation-add/-del (host_cmds), not
    inline in subnet4-add/-update, since Kea rejects the latter outright."""
    scope = _scope("11111111-2222-3333-4444-555555555555", "10.0.0.0/24")
    scope.static_leases = [_static_lease("aa:bb:cc:dd:ee:01", "10.0.0.50")]
    kea_id = kea_config._scope_kea_id(scope.id)
    db = _fake_db([scope])
    calls = []

    async def fake_kea_command(command, service=None, arguments=None):
        calls.append((command, service, arguments))
        if command == "subnet4-list":
            return {"result": 0, "arguments": {"subnets": [{"id": kea_id, "subnet": scope.subnet}]}}
        if command == "reservation-get-all":
            return {"result": 0, "arguments": {"hosts": [
                {"hw-address": "aa:bb:cc:dd:ee:99", "ip-address": "10.0.0.99", "subnet-id": kea_id},
            ]}}
        return {"result": 0}

    monkeypatch.setattr(kea_config, "kea_command", fake_kea_command)

    await kea_config.push_full_config(db)

    res_del = next(c for c in calls if c[0] == "reservation-del")
    assert res_del[2] == {"subnet-id": kea_id, "identifier-type": "hw-address", "identifier": "aa:bb:cc:dd:ee:99"}

    res_add = next(c for c in calls if c[0] == "reservation-add")
    assert res_add[2] == {"reservation": {
        "hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "10.0.0.50", "subnet-id": kea_id,
    }}


async def test_push_full_config_raises_on_rejected_command(monkeypatch):
    scope = _scope("11111111-2222-3333-4444-555555555555", "10.0.0.0/24")
    db = _fake_db([scope])

    async def fake_kea_command(command, service=None, arguments=None):
        if command == "subnet4-list":
            return {"result": 0, "arguments": {"subnets": []}}
        return {"result": 1, "text": "boom"}

    monkeypatch.setattr(kea_config, "kea_command", fake_kea_command)

    try:
        await kea_config.push_full_config(db)
    except RuntimeError as exc:
        assert "boom" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")


async def test_synced_kea_subnet_ids_treats_empty_result_as_no_subnets(monkeypatch):
    async def fake_kea_command(command, service=None, arguments=None):
        assert command == "subnet4-list"
        return {"result": 3, "text": "0 IPv4 subnets found"}

    monkeypatch.setattr(kea_config, "kea_command", fake_kea_command)

    assert await kea_config._synced_kea_subnet_ids(["dhcp4"]) == set()


def _scope6(scope_id: str, subnet: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=scope_id,
        tenant_id="tenant-1",
        subnet=subnet,
        pool_start="2001:db8::10",
        pool_end="2001:db8::ff",
        preferred_lifetime_s=3000,
        valid_lifetime_s=4000,
        renew_time_s=None,
        rebind_time_s=None,
        interface=None,
        pd_prefix=None,
        pd_prefix_len=None,
        dns_servers=[],
        domain_name=None,
        reservations6=[],
        kea_subnet_id=None,
    )


async def test_push_full_config6_adds_updates_and_deletes_subnets(monkeypatch):
    kept = _scope6("11111111-2222-3333-4444-555555555555", "2001:db8:1::/64")
    added = _scope6("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "2001:db8:2::/64")
    kept_id = kea_config6._scope_kea_id6(kept.id)
    added_id = kea_config6._scope_kea_id6(added.id)
    stale_id = 999999

    db = _fake_db([kept, added])
    calls = []

    async def fake_kea_command(command, service=None, arguments=None):
        calls.append((command, service, arguments))
        if command == "subnet6-list":
            return {"result": 0, "arguments": {"subnets": [
                {"id": kept_id, "subnet": kept.subnet},
                {"id": stale_id, "subnet": "2001:db8:ff::/64"},
            ]}}
        return {"result": 0}

    monkeypatch.setattr(kea_config, "kea_command", fake_kea_command)
    monkeypatch.setattr(kea_config6, "kea_command", fake_kea_command)

    await kea_config6.push_full_config6(db)

    commands = {c[0] for c in calls}
    assert commands == {"subnet6-list", "subnet6-del", "subnet6-update", "subnet6-add", "reservation-get-all"}

    del_call = next(c for c in calls if c[0] == "subnet6-del")
    assert del_call[2] == {"id": stale_id}

    update_call = next(c for c in calls if c[0] == "subnet6-update")
    assert update_call[2]["subnet6"][0]["id"] == kept_id

    add_call = next(c for c in calls if c[0] == "subnet6-add")
    assert add_call[2]["subnet6"][0]["id"] == added_id

    # subnet_cmds rejects inline "reservations" on subnet6-add/-update.
    assert "reservations" not in update_call[2]["subnet6"][0]
    assert "reservations" not in add_call[2]["subnet6"][0]

    assert kept.kea_subnet_id == kept_id
    assert added.kea_subnet_id == added_id


def _reservation6(duid: str, ip: str, enabled: bool = True) -> SimpleNamespace:
    return SimpleNamespace(enabled=enabled, duid=duid, ip_address=ip, hostname=None)


async def test_push_full_config6_syncs_reservations_via_host_cmds(monkeypatch):
    scope = _scope6("11111111-2222-3333-4444-555555555555", "2001:db8:1::/64")
    scope.reservations6 = [_reservation6("01:02:03:04:05:06", "2001:db8:1::50")]
    kea_id = kea_config6._scope_kea_id6(scope.id)
    db = _fake_db([scope])
    calls = []

    async def fake_kea_command(command, service=None, arguments=None):
        calls.append((command, service, arguments))
        if command == "subnet6-list":
            return {"result": 0, "arguments": {"subnets": [{"id": kea_id, "subnet": scope.subnet}]}}
        if command == "reservation-get-all":
            return {"result": 0, "arguments": {"hosts": [
                {"duid": "aa:aa:aa:aa:aa:aa", "ip-addresses": ["2001:db8:1::99"], "subnet-id": kea_id},
            ]}}
        return {"result": 0}

    monkeypatch.setattr(kea_config, "kea_command", fake_kea_command)
    monkeypatch.setattr(kea_config6, "kea_command", fake_kea_command)

    await kea_config6.push_full_config6(db)

    res_del = next(c for c in calls if c[0] == "reservation-del")
    assert res_del[2] == {"subnet-id": kea_id, "identifier-type": "duid", "identifier": "aa:aa:aa:aa:aa:aa"}

    res_add = next(c for c in calls if c[0] == "reservation-add")
    assert res_add[2] == {"reservation": {
        "duid": "01:02:03:04:05:06", "ip-addresses": ["2001:db8:1::50"], "subnet-id": kea_id,
    }}
