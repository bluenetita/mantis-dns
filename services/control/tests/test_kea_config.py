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
