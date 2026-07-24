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

"""Thin REST client for the control plane, used to set up/inspect the DHCP
config mantis-dhcp reads directly out of Postgres (design.md §22.2) — the
testbench never talks to Postgres itself, only through this same API a real
operator would use."""
from __future__ import annotations

import os
import time

import requests

BASE = os.environ.get("CONTROL_URL", "http://control:8000") + "/api/v1"


def _raise_with_body(r: requests.Response) -> None:
    if r.status_code >= 400:
        raise requests.exceptions.HTTPError(f"{r.status_code} for {r.url}: {r.text}", response=r)


def _retry_5xx(do_request, attempts: int = 3) -> requests.Response:
    # A freshly-"healthy" control plane has occasionally 500'd on its very
    # first request in this testbench (commit succeeds, something after it
    # doesn't) and been fine on retry -- not something worth chasing here,
    # just don't let it fail an entire phase.
    r = None
    for i in range(attempts):
        r = do_request()
        if r.status_code < 500:
            break
        time.sleep(1 + i)
    _raise_with_body(r)
    return r


class Api:
    def __init__(self) -> None:
        self.s = requests.Session()
        self.csrf = ""

    def login(self, email: str = "admin@mantis.local", password: str = "change-me-now", retries: int = 60) -> None:
        last_exc: Exception | None = None
        for _ in range(retries):
            try:
                r = self.s.post(f"{BASE}/auth/login", json={"email": email, "password": password}, timeout=5)
                r.raise_for_status()
                self.csrf = r.json()["csrf_token"]
                return
            except Exception as e:  # noqa: BLE001 - control plane may still be booting/migrating
                last_exc = e
                time.sleep(2)
        raise RuntimeError(f"could not log in to control plane at {BASE}: {last_exc}")

    def _hdr(self) -> dict:
        return {"x-mantis-csrf-token": self.csrf}

    def post(self, path: str, body: dict) -> requests.Response:
        return _retry_5xx(lambda: self.s.post(f"{BASE}{path}", json=body, headers=self._hdr(), timeout=10))

    def patch(self, path: str, body: dict) -> requests.Response:
        return _retry_5xx(lambda: self.s.patch(f"{BASE}{path}", json=body, headers=self._hdr(), timeout=10))

    def get(self, path: str, **params) -> requests.Response:
        r = self.s.get(f"{BASE}{path}", params=params, headers=self._hdr(), timeout=10)
        r.raise_for_status()
        return r

    def delete(self, path: str) -> None:
        r = self.s.delete(f"{BASE}{path}", headers=self._hdr(), timeout=10)
        if r.status_code not in (204, 404):
            r.raise_for_status()

    # ── Tenant / zone ────────────────────────────────────────────────────

    def create_tenant(self, name: str) -> str:
        return self.post("/tenants", {"name": name}).json()["id"]

    def delete_tenant(self, tenant_id: str) -> None:
        self.delete(f"/tenants/{tenant_id}")

    def create_zone(self, tenant_id: str, name: str) -> str:
        return self.post("/dns-zones", {
            "tenant_id": tenant_id, "name": name, "zone_type": "local", "enabled": True,
        }).json()["id"]

    def list_records(self, zone_id: str) -> list[dict]:
        return self.get(f"/dns-zones/{zone_id}/records").json()

    # ── DHCPv4 ───────────────────────────────────────────────────────────

    def create_scope(self, **body) -> dict:
        return self.post("/dhcp/scopes", body).json()

    def update_scope(self, scope_id: str, **body) -> dict:
        return self.patch(f"/dhcp/scopes/{scope_id}", body).json()

    def delete_scope(self, scope_id: str) -> None:
        self.delete(f"/dhcp/scopes/{scope_id}")

    def create_reservation(self, scope_id: str, **body) -> dict:
        return self.post(f"/dhcp/scopes/{scope_id}/reservations", body).json()

    def create_option(self, scope_id: str, **body) -> dict:
        return self.post(f"/dhcp/scopes/{scope_id}/options", body).json()

    def create_relay(self, scope_id: str, **body) -> dict:
        return self.post(f"/dhcp/scopes/{scope_id}/relays", body).json()

    def update_relay_via_replace(self, scope_id: str, relay_id: str, **body) -> dict:
        # No PATCH endpoint for relays (dhcp_routers.py) — replace it.
        self.delete(f"/dhcp/scopes/{scope_id}/relays/{relay_id}")
        return self.create_relay(scope_id, **body)

    def list_leases(self, scope_id: str, state: int = 0) -> list[dict]:
        return self.get("/dhcp/leases", scope_id=scope_id, state=state).json()

    def dhcp_stats(self) -> list[dict]:
        return self.get("/dhcp/stats").json()

    # ── DHCPv6 ───────────────────────────────────────────────────────────

    def create_scope6(self, **body) -> dict:
        return self.post("/dhcp6/scopes", body).json()

    def create_reservation6(self, scope_id: str, **body) -> dict:
        return self.post(f"/dhcp6/scopes/{scope_id}/reservations", body).json()

    def list_leases6(self, scope_id: str, state: int = 0) -> list[dict]:
        return self.get("/dhcp6/leases", scope_id=scope_id, state=state).json()
