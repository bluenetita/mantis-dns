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

from fastapi import FastAPI
from fastapi.testclient import TestClient

from mantis_control.auth import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME, CsrfMiddleware


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(CsrfMiddleware)

    @app.get("/safe")
    def safe() -> dict:
        return {"ok": True}

    @app.post("/mutate")
    def mutate() -> dict:
        return {"ok": True}

    @app.post("/api/v1/auth/login")
    def login() -> dict:
        return {"ok": True}

    return app


def _client() -> TestClient:
    return TestClient(_make_app())


def test_get_is_never_csrf_checked():
    client = _client()
    resp = client.get("/safe", cookies={SESSION_COOKIE_NAME: "tok"})
    assert resp.status_code == 200


def test_login_path_is_exempt_even_with_session_cookie():
    client = _client()
    resp = client.post("/api/v1/auth/login", cookies={SESSION_COOKIE_NAME: "tok"})
    assert resp.status_code == 200


def test_mutation_without_session_cookie_is_not_csrf_checked():
    """No session cookie -> not a cookie-authenticated request (e.g. a
    Bearer/service-token caller) -> CSRF check is skipped entirely."""
    client = _client()
    resp = client.post("/mutate")
    assert resp.status_code == 200


def test_mutation_with_session_cookie_and_no_csrf_header_is_rejected():
    client = _client()
    resp = client.post("/mutate", cookies={SESSION_COOKIE_NAME: "tok", CSRF_COOKIE_NAME: "csrf-value"})
    assert resp.status_code == 403


def test_mutation_with_mismatched_csrf_header_is_rejected():
    client = _client()
    resp = client.post(
        "/mutate",
        cookies={SESSION_COOKIE_NAME: "tok", CSRF_COOKIE_NAME: "csrf-value"},
        headers={CSRF_HEADER_NAME: "wrong-value"},
    )
    assert resp.status_code == 403


def test_mutation_with_matching_csrf_header_is_allowed():
    client = _client()
    resp = client.post(
        "/mutate",
        cookies={SESSION_COOKIE_NAME: "tok", CSRF_COOKIE_NAME: "csrf-value"},
        headers={CSRF_HEADER_NAME: "csrf-value"},
    )
    assert resp.status_code == 200


def test_bearer_auth_bypasses_csrf_check_even_with_session_cookie():
    """A caller presenting its own Authorization header isn't relying on the
    ambient session cookie, so CSRF (a browser-cookie-specific attack) does
    not apply."""
    client = _client()
    resp = client.post(
        "/mutate",
        cookies={SESSION_COOKIE_NAME: "tok"},
        headers={"Authorization": "Bearer sometoken"},
    )
    assert resp.status_code == 200
