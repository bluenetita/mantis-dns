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

"""Sprint 8: JWT auth + fixed-hierarchy RBAC (admin > operator > viewer).

No OIDC/SSO yet (design.md §19.2 notes that as a later UI-2 phase) — this is
local email/password auth, good enough to get every mutating endpoint behind
a real identity instead of "unauthenticated".
"""

from __future__ import annotations

import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from typing import Any

import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from mantis_control.db import models
from mantis_control.db.session import get_db

# Dev default — set MANTIS_JWT_SECRET before any non-dev deployment.
_JWT_SECRET = os.environ.get("MANTIS_JWT_SECRET", "dev-insecure-secret-change-me")
_JWT_ALGORITHM = "HS256"
_ACCESS_TOKEN_TTL = timedelta(hours=12)

_ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}

_bearer = HTTPBearer(auto_error=False)

# Session lives in an httpOnly cookie (JS/XSS can't read it) instead of
# localStorage. SESSION_COOKIE_NAME carries the JWT; CSRF_COOKIE_NAME carries
# a companion, JS-readable random token the frontend must echo back as
# CSRF_HEADER_NAME on every mutating request (double-submit pattern — see
# CsrfMiddleware). SameSite=lax is enough here: the UI and API share the same
# registrable "site" (same host or same parent domain) even across
# ports/subdomains, so it's still attached on the app's own cross-origin
# fetches but never on a genuinely cross-site request.
SESSION_COOKIE_NAME = "mantis_session"
CSRF_COOKIE_NAME = "mantis_csrf"
CSRF_HEADER_NAME = "x-mantis-csrf-token"


def _cookies_secure() -> bool:
    return os.environ.get("MANTIS_ENV", "").lower() == "production"


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def set_auth_cookies(response: Response, access_token: str, csrf_token: str) -> None:
    max_age = int(_ACCESS_TOKEN_TTL.total_seconds())
    response.set_cookie(
        SESSION_COOKIE_NAME, access_token, max_age=max_age, httponly=True,
        samesite="lax", secure=_cookies_secure(), path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME, csrf_token, max_age=max_age, httponly=False,
        samesite="lax", secure=_cookies_secure(), path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")

# Shared secret authenticating filter-node -> control-plane machine calls
# (/public-key, /routing-table, /groups/{id}/bundle GET, /upstream-bundle/{id},
# /query-events). Empty by default: these endpoints predate auth and stay open
# in dev unless MANTIS_SERVICE_TOKEN is set. Production startup (main.py)
# refuses to boot with MANTIS_ENV=production unless it's configured.
_SERVICE_TOKEN = os.environ.get("MANTIS_SERVICE_TOKEN", "")


def require_service_token(authorization: str | None = Header(None)) -> None:
    if not _SERVICE_TOKEN:
        return
    token = authorization.removeprefix("Bearer ") if authorization else None
    if not token or not hmac.compare_digest(token, _SERVICE_TOKEN):
        raise HTTPException(403, "invalid or missing service token")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        # bcrypt raises rather than truncating for passwords >72 bytes
        # (registration already rejects those — see auth_routers'
        # _strong_password validator) — treat an over-length login
        # attempt as simply wrong instead of crashing the request.
        return False


def create_access_token(user: models.User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "tenant_id": user.tenant_id,
        "iat": now,
        "exp": now + _ACCESS_TOKEN_TTL,
    }
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> models.User:
    # Prefer an explicit Bearer token (scripts/API clients); fall back to the
    # httpOnly session cookie the browser UI relies on.
    token = creds.credentials if creds is not None else request.cookies.get(SESSION_COOKIE_NAME)
    if token is None:
        raise HTTPException(401, "missing bearer token or session cookie")
    try:
        payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
    except jwt.PyJWTError as e:
        raise HTTPException(401, "invalid token") from e

    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(401, "invalid token")

    user = db.get(models.User, sub)
    if user is None:
        raise HTTPException(401, "user no longer exists")
    return user


def check_tenant_access(user: models.User, tenant_id: str) -> None:
    """403 if a non-admin user is scoped to a different tenant."""
    if user.role == "admin":
        return
    if user.tenant_id is not None and user.tenant_id != tenant_id:
        raise HTTPException(403, "access denied — resource belongs to a different tenant")


def user_tenant_filter(user: models.User) -> str | None:
    """Returns the tenant_id to filter by, or None (= unrestricted) for admins."""
    if user.role == "admin":
        return None
    return user.tenant_id


def get_group_or_403(db: Session, group_id: str, user: models.User) -> models.Group:
    group = db.get(models.Group, group_id)
    if group is None:
        raise HTTPException(404, "group not found")
    check_tenant_access(user, group.tenant_id)
    return group


def require_role(*roles: str) -> Any:
    """Dependency factory: caller's role must be >= the lowest rank in `roles`."""
    min_rank = min(_ROLE_RANK[r] for r in roles)

    def _check(user: models.User = Depends(get_current_user)) -> models.User:
        if _ROLE_RANK.get(user.role, -1) < min_rank:
            raise HTTPException(403, f"role '{user.role}' insufficient, requires >= {roles}")
        return user

    return _check


_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# /auth/login is exempt: there's no CSRF cookie to double-submit yet before a
# session exists. Every other mutating route is covered automatically —
# machine-to-machine callers (service token, internal token) never carry the
# session cookie, so the check below is a no-op for them regardless.
_CSRF_EXEMPT_PATHS = {"/api/v1/auth/login"}


class CsrfMiddleware:
    """Double-submit-cookie CSRF check, enforced only when a request is
    actually authenticated via the httpOnly session cookie (no Authorization
    header). Bearer-token callers aren't exposed to browser-driven CSRF in
    the first place, so they're left alone."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        needs_check = (
            request.method not in _SAFE_METHODS
            and request.url.path not in _CSRF_EXEMPT_PATHS
            and "authorization" not in request.headers
            and SESSION_COOKIE_NAME in request.cookies
        )
        if needs_check:
            cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
            header_csrf = request.headers.get(CSRF_HEADER_NAME)
            if not cookie_csrf or not header_csrf or not hmac.compare_digest(cookie_csrf, header_csrf):
                response = Response(
                    content='{"detail":"missing or invalid CSRF token"}',
                    status_code=403,
                    media_type="application/json",
                )
                await response(scope, receive, send)
                return

        await self.app(scope, receive, send)
