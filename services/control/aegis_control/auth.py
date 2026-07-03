"""Sprint 8: JWT auth + fixed-hierarchy RBAC (admin > operator > viewer).

No OIDC/SSO yet (design.md §19.2 notes that as a later UI-2 phase) — this is
local email/password auth, good enough to get every mutating endpoint behind
a real identity instead of "unauthenticated".
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from typing import Any

import bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from aegis_control.db import models
from aegis_control.db.session import get_db

# Dev default — set AEGIS_JWT_SECRET before any non-dev deployment.
_JWT_SECRET = os.environ.get("AEGIS_JWT_SECRET", "dev-insecure-secret-change-me")
_JWT_ALGORITHM = "HS256"
_ACCESS_TOKEN_TTL = timedelta(hours=12)

_ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}

_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


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
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> models.User:
    if creds is None:
        raise HTTPException(401, "missing bearer token")
    try:
        payload = jwt.decode(creds.credentials, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
    except jwt.PyJWTError as e:
        raise HTTPException(401, "invalid token") from e

    user = db.get(models.User, payload["sub"])
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
