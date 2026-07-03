from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from pydantic import AfterValidator, BaseModel, field_validator
from sqlalchemy.orm import Session

from aegis_control.audit import write_audit_log
from aegis_control.auth import create_access_token, get_current_user, hash_password, require_role, verify_password, user_tenant_filter
from aegis_control.db import models
from aegis_control.db.session import get_db
from aegis_control.rate_limit import login_rate_limit

router = APIRouter()

# Accepts internal TLDs (.local, .corp, .internal, etc.) that the email-validator
# package rejects. Good enough format check for an internal enterprise product.
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.\-]+"  # local part
    r"@"
    r"[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)*"    # domain labels
    r"\.[a-zA-Z]{2,}$"                        # TLD (min 2 chars)
)


def _validate_email(v: str) -> str:
    v = v.strip().lower()
    if not _EMAIL_RE.match(v):
        raise ValueError("invalid email address format")
    return v


EmailAddress = Annotated[str, AfterValidator(_validate_email)]


class LoginRequest(BaseModel):
    email: str  # plain str — login is a DB lookup, no format validation needed
    password: str


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    tenant_id: str | None = None

    class Config:
        from_attributes = True


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class UserCreate(BaseModel):
    email: EmailAddress
    password: str
    role: str = "viewer"
    tenant_id: str | None = None

    @field_validator("password")
    @classmethod
    def _strong_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("password must be at least 12 characters")
        return v


@router.post("/auth/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
    _: None = Depends(login_rate_limit),
) -> LoginResponse:
    user = db.query(models.User).filter(models.User.email == payload.email).one_or_none()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "invalid email or password")
    return LoginResponse(access_token=create_access_token(user), user=user)  # type: ignore[arg-type]


@router.get("/auth/me", response_model=UserOut)
def me(user: models.User = Depends(get_current_user)) -> models.User:
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db), admin: models.User = Depends(require_role("admin"))
) -> list[models.User]:
    scope = user_tenant_filter(admin)
    q = db.query(models.User)
    if scope is not None:
        q = q.filter(models.User.tenant_id == scope)
    return list(q.all())


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.User:
    if payload.role not in ("admin", "operator", "viewer"):
        raise HTTPException(422, "role must be admin, operator, or viewer")
    if db.query(models.User).filter(models.User.email == payload.email).one_or_none() is not None:
        raise HTTPException(409, "a user with this email already exists")
    user = models.User(email=payload.email, password_hash=hash_password(payload.password), role=payload.role, tenant_id=payload.tenant_id)
    try:
        db.add(user)
        db.flush()
        write_audit_log(db, "user.create", "user", user.id, detail=f"email={user.email} role={user.role} tenant_id={user.tenant_id}", actor=admin.email)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "a user with this email already exists")
    db.refresh(user)
    return user


class UserUpdate(BaseModel):
    role: str
    tenant_id: str | None = None


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.User:
    if payload.role not in ("admin", "operator", "viewer"):
        raise HTTPException(422, "role must be admin, operator, or viewer")
    user = db.get(models.User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    old_role = user.role
    user.role = payload.role
    user.tenant_id = payload.tenant_id
    write_audit_log(db, "user.update", "user", user.id, detail=f"role={old_role}->{user.role} tenant_id={user.tenant_id}", actor=admin.email)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> None:
    user = db.get(models.User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    if user.id == admin.id:
        raise HTTPException(400, "cannot delete your own account")
    write_audit_log(db, "user.delete", "user", user.id, detail=f"email={user.email}", actor=admin.email)
    db.delete(user)
    db.commit()
