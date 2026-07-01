from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis_control.audit import write_audit_log
from aegis_control.auth import create_access_token, get_current_user, hash_password, require_role, verify_password
from aegis_control.db import models
from aegis_control.db.session import get_db

router = APIRouter()


class LoginRequest(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: str
    email: str
    role: str

    class Config:
        from_attributes = True


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class UserCreate(BaseModel):
    email: str
    password: str
    role: str = "viewer"


@router.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    user = db.query(models.User).filter(models.User.email == payload.email).one_or_none()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "invalid email or password")
    return LoginResponse(access_token=create_access_token(user), user=user)  # type: ignore[arg-type]


@router.get("/auth/me", response_model=UserOut)
def me(user: models.User = Depends(get_current_user)) -> models.User:
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db), _admin: models.User = Depends(require_role("admin"))
) -> list[models.User]:
    return list(db.query(models.User).all())


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
    user = models.User(email=payload.email, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.flush()
    write_audit_log(db, "user.create", "user", user.id, detail=f"email={user.email} role={user.role}", actor=admin.email)
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
