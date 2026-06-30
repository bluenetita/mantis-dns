from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from aegis_control.api import schemas
from aegis_control.compiler.build_policy_bundle import compile_and_store
from aegis_control.compiler.keys import KEY_ID, load_or_create_signing_key, public_key_bytes_for
from aegis_control.config import BUNDLE_STORAGE_DIR
from aegis_control.db import models
from aegis_control.db.session import get_db

router = APIRouter()
_signing_key = load_or_create_signing_key()


@router.post("/tenants", response_model=schemas.TenantOut, status_code=201)
def create_tenant(payload: schemas.TenantCreate, db: Session = Depends(get_db)) -> models.Tenant:
    tenant = models.Tenant(name=payload.name)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


@router.get("/tenants", response_model=list[schemas.TenantOut])
def list_tenants(db: Session = Depends(get_db)) -> list[models.Tenant]:
    return list(db.query(models.Tenant).all())


@router.get("/tenants/{tenant_id}", response_model=schemas.TenantOut)
def get_tenant(tenant_id: str, db: Session = Depends(get_db)) -> models.Tenant:
    tenant = db.get(models.Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    return tenant


@router.delete("/tenants/{tenant_id}", status_code=204)
def delete_tenant(tenant_id: str, db: Session = Depends(get_db)) -> None:
    tenant = db.get(models.Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    db.delete(tenant)
    db.commit()


@router.post("/tenants/{tenant_id}/groups", response_model=schemas.GroupOut, status_code=201)
def create_group(
    tenant_id: str, payload: schemas.GroupCreate, db: Session = Depends(get_db)
) -> models.Group:
    tenant = db.get(models.Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    group = models.Group(tenant_id=tenant_id, name=payload.name)
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


@router.get("/tenants/{tenant_id}/groups", response_model=list[schemas.GroupOut])
def list_groups(tenant_id: str, db: Session = Depends(get_db)) -> list[models.Group]:
    return list(db.query(models.Group).filter(models.Group.tenant_id == tenant_id).all())


@router.get("/groups/{group_id}/policy", response_model=schemas.PolicyOut)
def get_policy(group_id: str, db: Session = Depends(get_db)) -> models.Policy:
    policy = db.query(models.Policy).filter(models.Policy.group_id == group_id).one_or_none()
    if policy is None:
        raise HTTPException(404, "policy not found for group")
    return policy


@router.put("/groups/{group_id}/policy", response_model=schemas.PolicyOut)
def upsert_policy(
    group_id: str, payload: schemas.PolicyUpsert, db: Session = Depends(get_db)
) -> models.Policy:
    group = db.get(models.Group, group_id)
    if group is None:
        raise HTTPException(404, "group not found")

    policy = db.query(models.Policy).filter(models.Policy.group_id == group_id).one_or_none()
    if policy is None:
        policy = models.Policy(group_id=group_id)
        db.add(policy)
        db.flush()

    policy.on_load_failure = payload.on_load_failure

    db.query(models.PolicyCategoryToggle).filter(
        models.PolicyCategoryToggle.policy_id == policy.id
    ).delete()
    db.query(models.PolicyOverride).filter(models.PolicyOverride.policy_id == policy.id).delete()

    for toggle in payload.category_toggles:
        db.add(
            models.PolicyCategoryToggle(
                policy_id=policy.id, category_id=toggle.category_id, action=toggle.action
            )
        )
    for override in payload.overrides:
        db.add(
            models.PolicyOverride(
                policy_id=policy.id, domain=override.domain, kind=override.kind
            )
        )

    db.commit()
    db.refresh(policy)
    return policy


@router.get("/public-key")
def get_public_key() -> Response:
    """Filter nodes fetch this once and pin it for bundle verification."""
    return Response(
        content=public_key_bytes_for(_signing_key),
        media_type="application/octet-stream",
        headers={"X-Key-Id": KEY_ID},
    )


@router.post("/groups/{group_id}/bundle", status_code=201)
def compile_bundle(group_id: str, db: Session = Depends(get_db)) -> Response:
    """Compiles the group's current policy into a signed bundle, stores it
    content-addressed on disk, bumps the version, and returns the bytes."""
    policy = db.query(models.Policy).filter(models.Policy.group_id == group_id).one_or_none()
    if policy is None:
        raise HTTPException(404, "policy not found for group")

    policy.bundle_version += 1
    db.commit()
    db.refresh(policy)

    bundle_path = compile_and_store(
        policy, policy.bundle_version, _signing_key, KEY_ID, BUNDLE_STORAGE_DIR, db
    )
    return Response(content=bundle_path.read_bytes(), media_type="application/octet-stream")


@router.get("/groups/{group_id}/bundle")
def get_latest_bundle(group_id: str) -> Response:
    pointer = BUNDLE_STORAGE_DIR / f"{group_id}.latest"
    if not pointer.exists():
        raise HTTPException(404, "no bundle compiled yet for this group")
    digest = pointer.read_text().strip()
    bundle_bytes = (BUNDLE_STORAGE_DIR / f"{digest}.bin").read_bytes()
    return Response(content=bundle_bytes, media_type="application/octet-stream")
