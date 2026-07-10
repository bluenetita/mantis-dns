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

from __future__ import annotations

import ipaddress
import re

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from mantis_control.api import schemas
from mantis_control.audit import write_audit_log
from mantis_control.auth import check_tenant_access, get_current_user, get_group_or_403, require_role, require_service_token, user_tenant_filter
from mantis_control.categories import CATEGORY_REGISTRY
from mantis_control.compiler.build_policy_bundle import compile_and_store
from mantis_control.compiler.keys import KEY_ID, load_or_create_signing_key, public_key_bytes_for
from mantis_control.config import BUNDLE_STORAGE_DIR, FEED_STORAGE_DIR
from mantis_control.db import models
from mantis_control.db.session import get_db
from mantis_control.feeds.ingest import load_domains

router = APIRouter()


@router.get("/categories", response_model=list[schemas.CategoryOut])
def list_categories(user: models.User = Depends(get_current_user)) -> list[schemas.CategoryOut]:
    """Canonical category taxonomy (design.md §18.1) — static, system-defined,
    same for every tenant. Drives the PolicyPage category picker and the
    FeedsPage category filter/badges."""
    return [schemas.CategoryOut(**c.__dict__) for c in CATEGORY_REGISTRY]


@router.post("/tenants", response_model=schemas.TenantOut, status_code=201)
def create_tenant(
    payload: schemas.TenantCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> models.Tenant:
    tenant = models.Tenant(name=payload.name)
    db.add(tenant)
    db.flush()
    write_audit_log(db, "tenant.create", "tenant", tenant.id, detail=f"name={tenant.name}", actor=user.email, tenant_id=tenant.id)
    db.commit()
    db.refresh(tenant)
    return tenant


@router.get("/tenants", response_model=list[schemas.TenantOut])
def list_tenants(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)) -> list[models.Tenant]:
    scope = user_tenant_filter(user)
    if scope is not None:
        return list(db.query(models.Tenant).filter(models.Tenant.id == scope).all())
    return list(db.query(models.Tenant).all())


@router.get("/tenants/{tenant_id}", response_model=schemas.TenantOut)
def get_tenant(
    tenant_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)
) -> models.Tenant:
    check_tenant_access(user, tenant_id)
    tenant = db.get(models.Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    return tenant


@router.delete("/tenants/{tenant_id}", status_code=204)
def delete_tenant(
    tenant_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin")),
) -> None:
    tenant = db.get(models.Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    write_audit_log(db, "tenant.delete", "tenant", tenant.id, detail=f"name={tenant.name}", actor=user.email, tenant_id=tenant.id)
    db.delete(tenant)
    db.commit()


def _validate_cidr(cidr: str) -> str:
    try:
        return str(ipaddress.ip_network(cidr, strict=True))
    except ValueError as e:
        raise HTTPException(422, f"invalid CIDR '{cidr}': {e}") from e


@router.post("/tenants/{tenant_id}/groups", response_model=schemas.GroupOut, status_code=201)
def create_group(
    tenant_id: str,
    payload: schemas.GroupCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> models.Group:
    check_tenant_access(user, tenant_id)
    tenant = db.get(models.Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    vpn_subnet = _validate_cidr(payload.vpn_subnet) if payload.vpn_subnet else None
    group = models.Group(tenant_id=tenant_id, name=payload.name, vpn_subnet=vpn_subnet)
    db.add(group)
    db.flush()
    write_audit_log(db, "group.create", "group", group.id, detail=f"name={group.name} tenant_id={tenant_id}", actor=user.email, tenant_id=tenant_id)
    db.commit()
    db.refresh(group)
    return group


@router.get("/tenants/{tenant_id}/groups", response_model=list[schemas.GroupOut])
def list_groups(
    tenant_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)
) -> list[models.Group]:
    check_tenant_access(user, tenant_id)
    if db.get(models.Tenant, tenant_id) is None:
        raise HTTPException(404, "tenant not found")
    return list(db.query(models.Group).filter(models.Group.tenant_id == tenant_id).all())


@router.put("/groups/{group_id}/subnet", response_model=schemas.GroupOut)
def set_group_subnet(
    group_id: str,
    payload: schemas.GroupSubnetUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> models.Group:
    group = get_group_or_403(db, group_id, user)
    group.vpn_subnet = _validate_cidr(payload.vpn_subnet)
    write_audit_log(db, "group.subnet_update", "group", group.id, detail=f"vpn_subnet={group.vpn_subnet}", actor=user.email, tenant_id=group.tenant_id)
    db.commit()
    db.refresh(group)
    return group


@router.get("/routing-table", response_model=list[schemas.RoutingTableEntry])
def get_routing_table(
    db: Session = Depends(get_db), _: None = Depends(require_service_token)
) -> list[schemas.RoutingTableEntry]:
    """Source-IP -> tenant routing table for filter nodes (design.md §7.3
    option 2). Polled machine-to-machine by Rust filter nodes — no user JWT
    involved, so this uses the shared MANTIS_SERVICE_TOKEN instead (see
    require_service_token), like /public-key and the bundle GET endpoint."""
    groups = db.query(models.Group).filter(models.Group.vpn_subnet.is_not(None)).all()
    return [
        schemas.RoutingTableEntry(cidr=g.vpn_subnet, group_id=g.id)
        for g in groups
        if g.vpn_subnet is not None
    ]


@router.get("/local-zones", response_model=list[schemas.LocalZoneRecord])
def get_local_zone_records(
    group_id: str, db: Session = Depends(get_db), _: None = Depends(require_service_token)
) -> list[schemas.LocalZoneRecord]:
    """Flattened local-zone records for the group's tenant (design.md
    §DNS-Zones "stub zone" route type). Polled machine-to-machine by filter
    nodes alongside /routing-table and the policy bundle — same service-token
    auth, no user JWT involved."""
    group = db.get(models.Group, group_id)
    if group is None:
        raise HTTPException(404, "group not found")
    zones = (
        db.query(models.DnsZone)
        .filter(
            models.DnsZone.tenant_id == group.tenant_id,
            models.DnsZone.zone_type == "local",
            models.DnsZone.enabled.is_(True),
        )
        .all()
    )
    out: list[schemas.LocalZoneRecord] = []
    for zone in zones:
        for rec in zone.records:
            if not rec.enabled:
                continue
            fqdn = zone.name if rec.name == "@" else f"{rec.name}.{zone.name}"
            out.append(
                schemas.LocalZoneRecord(
                    name=fqdn,
                    zone=zone.name,
                    record_type=rec.record_type,
                    ttl=rec.ttl if rec.ttl is not None else zone.ttl_default,
                    data=rec.data,
                    priority=rec.priority,
                )
            )
    return out


@router.get("/groups/{group_id}/policy", response_model=schemas.PolicyOut)
def get_policy(
    group_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)
) -> models.Policy:
    get_group_or_403(db, group_id, user)
    policy = db.query(models.Policy).filter(models.Policy.group_id == group_id).one_or_none()
    if policy is None:
        raise HTTPException(404, "policy not found for group")
    return policy


@router.put("/groups/{group_id}/policy", response_model=schemas.PolicyOut)
def upsert_policy(
    group_id: str,
    payload: schemas.PolicyUpsert,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> models.Policy:
    group = get_group_or_403(db, group_id, user)

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
    db.flush()

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

    write_audit_log(
        db,
        "policy.update",
        "policy",
        policy.id,
        detail=f"group_id={group_id} categories={len(payload.category_toggles)} overrides={len(payload.overrides)}",
        actor=user.email,
        tenant_id=group.tenant_id,
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.get("/public-key")
def get_public_key(_: None = Depends(require_service_token)) -> Response:
    """Filter nodes fetch this once and pin it for bundle verification.
    Machine-to-machine, guarded by MANTIS_SERVICE_TOKEN like /routing-table."""
    return Response(
        content=public_key_bytes_for(load_or_create_signing_key()),
        media_type="application/octet-stream",
        headers={"X-Key-Id": KEY_ID},
    )


@router.post("/groups/{group_id}/bundle", status_code=201)
def compile_bundle(
    group_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "operator")),
) -> dict[str, int]:
    """Compiles the group's current policy into a signed bundle, stores it
    content-addressed on disk, and bumps the version. Callers that need the
    bundle bytes fetch them separately via GET /groups/{group_id}/bundle."""
    group = get_group_or_403(db, group_id, user)
    policy = db.query(models.Policy).filter(models.Policy.group_id == group_id).one_or_none()
    if policy is None:
        raise HTTPException(404, "policy not found for group")

    next_version = policy.bundle_version + 1
    bundle_path = compile_and_store(
        policy, next_version, load_or_create_signing_key(), KEY_ID, BUNDLE_STORAGE_DIR, db
    )
    policy.bundle_version = next_version
    write_audit_log(db, "bundle.compile", "policy", policy.id, detail=f"version={next_version}", actor=user.email, tenant_id=group.tenant_id)
    db.commit()
    if not bundle_path.exists():
        raise HTTPException(500, "bundle file missing after compile — storage error")
    return {"version": next_version}


@router.get("/groups/{group_id}/bundle")
def get_latest_bundle(
    group_id: str, db: Session = Depends(get_db), _: None = Depends(require_service_token)
) -> Response:
    """Fetched by filter nodes after they detect a new bundle_version.
    Machine-to-machine traffic guarded by MANTIS_SERVICE_TOKEN like /routing-table."""
    # Validate group_id exists in DB — prevents probing for arbitrary file paths.
    if db.get(models.Group, group_id) is None:
        raise HTTPException(404, "group not found")
    pointer = BUNDLE_STORAGE_DIR / f"{group_id}.latest"
    if not pointer.exists():
        raise HTTPException(404, "no bundle compiled yet for this group")
    digest = pointer.read_text().strip()
    # digest is a hex/content-addressed string written by compile_and_store;
    # verify it contains no path separators before using it as a filename.
    if "/" in digest or "\\" in digest or ".." in digest:
        raise HTTPException(500, "bundle store corrupted")
    bundle_bytes = (BUNDLE_STORAGE_DIR / f"{digest}.bin").read_bytes()
    return Response(content=bundle_bytes, media_type="application/octet-stream")


_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


class PolicyTestRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def _valid_domain(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        if not _DOMAIN_RE.match(v):
            raise ValueError("not a valid domain name")
        return v


class PolicyTestResult(BaseModel):
    domain: str
    decision: str  # "allow" | "block"
    matched: str   # "override_allow" | "override_deny" | "category" | "default"
    matched_category: str | None = None
    matched_feed_id: str | None = None


@router.post("/groups/{group_id}/policy/test", response_model=PolicyTestResult)
def test_domain(
    group_id: str,
    payload: PolicyTestRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("operator", "admin")),
) -> PolicyTestResult:
    """Simulates the filter's decision for a given domain against this group's
    current saved policy (overrides + category toggles). Does NOT require a
    compiled bundle — reads directly from DB + feed domain files."""
    get_group_or_403(db, group_id, user)
    policy = db.query(models.Policy).filter(models.Policy.group_id == group_id).one_or_none()
    if policy is None:
        raise HTTPException(404, "no policy found for this group")

    domain = payload.domain  # already normalised by the validator

    # 1. Allow overrides take precedence over deny overrides (mirrors filter logic).
    for override in policy.overrides:
        if override.kind == "allow" and override.domain.lower() == domain:
            return PolicyTestResult(domain=domain, decision="allow", matched="override_allow")

    # 2. Deny overrides.
    for override in policy.overrides:
        if override.kind == "deny" and override.domain.lower() == domain:
            return PolicyTestResult(domain=domain, decision="block", matched="override_deny")

    # 3. Category toggles — check every enabled feed of each blocked category
    # (a category may have several feeds; the compiler unions them all).
    for toggle in policy.category_toggles:
        if toggle.action != "ACTION_BLOCK":
            continue
        feeds = db.execute(
            select(models.Feed).where(
                models.Feed.category_id == toggle.category_id,
                models.Feed.enabled.is_(True),
                # Mirror the compiler: a never-ingested feed contributes no
                # domains to the bundle, so it must not block here either.
                models.Feed.last_domain_count.is_not(None),
            ).order_by(models.Feed.id)
        ).scalars().all()
        for feed in feeds:
            if domain in load_domains(FEED_STORAGE_DIR, feed.id):
                return PolicyTestResult(
                    domain=domain,
                    decision="block",
                    matched="category",
                    matched_category=toggle.category_id,
                    matched_feed_id=feed.id,
                )

    return PolicyTestResult(domain=domain, decision="allow", matched="default")
