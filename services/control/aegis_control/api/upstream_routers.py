"""DNS Upstream Configuration API (design.md §21, Sprint 17).

Manages UpstreamResolver, UpstreamPool, UpstreamRoute and UpstreamTenantPolicy
objects. Also exposes:
  - POST /upstream/resolvers/{id}/probe  — live DNS probe (round-trip test)
  - GET  /upstream-bundle/{tenant_id}    — signed upstream config bundle consumed
                                           by the Rust filter node.

Bundle signing uses the same ed25519 key as policy bundles. The payload is
serialized as canonical JSON (sort_keys=True, no whitespace); the HTTP response
body IS the payload and the ed25519 signature over those bytes is returned in
the X-Aegis-Signature header (hex-encoded). The Rust loader verifies the
signature before trusting the bundle.
"""

from __future__ import annotations

import asyncio
import base64
import json
import socket
import ssl
import struct
import time
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, selectinload

from aegis_control.audit import write_audit_log
from aegis_control.auth import check_tenant_access, get_current_user, require_role
from aegis_control.compiler.keys import KEY_ID, load_or_create_signing_key
from aegis_control.compiler.signing import public_key_raw_bytes
from aegis_control.db import models
from aegis_control.db.session import get_db

router = APIRouter()

_SIGNING_KEY = load_or_create_signing_key()

# ── Pydantic schemas ───────────────────────────────────────────────────────────

class ResolverCreate(BaseModel):
    name: str
    protocol: Literal["dot", "doh", "do53"]
    address: str
    port: int = 853
    tls_hostname: str | None = None
    tls_pin_sha256: list[str] = []
    doh_path: str = "/dns-query"
    doh_method: Literal["get", "post"] = "post"
    dnssec_validation: Literal["strict", "opportunistic", "disabled"] = "opportunistic"
    qname_minimization: bool = True
    edns_client_subnet: bool = False
    timeout_ms: int = Field(5000, ge=100, le=30000)
    max_retries: int = Field(2, ge=0, le=5)
    connect_timeout_ms: int = Field(3000, ge=100, le=15000)
    tags: list[str] = []
    enabled: bool = True


class ResolverUpdate(BaseModel):
    name: str | None = None
    protocol: Literal["dot", "doh", "do53"] | None = None
    address: str | None = None
    port: int | None = None
    tls_hostname: str | None = None
    tls_pin_sha256: list[str] | None = None
    doh_path: str | None = None
    doh_method: Literal["get", "post"] | None = None
    dnssec_validation: Literal["strict", "opportunistic", "disabled"] | None = None
    qname_minimization: bool | None = None
    edns_client_subnet: bool | None = None
    timeout_ms: int | None = Field(None, ge=100, le=30000)
    max_retries: int | None = Field(None, ge=0, le=5)
    connect_timeout_ms: int | None = Field(None, ge=100, le=15000)
    tags: list[str] | None = None
    enabled: bool | None = None


class ResolverOut(BaseModel):
    id: str
    name: str
    protocol: str
    address: str
    port: int
    tls_hostname: str | None
    tls_pin_sha256: list[str]
    doh_path: str
    doh_method: str
    dnssec_validation: str
    qname_minimization: bool
    edns_client_subnet: bool
    timeout_ms: int
    max_retries: int
    connect_timeout_ms: int
    tags: list[str]
    enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PoolMemberIn(BaseModel):
    resolver_id: str
    weight: int = Field(1, ge=1, le=100)
    priority: int = Field(0, ge=0)


class PoolMemberOut(BaseModel):
    id: str
    pool_id: str
    resolver_id: str
    weight: int
    priority: int

    class Config:
        from_attributes = True


class PoolCreate(BaseModel):
    name: str
    strategy: Literal["round_robin", "weighted_round_robin", "failover", "latency"] = "round_robin"
    health_check_interval_s: int = Field(30, ge=5, le=3600)
    health_check_timeout_ms: int = Field(2000, ge=100, le=10000)
    health_check_query: str = "."
    health_check_type: Literal["soa", "a", "txt"] = "soa"
    unhealthy_threshold: int = Field(3, ge=1, le=10)
    healthy_threshold: int = Field(2, ge=1, le=10)
    min_healthy_members: int = Field(1, ge=1)
    fallback_pool_id: str | None = None
    members: list[PoolMemberIn] = []


class PoolUpdate(BaseModel):
    name: str | None = None
    strategy: Literal["round_robin", "weighted_round_robin", "failover", "latency"] | None = None
    health_check_interval_s: int | None = Field(None, ge=5, le=3600)
    health_check_timeout_ms: int | None = Field(None, ge=100, le=10000)
    health_check_query: str | None = None
    health_check_type: Literal["soa", "a", "txt"] | None = None
    unhealthy_threshold: int | None = Field(None, ge=1, le=10)
    healthy_threshold: int | None = Field(None, ge=1, le=10)
    min_healthy_members: int | None = Field(None, ge=1)
    fallback_pool_id: str | None = None


class PoolOut(BaseModel):
    id: str
    name: str
    strategy: str
    health_check_interval_s: int
    health_check_timeout_ms: int
    health_check_query: str
    health_check_type: str
    unhealthy_threshold: int
    healthy_threshold: int
    min_healthy_members: int
    fallback_pool_id: str | None
    members: list[PoolMemberOut]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RouteCreate(BaseModel):
    name: str
    group_id: str | None = None
    match_type: Literal["domain_suffix", "domain_exact", "qtype", "category", "default"]
    match_value: str | None = None
    pool_id: str
    nxdomain_ttl_override: int | None = None
    require_dnssec: bool | None = None
    priority: int = 100
    enabled: bool = True


class RouteUpdate(BaseModel):
    name: str | None = None
    group_id: str | None = None
    match_type: Literal["domain_suffix", "domain_exact", "qtype", "category", "default"] | None = None
    match_value: str | None = None
    pool_id: str | None = None
    nxdomain_ttl_override: int | None = None
    require_dnssec: bool | None = None
    priority: int | None = None
    enabled: bool | None = None


class RouteOut(BaseModel):
    id: str
    name: str
    tenant_id: str | None
    group_id: str | None
    match_type: str
    match_value: str | None
    pool_id: str
    nxdomain_ttl_override: int | None
    require_dnssec: bool | None
    priority: int
    enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TenantPolicyIn(BaseModel):
    require_encrypted: bool = False
    dnssec_validation: Literal["strict", "opportunistic", "disabled"] = "opportunistic"
    qname_minimization: bool = True
    blocked_response_type: Literal["nxdomain", "refused", "zero_ip"] = "nxdomain"
    min_ttl_s: int = Field(0, ge=0)
    max_ttl_s: int = Field(86400, ge=0)
    negative_ttl_s: int = Field(300, ge=0)


class TenantPolicyOut(BaseModel):
    tenant_id: str
    require_encrypted: bool
    dnssec_validation: str
    qname_minimization: bool
    blocked_response_type: str
    min_ttl_s: int
    max_ttl_s: int
    negative_ttl_s: int

    class Config:
        from_attributes = True


class ProbeResult(BaseModel):
    ok: bool
    latency_ms: float | None
    response_code: str | None
    dnssec_ad: bool
    tls_subject: str | None
    error: str | None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _soa_query_bytes() -> bytes:
    """Minimal RFC 1035 SOA query for '.' (root zone)."""
    # Header: txid=0xABCD, RD=1, QDCOUNT=1, rest 0
    header = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    # QNAME: root = single null byte; QTYPE=SOA(6); QCLASS=IN(1)
    question = b"\x00" + struct.pack("!HH", 6, 1)
    return header + question


def _parse_response_code(data: bytes) -> tuple[str, bool]:
    """Returns (rcode_name, ad_bit) from a DNS wire-format response."""
    if len(data) < 4:
        return ("PARSE_ERROR", False)
    flags = struct.unpack("!H", data[2:4])[0]
    rcode = flags & 0x000F
    ad = bool(flags & 0x0020)
    names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
             4: "NOTIMP", 5: "REFUSED"}
    return (names.get(rcode, f"RCODE{rcode}"), ad)


async def _probe_do53(address: str, port: int, timeout_ms: int) -> ProbeResult:
    query = _soa_query_bytes()
    loop = asyncio.get_event_loop()
    t0 = time.monotonic()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_ms / 1000)
        await loop.run_in_executor(None, lambda: sock.sendto(query, (address, port)))
        data, _ = await loop.run_in_executor(None, lambda: sock.recvfrom(512))
        latency_ms = (time.monotonic() - t0) * 1000
        sock.close()
        rcode, ad = _parse_response_code(data)
        return ProbeResult(ok=True, latency_ms=round(latency_ms, 2),
                           response_code=rcode, dnssec_ad=ad, tls_subject=None, error=None)
    except Exception as e:
        return ProbeResult(ok=False, latency_ms=None, response_code=None,
                           dnssec_ad=False, tls_subject=None, error=str(e))


async def _probe_dot(
    address: str, port: int, tls_hostname: str | None, timeout_ms: int
) -> ProbeResult:
    server_hostname = tls_hostname or address
    query = _soa_query_bytes()
    # TCP DNS requires a 2-byte length prefix
    tcp_payload = struct.pack("!H", len(query)) + query
    loop = asyncio.get_event_loop()
    t0 = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        conn = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: _dot_connect(address, port, server_hostname, ctx, tcp_payload),
            ),
            timeout=timeout_ms / 1000,
        )
        latency_ms = (time.monotonic() - t0) * 1000
        data, tls_subject = conn
        rcode, ad = _parse_response_code(data)
        return ProbeResult(ok=True, latency_ms=round(latency_ms, 2),
                           response_code=rcode, dnssec_ad=ad, tls_subject=tls_subject, error=None)
    except Exception as e:
        return ProbeResult(ok=False, latency_ms=None, response_code=None,
                           dnssec_ad=False, tls_subject=None, error=str(e))


def _dot_connect(
    address: str, port: int, server_hostname: str, ctx: ssl.SSLContext, payload: bytes
) -> tuple[bytes, str | None]:
    with socket.create_connection((address, port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
            cert = tls.getpeercert()
            subject = None
            if cert:
                for field in cert.get("subject", []):
                    for key, val in field:
                        if key == "commonName":
                            subject = val
            tls.sendall(payload)
            # Read 2-byte length prefix
            length_bytes = tls.recv(2)
            if len(length_bytes) < 2:
                raise ValueError("short length prefix in DoT response")
            length = struct.unpack("!H", length_bytes)[0]
            data = b""
            while len(data) < length:
                chunk = tls.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            return data, subject


async def _probe_doh(
    address: str, port: int, tls_hostname: str | None, path: str,
    method: str, timeout_ms: int
) -> ProbeResult:
    host = tls_hostname or address
    url = f"https://{host}:{port}{path}"
    query = _soa_query_bytes()
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(verify=True, timeout=timeout_ms / 1000) as client:
            if method == "get":
                encoded = base64.urlsafe_b64encode(query).rstrip(b"=").decode()
                resp = await client.get(url, params={"dns": encoded},
                                        headers={"Accept": "application/dns-message"})
            else:
                resp = await client.post(url, content=query,
                                         headers={"Content-Type": "application/dns-message",
                                                  "Accept": "application/dns-message"})
            latency_ms = (time.monotonic() - t0) * 1000
            resp.raise_for_status()
            rcode, ad = _parse_response_code(resp.content)
            return ProbeResult(ok=True, latency_ms=round(latency_ms, 2),
                               response_code=rcode, dnssec_ad=ad, tls_subject=host, error=None)
    except Exception as e:
        return ProbeResult(ok=False, latency_ms=None, response_code=None,
                           dnssec_ad=False, tls_subject=None, error=str(e))


def _sign_bundle_body(payload: dict[str, Any]) -> tuple[bytes, str]:
    """Serialize payload as canonical JSON; sign with ed25519. Returns (body_bytes, hex_sig)."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    sig = _SIGNING_KEY.sign(body)
    return body, sig.hex()


def _get_resolver_or_404(db: Session, resolver_id: str) -> models.UpstreamResolver:
    r = db.get(models.UpstreamResolver, resolver_id)
    if r is None:
        raise HTTPException(404, "resolver not found")
    return r


def _get_pool_or_404(db: Session, pool_id: str) -> models.UpstreamPool:
    p = db.query(models.UpstreamPool).options(
        selectinload(models.UpstreamPool.members).selectinload(models.UpstreamPoolMember.resolver)
    ).filter(models.UpstreamPool.id == pool_id).one_or_none()
    if p is None:
        raise HTTPException(404, "pool not found")
    return p


# ── Resolvers ──────────────────────────────────────────────────────────────────

@router.get("/upstream/resolvers", response_model=list[ResolverOut])
def list_resolvers(
    db: Session = Depends(get_db),
    _admin: models.User = Depends(require_role("admin")),
) -> list[models.UpstreamResolver]:
    return list(db.query(models.UpstreamResolver).order_by(models.UpstreamResolver.name).all())


@router.post("/upstream/resolvers", response_model=ResolverOut, status_code=201)
def create_resolver(
    payload: ResolverCreate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.UpstreamResolver:
    r = models.UpstreamResolver(**payload.model_dump())
    db.add(r)
    db.flush()
    write_audit_log(db, "upstream_resolver.create", "upstream_resolver", r.id,
                    detail=f"name={r.name} proto={r.protocol} addr={r.address}:{r.port}",
                    actor=admin.email)
    db.commit()
    db.refresh(r)
    return r


@router.patch("/upstream/resolvers/{resolver_id}", response_model=ResolverOut)
def update_resolver(
    resolver_id: str,
    payload: ResolverUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.UpstreamResolver:
    r = _get_resolver_or_404(db, resolver_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(r, field, value)
    write_audit_log(db, "upstream_resolver.update", "upstream_resolver", r.id,
                    detail=str(payload.model_dump(exclude_unset=True)), actor=admin.email)
    db.commit()
    db.refresh(r)
    return r


@router.delete("/upstream/resolvers/{resolver_id}", status_code=204)
def delete_resolver(
    resolver_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> None:
    r = _get_resolver_or_404(db, resolver_id)
    write_audit_log(db, "upstream_resolver.delete", "upstream_resolver", r.id,
                    detail=f"name={r.name}", actor=admin.email)
    db.delete(r)
    db.commit()


@router.post("/upstream/resolvers/{resolver_id}/probe", response_model=ProbeResult)
async def probe_resolver(
    resolver_id: str,
    db: Session = Depends(get_db),
    _admin: models.User = Depends(require_role("admin")),
) -> ProbeResult:
    r = _get_resolver_or_404(db, resolver_id)
    if r.protocol == "do53":
        return await _probe_do53(r.address, r.port, r.timeout_ms)
    if r.protocol == "dot":
        return await _probe_dot(r.address, r.port, r.tls_hostname, r.timeout_ms)
    # doh
    return await _probe_doh(r.address, r.port, r.tls_hostname,
                             r.doh_path, r.doh_method, r.timeout_ms)


# ── Pools ──────────────────────────────────────────────────────────────────────

@router.get("/upstream/pools", response_model=list[PoolOut])
def list_pools(
    db: Session = Depends(get_db),
    _admin: models.User = Depends(require_role("admin")),
) -> list[models.UpstreamPool]:
    return list(
        db.query(models.UpstreamPool)
        .options(selectinload(models.UpstreamPool.members).selectinload(models.UpstreamPoolMember.resolver))
        .order_by(models.UpstreamPool.name)
        .all()
    )


@router.post("/upstream/pools", response_model=PoolOut, status_code=201)
def create_pool(
    payload: PoolCreate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.UpstreamPool:
    members_data = payload.members
    pool_data = payload.model_dump(exclude={"members"})
    pool = models.UpstreamPool(**pool_data)
    db.add(pool)
    db.flush()
    for m in members_data:
        if db.get(models.UpstreamResolver, m.resolver_id) is None:
            raise HTTPException(422, f"resolver {m.resolver_id} not found")
        db.add(models.UpstreamPoolMember(pool_id=pool.id, **m.model_dump()))
    write_audit_log(db, "upstream_pool.create", "upstream_pool", pool.id,
                    detail=f"name={pool.name} strategy={pool.strategy}", actor=admin.email)
    db.commit()
    return _get_pool_or_404(db, pool.id)


@router.patch("/upstream/pools/{pool_id}", response_model=PoolOut)
def update_pool(
    pool_id: str,
    payload: PoolUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.UpstreamPool:
    pool = _get_pool_or_404(db, pool_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(pool, field, value)
    write_audit_log(db, "upstream_pool.update", "upstream_pool", pool.id,
                    detail=str(payload.model_dump(exclude_unset=True)), actor=admin.email)
    db.commit()
    return _get_pool_or_404(db, pool_id)


@router.delete("/upstream/pools/{pool_id}", status_code=204)
def delete_pool(
    pool_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> None:
    pool = _get_pool_or_404(db, pool_id)
    write_audit_log(db, "upstream_pool.delete", "upstream_pool", pool.id,
                    detail=f"name={pool.name}", actor=admin.email)
    db.delete(pool)
    db.commit()


@router.put("/upstream/pools/{pool_id}/members/{resolver_id}", response_model=PoolMemberOut)
def upsert_pool_member(
    pool_id: str,
    resolver_id: str,
    payload: PoolMemberIn,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.UpstreamPoolMember:
    _get_pool_or_404(db, pool_id)
    if db.get(models.UpstreamResolver, resolver_id) is None:
        raise HTTPException(404, "resolver not found")
    member = (
        db.query(models.UpstreamPoolMember)
        .filter_by(pool_id=pool_id, resolver_id=resolver_id)
        .one_or_none()
    )
    if member is None:
        member = models.UpstreamPoolMember(pool_id=pool_id, resolver_id=resolver_id)
        db.add(member)
    member.weight = payload.weight
    member.priority = payload.priority
    db.commit()
    db.refresh(member)
    return member


@router.delete("/upstream/pools/{pool_id}/members/{resolver_id}", status_code=204)
def remove_pool_member(
    pool_id: str,
    resolver_id: str,
    db: Session = Depends(get_db),
    _admin: models.User = Depends(require_role("admin")),
) -> None:
    member = (
        db.query(models.UpstreamPoolMember)
        .filter_by(pool_id=pool_id, resolver_id=resolver_id)
        .one_or_none()
    )
    if member is None:
        raise HTTPException(404, "member not found")
    db.delete(member)
    db.commit()


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/tenants/{tenant_id}/upstream/routes", response_model=list[RouteOut])
def list_routes(
    tenant_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[models.UpstreamRoute]:
    check_tenant_access(user, tenant_id)
    return list(
        db.query(models.UpstreamRoute)
        .filter(models.UpstreamRoute.tenant_id == tenant_id)
        .order_by(models.UpstreamRoute.priority, models.UpstreamRoute.name)
        .all()
    )


@router.post("/tenants/{tenant_id}/upstream/routes", response_model=RouteOut, status_code=201)
def create_route(
    tenant_id: str,
    payload: RouteCreate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.UpstreamRoute:
    check_tenant_access(admin, tenant_id)
    if db.get(models.UpstreamPool, payload.pool_id) is None:
        raise HTTPException(422, "pool not found")
    route = models.UpstreamRoute(tenant_id=tenant_id, **payload.model_dump())
    db.add(route)
    db.flush()
    write_audit_log(db, "upstream_route.create", "upstream_route", route.id,
                    detail=f"tenant={tenant_id} match={route.match_type}:{route.match_value}",
                    actor=admin.email)
    db.commit()
    db.refresh(route)
    return route


@router.patch("/tenants/{tenant_id}/upstream/routes/{route_id}", response_model=RouteOut)
def update_route(
    tenant_id: str,
    route_id: str,
    payload: RouteUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.UpstreamRoute:
    check_tenant_access(admin, tenant_id)
    route = db.get(models.UpstreamRoute, route_id)
    if route is None or route.tenant_id != tenant_id:
        raise HTTPException(404, "route not found")
    changes = payload.model_dump(exclude_unset=True)
    if "pool_id" in changes and db.get(models.UpstreamPool, changes["pool_id"]) is None:
        raise HTTPException(422, "pool not found")
    for field, value in changes.items():
        setattr(route, field, value)
    write_audit_log(db, "upstream_route.update", "upstream_route", route.id,
                    detail=str(changes), actor=admin.email)
    db.commit()
    db.refresh(route)
    return route


@router.delete("/tenants/{tenant_id}/upstream/routes/{route_id}", status_code=204)
def delete_route(
    tenant_id: str,
    route_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> None:
    check_tenant_access(admin, tenant_id)
    route = db.get(models.UpstreamRoute, route_id)
    if route is None or route.tenant_id != tenant_id:
        raise HTTPException(404, "route not found")
    write_audit_log(db, "upstream_route.delete", "upstream_route", route.id,
                    detail=f"tenant={tenant_id}", actor=admin.email)
    db.delete(route)
    db.commit()


# ── Tenant policy ──────────────────────────────────────────────────────────────

_DEFAULT_POLICY = TenantPolicyOut(
    tenant_id="",
    require_encrypted=False,
    dnssec_validation="opportunistic",
    qname_minimization=True,
    blocked_response_type="nxdomain",
    min_ttl_s=0,
    max_ttl_s=86400,
    negative_ttl_s=300,
)


@router.get("/tenants/{tenant_id}/upstream/policy", response_model=TenantPolicyOut)
def get_tenant_policy(
    tenant_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> TenantPolicyOut | models.UpstreamTenantPolicy:
    check_tenant_access(user, tenant_id)
    policy = db.get(models.UpstreamTenantPolicy, tenant_id)
    if policy is None:
        out = _DEFAULT_POLICY.model_copy(update={"tenant_id": tenant_id})
        return out
    return policy


@router.put("/tenants/{tenant_id}/upstream/policy", response_model=TenantPolicyOut)
def upsert_tenant_policy(
    tenant_id: str,
    payload: TenantPolicyIn,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_role("admin")),
) -> models.UpstreamTenantPolicy:
    check_tenant_access(admin, tenant_id)
    if db.get(models.Tenant, tenant_id) is None:
        raise HTTPException(404, "tenant not found")
    policy = db.get(models.UpstreamTenantPolicy, tenant_id)
    if policy is None:
        policy = models.UpstreamTenantPolicy(tenant_id=tenant_id, **payload.model_dump())
        db.add(policy)
    else:
        for field, value in payload.model_dump().items():
            setattr(policy, field, value)
    write_audit_log(db, "upstream_policy.upsert", "upstream_tenant_policy", tenant_id,
                    detail=str(payload.model_dump()), actor=admin.email)
    db.commit()
    db.refresh(policy)
    return policy


# ── Bundle endpoint (consumed by Rust filter node) ─────────────────────────────

@router.get("/upstream-bundle/{tenant_id}")
def get_upstream_bundle(tenant_id: str, db: Session = Depends(get_db)) -> Response:
    """
    Compiles a signed upstream config bundle for the given tenant.
    No auth — like /api/v1/groups/{id}/bundle, integrity is provided by the
    ed25519 signature; network isolation secures delivery.

    Response body: canonical JSON bundle payload (sort_keys, no whitespace).
    X-Aegis-Signature header: hex-encoded ed25519 signature over the body bytes.
    X-Aegis-Bundle-Version: unix timestamp of compilation (for cache-busting).
    """
    # Collect routes: global (tenant_id=NULL) + tenant-specific, sorted by priority.
    routes = (
        db.query(models.UpstreamRoute)
        .filter(
            (models.UpstreamRoute.tenant_id == tenant_id)
            | (models.UpstreamRoute.tenant_id.is_(None))
        )
        .filter(models.UpstreamRoute.enabled.is_(True))
        .order_by(models.UpstreamRoute.priority, models.UpstreamRoute.name)
        .all()
    )

    # Collect all referenced pools and resolvers.
    pool_ids = {r.pool_id for r in routes}
    pools = {
        p.id: p
        for p in db.query(models.UpstreamPool)
        .options(selectinload(models.UpstreamPool.members).selectinload(models.UpstreamPoolMember.resolver))
        .filter(models.UpstreamPool.id.in_(pool_ids))
        .all()
    } if pool_ids else {}

    resolver_ids = {
        m.resolver_id
        for p in pools.values()
        for m in p.members
        if m.resolver.enabled
    }
    resolvers = {
        r.id: r
        for r in db.query(models.UpstreamResolver)
        .filter(models.UpstreamResolver.id.in_(resolver_ids))
        .all()
    } if resolver_ids else {}

    # Tenant policy (or defaults).
    policy = db.get(models.UpstreamTenantPolicy, tenant_id)

    now_ts = int(datetime.now(timezone.utc).timestamp())

    bundle: dict[str, Any] = {
        "version": now_ts,
        "tenant_id": tenant_id,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "routes": [
            {
                "id": rt.id,
                "name": rt.name,
                "tenant_id": rt.tenant_id,
                "group_id": rt.group_id,
                "match_type": rt.match_type,
                "match_value": rt.match_value,
                "pool_id": rt.pool_id,
                "nxdomain_ttl_override": rt.nxdomain_ttl_override,
                "require_dnssec": rt.require_dnssec,
                "priority": rt.priority,
            }
            for rt in routes
        ],
        "pools": {
            pid: {
                "id": p.id,
                "name": p.name,
                "strategy": p.strategy,
                "health_check_interval_s": p.health_check_interval_s,
                "health_check_timeout_ms": p.health_check_timeout_ms,
                "health_check_query": p.health_check_query,
                "health_check_type": p.health_check_type,
                "unhealthy_threshold": p.unhealthy_threshold,
                "healthy_threshold": p.healthy_threshold,
                "min_healthy_members": p.min_healthy_members,
                "fallback_pool_id": p.fallback_pool_id,
                "members": [
                    {
                        "resolver_id": m.resolver_id,
                        "weight": m.weight,
                        "priority": m.priority,
                    }
                    for m in sorted(p.members, key=lambda x: (x.priority, x.weight))
                    if m.resolver.enabled
                ],
            }
            for pid, p in pools.items()
        },
        "resolvers": {
            rid: {
                "id": r.id,
                "name": r.name,
                "protocol": r.protocol,
                "address": r.address,
                "port": r.port,
                "tls_hostname": r.tls_hostname,
                "tls_pin_sha256": r.tls_pin_sha256 or [],
                "doh_path": r.doh_path,
                "doh_method": r.doh_method,
                "dnssec_validation": r.dnssec_validation,
                "qname_minimization": r.qname_minimization,
                "edns_client_subnet": r.edns_client_subnet,
                "timeout_ms": r.timeout_ms,
                "max_retries": r.max_retries,
                "connect_timeout_ms": r.connect_timeout_ms,
            }
            for rid, r in resolvers.items()
        },
        "tenant_policy": {
            "require_encrypted": policy.require_encrypted if policy else False,
            "dnssec_validation": policy.dnssec_validation if policy else "opportunistic",
            "qname_minimization": policy.qname_minimization if policy else True,
            "blocked_response_type": policy.blocked_response_type if policy else "nxdomain",
            "min_ttl_s": policy.min_ttl_s if policy else 0,
            "max_ttl_s": policy.max_ttl_s if policy else 86400,
            "negative_ttl_s": policy.negative_ttl_s if policy else 300,
        },
    }

    body, sig_hex = _sign_bundle_body(bundle)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "X-Aegis-Signature": sig_hex,
            "X-Aegis-Bundle-Version": str(now_ts),
        },
    )
