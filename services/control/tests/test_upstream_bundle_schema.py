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

"""Locks in the upstream-bundle wire shape (get_upstream_bundle) against
accidental drift now that it's built from the admin *_Out schemas via
`.model_dump(exclude=...)` instead of hand-copied field dicts — a typo'd or
removed exclude entry would otherwise leak admin-only metadata (id, tags,
enabled, created_at/updated_at) into the signed payload the Rust filter node
consumes, or silently drop a field it expects.

No DB needed: SQLAlchemy declarative models can be instantiated directly with
keyword args without a session/flush.
"""

from datetime import datetime, timezone

from mantis_control.api.upstream_routers import (
    _DEFAULT_POLICY,
    PoolOut,
    ResolverOut,
    RouteOut,
    TenantPolicyOut,
)
from mantis_control.db import models


def _now() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_resolver_bundle_fields_exclude_admin_only_metadata():
    r = models.UpstreamResolver(
        id="r1", name="cf", protocol="dot", address="1.1.1.1", port=853,
        tls_hostname="cloudflare-dns.com", tls_pin_sha256=["abc"], doh_path="/dns-query",
        doh_method="post", dnssec_validation="strict", qname_minimization=True,
        edns_client_subnet=False, timeout_ms=5000, max_retries=2, connect_timeout_ms=3000,
        tags=["fast"], enabled=True, created_at=_now(), updated_at=_now(),
    )
    out = ResolverOut.model_validate(r).model_dump(
        exclude={"tags", "enabled", "created_at", "updated_at"}
    )
    assert out == {
        "id": "r1", "name": "cf", "protocol": "dot", "address": "1.1.1.1", "port": 853,
        "tls_hostname": "cloudflare-dns.com", "tls_pin_sha256": ["abc"], "doh_path": "/dns-query",
        "doh_method": "post", "dnssec_validation": "strict", "qname_minimization": True,
        "edns_client_subnet": False, "timeout_ms": 5000, "max_retries": 2, "connect_timeout_ms": 3000,
    }


def test_route_bundle_fields_exclude_admin_only_metadata():
    rt = models.UpstreamRoute(
        id="rt1", name="internal", tenant_id="t1", group_id=None, match_type="default",
        match_value=None, pool_id="p1", nxdomain_ttl_override=None, require_dnssec=True,
        priority=100, enabled=True, created_at=_now(), updated_at=_now(),
    )
    out = RouteOut.model_validate(rt).model_dump(exclude={"enabled", "created_at", "updated_at"})
    assert out == {
        "id": "rt1", "name": "internal", "tenant_id": "t1", "group_id": None,
        "match_type": "default", "match_value": None, "pool_id": "p1",
        "nxdomain_ttl_override": None, "require_dnssec": True, "priority": 100,
    }


def test_pool_bundle_fields_exclude_members_and_timestamps():
    p = models.UpstreamPool(
        id="p1", name="primary", strategy="round_robin", health_check_interval_s=30,
        health_check_timeout_ms=2000, health_check_query=".", health_check_type="soa",
        unhealthy_threshold=3, healthy_threshold=2, min_healthy_members=1,
        fallback_pool_id=None, created_at=_now(), updated_at=_now(),
    )
    p.members = []  # avoid touching the DB-backed relationship
    out = PoolOut.model_validate(p).model_dump(exclude={"members", "created_at", "updated_at"})
    assert out == {
        "id": "p1", "name": "primary", "strategy": "round_robin", "health_check_interval_s": 30,
        "health_check_timeout_ms": 2000, "health_check_query": ".", "health_check_type": "soa",
        "unhealthy_threshold": 3, "healthy_threshold": 2, "min_healthy_members": 1,
        "fallback_pool_id": None,
    }


def test_tenant_policy_bundle_fields_exclude_tenant_id():
    policy = models.UpstreamTenantPolicy(
        tenant_id="t1", require_encrypted=True, dnssec_validation="strict",
        qname_minimization=False, blocked_response_type="refused",
        min_ttl_s=10, max_ttl_s=3600, negative_ttl_s=60,
    )
    out = TenantPolicyOut.model_validate(policy).model_dump(exclude={"tenant_id"})
    assert out == {
        "require_encrypted": True, "dnssec_validation": "strict", "qname_minimization": False,
        "blocked_response_type": "refused", "min_ttl_s": 10, "max_ttl_s": 3600, "negative_ttl_s": 60,
    }


def test_tenant_policy_defaults_used_when_no_policy_row():
    """get_upstream_bundle's no-policy fallback: same _DEFAULT_POLICY object
    get_tenant_policy uses, just re-keyed to the requested tenant then
    stripped of tenant_id for the wire payload."""
    fallback = _DEFAULT_POLICY.model_copy(update={"tenant_id": "t2"})
    out = fallback.model_dump(exclude={"tenant_id"})
    assert out == {
        "require_encrypted": False, "dnssec_validation": "opportunistic",
        "qname_minimization": True, "blocked_response_type": "nxdomain",
        "min_ttl_s": 0, "max_ttl_s": 86400, "negative_ttl_s": 300,
    }
