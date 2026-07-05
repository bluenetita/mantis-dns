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

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, ForeignKey, Identity, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)

    groups: Mapped[list["Group"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")


class Group(Base):
    """Maps 1:1 to an OpenVPN AS / community user-group (see design doc §7.3)."""

    __tablename__ = "groups"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_group_tenant_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(255))
    # CIDR of this group's OpenVPN IP pool, e.g. "10.8.1.0/24" (design.md §7.3
    # option 2 — source-IP tenant resolution). Null until an operator wires
    # the group to a real VPN subnet.
    vpn_subnet: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)

    tenant: Mapped[Tenant] = relationship(back_populates="groups")
    policy: Mapped["Policy | None"] = relationship(back_populates="group", uselist=False, cascade="all, delete-orphan")


class Policy(Base):
    """One active policy per group. Versioned via PolicyRevision (not yet modeled - Sprint 2)."""

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    group_id: Mapped[str] = mapped_column(ForeignKey("groups.id"), unique=True)
    on_load_failure: Mapped[str] = mapped_column(String(20), default="FAIL_OPEN")
    bundle_version: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    group: Mapped[Group] = relationship(back_populates="policy")
    category_toggles: Mapped[list["PolicyCategoryToggle"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )
    overrides: Mapped[list["PolicyOverride"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )


class PolicyCategoryToggle(Base):
    __tablename__ = "policy_category_toggles"
    __table_args__ = (UniqueConstraint("policy_id", "category_id", name="uq_policy_category"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id"))
    category_id: Mapped[str] = mapped_column(String(64))  # e.g. "adult", "gambling", "malware"
    action: Mapped[str] = mapped_column(String(20), default="ACTION_BLOCK")

    policy: Mapped[Policy] = relationship(back_populates="category_toggles")


class PolicyOverride(Base):
    __tablename__ = "policy_overrides"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id"))
    domain: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(10))  # "allow" | "deny"

    policy: Mapped[Policy] = relationship(back_populates="overrides")


class QueryEvent(Base):
    """Lightweight query log. Sprint 6: Postgres. design.md §6 calls for
    Kafka -> ClickHouse at scale; this is the local-disk-storage-equivalent
    stepping stone, same pattern as bundle/feed storage.

    Sprint 14 (design.md §20): enriched with client/decision-detail fields so
    the SIEM export API can hand a consuming SIEM actionable data without
    post-processing. `seq` is a monotonic identity column used purely as the
    SIEM pull API's pagination cursor — `id` (UUID) stays the public/external
    identity, `seq` is never exposed as anything but an opaque cursor string.
    """

    __tablename__ = "query_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), unique=True, index=True)
    group_id: Mapped[str] = mapped_column(String(36), index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    qname: Mapped[str] = mapped_column(String(255))
    qtype: Mapped[str | None] = mapped_column(String(16), nullable=True)
    decision: Mapped[str] = mapped_column(String(20))  # "allow" | "block"
    matched_rule: Mapped[str | None] = mapped_column(String(32), nullable=True)
    matched_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    matched_feed_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    response_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cache_hit: Mapped[bool | None] = mapped_column(nullable=True)
    latency_us: Mapped[int | None] = mapped_column(nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(default=_now, index=True)


class SiemWebhook(Base):
    """SIEM push delivery config (design.md §20.4, Sprint 15). `last_delivered_seq`
    is this webhook's own cursor into `QueryEvent.seq` — independent per webhook
    so one slow/misconfigured SIEM can't affect another's delivery progress."""

    __tablename__ = "siem_webhooks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String(1024))
    secret_encrypted: Mapped[str] = mapped_column(String(1024))
    format: Mapped[str] = mapped_column(String(10), default="json")  # "json" | "cef"
    batch_size: Mapped[int] = mapped_column(default=200)
    flush_interval_s: Mapped[int] = mapped_column(default=30)
    filter_decision: Mapped[str] = mapped_column(String(10), default="all")  # "all" | "block" | "allow"
    enabled: Mapped[bool] = mapped_column(default=True)
    last_delivered_seq: Mapped[int] = mapped_column(BigInteger, default=0)
    last_delivered_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(default=0)
    next_retry_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)


class ClientEntry(Base):
    """Client registry (design.md §20.6, Sprint 16) — the bridge between a
    raw client IP in a QueryEvent and a meaningful SIEM alert. Rows are
    auto-created (stub, hostname/owner null) by the query-event ingest path
    the first time a given (tenant_id, ip) is seen; operators fill in the
    rest via the registry API/UI."""

    __tablename__ = "client_entries"
    __table_args__ = (UniqueConstraint("tenant_id", "ip", name="uq_client_tenant_ip"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    group_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    last_seen: Mapped[datetime] = mapped_column(default=_now)
    registered_at: Mapped[datetime | None] = mapped_column(nullable=True)
    registered_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)


class AuditLog(Base):
    """Append-only audit trail for mutating API calls. No UPDATE/DELETE path
    exposed anywhere in this codebase on purpose — see write_audit_log()."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    occurred_at: Mapped[datetime] = mapped_column(default=_now, index=True)
    actor: Mapped[str] = mapped_column(String(255), default="unauthenticated")
    action: Mapped[str] = mapped_column(String(64))  # e.g. "policy.update", "feed.delete"
    resource_type: Mapped[str] = mapped_column(String(64))  # "tenant" | "group" | "policy" | "feed"
    resource_id: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(String(2000), default="")
    # None = a genuinely global action (feed/upstream-resolver management, an
    # unscoped admin push, etc.) — visible only to admins. Populated wherever
    # the mutated resource has a tenant, so a tenant-scoped operator/viewer
    # sees their own tenant's history (see list_audit_log's user_tenant_filter).
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class User(Base):
    """Sprint 8: minimal RBAC. Roles are a fixed hierarchy, not a separate
    table — admin > operator > viewer, see auth.py for the enforcement."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin | operator | viewer
    # NULL = unrestricted; admin role always unrestricted regardless of value.
    # Non-admin with tenant_id set is scoped to that tenant only.
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)


class DnsZone(Base):
    """Local/forward/passthrough DNS zone definitions (design §DNS-Zones)."""

    __tablename__ = "dns_zones"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # Nullable at the DB level only for pre-migration rows (see main.py's
    # additive ALTER TABLE) — every new zone requires one; a null-tenant zone
    # is only visible/manageable by admins (see zone_routers._get_zone_or_403).
    tenant_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    zone_type: Mapped[str] = mapped_column(String(20))  # "local" | "forward" | "passthrough"
    description: Mapped[str] = mapped_column(String(500), default="")
    enabled: Mapped[bool] = mapped_column(default=True)
    ttl_default: Mapped[int] = mapped_column(default=300)
    forwarder: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    records: Mapped[list["DnsRecord"]] = relationship(back_populates="zone", cascade="all, delete-orphan")


class DnsRecord(Base):
    """Resource record belonging to a DnsZone."""

    __tablename__ = "dns_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    zone_id: Mapped[str] = mapped_column(ForeignKey("dns_zones.id"))
    name: Mapped[str] = mapped_column(String(255))  # "@", "www", "*", "mail"
    record_type: Mapped[str] = mapped_column(String(10))  # A AAAA CNAME MX TXT NS PTR SRV CAA
    ttl: Mapped[int | None] = mapped_column(nullable=True)   # None → inherit zone default
    data: Mapped[str] = mapped_column(String(1024))
    priority: Mapped[int | None] = mapped_column(nullable=True)  # MX / SRV
    enabled: Mapped[bool] = mapped_column(default=True)
    # Set only for records created/updated via the DDNS bridge
    # (dhcp_internal_routers._upsert_a_record) — the MAC of the DHCP client
    # that currently "owns" this name. NULL means the record was created
    # through the normal zone-editing API (or predates this column) and DDNS
    # must never silently overwrite it. A non-NULL owner that doesn't match
    # the requesting event's MAC also blocks the overwrite — otherwise any
    # DHCP client could set its hostname option to an existing name (e.g.
    # another host's "printer") and hijack that name's A record.
    ddns_owner_mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    zone: Mapped["DnsZone"] = relationship(back_populates="records")


class UpstreamResolver(Base):
    """Named upstream DNS resolver profile (design.md §21.2)."""

    __tablename__ = "upstream_resolvers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    protocol: Mapped[str] = mapped_column(String(10))  # "dot" | "doh" | "do53"
    address: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(default=853)
    tls_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tls_pin_sha256: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    doh_path: Mapped[str] = mapped_column(String(255), default="/dns-query")
    doh_method: Mapped[str] = mapped_column(String(10), default="post")
    dnssec_validation: Mapped[str] = mapped_column(String(20), default="opportunistic")
    qname_minimization: Mapped[bool] = mapped_column(default=True)
    edns_client_subnet: Mapped[bool] = mapped_column(default=False)
    timeout_ms: Mapped[int] = mapped_column(default=5000)
    max_retries: Mapped[int] = mapped_column(default=2)
    connect_timeout_ms: Mapped[int] = mapped_column(default=3000)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    pool_memberships: Mapped[list["UpstreamPoolMember"]] = relationship(
        back_populates="resolver", cascade="all, delete-orphan"
    )


class UpstreamPool(Base):
    """Load-balancing / failover pool grouping one or more UpstreamResolvers."""

    __tablename__ = "upstream_pools"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    strategy: Mapped[str] = mapped_column(String(30), default="round_robin")
    health_check_interval_s: Mapped[int] = mapped_column(default=30)
    health_check_timeout_ms: Mapped[int] = mapped_column(default=2000)
    health_check_query: Mapped[str] = mapped_column(String(255), default=".")
    health_check_type: Mapped[str] = mapped_column(String(10), default="soa")
    unhealthy_threshold: Mapped[int] = mapped_column(default=3)
    healthy_threshold: Mapped[int] = mapped_column(default=2)
    min_healthy_members: Mapped[int] = mapped_column(default=1)
    fallback_pool_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("upstream_pools.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    members: Mapped[list["UpstreamPoolMember"]] = relationship(
        back_populates="pool", cascade="all, delete-orphan"
    )


class UpstreamPoolMember(Base):
    """Joins an UpstreamResolver into an UpstreamPool with weight / priority."""

    __tablename__ = "upstream_pool_members"
    __table_args__ = (UniqueConstraint("pool_id", "resolver_id", name="uq_pool_member"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    pool_id: Mapped[str] = mapped_column(ForeignKey("upstream_pools.id"))
    resolver_id: Mapped[str] = mapped_column(ForeignKey("upstream_resolvers.id"))
    weight: Mapped[int] = mapped_column(default=1)
    priority: Mapped[int] = mapped_column(default=0)

    pool: Mapped["UpstreamPool"] = relationship(back_populates="members")
    resolver: Mapped["UpstreamResolver"] = relationship(back_populates="pool_memberships")


class UpstreamRoute(Base):
    """Routes a (tenant, qname-pattern) to a pool (design.md §21.2)."""

    __tablename__ = "upstream_routes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    group_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    match_type: Mapped[str] = mapped_column(String(20))  # domain_suffix|domain_exact|qtype|category|default
    match_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pool_id: Mapped[str] = mapped_column(ForeignKey("upstream_pools.id"))
    nxdomain_ttl_override: Mapped[int | None] = mapped_column(nullable=True)
    require_dnssec: Mapped[bool | None] = mapped_column(nullable=True)
    priority: Mapped[int] = mapped_column(default=100)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    pool: Mapped["UpstreamPool"] = relationship()


class UpstreamTenantPolicy(Base):
    """Per-tenant upstream DNS behaviour defaults (design.md §21.2)."""

    __tablename__ = "upstream_tenant_policies"

    tenant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    require_encrypted: Mapped[bool] = mapped_column(default=False)
    dnssec_validation: Mapped[str] = mapped_column(String(20), default="opportunistic")
    qname_minimization: Mapped[bool] = mapped_column(default=True)
    blocked_response_type: Mapped[str] = mapped_column(String(20), default="nxdomain")
    min_ttl_s: Mapped[int] = mapped_column(default=0)
    max_ttl_s: Mapped[int] = mapped_column(default=86400)
    negative_ttl_s: Mapped[int] = mapped_column(default=300)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)


class Feed(Base):
    """Declarative feed registry — see design doc §18.6."""

    __tablename__ = "feeds"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. "ut1-adult"
    category_id: Mapped[str] = mapped_column(String(64))
    url: Mapped[str] = mapped_column(String(1024))
    format: Mapped[str] = mapped_column(String(32))
    interval_seconds: Mapped[int] = mapped_column(default=86400)
    license: Mapped[str] = mapped_column(String(255), default="")
    provider: Mapped[str] = mapped_column(String(255), default="")
    # True for feeds seeded from catalog.json; lets the UI distinguish
    # "built-in, toggle me" from "custom, you can delete me".
    from_catalog: Mapped[bool] = mapped_column(default=False)
    enabled: Mapped[bool] = mapped_column(default=True)
    last_fetched_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_etag: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_domain_count: Mapped[int | None] = mapped_column(nullable=True)


# ── DHCP (Epic M — ISC Kea integration, Sprint 19) ───────────────────────────

class DhcpScope(Base):
    """DHCP subnet/scope pushed to Kea via config-set (design.md §22)."""

    __tablename__ = "dhcp_scopes"
    __table_args__ = (UniqueConstraint("tenant_id", "subnet", name="uq_dhcp_scope_subnet"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    subnet: Mapped[str] = mapped_column(String(50))         # CIDR, e.g. "10.8.1.0/24"
    range_start: Mapped[str] = mapped_column(String(45))    # first IP in dynamic pool
    range_end: Mapped[str] = mapped_column(String(45))      # last IP in dynamic pool
    router_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)    # option 3
    dns_servers: Mapped[list[str]] = mapped_column(ARRAY(String), default=list) # option 6
    ntp_server: Mapped[str | None] = mapped_column(String(45), nullable=True)   # option 42
    domain_name: Mapped[str | None] = mapped_column(String(255), nullable=True) # option 15
    interface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vlan_id: Mapped[int | None] = mapped_column(nullable=True)
    lease_time_s: Mapped[int] = mapped_column(default=86400)
    max_lease_time_s: Mapped[int] = mapped_column(default=604800)
    renew_time_s: Mapped[int | None] = mapped_column(nullable=True)
    rebind_time_s: Mapped[int | None] = mapped_column(nullable=True)
    ddns_enabled: Mapped[bool] = mapped_column(default=False)
    ddns_zone_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    ddns_ttl_s: Mapped[int] = mapped_column(default=300)
    pxe_next_server: Mapped[str | None] = mapped_column(String(45), nullable=True)   # siaddr for all PXE clients
    pxe_boot_filename: Mapped[str | None] = mapped_column(String(255), nullable=True) # option 67 default
    kea_subnet_id: Mapped[int | None] = mapped_column(nullable=True)
    last_pushed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    static_leases: Mapped[list["DhcpStaticLease"]] = relationship(
        back_populates="scope", cascade="all, delete-orphan"
    )
    options: Mapped[list["DhcpOption"]] = relationship(
        back_populates="scope",
        cascade="all, delete-orphan",
        foreign_keys="[DhcpOption.scope_id]",
    )
    relay_configs: Mapped[list["DhcpRelayConfig"]] = relationship(
        back_populates="scope", cascade="all, delete-orphan"
    )


class DhcpStaticLease(Base):
    """Host reservation: fixed IP for a known MAC (design.md §22)."""

    __tablename__ = "dhcp_static_leases"
    __table_args__ = (UniqueConstraint("scope_id", "ip_address", name="uq_dhcp_static_ip"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scope_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("dhcp_scopes.id", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), index=True)
    mac_address: Mapped[str] = mapped_column(String(17))    # "aa:bb:cc:dd:ee:ff"
    ip_address: Mapped[str] = mapped_column(String(45))
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    next_server: Mapped[str | None] = mapped_column(String(45), nullable=True)  # PXE siaddr
    boot_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    scope: Mapped["DhcpScope"] = relationship(back_populates="static_leases")
    options: Mapped[list["DhcpOption"]] = relationship(
        back_populates="static_lease",
        cascade="all, delete-orphan",
        foreign_keys="[DhcpOption.static_lease_id]",
    )


class DhcpOption(Base):
    """Custom DHCP option attached to a scope or a static lease."""

    __tablename__ = "dhcp_options"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scope_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("dhcp_scopes.id", ondelete="CASCADE"), nullable=True
    )
    static_lease_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("dhcp_static_leases.id", ondelete="CASCADE"), nullable=True
    )
    option_code: Mapped[int]
    option_space: Mapped[str] = mapped_column(String(20), default="dhcp4")
    value: Mapped[str] = mapped_column(String(1024))
    always_send: Mapped[bool] = mapped_column(default=False)

    scope: Mapped["DhcpScope | None"] = relationship(
        back_populates="options", foreign_keys="[DhcpOption.scope_id]"
    )
    static_lease: Mapped["DhcpStaticLease | None"] = relationship(
        back_populates="options", foreign_keys="[DhcpOption.static_lease_id]"
    )


class DhcpRelayConfig(Base):
    """DHCP relay agent IPs for a scope."""

    __tablename__ = "dhcp_relay_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scope_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("dhcp_scopes.id", ondelete="CASCADE")
    )
    relay_ip: Mapped[str] = mapped_column(String(45))
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Option 82 sub-option matching (hex strings, e.g. "0x0102030405").
    # Used in Sprint 20+ for client-class based relay classification.
    circuit_id_hex: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remote_id_hex: Mapped[str | None] = mapped_column(String(255), nullable=True)

    scope: Mapped["DhcpScope"] = relationship(back_populates="relay_configs")


class DhcpHaConfig(Base):
    """ISC Kea HA (High Availability) configuration for a tenant.

    One row per tenant.  When enabled, `build_dhcp4_config()` injects
    libdhcp_ha.so + libdhcp_lease_cmds.so hook blocks into the Kea config.
    Supports hot-standby and load-balancing modes.
    """

    __tablename__ = "dhcp_ha_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # HA mode: "hot-standby" (active/passive) or "load-balancing" (active/active)
    mode: Mapped[str] = mapped_column(String(32), default="hot-standby")

    # This server's identity within the HA pair
    this_server_name: Mapped[str] = mapped_column(String(128), default="primary")
    this_server_url: Mapped[str] = mapped_column(String(255), default="http://kea:8004/")

    # Peer (the other Kea instance)
    peer_name: Mapped[str] = mapped_column(String(128), default="secondary")
    peer_url: Mapped[str] = mapped_column(String(255), default="http://kea-secondary:8004/")
    peer_role: Mapped[str] = mapped_column(String(32), default="standby")  # "standby" or "primary"

    # Thresholds (Kea defaults shown)
    max_unacked_clients: Mapped[int | None] = mapped_column(Integer, nullable=True, default=10)
    max_ack_delay_ms: Mapped[int | None] = mapped_column(Integer, nullable=True, default=10000)
    heartbeat_delay_ms: Mapped[int | None] = mapped_column(Integer, nullable=True, default=10000)
    retry_wait_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True, default=5000)

    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)


class DhcpScope6(Base):
    """IPv6 DHCP subnet/scope pushed to kea-dhcp6 via config-set (Sprint 22)."""

    __tablename__ = "dhcp_scopes6"
    __table_args__ = (UniqueConstraint("tenant_id", "subnet", name="uq_dhcp_scope6_subnet"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    subnet: Mapped[str] = mapped_column(String(50))          # e.g. "2001:db8::/48"
    pool_start: Mapped[str] = mapped_column(String(45))      # first IA_NA address
    pool_end: Mapped[str] = mapped_column(String(45))        # last IA_NA address
    pd_prefix: Mapped[str | None] = mapped_column(String(50), nullable=True)
    pd_prefix_len: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dns_servers: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    domain_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    interface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    preferred_lifetime_s: Mapped[int] = mapped_column(default=3000)
    valid_lifetime_s: Mapped[int] = mapped_column(default=4000)
    renew_time_s: Mapped[int | None] = mapped_column(nullable=True)
    rebind_time_s: Mapped[int | None] = mapped_column(nullable=True)
    ddns_enabled: Mapped[bool] = mapped_column(default=False)
    ddns_zone_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    ddns_ttl_s: Mapped[int] = mapped_column(default=300)
    kea_subnet_id: Mapped[int | None] = mapped_column(nullable=True)
    last_pushed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    reservations6: Mapped[list["DhcpStaticLease6"]] = relationship(
        back_populates="scope", cascade="all, delete-orphan"
    )


class DhcpStaticLease6(Base):
    """IPv6 host reservation: fixed address for a known DUID (Sprint 22)."""

    __tablename__ = "dhcp_static_leases6"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scope_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("dhcp_scopes6.id", ondelete="CASCADE")
    )
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    duid: Mapped[str] = mapped_column(String(255))
    ip_address: Mapped[str] = mapped_column(String(45))
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)

    scope: Mapped["DhcpScope6"] = relationship(back_populates="reservations6")
