from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, ForeignKey, Identity, String, UniqueConstraint
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


class User(Base):
    """Sprint 8: minimal RBAC. Roles are a fixed hierarchy, not a separate
    table — admin > operator > viewer, see auth.py for the enforcement."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin | operator | viewer
    created_at: Mapped[datetime] = mapped_column(default=_now)


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
