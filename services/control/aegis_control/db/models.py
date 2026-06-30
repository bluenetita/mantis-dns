from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import ForeignKey, String, UniqueConstraint
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
    stepping stone, same pattern as bundle/feed storage."""

    __tablename__ = "query_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    group_id: Mapped[str] = mapped_column(String(36), index=True)
    qname: Mapped[str] = mapped_column(String(255))
    decision: Mapped[str] = mapped_column(String(20))  # "allow" | "block"
    occurred_at: Mapped[datetime] = mapped_column(default=_now, index=True)


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
