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

"""Block-page feature: template resolution (group override → tenant default),
compiler wiring of the signed bundle's `block_response`, and the upsert/resolve
endpoints. In-memory sqlite with just the tables under test, mirroring
test_local_zones_endpoint.py."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api import schemas
from mantis_control.api.routers import (
    _upsert_block_template,
    get_effective_block_template,
    upsert_group_block_template,
)
from mantis_control.block_page import resolve_block_template
from mantis_control.compiler.build_policy_bundle import build_bundle
from mantis_control.db.models import (
    AuditLog,
    Base,
    BlockPageTemplate,
    Group,
    Policy,
    PolicyCategoryToggle,
    PolicyOverride,
    Tenant,
)
from mantis_control.gen import bundle_pb2

_TABLES = [
    Tenant.__table__,
    Group.__table__,
    Policy.__table__,
    PolicyCategoryToggle.__table__,
    PolicyOverride.__table__,
    BlockPageTemplate.__table__,
    AuditLog.__table__,
]


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=_TABLES)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def group(db) -> Group:
    t = Tenant(name="acme")
    db.add(t)
    db.flush()
    g = Group(tenant_id=t.id, name="default")
    db.add(g)
    db.commit()
    return g


class _User:
    email = "admin@example.test"
    role = "admin"
    tenant_id = None


# ── resolution ─────────────────────────────────────────────────────────────

def test_resolve_prefers_group_override_over_tenant_default(db, group):
    db.add(BlockPageTemplate(tenant_id=group.tenant_id, group_id=None, title="tenant"))
    db.add(BlockPageTemplate(tenant_id=group.tenant_id, group_id=group.id, title="group"))
    db.commit()

    resolved = resolve_block_template(db, group.tenant_id, group.id)
    assert resolved is not None and resolved.title == "group"


def test_resolve_falls_back_to_tenant_default(db, group):
    db.add(BlockPageTemplate(tenant_id=group.tenant_id, group_id=None, title="tenant"))
    db.commit()

    resolved = resolve_block_template(db, group.tenant_id, group.id)
    assert resolved is not None and resolved.title == "tenant"


def test_resolve_none_when_unconfigured(db, group):
    assert resolve_block_template(db, group.tenant_id, group.id) is None


# ── compiler wiring ────────────────────────────────────────────────────────

def test_compiler_sets_block_response_for_redirect(db, group):
    db.add(Policy(group_id=group.id))
    db.add(
        BlockPageTemplate(
            tenant_id=group.tenant_id,
            group_id=group.id,
            block_mode="BLOCK_MODE_REDIRECT",
            redirect_ipv4="10.0.0.53",
            ttl_seconds=45,
        )
    )
    db.commit()
    policy = db.query(Policy).one()

    bundle = build_bundle(policy, 1, db)

    assert bundle.HasField("block_response")
    assert bundle.block_response.mode == bundle_pb2.BLOCK_MODE_REDIRECT
    assert bundle.block_response.redirect_ipv4 == "10.0.0.53"
    assert bundle.block_response.ttl_seconds == 45


def test_compiler_omits_block_response_for_nxdomain(db, group):
    db.add(Policy(group_id=group.id))
    db.add(
        BlockPageTemplate(
            tenant_id=group.tenant_id, group_id=group.id, block_mode="BLOCK_MODE_NXDOMAIN"
        )
    )
    db.commit()
    policy = db.query(Policy).one()

    bundle = build_bundle(policy, 1, db)
    # NXDOMAIN is the default; leaving the field absent keeps old filters happy.
    assert not bundle.HasField("block_response")


def test_compiler_omits_block_response_when_no_template(db, group):
    db.add(Policy(group_id=group.id))
    db.commit()
    policy = db.query(Policy).one()

    bundle = build_bundle(policy, 1, db)
    assert not bundle.HasField("block_response")


# ── endpoints ──────────────────────────────────────────────────────────────

def test_upsert_then_resolve_via_service_endpoint(db, group):
    payload = schemas.BlockPageTemplateUpsert(
        block_mode="BLOCK_MODE_REDIRECT",
        redirect_ipv4="10.0.0.53",
        title="Blocked by Acme",
        brand_color="#ff0000",
    )
    upsert_group_block_template(group_id=group.id, payload=payload, db=db, user=_User())

    out = get_effective_block_template(group_id=group.id, db=db, _=None)
    assert out.block_mode == "BLOCK_MODE_REDIRECT"
    assert out.redirect_ipv4 == "10.0.0.53"
    assert out.title == "Blocked by Acme"


def test_upsert_is_idempotent_update(db, group):
    _upsert_block_template(
        db, group.tenant_id, group.id, schemas.BlockPageTemplateUpsert(title="v1"), _User()
    )
    _upsert_block_template(
        db, group.tenant_id, group.id, schemas.BlockPageTemplateUpsert(title="v2"), _User()
    )
    assert db.query(BlockPageTemplate).count() == 1
    assert db.query(BlockPageTemplate).one().title == "v2"


def test_redirect_mode_requires_redirect_ip():
    payload = schemas.BlockPageTemplateUpsert(block_mode="BLOCK_MODE_REDIRECT")
    with pytest.raises(ValueError):
        payload.require_redirect_ip()


def test_invalid_redirect_ip_rejected():
    with pytest.raises(ValueError):
        schemas.BlockPageTemplateUpsert(redirect_ipv4="not-an-ip")


def test_invalid_brand_color_rejected():
    with pytest.raises(ValueError):
        schemas.BlockPageTemplateUpsert(brand_color="red")
