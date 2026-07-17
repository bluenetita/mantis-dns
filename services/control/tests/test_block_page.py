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
from unittest.mock import patch

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
from mantis_control.compiler import build_policy_bundle
from mantis_control.compiler.bloom import BloomFilterBuilder
from mantis_control.compiler.build_policy_bundle import build_bundle
from mantis_control.db.models import (
    AuditLog,
    Base,
    BlockPageTemplate,
    Feed,
    Group,
    Policy,
    PolicyCategoryToggle,
    PolicyOverride,
    Tenant,
)
from mantis_control.feeds.ingest import _feed_path
from mantis_control.gen import bundle_pb2

_TABLES = [
    Tenant.__table__,
    Group.__table__,
    Policy.__table__,
    PolicyCategoryToggle.__table__,
    PolicyOverride.__table__,
    BlockPageTemplate.__table__,
    AuditLog.__table__,
    Feed.__table__,
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


# ── parallel category compile ───────────────────────────────────────────────

def test_compiler_parallelizes_bloom_build_across_categories(db, group, tmp_path):
    """>=2 categories with ingested feeds routes through the process-pool
    branch in build_bundle (services/control/mantis_control/compiler/
    build_policy_bundle.py) instead of the sequential fallback. Each
    category's bloom must still come out correct once recombined."""
    policy = Policy(group_id=group.id)
    db.add(policy)
    db.add(PolicyCategoryToggle(policy=policy, category_id="malware", action="ACTION_BLOCK"))
    db.add(PolicyCategoryToggle(policy=policy, category_id="ads", action="ACTION_BLOCK"))
    db.add(Feed(id="feed-malware", category_id="malware", url="https://example.test/malware",
                format="domain-list", enabled=True, last_domain_count=1))
    db.add(Feed(id="feed-ads", category_id="ads", url="https://example.test/ads",
                format="domain-list", enabled=True, last_domain_count=1))
    db.commit()

    _feed_path(tmp_path, "feed-malware").write_text("evil.example")
    _feed_path(tmp_path, "feed-ads").write_text("tracker.example")

    with patch.object(build_policy_bundle, "FEED_STORAGE_DIR", tmp_path):
        bundle = build_bundle(policy, 1, db)

    by_category = {c.category_id: c for c in bundle.categories}
    assert set(by_category) == {"malware", "ads"}

    for category_id, domain, other_domain in (
        ("malware", "evil.example", "tracker.example"),
        ("ads", "tracker.example", "evil.example"),
    ):
        c = by_category[category_id]
        bf = BloomFilterBuilder(
            build_policy_bundle.BloomParams(c.bloom.num_hashes, c.bloom.num_bits, c.bloom.seed)
        )
        bf._bits = bytearray(c.bloom_bits)
        assert bf.might_contain(domain)
        assert not bf.might_contain(other_domain)


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


# ── uploaded logo (data: URI) ─────────────────────────────────────────────

def test_hosted_logo_url_still_accepted():
    payload = schemas.BlockPageTemplateUpsert(logo_url="https://example.com/logo.png")
    assert payload.logo_url == "https://example.com/logo.png"


def test_uploaded_logo_data_uri_accepted():
    data_uri = "data:image/png;base64," + "A" * 100
    payload = schemas.BlockPageTemplateUpsert(logo_url=data_uri)
    assert payload.logo_url == data_uri


def test_logo_data_uri_rejects_non_image_mime():
    with pytest.raises(ValueError):
        schemas.BlockPageTemplateUpsert(logo_url="data:text/html;base64,PHNjcmlwdD4=")


def test_logo_data_uri_rejects_malformed_base64():
    with pytest.raises(ValueError):
        schemas.BlockPageTemplateUpsert(logo_url="data:image/png;base64,not base64!!")


def test_logo_oversize_rejected():
    with pytest.raises(ValueError):
        schemas.BlockPageTemplateUpsert(logo_url="data:image/png;base64," + "A" * 300_001)


def test_uploaded_logo_round_trips_through_compiler_bundle(db, group):
    """logo_url is a presentation field, not compiled into the signed bundle —
    guards against it accidentally bloating the hot-path artifact."""
    db.add(Policy(group_id=group.id))
    data_uri = "data:image/png;base64," + "A" * 1000
    db.add(
        BlockPageTemplate(
            tenant_id=group.tenant_id,
            group_id=group.id,
            block_mode="BLOCK_MODE_REDIRECT",
            redirect_ipv4="10.0.0.53",
            logo_url=data_uri,
        )
    )
    db.commit()
    policy = db.query(Policy).one()

    bundle = build_bundle(policy, 1, db)
    assert bundle.block_response.mode == bundle_pb2.BLOCK_MODE_REDIRECT
    assert not hasattr(bundle.block_response, "logo_url")

    resolved = resolve_block_template(db, group.tenant_id, group.id)
    assert resolved is not None and resolved.logo_url == data_uri
