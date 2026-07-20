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

"""Regression tests for POST /groups/{id}/policy/test (`test_domain`):

1. It must strip a leading "www." like the real filter's decide()/normalize()
   does, or it reports "allow" for a "www.<blocked-domain>" query the filter
   actually blocks — the exact divergence _normalize_domain's cross-file
   contract exists to prevent.
2. It must surface an ACTION_LOG_ONLY category match (as "category_log_only",
   decision "allow") instead of silently treating it as "default" — and an
   ACTION_BLOCK category match must still win over a log-only match.
"""
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api.routers import PolicyTestRequest
# Aliased on import: pytest's default collection picks up any module-level
# `test_*` name as a test item, including one merely imported (not defined)
# here — without the alias it tries to collect the endpoint function itself
# as a fixture-taking test and errors on missing fixtures.
from mantis_control.api.routers import test_domain as run_policy_test
from mantis_control.db.models import (
    Base,
    Feed,
    Group,
    Policy,
    PolicyCategoryToggle,
    PolicyOverride,
    Tenant,
)
from mantis_control.feeds.ingest import _feed_path

_TABLES = [
    Tenant.__table__,
    Group.__table__,
    Policy.__table__,
    PolicyCategoryToggle.__table__,
    PolicyOverride.__table__,
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
    db.flush()
    db.add(Policy(group_id=g.id))
    db.commit()
    return g


class _Admin:
    email = "admin@example.test"
    role = "admin"
    tenant_id = None


def _add_category_feed(db, tmp_path, group: Group, category_id: str, action: str, domains: list[str]) -> None:
    policy = db.query(Policy).filter(Policy.group_id == group.id).one()
    db.add(PolicyCategoryToggle(policy_id=policy.id, category_id=category_id, action=action))
    feed_id = f"{category_id}-feed"
    db.add(Feed(
        id=feed_id, category_id=category_id, url=f"https://example.test/{feed_id}",
        format="domain-list", enabled=True, last_domain_count=len(domains),
    ))
    db.commit()
    _feed_path(tmp_path, feed_id).write_text("\n".join(domains))


def test_www_prefixed_query_matches_a_feed_stored_without_www(db, group, tmp_path):
    _add_category_feed(db, tmp_path, group, "malware", "ACTION_BLOCK", ["evil.example"])

    with patch("mantis_control.api.routers.FEED_STORAGE_DIR", tmp_path):
        result = run_policy_test(group.id, PolicyTestRequest(domain="www.evil.example"), db, _Admin())

    assert result.decision == "block"
    assert result.matched == "category"
    assert result.matched_category == "malware"


def test_log_only_category_match_is_reported_not_swallowed_as_default(db, group, tmp_path):
    _add_category_feed(db, tmp_path, group, "social", "ACTION_LOG_ONLY", ["chat.example"])

    with patch("mantis_control.api.routers.FEED_STORAGE_DIR", tmp_path):
        result = run_policy_test(group.id, PolicyTestRequest(domain="chat.example"), db, _Admin())

    assert result.decision == "allow", "log-only must never block"
    assert result.matched == "category_log_only"
    assert result.matched_category == "social"


def test_block_category_wins_over_log_only_match(db, group, tmp_path):
    _add_category_feed(db, tmp_path, group, "social", "ACTION_LOG_ONLY", ["evil.example"])
    _add_category_feed(db, tmp_path, group, "malware", "ACTION_BLOCK", ["evil.example"])

    with patch("mantis_control.api.routers.FEED_STORAGE_DIR", tmp_path):
        result = run_policy_test(group.id, PolicyTestRequest(domain="evil.example"), db, _Admin())

    assert result.decision == "block"
    assert result.matched == "category"
    assert result.matched_category == "malware"


def test_www_prefixed_query_matches_a_www_stripped_override(db, group, tmp_path):
    policy = db.query(Policy).filter(Policy.group_id == group.id).one()
    db.add(PolicyOverride(policy_id=policy.id, domain="blocked-by-name.example", kind="deny"))
    db.commit()

    with patch("mantis_control.api.routers.FEED_STORAGE_DIR", tmp_path):
        result = run_policy_test(group.id, PolicyTestRequest(domain="www.blocked-by-name.example"), db, _Admin())

    assert result.decision == "block"
    assert result.matched == "override_deny"
