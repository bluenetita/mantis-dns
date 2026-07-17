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

"""Group rename/delete endpoints. In-memory sqlite, mirroring test_block_page.py."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api import schemas
from mantis_control.api.routers import delete_group, rename_group
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


def test_rename_group_updates_name(db, group):
    rename_group(group.id, schemas.GroupUpdate(name="renamed"), db, _User())
    db.refresh(group)
    assert group.name == "renamed"


def test_delete_group_removes_group(db, group):
    group_id = group.id
    delete_group(group_id, db, _User())
    assert db.get(Group, group_id) is None


def test_delete_group_cascades_policy(db, group):
    policy = Policy(group_id=group.id)
    db.add(policy)
    db.commit()
    policy_id = policy.id

    delete_group(group.id, db, _User())

    assert db.get(Policy, policy_id) is None


def test_delete_group_removes_block_page_override(db, group):
    template = BlockPageTemplate(tenant_id=group.tenant_id, group_id=group.id, title="override")
    db.add(template)
    db.commit()
    template_id = template.id

    delete_group(group.id, db, _User())

    assert db.get(BlockPageTemplate, template_id) is None


def test_delete_group_keeps_tenant_default_template(db, group):
    tenant_default = BlockPageTemplate(tenant_id=group.tenant_id, group_id=None, title="tenant default")
    db.add(tenant_default)
    db.commit()
    template_id = tenant_default.id

    delete_group(group.id, db, _User())

    assert db.get(BlockPageTemplate, template_id) is not None
