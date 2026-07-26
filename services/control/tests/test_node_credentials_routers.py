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

"""design.md §26 R3: admin CRUD for per-node M2M credentials."""

from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control import auth
from mantis_control.api.node_credentials_routers import (
    create_node_credential,
    list_node_credentials,
    revoke_node_credential,
    rotate_node_credential,
    NodeCredentialCreate,
)
from mantis_control.api.routers import get_routing_table
from mantis_control.db.models import AuditLog, Base, Group, NodeCredential, Tenant, User


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[
            Tenant.__table__,
            Group.__table__,
            NodeCredential.__table__,
            AuditLog.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _admin() -> User:
    return User(email="admin@mantis.local", role="admin")


def _global_node(node_name: str) -> NodeCredentialCreate:
    return NodeCredentialCreate(node_name=node_name, allow_all=True)


def test_create_then_authenticate_with_the_issued_token(db):
    issued = create_node_credential(_global_node("filter-1"), db=db, user=_admin())
    assert issued.node_name == "filter-1"
    assert issued.token  # raw token only ever appears in this response

    # The issued token must actually authenticate — proves hash_node_token
    # round-trips between issuance here and verification in require_node_token.
    auth.require_node_token(authorization=f"Bearer {issued.token}", x_mantis_node="filter-1", db=db)


def test_create_rejects_a_duplicate_node_name(db):
    create_node_credential(_global_node("filter-1"), db=db, user=_admin())
    with pytest.raises(HTTPException) as exc:
        create_node_credential(_global_node("filter-1"), db=db, user=_admin())
    assert exc.value.status_code == 409


def test_revoke_then_the_old_token_no_longer_authenticates(db):
    issued = create_node_credential(_global_node("filter-1"), db=db, user=_admin())
    revoke_node_credential("filter-1", db=db, user=_admin())

    with pytest.raises(HTTPException) as exc:
        auth.require_node_token(authorization=f"Bearer {issued.token}", x_mantis_node="filter-1", db=db)
    assert exc.value.status_code == 403


def test_revoking_one_node_does_not_affect_another(db):
    """The whole point of per-node credentials over one shared secret."""
    issued_1 = create_node_credential(_global_node("filter-1"), db=db, user=_admin())
    issued_2 = create_node_credential(_global_node("filter-2"), db=db, user=_admin())
    revoke_node_credential("filter-1", db=db, user=_admin())

    with pytest.raises(HTTPException):
        auth.require_node_token(authorization=f"Bearer {issued_1.token}", x_mantis_node="filter-1", db=db)
    auth.require_node_token(authorization=f"Bearer {issued_2.token}", x_mantis_node="filter-2", db=db)


def test_rotate_issues_a_new_token_and_invalidates_the_old_one(db):
    issued = create_node_credential(_global_node("filter-1"), db=db, user=_admin())
    rotated = rotate_node_credential("filter-1", db=db, user=_admin())

    assert rotated.token != issued.token
    with pytest.raises(HTTPException):
        auth.require_node_token(authorization=f"Bearer {issued.token}", x_mantis_node="filter-1", db=db)
    auth.require_node_token(authorization=f"Bearer {rotated.token}", x_mantis_node="filter-1", db=db)


def test_rotate_also_un_revokes(db):
    create_node_credential(_global_node("filter-1"), db=db, user=_admin())
    revoke_node_credential("filter-1", db=db, user=_admin())
    rotated = rotate_node_credential("filter-1", db=db, user=_admin())

    auth.require_node_token(authorization=f"Bearer {rotated.token}", x_mantis_node="filter-1", db=db)


def test_revoke_missing_node_is_404(db):
    with pytest.raises(HTTPException) as exc:
        revoke_node_credential("ghost", db=db, user=_admin())
    assert exc.value.status_code == 404


def test_list_never_includes_the_token(db):
    create_node_credential(_global_node("filter-1"), db=db, user=_admin())
    [node] = list_node_credentials(db=db, _user=_admin())
    assert not hasattr(node, "token")


def test_new_credential_requires_an_explicit_scope():
    with pytest.raises(ValueError, match="scope is required"):
        NodeCredentialCreate(node_name="unscoped")


def test_group_scoped_credential_cannot_cross_group_or_tenant(db):
    tenant_a = Tenant(id="tenant-a", name="Tenant A")
    tenant_b = Tenant(id="tenant-b", name="Tenant B")
    group_a = Group(id="group-a", tenant_id=tenant_a.id, name="A")
    group_b = Group(id="group-b", tenant_id=tenant_b.id, name="B")
    db.add_all([tenant_a, tenant_b, group_a, group_b])
    db.commit()

    issued = create_node_credential(
        NodeCredentialCreate(node_name="filter-a", allowed_group_ids=[group_a.id]),
        db=db,
        user=_admin(),
    )
    node = auth.require_node_token(
        authorization=f"Bearer {issued.token}", x_mantis_node="filter-a", db=db
    )

    auth.require_node_group_access(node, group_a)
    assert auth.node_can_access_tenant(db, node, tenant_a.id)
    with pytest.raises(HTTPException, match="not authorized"):
        auth.require_node_group_access(node, group_b)
    with pytest.raises(HTTPException, match="not authorized"):
        auth.require_node_tenant_access(db, node, tenant_b.id)


def test_routing_table_only_exposes_the_nodes_scoped_groups(db):
    tenant = Tenant(id="tenant-a", name="Tenant A")
    group_a = Group(
        id="group-a",
        tenant_id=tenant.id,
        name="A",
        vpn_subnet="10.0.1.0/24",
    )
    group_b = Group(
        id="group-b",
        tenant_id=tenant.id,
        name="B",
        vpn_subnet="10.0.2.0/24",
    )
    db.add_all([tenant, group_a, group_b])
    db.commit()
    node = NodeCredential(
        node_name="filter-a",
        token_hash="x",
        created_by="test",
        allow_all=False,
        allowed_group_ids=[group_a.id],
        allowed_tenant_ids=[],
    )

    assert [entry.model_dump() for entry in get_routing_table(db=db, node=node)] == [
        {
            "cidr": "10.0.1.0/24",
            "group_id": "group-a",
            "tenant_id": "tenant-a",
        }
    ]
