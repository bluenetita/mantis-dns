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
from mantis_control.db.models import AuditLog, Base, NodeCredential, User


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[NodeCredential.__table__, AuditLog.__table__])
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _admin() -> User:
    return User(email="admin@mantis.local", role="admin")


def test_create_then_authenticate_with_the_issued_token(db):
    issued = create_node_credential(NodeCredentialCreate(node_name="filter-1"), db=db, user=_admin())
    assert issued.node_name == "filter-1"
    assert issued.token  # raw token only ever appears in this response

    # The issued token must actually authenticate — proves hash_node_token
    # round-trips between issuance here and verification in require_node_token.
    auth.require_node_token(authorization=f"Bearer {issued.token}", x_mantis_node="filter-1", db=db)


def test_create_rejects_a_duplicate_node_name(db):
    create_node_credential(NodeCredentialCreate(node_name="filter-1"), db=db, user=_admin())
    with pytest.raises(HTTPException) as exc:
        create_node_credential(NodeCredentialCreate(node_name="filter-1"), db=db, user=_admin())
    assert exc.value.status_code == 409


def test_revoke_then_the_old_token_no_longer_authenticates(db):
    issued = create_node_credential(NodeCredentialCreate(node_name="filter-1"), db=db, user=_admin())
    revoke_node_credential("filter-1", db=db, user=_admin())

    with pytest.raises(HTTPException) as exc:
        auth.require_node_token(authorization=f"Bearer {issued.token}", x_mantis_node="filter-1", db=db)
    assert exc.value.status_code == 403


def test_revoking_one_node_does_not_affect_another(db):
    """The whole point of per-node credentials over one shared secret."""
    issued_1 = create_node_credential(NodeCredentialCreate(node_name="filter-1"), db=db, user=_admin())
    issued_2 = create_node_credential(NodeCredentialCreate(node_name="filter-2"), db=db, user=_admin())
    revoke_node_credential("filter-1", db=db, user=_admin())

    with pytest.raises(HTTPException):
        auth.require_node_token(authorization=f"Bearer {issued_1.token}", x_mantis_node="filter-1", db=db)
    auth.require_node_token(authorization=f"Bearer {issued_2.token}", x_mantis_node="filter-2", db=db)


def test_rotate_issues_a_new_token_and_invalidates_the_old_one(db):
    issued = create_node_credential(NodeCredentialCreate(node_name="filter-1"), db=db, user=_admin())
    rotated = rotate_node_credential("filter-1", db=db, user=_admin())

    assert rotated.token != issued.token
    with pytest.raises(HTTPException):
        auth.require_node_token(authorization=f"Bearer {issued.token}", x_mantis_node="filter-1", db=db)
    auth.require_node_token(authorization=f"Bearer {rotated.token}", x_mantis_node="filter-1", db=db)


def test_rotate_also_un_revokes(db):
    create_node_credential(NodeCredentialCreate(node_name="filter-1"), db=db, user=_admin())
    revoke_node_credential("filter-1", db=db, user=_admin())
    rotated = rotate_node_credential("filter-1", db=db, user=_admin())

    auth.require_node_token(authorization=f"Bearer {rotated.token}", x_mantis_node="filter-1", db=db)


def test_revoke_missing_node_is_404(db):
    with pytest.raises(HTTPException) as exc:
        revoke_node_credential("ghost", db=db, user=_admin())
    assert exc.value.status_code == 404


def test_list_never_includes_the_token(db):
    create_node_credential(NodeCredentialCreate(node_name="filter-1"), db=db, user=_admin())
    [node] = list_node_credentials(db=db, _user=_admin())
    assert not hasattr(node, "token")
