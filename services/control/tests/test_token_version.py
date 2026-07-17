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

"""A JWT is otherwise stateless for its full 12h TTL — the "tv" (token
version) claim + users.token_version column is what lets change-password
revoke every other already-issued token immediately. In-memory sqlite,
mirroring test_group_crud.py."""
from unittest.mock import MagicMock

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control import auth
from mantis_control.config import settings
from mantis_control.db.models import Base, User

_TABLES = [User.__table__]


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=_TABLES)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def user(db) -> User:
    u = User(email="user@example.test", password_hash="x", role="admin")
    db.add(u)
    db.commit()
    return u


def _creds(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_token_survives_when_token_version_unchanged(db, user):
    token = auth.create_access_token(user)
    result = auth.get_current_user(MagicMock(cookies={}), _creds(token), db)
    assert result.id == user.id


def test_token_rejected_after_password_change_bumps_token_version(db, user):
    token = auth.create_access_token(user)

    user.token_version += 1
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        auth.get_current_user(MagicMock(cookies={}), _creds(token), db)
    assert exc_info.value.status_code == 401


def test_token_issued_after_bump_is_accepted(db, user):
    user.token_version += 1
    db.commit()

    fresh_token = auth.create_access_token(user)
    result = auth.get_current_user(MagicMock(cookies={}), _creds(fresh_token), db)
    assert result.id == user.id


def test_pre_migration_token_without_tv_claim_is_accepted_when_version_still_zero(db, user):
    """A token issued before this field existed has no "tv" claim at all —
    deploying this change must not retroactively invalidate every
    already-issued session, only future password changes."""
    now_payload = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "tenant_id": user.tenant_id,
        # deliberately no "tv" claim
    }
    import datetime as dt
    now_payload["iat"] = dt.datetime.now(dt.timezone.utc)
    now_payload["exp"] = now_payload["iat"] + dt.timedelta(hours=1)
    legacy_token = jwt.encode(now_payload, settings.MANTIS_JWT_SECRET, algorithm="HS256")

    result = auth.get_current_user(MagicMock(cookies={}), _creds(legacy_token), db)
    assert result.id == user.id
