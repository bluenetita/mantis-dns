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

"""Admin CRUD for per-node M2M credentials (design.md §26 R3). Issuing or
rotating a credential returns the raw token exactly once — like any API-key
pattern, only the sha256 hash is ever persisted (see auth.require_node_token).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from mantis_control.audit import write_audit_log
from mantis_control.auth import generate_node_token, hash_node_token, require_role
from mantis_control.db import models
from mantis_control.db.session import get_db

router = APIRouter()


class NodeCredentialOut(BaseModel):
    node_name: str
    created_at: datetime
    created_by: str
    revoked_at: datetime | None
    last_seen_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NodeCredentialIssued(NodeCredentialOut):
    token: str  # only ever present in the create/rotate response body


class NodeCredentialCreate(BaseModel):
    node_name: str


@router.get("/nodes/credentials", response_model=list[NodeCredentialOut])
def list_node_credentials(
    db: Session = Depends(get_db),
    _user: models.User = Depends(require_role("admin")),
) -> list[models.NodeCredential]:
    return list(db.query(models.NodeCredential).order_by(models.NodeCredential.node_name).all())


@router.post("/nodes/credentials", response_model=NodeCredentialIssued, status_code=201)
def create_node_credential(
    payload: NodeCredentialCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin")),
) -> NodeCredentialIssued:
    if db.get(models.NodeCredential, payload.node_name) is not None:
        raise HTTPException(409, f"a credential for node_name={payload.node_name!r} already exists — use rotate")
    token = generate_node_token()
    node = models.NodeCredential(
        node_name=payload.node_name,
        token_hash=hash_node_token(token),
        created_by=user.email,
        last_seen_at=datetime.now(timezone.utc),
    )
    db.add(node)
    write_audit_log(db, "node_credential.create", "node_credential", payload.node_name, actor=user.email)
    db.commit()
    db.refresh(node)
    return NodeCredentialIssued(token=token, **NodeCredentialOut.model_validate(node).model_dump())


@router.post("/nodes/credentials/{node_name}/rotate", response_model=NodeCredentialIssued)
def rotate_node_credential(
    node_name: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin")),
) -> NodeCredentialIssued:
    """Issues a fresh token for an existing node identity and clears any
    prior revocation — a rotated node is trusted again under the same name,
    the old token stops working the instant this commits."""
    node = db.get(models.NodeCredential, node_name)
    if node is None:
        raise HTTPException(404, "node credential not found")
    token = generate_node_token()
    node.token_hash = hash_node_token(token)
    node.revoked_at = None
    write_audit_log(db, "node_credential.rotate", "node_credential", node_name, actor=user.email)
    db.commit()
    db.refresh(node)
    return NodeCredentialIssued(token=token, **NodeCredentialOut.model_validate(node).model_dump())


@router.post("/nodes/credentials/{node_name}/revoke", response_model=NodeCredentialOut)
def revoke_node_credential(
    node_name: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin")),
) -> models.NodeCredential:
    node = db.get(models.NodeCredential, node_name)
    if node is None:
        raise HTTPException(404, "node credential not found")
    if node.revoked_at is None:
        node.revoked_at = datetime.now(timezone.utc)
        write_audit_log(db, "node_credential.revoke", "node_credential", node_name, actor=user.email)
        db.commit()
        db.refresh(node)
    return node
