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

"""Append-only audit log helper.

No auth/OIDC exists yet (design.md §9, sprint-plan.md Sprint 8 backend item),
so `actor` is always "unauthenticated" for now — wire this to the
authenticated principal once that lands. Logging now rather than waiting
means the audit trail has history from day one instead of a gap before
auth ships.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from mantis_control.db.models import AuditLog


def write_audit_log(
    db: Session,
    action: str,
    resource_type: str,
    resource_id: str,
    detail: str = "",
    actor: str = "unauthenticated",
    tenant_id: str | None = None,
) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=detail,
            tenant_id=tenant_id,
        )
    )
