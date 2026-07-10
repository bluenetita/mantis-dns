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

"""Block-page template resolution.

A block page is configured per group with a tenant-wide default fallback. Both
the policy compiler (which needs the hot-path fields — mode/redirect/ttl) and
the filter node's block-page listener (which needs the branding fields) resolve
a template the same way, so that logic lives here.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from mantis_control.db import models

VALID_BLOCK_MODES = frozenset(
    {"BLOCK_MODE_NXDOMAIN", "BLOCK_MODE_ZERO_IP", "BLOCK_MODE_REDIRECT"}
)


def resolve_block_template(
    db: Session, tenant_id: str, group_id: str | None
) -> models.BlockPageTemplate | None:
    """Returns the effective block-page template for a group: the group's own
    override if present, else the tenant default (group_id NULL), else None
    (the caller falls back to built-in defaults / NXDOMAIN)."""
    if group_id is not None:
        override = db.execute(
            select(models.BlockPageTemplate).where(
                models.BlockPageTemplate.tenant_id == tenant_id,
                models.BlockPageTemplate.group_id == group_id,
            )
        ).scalar_one_or_none()
        if override is not None:
            return override

    return db.execute(
        select(models.BlockPageTemplate).where(
            models.BlockPageTemplate.tenant_id == tenant_id,
            models.BlockPageTemplate.group_id.is_(None),
        )
    ).scalar_one_or_none()
