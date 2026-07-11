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

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TenantCreate(BaseModel):
    name: str


class TenantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    created_at: datetime


class GroupCreate(BaseModel):
    name: str
    vpn_subnet: str | None = None


class GroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    name: str
    vpn_subnet: str | None
    created_at: datetime


class GroupSubnetUpdate(BaseModel):
    vpn_subnet: str


class RoutingTableEntry(BaseModel):
    cidr: str
    group_id: str


class LocalZoneRecord(BaseModel):
    """Flattened resource record for the filter node's stub-zone store
    (design.md §7.3, §DNS-Zones). `name` is the fully-qualified owner name."""

    name: str
    zone: str
    record_type: str
    ttl: int
    data: str
    priority: int | None = None


class CategoryOut(BaseModel):
    id: str
    label: str
    description: str
    group: str
    color: str
    icon: str
    default_action: str
    has_bundled_feed: bool


class CategoryToggleIn(BaseModel):
    category_id: str = Field(max_length=64)
    action: Literal["ACTION_BLOCK", "ACTION_LOG_ONLY", "ACTION_ALLOW"] = "ACTION_BLOCK"


class CategoryToggleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    category_id: str
    action: str


class OverrideIn(BaseModel):
    domain: str = Field(max_length=255)
    kind: Literal["allow", "deny"]


class OverrideOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    domain: str
    kind: str


class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    group_id: str
    on_load_failure: str
    category_toggles: list[CategoryToggleOut]
    overrides: list[OverrideOut]


class PolicyUpsert(BaseModel):
    on_load_failure: Literal["FAIL_OPEN", "FAIL_CLOSED"] = "FAIL_OPEN"
    category_toggles: list[CategoryToggleIn] = []
    overrides: list[OverrideIn] = []


_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
# Uploaded logos are stored inline as a base64 data: URI (see BlockPageCard.tsx);
# restrict to image mimetypes so the field can't carry arbitrary payloads.
_LOGO_DATA_URI_RE = re.compile(
    r"^data:image/(?:png|jpeg|gif|webp|svg\+xml);base64,[A-Za-z0-9+/]+=*$"
)
# ~220KB raw image after base64 expansion (~1.37x) — generous for a logo, small
# enough that the branding fetch/cache in the filter's block-page listener
# (docs/design-block-page.md §5.2) stays cheap.
_LOGO_MAX_LEN = 300_000

BlockMode = Literal["BLOCK_MODE_NXDOMAIN", "BLOCK_MODE_ZERO_IP", "BLOCK_MODE_REDIRECT"]


class BlockPageTemplateUpsert(BaseModel):
    """Create/update payload for a group's block page. `group_id` is set by the
    path; a tenant-default template is written with the group's tenant and a
    null group at the router layer."""

    block_mode: BlockMode = "BLOCK_MODE_NXDOMAIN"
    redirect_ipv4: str | None = None
    redirect_ipv6: str | None = None
    ttl_seconds: int = Field(default=30, ge=0, le=86_400)
    title: str | None = Field(default=None, max_length=255)
    message: str | None = Field(default=None, max_length=2000)
    logo_url: str | None = Field(default=None, max_length=_LOGO_MAX_LEN)
    brand_color: str | None = None
    contact_url: str | None = Field(default=None, max_length=1024)
    show_domain: bool = True
    show_category: bool = True

    @field_validator("logo_url")
    @classmethod
    def _valid_logo(cls, v: str | None) -> str | None:
        # Uploaded logos arrive as data: URIs; anything else is treated as a
        # hosted-URL string, same as before this field supported uploads.
        if v and v.startswith("data:") and not _LOGO_DATA_URI_RE.match(v):
            raise ValueError("logo_url data URI must be a base64 png/jpeg/gif/webp/svg image")
        return v or None

    @field_validator("redirect_ipv4")
    @classmethod
    def _valid_v4(cls, v: str | None) -> str | None:
        if v:
            ipaddress.IPv4Address(v)  # raises ValueError -> 422
        return v or None

    @field_validator("redirect_ipv6")
    @classmethod
    def _valid_v6(cls, v: str | None) -> str | None:
        if v:
            ipaddress.IPv6Address(v)
        return v or None

    @field_validator("brand_color")
    @classmethod
    def _valid_color(cls, v: str | None) -> str | None:
        if v and not _HEX_COLOR_RE.match(v):
            raise ValueError("brand_color must be a #rgb or #rrggbb hex color")
        return v or None

    def require_redirect_ip(self) -> None:
        """REDIRECT mode is meaningless without at least one redirect IP."""
        if self.block_mode == "BLOCK_MODE_REDIRECT" and not (
            self.redirect_ipv4 or self.redirect_ipv6
        ):
            raise ValueError("BLOCK_MODE_REDIRECT requires redirect_ipv4 or redirect_ipv6")


class BlockPageTemplateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    group_id: str | None
    block_mode: str
    redirect_ipv4: str | None
    redirect_ipv6: str | None
    ttl_seconds: int
    title: str | None
    message: str | None
    logo_url: str | None
    brand_color: str | None
    contact_url: str | None
    show_domain: bool
    show_category: bool
