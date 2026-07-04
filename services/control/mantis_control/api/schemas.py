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

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


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
