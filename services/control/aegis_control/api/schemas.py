from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TenantCreate(BaseModel):
    name: str


class TenantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    created_at: datetime


class GroupCreate(BaseModel):
    name: str


class GroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    name: str
    created_at: datetime


class CategoryToggleIn(BaseModel):
    category_id: str
    action: str = "ACTION_BLOCK"


class CategoryToggleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    category_id: str
    action: str


class OverrideIn(BaseModel):
    domain: str
    kind: str  # "allow" | "deny"


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
    on_load_failure: str = "FAIL_OPEN"
    category_toggles: list[CategoryToggleIn] = []
    overrides: list[OverrideIn] = []
