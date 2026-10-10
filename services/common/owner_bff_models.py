"""Typed private cross-image owner BFF source DTOs.

Both Control and Admin API are separate images. Shared immutable wire values
belong in `common`, never import Admin presentation from Control service.
They are not grants without a separately verified current C2 caller.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from common.platform_db import OwnerName


class OwnerBffModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class VerifiedAdminCaller(OwnerBffModel):
    """Opaque result from trusted current Admin bearer source; never a user header."""

    user_id: UUID
    credential_version: int = Field(ge=1)
    source: Literal["verified-admin-bearer"]


class OwnerProjectView(OwnerBffModel):
    project_id: UUID
    name: str
    owner_user_id: UUID | None = None
    owner_team_id: UUID | None = None
    version: int = Field(ge=1)
    lifecycle_status: Literal["active", "deleting", "deleted"] = "active"
    resource_revision: int = Field(ge=0)
    current_identity_revision: int = Field(ge=1)
    current_access_revision: int = Field(ge=1)
    effective_permissions: tuple[str, ...] = ()


class OwnerTeamView(OwnerBffModel):
    team_id: UUID
    name: str
    owner_user_id: UUID
    version: int = Field(ge=1)
    current_membership_revision: int = Field(ge=1)


class OwnerPage[T](OwnerBffModel):
    items: tuple[T, ...]
    next_after_id: UUID | None = None
    has_more: bool = False


class OwnerCommandState(OwnerBffModel):
    owner: OwnerName
    operation_uuid: UUID
    project_id: UUID
    operation: str
    state: Literal["NOT_FOUND", "UNKNOWN", "COMMITTED", "DENIED"]
    reconciliation_required: bool = True
    # A settled original operation is not permission to retry with a NEW key.
    operation_replay_safe: Literal[False] = False


class OwnerTeamCommandState(OwnerBffModel):
    team_id: UUID
    operation_uuid: UUID
    operation: Literal["team.member.add", "team.member.remove", "team.owner.transfer"]
    state: Literal["NOT_FOUND", "UNKNOWN", "COMMITTED", "DENIED"]
    reconciliation_required: bool = True
    operation_replay_safe: Literal[False] = False


class OwnerRealtimeProjection(OwnerBffModel):
    """Current identity filtering is still required; events are NOT grants."""

    scope_kind: Literal["user", "team", "project"]
    scope_id: UUID
    sequence: int = Field(ge=0)
    epoch: UUID
    event_type: str = Field(min_length=1, max_length=128)
    created_at: datetime
