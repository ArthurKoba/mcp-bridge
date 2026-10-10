"""Field-exact A11 owner command DTO projection, private/unmounted.

Source: Backend A11 `common.owner_contracts.OwnerCommandDTO`, whose CODE is
Backend-owned and not yet accepted into Runtime's released baseline. This
module projects its strictly typed NONSECRET command fields only, without
importing any owner ORM, shared SQL engine, key or signing implementation.

A11 `SignedOwnerProofs` (three SecretStr JWTs) are intentionally NOT returned
to Runtime, MCP or browser. The actual owner transaction must fetch/consume
and independently verify Identity/Platform/Access proof epochs at effect time.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .authorization import ProjectInvocation, ProjectPermit
from .owner_authorization import VerifiedOwnerRecipient

A11TargetOwner = Literal[
    "identity", "access", "platform", "resources", "files", "runtime", "reverse", "ingest"
]


class A11OwnerCommandDTO(BaseModel):
    """Matches A11 `OwnerCommandDTO` field names/types and strict bounds."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    operation_uuid: UUID
    caller_user_id: UUID
    project_id: UUID
    session_uuid: UUID
    target_owner: A11TargetOwner
    operation: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=128)
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_identity_revision: int = Field(ge=1)
    expected_control_revision: int = Field(ge=1)
    expected_control_resource_revision: int = Field(ge=0)
    expected_team_id: UUID | None = None
    expected_team_revision: int | None = Field(default=None, ge=1)
    expected_team_resource_revision: int | None = Field(default=None, ge=0)
    expected_access_revision: int = Field(ge=1)

    @field_validator("idempotency_key")
    @classmethod
    def printable_idempotency_key(cls, value: str) -> str:
        if not value.isascii() or not value.isprintable():
            raise ValueError("owner idempotency key must be printable ASCII")
        return value

    @field_validator("expected_team_id")
    @classmethod
    def team_identifier(cls, value: UUID | None) -> UUID | None:
        if value is not None and value.version != 4:
            raise ValueError("Team scope identifier must be UUIDv4")
        return value

    @field_validator("operation_uuid", "caller_user_id", "project_id", "session_uuid")
    @classmethod
    def uuidv4(cls, value: UUID) -> UUID:
        if not isinstance(value, UUID) or value.version != 4:
            raise ValueError("A11 operation/identity IDs must be UUIDv4")
        return value


class VerifiedA11SourceVersions(BaseModel):
    """Three-owner verified current proof projection, no JWT contents.

    A11 transport must authenticate and verify original EdDSA Identity,
    Platform and Access authority epochs+signed resource/Team revisions. This
    value is expected-state and not itself a bearer or owner's SQL decision.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    owner: A11TargetOwner
    audience: str = Field(min_length=9, max_length=40)
    operation: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=128)
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    recipient_service_id: UUID
    recipient_instance_uuid: UUID
    actor_user_id: UUID
    project_id: UUID
    session_uuid: UUID
    operation_uuid: UUID
    expected_identity_revision: int = Field(ge=1)
    expected_control_revision: int = Field(ge=1)
    expected_control_resource_revision: int = Field(ge=0)
    expected_team_id: UUID | None = None
    expected_team_revision: int | None = Field(default=None, ge=1)
    expected_team_resource_revision: int | None = Field(default=None, ge=0)
    expected_access_revision: int = Field(ge=1)
    identity_epoch: UUID
    platform_epoch: UUID
    access_epoch: UUID
    expires_at: datetime

    @model_validator(mode="after")
    def check_epoch_and_ownership(self) -> VerifiedA11SourceVersions:
        if (
            not all(
                isinstance(x, UUID) and x.version == 4
                for x in (
                    self.recipient_service_id,
                    self.recipient_instance_uuid,
                    self.actor_user_id,
                    self.project_id,
                    self.session_uuid,
                    self.operation_uuid,
                    self.identity_epoch,
                    self.platform_epoch,
                    self.access_epoch,
                )
            )
            or not (
                (self.expected_team_id is None)
                == (self.expected_team_revision is None)
                == (self.expected_team_resource_revision is None)
            )
            or (self.expected_team_id is not None and self.expected_team_id.version != 4)
            or self.audience != f"briareus:{self.owner}"
            or self.expires_at.tzinfo is None
            or self.expires_at <= datetime.now(UTC)
            or (self.expires_at - datetime.now(UTC)).total_seconds() > 15
        ):
            raise ValueError("A11 signed owner revision projection is invalid")
        return self


class VerifiedA11RevisionPort(Protocol):
    """C2 independent current Identity+Platform+Access proof authority.

    Backend A11 must produce this projection by verifying its *actual* signed
    proofs and JTI/current grant sources. A Project/Team read model, untrusted
    header or cached bearer is not accepted; absent live A11 port DENIES.
    In particular, TEAM revisions cannot be inferred from a Project SHA.
    """

    async def current_owner_revisions(
        self,
        invocation: ProjectInvocation,
        *,
        owner: A11TargetOwner,
        action: str,
        phase: str,
        operation: str,
        payload_sha256: str,
        idempotency_key: str,
        recipient: VerifiedOwnerRecipient,
        permit: ProjectPermit,
    ) -> VerifiedA11SourceVersions: ...
