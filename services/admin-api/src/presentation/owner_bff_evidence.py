"""Exact B16 BFF owner-evidence SOURCE: one authenticated UI boundary.

Follows `admin-web-app/src/features/platform/api/bff-boundary.ts` source
contract. Does not install HTTP/WS or infer owner availability from healthy
containers, raw headers, local ClientState, events, or fake DB URLs.
Physical same-origin HTTPS, C2 admin bearer and signer verification are
mandatory injected ports and currently NOT accepted for public activation.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from common.owner_bff_models import VerifiedAdminCaller
from common.owner_bff_signed import (
    OriginalOwnerSignedEnvelope,
    PinnedBffOwnerKeys,
    canonical_original_identity,
    canonical_sha256,
    verify_source_owner_status,
)


class BffScope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    kind: Literal["account", "team", "project", "operator"]
    teamId: UUID | None = None
    projectId: UUID | None = None

    @model_validator(mode="after")
    def exact_scope(self) -> BffScope:
        if (
            (self.kind == "team") != (self.teamId is not None)
            or (self.kind == "project") != (self.projectId is not None)
            or (self.teamId is not None and self.teamId.version != 4)
            or (self.projectId is not None and self.projectId.version != 4)
        ):
            raise ValueError("BFF scope kind/owner ID inconsistent")
        return self


class BffOwnerState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    availability: Literal["ready", "upgrading", "unavailable", "unknown"]
    revision: str | None = None

    @model_validator(mode="after")
    def verified_state(self) -> BffOwnerState:
        if (self.availability == "ready") != (
            self.revision is not None
            and bool(self.revision)
            and len(self.revision) <= 160
            and all(c.isascii() and (c.isalnum() or c in "_.:-") for c in self.revision)
        ):
            raise ValueError("BFF ready state requires source revision; unready forbids one")
        return self


class BffOwnerEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    actorUserId: UUID
    scope: BffScope
    observedAtUtc: datetime
    expiresAtUtc: datetime
    owners: dict[Literal["identity", "access", "control", "catalog"], BffOwnerState]

    @model_validator(mode="after")
    def pinned_owner_shape(self) -> BffOwnerEvidence:
        if (
            set(self.owners) != {"identity", "access", "control", "catalog"}
            or self.observedAtUtc.tzinfo is None
            or self.expiresAtUtc.tzinfo is None
            or not self.observedAtUtc
            < self.expiresAtUtc
            <= self.observedAtUtc + timedelta(seconds=60)
        ):
            raise ValueError("BFF source evidence incomplete or outside 60s")
        return self


class SourceResourceOwner(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    kind: Literal["team", "project"]
    teamId: UUID | None = None
    projectId: UUID | None = None

    @model_validator(mode="after")
    def match_owner(self) -> SourceResourceOwner:
        if (
            (self.kind == "team") != (self.teamId is not None)
            or (self.kind == "project") != (self.projectId is not None)
            or (self.teamId is not None and self.teamId.version != 4)
            or (self.projectId is not None and self.projectId.version != 4)
        ):
            raise ValueError("resource Owner must be exactly one Team OR Project")
        return self


class SourceCommandTarget(BaseModel):
    """Exact Frontend B16 SourceCommandTarget, no arbitrary scope dict."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    kind: Literal["project", "team", "project_resource", "resource"]
    id: UUID
    owner: SourceResourceOwner | None = None

    @model_validator(mode="after")
    def exact_target(self) -> SourceCommandTarget:
        if self.id.version != 4 or (self.kind == "resource") != (self.owner is not None):
            raise ValueError("owner command target not properly scoped")
        return self


class OriginalCommandBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    operation: str = Field(min_length=1, max_length=128)
    target: SourceCommandTarget


class BffOwnerEffect(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    phase: Literal["pending", "unknown", "reconciling", "confirmed", "denied"]
    revision: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")


class BffEffectEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    actorUserId: UUID
    scope: BffScope
    binding: OriginalCommandBinding
    idempotencyKey: str = Field(min_length=1, max_length=128)
    operationUuid: UUID
    phase: Literal["pending", "unknown", "reconciling", "confirmed", "denied"]
    owners: dict[Literal["identity", "access", "control", "catalog"], BffOwnerEffect]
    observedAtUtc: datetime

    @model_validator(mode="after")
    def original_uuid_is_key(self) -> BffEffectEvidence:
        # No UI-key/owner-UUID aliasing may be created by transport serialization.
        canonical_original_identity(self.operationUuid, self.idempotencyKey)
        return self


class OwnerSourceAttestation(BaseModel):
    """Result already cryptographically verified by pinned private BFF port."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    owner: Literal["identity", "access", "control", "catalog"]
    revision: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")
    actorUserId: UUID
    scope: BffScope
    source_jws_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_expires_at: datetime


class TrustedBffOwnerPort(Protocol):
    async def current_owner(
        self,
        owner: Literal["identity", "access", "control", "catalog"],
        *,
        actor: VerifiedAdminCaller,
        scope: BffScope,
    ) -> OwnerSourceAttestation:
        """Verify owner Ed25519+current SQL and trusted mTLS/Unix peer."""
        ...

    async def required_effect_owners(
        self,
        *,
        actor: VerifiedAdminCaller,
        scope: BffScope,
        binding: OriginalCommandBinding,
    ) -> tuple[Literal["identity", "access", "control", "catalog"], ...]:
        """Independently reviewed command/saga owner policy, not UI guesses.

        Must return Identity+Access+Control and Catalog for resource effects.
        A source transport with no policy returns no effect confirmation.
        """
        ...

    async def original_command(
        self,
        owner: Literal["identity", "access", "control", "catalog"],
        *,
        actor: VerifiedAdminCaller,
        scope: BffScope,
        binding: OriginalCommandBinding,
        key: str,
        operation_uuid: UUID,
    ) -> OriginalOwnerSignedEnvelope:
        """Return the owner-pinned signed original SQL result only; no raw 2xx."""
        ...


class OwnerBffEvidenceSource:
    """Private backend facade; no routes installed until physical C2 acceptance."""

    def __init__(
        self,
        port: TrustedBffOwnerPort,
        *,
        pinned_keys: PinnedBffOwnerKeys,
        recipient_service_id: UUID,
        recipient_instance_uuid: UUID,
    ) -> None:
        if (
            port is None
            or pinned_keys is None
            or recipient_service_id.version != 4
            or recipient_instance_uuid.version != 4
        ):
            raise RuntimeError("BFF requires independently pinned owners and recipient C2")
        self.port = port
        self.pins = pinned_keys
        self.recipient_service_id = recipient_service_id
        self.recipient_instance_uuid = recipient_instance_uuid

    async def current(self, actor: VerifiedAdminCaller, scope: BffScope) -> BffOwnerEvidence:
        now = datetime.now(UTC)
        evidence: dict[Literal["identity", "access", "control", "catalog"], BffOwnerState] = {}
        earliest_expires = now + timedelta(seconds=5)
        for owner in ("identity", "access", "control", "catalog"):
            try:
                async with asyncio.timeout(3):
                    source = await self.port.current_owner(owner, actor=actor, scope=scope)
                if (
                    source.owner != owner
                    or source.actorUserId != actor.user_id
                    or source.scope != scope
                    or source.source_expires_at.tzinfo is None
                    or source.source_expires_at <= now
                ):
                    raise ValueError("owner attestation has wrong subject/scope")
                earliest_expires = min(earliest_expires, source.source_expires_at)
                evidence[owner] = BffOwnerState(availability="ready", revision=source.revision)
            except Exception:
                evidence[owner] = BffOwnerState(availability="unavailable", revision=None)
        return BffOwnerEvidence(
            actorUserId=actor.user_id,
            scope=scope,
            observedAtUtc=now,
            expiresAtUtc=earliest_expires,
            owners=evidence,
        )

    async def inspect_original(
        self,
        actor: VerifiedAdminCaller,
        scope: BffScope,
        binding: OriginalCommandBinding,
        key: str,
        operation_uuid: UUID,
    ) -> BffEffectEvidence:
        # Strict canonical original identity. The browser may carry two
        # independent UUIDv4 values, but the Runtime R15 signed source does
        # NOT: operation_uuid == idempotency_uuid and original key == UUID text.
        # Reject mismatches instead of manufacturing owner-local aliases.
        original_key_sha = canonical_original_identity(operation_uuid, key)
        status = await self.current(actor, scope)
        scope_sha = canonical_sha256(scope.model_dump(mode="json"))
        binding_sha = canonical_sha256(binding.model_dump(mode="json"))
        # Exactly the accepted source-domain owner set may confirm a saga;
        # absent policy is UNKNOWN, never optimistic confirmation.
        try:
            async with asyncio.timeout(3):
                policy = await self.port.required_effect_owners(
                    actor=actor,
                    scope=scope,
                    binding=binding,
                )
        except Exception:
            policy = ()
        trusted = {"identity", "access", "control", "catalog"}
        required = set(policy)
        catalog_needed = binding.target.kind == "resource" or binding.operation.startswith(
            ("catalog.", "credential.", "variable.", "integration.")
        )
        if (
            not {"identity", "access", "control"} <= required
            or not required <= trusted
            or (catalog_needed and "catalog" not in required)
            or len(policy) != len(required)
        ):
            required = set()
        effects: dict[Literal["identity", "access", "control", "catalog"], BffOwnerEffect] = {}
        for owner in ("identity", "access", "control", "catalog"):
            if owner not in required:
                continue
            row = status.owners[owner]
            if row.availability != "ready" or row.revision is None:
                continue
            try:
                async with asyncio.timeout(3):
                    signed = await self.port.original_command(
                        owner,
                        actor=actor,
                        scope=scope,
                        binding=binding,
                        key=key,
                        operation_uuid=operation_uuid,
                    )
                verified = verify_source_owner_status(
                    signed,
                    owner=owner,
                    key=self.pins.public_key(owner),
                    actor_user_id=actor.user_id,
                    operation_uuid=operation_uuid,
                    key_sha256=original_key_sha,
                    scope_sha256=scope_sha,
                    binding_sha256=binding_sha,
                    expected_revision=row.revision,
                    recipient_service_id=self.recipient_service_id,
                    recipient_instance_uuid=self.recipient_instance_uuid,
                )
                effects[owner] = BffOwnerEffect(
                    phase=verified.phase,
                    revision=verified.owner_revision,
                )
            except Exception:
                effects[owner] = BffOwnerEffect(phase="unknown", revision=row.revision)
        observed = datetime.now(UTC)
        phases = {effect.phase for effect in effects.values()}
        # Original owner-local COMMITTED is NEVER a global saga ACK by itself.
        aggregate = (
            "confirmed"
            if required and len(effects) == len(required) and phases == {"confirmed"}
            else "denied"
            if "denied" in phases
            else "unknown"
        )
        return BffEffectEvidence(
            actorUserId=actor.user_id,
            scope=scope,
            binding=binding,
            idempotencyKey=key,
            operationUuid=operation_uuid,
            phase=cast(
                Literal["pending", "unknown", "reconciling", "confirmed", "denied"], aggregate
            ),
            owners=effects,
            observedAtUtc=observed,
        )
