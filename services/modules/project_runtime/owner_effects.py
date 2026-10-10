"""Signed owner-local command/outcome port for Catalog, Files, Runtime, Reverse.

Four independent databases/roles/transaction journals. No global SQL UoW,
no direct ORM imports, no cross-DB FK or event-as-authorization. Backend A11
must independently accept exact wire DTOs before binding a real transport;
without an installed trusted source every operation denies, never migrates.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from common.owner_contracts import OwnerAuthorityUnavailable
from common.owner_effect_phase_map import require_exact_owner_operation

from .a11_owner_wire import (
    A11OwnerCommandDTO,
    A11TargetOwner,
    VerifiedA11RevisionPort,
    VerifiedA11SourceVersions,
)
from .authorization import (
    ProjectAccessDenied,
    ProjectAction,
    ProjectInvocation,
    ProjectOwnerFence,
    ProjectPermit,
    ProjectRuntimeAuthority,
    valid_project_revision,
)
from .owner_authorization import VerifiedOwnerRecipient
from .owner_wire import (
    A11OwnerWireNotAccepted,
    accepted_a11_owner_wire,
    require_accepted_owner_lifecycle,
)

EffectOwner = Literal["catalog", "files", "execution", "reverse"]
EffectPhase = Literal[
    "read",
    "list",
    "metadata",
    "file_dispatch",
    "file_reconcile",
    "reserve",
    "dispatch",
    "finalize",
    "inspect",
    "reconcile",
    "release",
    "claim",
    "cancel",
    "revoke",
    "open",
    "heartbeat",
    "queue_job",
    "start_job",
    "finish_job",
    "fail_job",
    "mark_unknown",
    "confirm_cleanup",
]
EffectState = Literal[
    "reserved",
    "dispatched",
    "unknown",
    "committed",
    "released",
    "active",
    "revoked",
    "closed",
    "running",
    "finished",
    "failed",
    "cancelled",
    "recorded",
    "absent",
]
_A11_TARGET: dict[EffectOwner, A11TargetOwner] = {
    "catalog": "resources",
    "files": "files",
    "execution": "runtime",
    "reverse": "reverse",
}

_DB: dict[
    EffectOwner,
    Literal["briareus_resources", "briareus_files", "briareus_runtime", "briareus_reverse"],
] = {
    "catalog": "briareus_resources",
    "files": "briareus_files",
    "execution": "briareus_runtime",
    "reverse": "briareus_reverse",
}
_PHASES: dict[EffectOwner, frozenset[EffectPhase]] = {
    "catalog": frozenset({"read", "inspect", "reserve", "revoke", "mark_unknown", "reconcile"}),
    "files": frozenset(
        {
            "read",
            "list",
            "metadata",
            "file_dispatch",
            "file_reconcile",
            "reserve",
            "dispatch",
            "finalize",
            "inspect",
            "reconcile",
            "release",
            "mark_unknown",
        }
    ),
    "execution": frozenset(
        {
            "open",
            "heartbeat",
            "queue_job",
            "start_job",
            "finish_job",
            "fail_job",
            "inspect",
            "revoke",
            "mark_unknown",
            "confirm_cleanup",
        }
    ),
    "reverse": frozenset({"claim", "dispatch", "inspect", "reconcile", "cancel", "mark_unknown"}),
}


def _uuid4(value: object) -> bool:
    return isinstance(value, UUID) and value.version == 4


def _digest(data: object) -> str:
    serialized = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    if len(serialized) > 600000:
        raise ProjectAccessDenied("OWNER_EFFECT_PAYLOAD_TOO_LARGE")
    return hashlib.sha256(serialized).hexdigest()


class OwnerFenceDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    identity_version: int = Field(ge=1)
    identity_revocation_epoch: int = Field(ge=0)
    identity_authority_epoch: UUID
    control_state_version: int = Field(ge=1)
    control_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    control_scope_epoch: int = Field(ge=0)
    control_authority_epoch: UUID
    access_session_version: int = Field(ge=1)
    access_revocation_epoch: int = Field(ge=0)
    access_authority_epoch: UUID

    @classmethod
    def from_permit(cls, permit: ProjectPermit) -> OwnerFenceDTO:
        fence = permit.owner_fence
        if not isinstance(fence, ProjectOwnerFence) or not fence.valid():
            raise ProjectAccessDenied("OWNER_EFFECT_THREE_REVOCATION_FENCES_REQUIRED")
        return cls.model_validate(
            {
                "identity_version": fence.identity_version,
                "identity_revocation_epoch": fence.identity_revocation_epoch,
                "identity_authority_epoch": fence.identity_authority_epoch,
                "control_state_version": fence.control_state_version,
                "control_revision": fence.control_revision,
                "control_scope_epoch": fence.control_scope_epoch,
                "control_authority_epoch": fence.control_authority_epoch,
                "access_session_version": fence.access_session_version,
                "access_revocation_epoch": fence.access_revocation_epoch,
                "access_authority_epoch": fence.access_authority_epoch,
            }
        )


class OwnerEffectCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    protocol: Literal["owner-effect-command-v1"] = "owner-effect-command-v1"
    owner: EffectOwner
    owner_database: Literal[
        "briareus_resources", "briareus_files", "briareus_runtime", "briareus_reverse"
    ]
    phase: EffectPhase
    action: ProjectAction
    operation_uuid: UUID
    idempotency_uuid: UUID
    project_id: UUID
    agent_session_uuid: UUID
    actor_id: UUID
    recipient_service_id: UUID
    recipient_instance_uuid: UUID
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload_type: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,95}$")
    expected_version: int = Field(ge=0)
    fence: OwnerFenceDTO

    @model_validator(mode="after")
    def check_owner(self) -> OwnerEffectCommand:
        if (
            self.owner_database != _DB[self.owner]
            or self.phase not in _PHASES[self.owner]
            or not _uuid4(self.operation_uuid)
            or self.operation_uuid != self.idempotency_uuid
            or not _uuid4(self.agent_session_uuid)
            or not _uuid4(self.recipient_service_id)
            or not _uuid4(self.recipient_instance_uuid)
        ):
            raise ValueError("owner effect command id/database invalid")
        return self


class OwnerEffectReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    protocol: Literal["owner-effect-receipt-v1"] = "owner-effect-receipt-v1"
    owner: EffectOwner
    owner_database: Literal[
        "briareus_resources", "briareus_files", "briareus_runtime", "briareus_reverse"
    ]
    recipient_service_id: UUID
    recipient_instance_uuid: UUID
    project_id: UUID
    actor_id: UUID
    agent_session_uuid: UUID
    operation_uuid: UUID
    idempotency_uuid: UUID
    action: ProjectAction
    phase: EffectPhase
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    result_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_revision: int = Field(ge=1)
    state: EffectState
    fence: OwnerFenceDTO
    expires_at: datetime
    acknowledged_at: datetime

    @model_validator(mode="after")
    def check_owner(self) -> OwnerEffectReceipt:
        if (
            self.owner_database != _DB[self.owner]
            or self.phase not in _PHASES[self.owner]
            or not _uuid4(self.operation_uuid)
            or self.idempotency_uuid != self.operation_uuid
            or not _uuid4(self.agent_session_uuid)
            or not _uuid4(self.recipient_service_id)
            or not _uuid4(self.recipient_instance_uuid)
            or self.expires_at.tzinfo is None
            or self.acknowledged_at.tzinfo is None
            or self.acknowledged_at > datetime.now(UTC)
        ):
            raise ValueError("owner effect reply invalid")
        return self


class SignedOwnerEffectReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    receipt: OwnerEffectReceipt
    attestation_jws: str = Field(min_length=100, max_length=8192)


@dataclass(frozen=True, slots=True)
class OwnerEffectReply[T: BaseModel]:
    attestation: SignedOwnerEffectReceipt
    payload: T


class OwnerEffectBackendPort(Protocol):
    """Real independent owner-local SQL dedupe+audit+outbox command.

    A11 MUST verify actual TLS/Unix recipient, caller+service, fresh Identity
    activity/revoke epoch, Control Project owner/Team member version and Access
    Session grant/revocation INSIDE the local committed owner transaction,
    then sign receipt with its own pinned key. No global Authorization UoW.
    """

    async def effect[T: BaseModel](
        self,
        invocation: ProjectInvocation,
        *,
        command: OwnerEffectCommand,
        a11_command: A11OwnerCommandDTO,
        business_payload: dict[str, object],
        payload: BaseModel,
        expected_type: type[T],
        recipient: VerifiedOwnerRecipient,
    ) -> OwnerEffectReply[T]: ...


class OwnerEffectTrustPort(Protocol):
    async def verified_recipient(self, evidence: object) -> VerifiedOwnerRecipient: ...

    async def pinned_effect_owner_key(
        self,
        owner: A11TargetOwner,
        *,
        recipient: VerifiedOwnerRecipient,
    ) -> Ed25519PublicKey: ...


class OwnerEffectUnavailable(Exception):
    def __init__(self, code: str, *, unknown: bool = False) -> None:
        self.code = code
        self.outcome_unknown = unknown
        super().__init__(code)


class OwnerEffectClient:
    """One signed owner command; UNKNOWN never authorizes blind replay."""

    def __init__(
        self,
        authority: ProjectRuntimeAuthority,
        *,
        backend: OwnerEffectBackendPort | None = None,
        trust: OwnerEffectTrustPort | None = None,
        a11_revisions: VerifiedA11RevisionPort | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
            raise ValueError("owner effect timeout invalid")
        self.authority = authority
        self.backend = backend
        self.trust = trust
        self.a11_revisions = a11_revisions
        self.timeout_seconds = timeout_seconds

    def require_ready(self) -> None:
        if self.backend is None or self.trust is None or self.a11_revisions is None:
            raise OwnerEffectUnavailable("OWNER_A11_SIGNED_DURABLE_PORTS_REQUIRED")

    def require_effect_lifecycle(self, owner: EffectOwner) -> None:
        self.require_ready()
        try:
            require_accepted_owner_lifecycle(owner)
        except A11OwnerWireNotAccepted as exc:
            raise OwnerEffectUnavailable(exc.code) from exc

    async def _recipient(self, invocation: ProjectInvocation) -> VerifiedOwnerRecipient:
        self.require_ready()
        if invocation.service_evidence is None:
            raise OwnerEffectUnavailable("OWNER_C2_RECIPIENT_REQUIRED")
        assert self.trust is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                peer = await self.trust.verified_recipient(invocation.service_evidence)
        except Exception as exc:
            raise OwnerEffectUnavailable("OWNER_C2_RECIPIENT_UNAVAILABLE") from exc
        if (
            not isinstance(peer, VerifiedOwnerRecipient)
            or not _uuid4(peer.service_id)
            or not _uuid4(peer.instance_uuid)
            or peer.expires_at.tzinfo is None
            or peer.expires_at <= datetime.now(UTC)
            or peer.transport not in {"mtls", "unix-peer"}
        ):
            raise OwnerEffectUnavailable("OWNER_C2_RECIPIENT_INVALID")
        return peer

    async def execute[T: BaseModel](
        self,
        invocation: ProjectInvocation,
        *,
        owner: EffectOwner,
        phase: EffectPhase,
        action: ProjectAction,
        target_sha256: str,
        payload: BaseModel,
        expected: type[T],
        expected_version: int = 0,
        original_operation_uuid: UUID | None = None,
        expected_service_id: UUID | None = None,
        expected_instance_uuid: UUID | None = None,
    ) -> OwnerEffectReply[T]:
        """Return only after verifying pinned Ed25519 owner+original UUID.

        Inspect/reconcile require SAME original operation identity with fresh
        JWT JTIs. Transport/ACK unknown is not a failure that can be retried
        with a new idempotency UUID or released after dispatch.
        """
        # Guard the low-level port itself: callers must not bypass full owner
        # lifecycle acceptance by skipping their domain-specific facade.
        self.require_effect_lifecycle(owner)
        scope = invocation.operation_scope
        if (
            scope is None
            or scope.action != action
            or owner not in _PHASES
            or phase not in _PHASES[owner]
            or not valid_project_revision(target_sha256)
            or not isinstance(payload, BaseModel)
            or type(expected_version) is not int
            or expected_version < 0
        ):
            raise OwnerEffectUnavailable("OWNER_COMMAND_INVALID")
        uuid = original_operation_uuid or scope.request_uuid
        if uuid != scope.request_uuid or not _uuid4(uuid):
            raise OwnerEffectUnavailable("OWNER_ORIGINAL_UUID_MISMATCH")
        permit = await self.authority.require(invocation, action)
        fence = OwnerFenceDTO.from_permit(permit)
        peer = await self._recipient(invocation)
        if (expected_service_id is not None and peer.service_id != expected_service_id) or (
            expected_instance_uuid is not None and peer.instance_uuid != expected_instance_uuid
        ):
            raise OwnerEffectUnavailable("OWNER_EFFECT_SERVICE_PEER_IDENTITY_MISMATCH")
        # A11 owner methods verify an exact operation name AND exact
        # business-only JSON schema. `payload.model_dump()` of a historical
        # A6 typed DTO does NOT match their owner-local business parameters.
        # Unsupported/OS-proof-dependent operations deny BEFORE any backend
        # command, never guess a generic `f"{owner}.{phase}"` API.
        try:
            wire = accepted_a11_owner_wire(owner, phase, payload, peer=peer)
        except A11OwnerWireNotAccepted as exc:
            raise OwnerEffectUnavailable(exc.code) from exc
        # Backend's accepted exact operation table is the authority, not a
        # larger Runtime-private phase enum or a concurrently edited A13 tree.
        try:
            require_exact_owner_operation(
                owner=owner,
                phase=phase,
                payload_type=type(payload).__name__,
                operation=wire.operation,
            )
        except OwnerAuthorityUnavailable as exc:
            raise OwnerEffectUnavailable("OWNER_BACKEND_PHASE_NOT_ACCEPTED") from exc
        a11_payload_hash = _digest(wire.business_payload)
        version_source = self.a11_revisions
        assert version_source is not None
        try:
            async with asyncio.timeout(min(self.timeout_seconds, 5.0)):
                versions = await version_source.current_owner_revisions(
                    invocation,
                    owner=_A11_TARGET[owner],
                    action=action,
                    phase=phase,
                    operation=wire.operation,
                    payload_sha256=a11_payload_hash,
                    idempotency_key=str(uuid),
                    recipient=peer,
                    permit=permit,
                )
        except Exception as exc:
            raise OwnerEffectUnavailable("OWNER_A11_CURRENT_PROOF_UNAVAILABLE") from exc
        expected_fence = permit.owner_fence
        if (
            not isinstance(versions, VerifiedA11SourceVersions)
            or not isinstance(expected_fence, ProjectOwnerFence)
            or versions.owner != _A11_TARGET[owner]
            or versions.audience != f"briareus:{_A11_TARGET[owner]}"
            or versions.operation != wire.operation
            or versions.idempotency_key != str(uuid)
            or versions.payload_sha256 != a11_payload_hash
            or versions.recipient_service_id != peer.service_id
            or versions.recipient_instance_uuid != peer.instance_uuid
            or versions.actor_user_id != permit.actor_id
            or versions.project_id != permit.project_id
            or versions.session_uuid != permit.session_uuid
            or versions.operation_uuid != uuid
            or versions.expected_identity_revision != expected_fence.identity_version
            or versions.expected_control_revision != expected_fence.control_state_version
            or versions.expected_access_revision != expected_fence.access_session_version
            or (
                permit.project_owner_scope == "team"
                and versions.expected_team_id != permit.project_owner_id
            )
            or (permit.project_owner_scope == "project" and versions.expected_team_id is not None)
            or versions.identity_epoch != expected_fence.identity_authority_epoch
            or versions.platform_epoch != expected_fence.control_authority_epoch
            or versions.access_epoch != expected_fence.access_authority_epoch
            or versions.expires_at > peer.expires_at
            or versions.expires_at > permit.expires_at
            or (
                permit.project_owner_scope == "team"
                and (
                    versions.expected_team_revision is None
                    or versions.expected_team_resource_revision is None
                )
            )
            or (
                permit.project_owner_scope == "project"
                and (
                    versions.expected_team_revision is not None
                    or versions.expected_team_resource_revision is not None
                )
            )
        ):
            raise OwnerEffectUnavailable("OWNER_A11_AUTHORITY_REVISION_MISMATCH")
        a11_command = A11OwnerCommandDTO(
            operation_uuid=uuid,
            caller_user_id=permit.actor_id,
            project_id=permit.project_id,
            session_uuid=permit.session_uuid,
            target_owner=_A11_TARGET[owner],
            operation=wire.operation,
            idempotency_key=str(uuid),
            payload_sha256=a11_payload_hash,
            expected_identity_revision=versions.expected_identity_revision,
            expected_control_revision=versions.expected_control_revision,
            expected_control_resource_revision=versions.expected_control_resource_revision,
            expected_team_id=versions.expected_team_id,
            expected_team_revision=versions.expected_team_revision,
            expected_team_resource_revision=versions.expected_team_resource_revision,
            expected_access_revision=versions.expected_access_revision,
        )
        if permit.expires_at <= datetime.now(UTC) or peer.expires_at <= datetime.now(UTC):
            raise OwnerEffectUnavailable("OWNER_ORIGINAL_GRANT_EXPIRED_BEFORE_DISPATCH")
        payload_hash = _digest(
            {
                "owner": owner,
                "phase": phase,
                "command": type(payload).__name__,
                "body": payload.model_dump(mode="json"),
            }
        )
        command = OwnerEffectCommand(
            owner=owner,
            owner_database=_DB[owner],
            phase=phase,
            action=action,
            operation_uuid=uuid,
            idempotency_uuid=uuid,
            project_id=permit.project_id,
            agent_session_uuid=permit.session_uuid,
            actor_id=permit.actor_id,
            recipient_service_id=peer.service_id,
            recipient_instance_uuid=peer.instance_uuid,
            request_sha256=scope.fingerprint,
            target_sha256=target_sha256,
            payload_sha256=payload_hash,
            payload_type=type(payload).__name__,
            expected_version=expected_version,
            fence=fence,
        )
        assert self.backend is not None and self.trust is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                response = await self.backend.effect(
                    invocation,
                    command=command,
                    a11_command=a11_command,
                    business_payload=dict(wire.business_payload),
                    payload=payload,
                    expected_type=expected,
                    recipient=peer,
                )
        except Exception as exc:
            raise OwnerEffectUnavailable("OWNER_EFFECT_OUTCOME_UNKNOWN", unknown=True) from exc
        try:
            async with asyncio.timeout(self.timeout_seconds):
                public_key = await self.trust.pinned_effect_owner_key(
                    _A11_TARGET[owner], recipient=peer
                )
            if not isinstance(public_key, Ed25519PublicKey):
                raise OwnerEffectUnavailable("OWNER_EFFECT_PINNED_KEY_REQUIRED", unknown=True)
            if not isinstance(response, OwnerEffectReply) or not isinstance(
                response.payload, expected
            ):
                raise OwnerEffectUnavailable("OWNER_EFFECT_REPLY_TYPE_INVALID", unknown=True)
            header = jwt.get_unverified_header(response.attestation.attestation_jws)
            kid = hashlib.sha256(
                public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ).hexdigest()
            if (
                header.get("alg") != "EdDSA"
                or header.get("typ") != "briareus-owner-effect+jwt"
                or header.get("kid") != kid
                or header.get("crit")
            ):
                raise OwnerEffectUnavailable("OWNER_EFFECT_SIGNER_INVALID", unknown=True)
            claims = jwt.decode(
                response.attestation.attestation_jws,
                public_key,
                algorithms=["EdDSA"],
                audience=f"owner-effect:{peer.service_id}",
                issuer=f"briareus-{_A11_TARGET[owner]}",
                leeway=0,
                options={
                    "require": ["iss", "aud", "iat", "nbf", "exp", "jti", "purpose", "receipt"]
                },
            )
            signed = OwnerEffectReceipt.model_validate_json(
                json.dumps(
                    claims["receipt"],
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            r = response.attestation.receipt
            now = datetime.now(UTC)
            if (
                not _uuid4(UUID(claims["jti"]))
                or claims["purpose"] != "owner-effect-receipt-v1"
                or type(claims["exp"]) is not int
                or type(claims["iat"]) is not int
                or not 0 < claims["exp"] - claims["iat"] <= 30
                or signed != r
                or r.owner != owner
                or r.owner_database != _DB[owner]
                or r.project_id != permit.project_id
                or r.actor_id != permit.actor_id
                or r.agent_session_uuid != permit.session_uuid
                or r.operation_uuid != uuid
                or r.recipient_service_id != peer.service_id
                or r.recipient_instance_uuid != peer.instance_uuid
                or r.phase != phase
                or r.action != action
                or r.request_sha256 != scope.fingerprint
                or r.target_sha256 != target_sha256
                or r.payload_sha256 != payload_hash
                or r.result_sha256 != _digest(response.payload.model_dump(mode="json"))
                or r.fence != fence
                or r.owner_revision < expected_version
                or r.expires_at <= now
                or r.expires_at > peer.expires_at
                or r.expires_at > datetime.fromtimestamp(claims["exp"], UTC)
            ):
                raise OwnerEffectUnavailable("OWNER_EFFECT_SIGNED_REPLY_INVALID", unknown=True)
            if r.state == "unknown" and phase != "inspect":
                raise OwnerEffectUnavailable("OWNER_EFFECT_REQUIRES_INSPECT", unknown=True)
            fresh = await self.authority.require(invocation, action)
            if (
                fresh.owner_fence != permit.owner_fence
                or fresh.project_id != permit.project_id
                or fresh.actor_id != permit.actor_id
                or fresh.session_uuid != permit.session_uuid
                or fresh.project_owner_scope != permit.project_owner_scope
                or fresh.project_owner_id != permit.project_owner_id
            ):
                raise OwnerEffectUnavailable("OWNER_EFFECT_ACCESS_CHANGED_AFTER_ACK", unknown=True)
            return response
        except OwnerEffectUnavailable:
            raise
        except Exception as exc:
            raise OwnerEffectUnavailable("OWNER_EFFECT_ATTESTATION_UNKNOWN", unknown=True) from exc

    async def verify_signed_status_v2(
        self,
        invocation: ProjectInvocation,
        *,
        command: OwnerEffectCommand,
        source_command: A11OwnerCommandDTO,
        signed: object,
    ) -> Literal["UNKNOWN", "COMMITTED", "DENIED"]:
        """Check owner-signed A12 status for ORIGINAL UUID, never replay.

        Signature, signer, recipient, original key SHA, exact command fields,
        owner revision, UTC TTL and *fresh* Identity/Control/Access are all
        checked. A signed COMMITTED owner-row state is not an OS completion
        receipt; the native Files/Ghidra/Terminal source must STILL supply
        independently verified evidence before any irreversible completion.
        """
        from .owner_status import SignedOwnerEffectStatusV2, verify_signed_owner_status_v2

        if not isinstance(signed, SignedOwnerEffectStatusV2):
            raise OwnerEffectUnavailable("A12_OWNER_SIGNED_STATUS_REQUIRED", unknown=True)
        if (
            not isinstance(command, OwnerEffectCommand)
            or not isinstance(source_command, A11OwnerCommandDTO)
            or command.operation_uuid != source_command.operation_uuid
            or command.project_id != invocation.project_id
            or command.agent_session_uuid != invocation.session_uuid
        ):
            raise OwnerEffectUnavailable("A12_OWNER_STATUS_ORIGINAL_SCOPE_MISMATCH", unknown=True)
        self.require_ready()
        # Signed inspection cannot validate an operation/phase combination
        # the producer has not accepted, even if the JWS fields look valid.
        try:
            require_exact_owner_operation(
                owner=command.owner,
                phase=command.phase,
                payload_type=command.payload_type,
                operation=source_command.operation,
            )
        except OwnerAuthorityUnavailable as exc:
            raise OwnerEffectUnavailable("A12_OWNER_STATUS_PHASE_UNACCEPTED", unknown=True) from exc
        permit = await self.authority.require(invocation, command.action)
        if (
            permit.project_id != command.project_id
            or permit.session_uuid != command.agent_session_uuid
            or permit.actor_id != command.actor_id
            or OwnerFenceDTO.from_permit(permit) != command.fence
            or invocation.operation_scope is None
            or invocation.operation_scope.request_uuid != command.operation_uuid
            or invocation.operation_scope.fingerprint != command.request_sha256
        ):
            raise OwnerEffectUnavailable("A12_OWNER_STATUS_REVOCATION_FENCE_CHANGED", unknown=True)
        peer = await self._recipient(invocation)
        if (
            peer.service_id != command.recipient_service_id
            or peer.instance_uuid != command.recipient_instance_uuid
        ):
            raise OwnerEffectUnavailable("A12_OWNER_STATUS_RECIPIENT_CHANGED", unknown=True)
        assert self.trust is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                pinned = await self.trust.pinned_effect_owner_key(
                    _A11_TARGET[command.owner],
                    recipient=peer,
                )
        except Exception as exc:
            raise OwnerEffectUnavailable(
                "A12_OWNER_STATUS_PINNED_KEY_UNAVAILABLE", unknown=True
            ) from exc
        # v2 status is not a bearer and cannot reuse a stale source-command
        # projection. Repeat the *real* A11 triple-owner verification before
        # consuming a current owner-local SQL status signature.
        assert self.a11_revisions is not None
        try:
            async with asyncio.timeout(min(self.timeout_seconds, 5.0)):
                versions = await self.a11_revisions.current_owner_revisions(
                    invocation,
                    owner=_A11_TARGET[command.owner],
                    action=command.action,
                    phase=command.phase,
                    operation=source_command.operation,
                    payload_sha256=source_command.payload_sha256,
                    idempotency_key=source_command.idempotency_key,
                    recipient=peer,
                    permit=permit,
                )
        except Exception as exc:
            raise OwnerEffectUnavailable(
                "A12_OWNER_STATUS_CURRENT_SOURCE_UNAVAILABLE", unknown=True
            ) from exc
        fence = permit.owner_fence
        if (
            not isinstance(versions, VerifiedA11SourceVersions)
            or not isinstance(fence, ProjectOwnerFence)
            or versions.owner != source_command.target_owner
            or versions.audience != f"briareus:{source_command.target_owner}"
            or versions.operation != source_command.operation
            or versions.idempotency_key != source_command.idempotency_key
            or versions.payload_sha256 != source_command.payload_sha256
            or versions.operation_uuid != command.operation_uuid
            or versions.actor_user_id != command.actor_id
            or versions.project_id != command.project_id
            or versions.session_uuid != command.agent_session_uuid
            or versions.recipient_service_id != peer.service_id
            or versions.recipient_instance_uuid != peer.instance_uuid
            or versions.expected_identity_revision != source_command.expected_identity_revision
            or versions.expected_control_revision != source_command.expected_control_revision
            or versions.expected_control_resource_revision
            != source_command.expected_control_resource_revision
            or versions.expected_access_revision != source_command.expected_access_revision
            or versions.expected_team_id != source_command.expected_team_id
            or versions.expected_team_revision != source_command.expected_team_revision
            or versions.expected_team_resource_revision
            != source_command.expected_team_resource_revision
            or versions.identity_epoch != fence.identity_authority_epoch
            or versions.platform_epoch != fence.control_authority_epoch
            or versions.access_epoch != fence.access_authority_epoch
            or (
                permit.project_owner_scope == "team"
                and versions.expected_team_id != permit.project_owner_id
            )
            or (permit.project_owner_scope == "project" and versions.expected_team_id is not None)
            or versions.expires_at > peer.expires_at
            or versions.expires_at > permit.expires_at
        ):
            raise OwnerEffectUnavailable("A12_OWNER_STATUS_SOURCE_REVOKED", unknown=True)
        status = verify_signed_owner_status_v2(
            signed,
            pinned_key=pinned,
            command=command,
            source_command=source_command,
            recipient=peer,
        )
        refreshed = await self.authority.require(invocation, command.action)
        if (
            OwnerFenceDTO.from_permit(refreshed) != command.fence
            or refreshed.actor_id != command.actor_id
            or refreshed.project_id != command.project_id
            or refreshed.session_uuid != command.agent_session_uuid
            or refreshed.project_owner_scope != permit.project_owner_scope
            or refreshed.project_owner_id != permit.project_owner_id
            or refreshed.project_access_revision != permit.project_access_revision
            or refreshed.expires_at <= datetime.now(UTC)
            or status.expires_at <= datetime.now(UTC)
        ):
            raise OwnerEffectUnavailable("A12_OWNER_STATUS_REVOKED_AFTER_VERIFY", unknown=True)
        return status.state
