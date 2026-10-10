"""A6 signed FilesQuota-v2 consumer — PRIVATE and deliberately unmounted.

Accepted authority: `authorization/_files_vertical.py` and
`authorization/_service_transport.py`. This package is built independently
from Authorization and MUST NOT import or construct Backend SQL/JWT signers.
A real `A6SignedFilesPort` must use verified TLS/Unix peer + Ed25519 service
assertion + independently Backend-issued human delegation in a fresh SQL UoW
for *every* command. `FilesQuotaReceipt` is metadata, NEVER an auth bearer.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from modules.project_runtime import ProjectInvocation, ProjectPermit, ProjectRuntimeAuthority
from modules.project_runtime.authorization import valid_project_revision
from modules.project_runtime.owner_effects import OwnerEffectClient, OwnerEffectUnavailable

from .project_workspace import _components

_FILE_STATE = Literal["reserved", "dispatched", "unknown", "committed", "released"]
_SHA = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class A6FilesUnavailable(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class FilesCommand(BaseModel):
    """Mirror of A6 Backend `FilesCommand`, not a public network DTO."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    operation_uuid: UUID

    @field_validator("operation_uuid")
    @classmethod
    def _uuid4(cls, value: UUID) -> UUID:
        if not isinstance(value, UUID) or value.version != 4:
            raise ValueError("Files operation ID must be UUIDv4")
        return value


class FilesReserve(FilesCommand):
    destination: str = Field(min_length=1, max_length=4096)
    maximum_bytes: int = Field(ge=0, le=100_000_000_000_000)
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_file_version: int = Field(ge=0)
    project_access_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=1, max_length=128)

    @field_validator("destination")
    @classmethod
    def _path(cls, value: str) -> str:
        return canonical_files_path(value)

    @field_validator("idempotency_key")
    @classmethod
    def _key(cls, value: str) -> str:
        if not value.isascii() or not value.isprintable():
            raise ValueError("Files idempotency key must be ASCII")
        return value


class FilesTransition(FilesCommand):
    reservation_id: UUID
    expected_version: int = Field(ge=1)
    destination: str
    phase: Literal["dispatch", "release", "unknown"]

    @field_validator("reservation_id")
    @classmethod
    def _reservation_id(cls, value: UUID) -> UUID:
        if not isinstance(value, UUID) or value.version != 4:
            raise ValueError("Files reservation UUID must be version 4")
        return value

    @field_validator("destination")
    @classmethod
    def _path(cls, value: str) -> str:
        return canonical_files_path(value)


class FilesCommittedObservation(FilesCommand):
    reservation_id: UUID
    expected_version: int = Field(ge=1)
    destination: str
    observed_file_version: int = Field(ge=0)
    observed_size_bytes: int = Field(ge=0, le=100_000_000_000_000)
    observed_inode_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    observed_content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    confirmed_absent: bool = False
    confirmed_at: datetime
    source_volume_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    phase: Literal["finalize", "reconcile"]

    @field_validator("reservation_id")
    @classmethod
    def _id(cls, value: UUID) -> UUID:
        if not isinstance(value, UUID) or value.version != 4:
            raise ValueError("Files reservation must be UUIDv4")
        return value

    @field_validator("destination")
    @classmethod
    def _path(cls, value: str) -> str:
        return canonical_files_path(value)


class FilesInspect(FilesCommand):
    destination: str
    phase: Literal["inspect"] = "inspect"

    @field_validator("destination")
    @classmethod
    def _path(cls, value: str) -> str:
        return canonical_files_path(value)


class FilesRead(FilesCommand):
    path: str = ""
    phase: Literal["read", "list", "metadata"]
    max_bytes: int = Field(default=1048576, ge=0, le=1048576)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return canonical_files_path(value) if value else ""


class FilesQuotaReceipt(BaseModel):
    """A6 Backend `FilesQuotaReceipt` field-exact projection, no authority."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    reservation_id: UUID
    project_id: UUID
    actor_id: UUID
    session_uuid: UUID
    requested_bytes: int = Field(ge=0)
    operation_uuid: UUID
    destination: str
    expected_sha256: str
    expires_at: datetime
    owner_revision: str
    expected_file_version: int = Field(ge=0)
    reservation_version: int = Field(ge=1)
    status: _FILE_STATE


class FilesReadPermit(BaseModel):
    """Metadata only: Files storage still revalidates current signed caller."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    project_id: UUID
    actor_id: UUID
    session_uuid: UUID
    operation_uuid: UUID
    action: Literal["files.read"]
    path: str
    owner_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedFilesPeer:
    """Attested mTLS/Unix instance, NEVER a client-provided header/DTO."""

    service_id: UUID
    key_id: UUID
    instance_uuid: UUID
    audience: Literal["files"]
    transport: Literal["mtls", "unix-peer"]
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class FilesSignedIntent:
    """A6 `ServiceOperationIntent` source fields for one exact command."""

    project_id: UUID
    session_uuid: UUID
    instance_uuid: UUID
    operation: Literal["files.read", "files.write"]
    target_audience: Literal["files"]
    resource_id: None
    operation_uuid: UUID
    payload_sha256: str

    def fingerprint(self) -> str:
        document = {
            "version": "project-operation-v1",
            "project_id": str(self.project_id),
            "session_uuid": str(self.session_uuid),
            "instance_uuid": str(self.instance_uuid),
            "operation": self.operation,
            "target_audience": self.target_audience,
            "resource_id": None,
            "operation_uuid": str(self.operation_uuid),
            "payload_sha256": self.payload_sha256,
        }
        return hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class AttestedFilesStorage:
    """Source projection from an independently verified OS Files supervisor.

    This object is not itself signed and cannot establish trust by existence.
    The real Backend `TrustedFilesStorageObserver` MUST verify its provenance
    cryptographically/through an independently attested in-process channel
    before accepting FilesCommittedObservation in a durable SQL transaction.
    """

    project_id: UUID
    session_uuid: UUID
    actor_id: UUID
    operation_uuid: UUID
    reservation_id: UUID
    destination: str
    path_digest: str
    observed_file_version: int
    observed_size_bytes: int
    observed_inode_digest: str | None
    observed_content_sha256: str | None
    confirmed_absent: bool
    confirmed_at: datetime
    source_volume_digest: str
    storage_instance_uuid: UUID
    isolated_project_uid: int
    project_mount_isolated: bool


class VerifiedFilesPeerPort(Protocol):
    """Transport owner validates OS/TLS peer, not arbitrary caller JSON."""

    async def verified_files_peer(self, evidence: object) -> VerifiedFilesPeer: ...


class TrustedFilesStoragePort(Protocol):
    """Independent Files root worker attests actual inode/mount/UID state."""

    async def observe_committed(
        self,
        invocation: ProjectInvocation,
        *,
        permit: ProjectPermit,
        reservation: FilesQuotaReceipt,
        inode_digest: str,
        content_sha256: str,
        observed_bytes: int,
    ) -> AttestedFilesStorage: ...

    async def observe_unknown(
        self,
        invocation: ProjectInvocation,
        *,
        permit: ProjectPermit,
        reservation: FilesQuotaReceipt,
    ) -> AttestedFilesStorage: ...


class SignedFilesBackendPort(Protocol):
    """Execute one A6 SignedFilesAuthority phase with FRESH signed proofs.

    Every call must create an independently verified service assertion plus
    Backend delegated User JWT bound to intent.fingerprint(), distinct JTIs,
    current Project/Team/Session grant, real VerifiedServicePeer and a fresh
    committed SQL unit of work. `FilesQuotaReceipt`/`FilesReadPermit` never
    authorize storage I/O by themselves. No URL/header/key is assumed here.
    The complete() implementation must use Backend's independent
    TrustedFilesStorageObserver, NEVER trust this client's dataclass alone.
    """

    async def reserve(
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesReserve,
        peer: VerifiedFilesPeer,
    ) -> FilesQuotaReceipt: ...

    async def transition(
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesTransition,
        peer: VerifiedFilesPeer,
    ) -> FilesQuotaReceipt: ...

    async def complete(
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesCommittedObservation,
        peer: VerifiedFilesPeer,
    ) -> FilesQuotaReceipt: ...

    async def inspect(
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesInspect,
        peer: VerifiedFilesPeer,
    ) -> FilesQuotaReceipt | None: ...

    async def issue_read_permit(
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesRead,
        peer: VerifiedFilesPeer,
    ) -> FilesReadPermit: ...


def canonical_files_path(value: str) -> str:
    """Mirror accepted A6 path validation; same descriptor namespace as store."""
    path = "/".join(_components(value))
    # The R6 store uses a different temporary naming convention; also deny
    # the A6 reserved name even if the legacy stage implementation would not.
    if any(re.fullmatch(r"\.upload-[0-9a-f]{32}\.tmp", p, re.ASCII) for p in path.split("/")):
        raise A6FilesUnavailable("A6_FILE_RESERVED_PATH")
    return path


def path_fingerprint(destination: str) -> str:
    """Accepted A6 `_files_vertical.path_fingerprint` domain separator."""
    return hashlib.sha256(
        b"files-project-relative-v1\x00" + canonical_files_path(destination).encode("utf-8")
    ).hexdigest()


def files_payload_fingerprint(command: FilesCommand) -> str:
    """Exact accepted A6 `_files_vertical.files_payload_fingerprint` bytes."""
    payload = {
        "protocol": "project-files-transaction-v2",
        "command": type(command).__name__,
        "body": command.model_dump(mode="json"),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


class A6SignedFilesFlow:
    """Exact A6 commands, one trusted service-human proof and SQL UoW per phase.

    NO transport or OS attestor is provided by default. Every phase is bound
    to a fresh A6 FilesCommand full-body SHA, the attested Files peer instance,
    current Project revision and originating AgentSession. A dropped response
    cannot be interpreted as permission to replay or release a dispatched file.
    """

    def __init__(
        self,
        authority: ProjectRuntimeAuthority,
        *,
        peer_port: VerifiedFilesPeerPort | None = None,
        backend: SignedFilesBackendPort | None = None,
        observer: TrustedFilesStoragePort | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
            raise ValueError("A6 signed Files timeout must be finite and positive")
        self.authority = authority
        self.peer_port = peer_port
        self.backend = backend
        self.observer = observer
        self.timeout_seconds = timeout_seconds

    def require_write_ready(self) -> None:
        # Fail BEFORE an external Web socket is opened, not after streaming
        # bytes to a missing Files owner. An arbitrary historical A6 Backend
        # or an adapter with unconfigured owner-local SQL cannot authorize
        # work in the split-database topology.
        if self.peer_port is None or self.backend is None or self.observer is None:
            raise A6FilesUnavailable("FILES_OWNER_OR_OS_SUPERVISOR_NOT_CONFIGURED")
        effects = getattr(self.backend, "effects", None)
        if not isinstance(effects, OwnerEffectClient):
            raise A6FilesUnavailable("FILES_OWNER_SIGNED_LEDGER_REQUIRED")
        try:
            effects.require_effect_lifecycle("files")
        except OwnerEffectUnavailable as exc:
            raise A6FilesUnavailable("FILES_OWNER_SIGNED_LEDGER_NOT_READY") from exc

    async def _authorized(
        self,
        invocation: ProjectInvocation,
        *,
        original: ProjectPermit,
        action: Literal["files.read", "files.write"],
        operation_uuid: UUID,
    ) -> tuple[ProjectPermit, VerifiedFilesPeer]:
        self.require_write_ready()
        scope = invocation.operation_scope
        if (
            invocation.service_evidence is None
            or scope is None
            or scope.request_uuid != operation_uuid
            or scope.project_id != invocation.project_id
            or scope.agent_session_uuid != invocation.session_uuid
            or scope.action != action
        ):
            raise A6FilesUnavailable("A6_FILES_REQUEST_SCOPE_INVALID")
        fresh = await self.authority.require(invocation, action)
        if (
            fresh.action != action
            or fresh.project_id != original.project_id
            or fresh.actor_id != original.actor_id
            or fresh.session_uuid != original.session_uuid
            or fresh.decision_version != original.decision_version
            or fresh.project_access_revision != original.project_access_revision
            or fresh.project_owner_scope != original.project_owner_scope
            or fresh.project_owner_id != original.project_owner_id
            or fresh.owner_fence != original.owner_fence
            or not valid_project_revision(fresh.project_access_revision)
            or fresh.expires_at <= datetime.now(UTC)
        ):
            raise A6FilesUnavailable("A6_FILES_ACCESS_REVOKED_OR_STALE")
        peer_source = self.peer_port
        if peer_source is None:
            raise A6FilesUnavailable("FILES_OWNER_C2_PEER_UNAVAILABLE")
        try:
            async with asyncio.timeout(self.timeout_seconds):
                peer = await peer_source.verified_files_peer(invocation.service_evidence)
        except Exception as exc:
            raise A6FilesUnavailable("A6_FILES_PEER_UNAVAILABLE") from exc
        if (
            not isinstance(peer, VerifiedFilesPeer)
            or peer.audience != "files"
            or peer.transport not in {"mtls", "unix-peer"}
            or not all(
                isinstance(item, UUID) and item.version == 4
                for item in (peer.service_id, peer.key_id, peer.instance_uuid)
            )
            or not isinstance(peer.expires_at, datetime)
            or peer.expires_at.tzinfo is None
            or peer.expires_at <= datetime.now(UTC)
        ):
            raise A6FilesUnavailable("A6_FILES_PEER_INVALID")
        return fresh, peer

    @staticmethod
    def _intent(
        invocation: ProjectInvocation,
        command: FilesCommand,
        *,
        peer: VerifiedFilesPeer,
        action: Literal["files.read", "files.write"],
    ) -> FilesSignedIntent:
        # This is the exact accepted A6 ServiceOperationIntent.fingerprint
        # preimage. Backend signs independently and checks its own peer/JTI.
        return FilesSignedIntent(
            project_id=invocation.project_id,
            session_uuid=invocation.session_uuid,
            instance_uuid=peer.instance_uuid,
            operation=action,
            target_audience="files",
            resource_id=None,
            operation_uuid=command.operation_uuid,
            payload_sha256=files_payload_fingerprint(command),
        )

    @staticmethod
    def _receipt(
        reply: FilesQuotaReceipt,
        *,
        permit: ProjectPermit,
        operation_uuid: UUID,
        destination: str,
        expected_sha256: str,
        maximum_bytes: int,
        state: _FILE_STATE,
        before: FilesQuotaReceipt | None = None,
    ) -> FilesQuotaReceipt:
        if (
            not isinstance(reply, FilesQuotaReceipt)
            or reply.reservation_id.version != 4
            or reply.operation_uuid != operation_uuid
            or reply.project_id != permit.project_id
            or reply.actor_id != permit.actor_id
            or reply.session_uuid != permit.session_uuid
            or reply.destination != destination
            or reply.requested_bytes != maximum_bytes
            or reply.expected_sha256 != expected_sha256
            or reply.owner_revision != permit.project_access_revision
            or reply.expected_file_version != 0
            or reply.status != state
            or reply.expires_at.tzinfo is None
            or (
                before is not None
                and (
                    reply.reservation_id != before.reservation_id
                    or reply.operation_uuid != before.operation_uuid
                    or reply.reservation_version != before.reservation_version + 1
                    or reply.expires_at != before.expires_at
                )
            )
        ):
            raise A6FilesUnavailable("A6_FILES_QUOTA_RECEIPT_MISMATCH")
        return reply

    async def reserve(
        self,
        invocation: ProjectInvocation,
        *,
        initial: ProjectPermit,
        destination: str,
        operation_uuid: UUID,
        size_bytes: int,
        sha256: str,
    ) -> FilesQuotaReceipt:
        self.require_write_ready()
        if (
            not isinstance(operation_uuid, UUID)
            or operation_uuid.version != 4
            or type(size_bytes) is not int
            or not 0 <= size_bytes <= 100_000_000_000_000
            or not isinstance(sha256, str)
            or _SHA.fullmatch(sha256) is None
        ):
            raise A6FilesUnavailable("A6_FILES_RESERVATION_INPUT_INVALID")
        normalized = canonical_files_path(destination)
        fresh, peer = await self._authorized(
            invocation,
            original=initial,
            action="files.write",
            operation_uuid=operation_uuid,
        )
        revision = fresh.project_access_revision
        if not isinstance(revision, str):
            raise A6FilesUnavailable("A6_FILES_PROJECT_REVISION_REQUIRED")
        command = FilesReserve(
            operation_uuid=operation_uuid,
            destination=normalized,
            maximum_bytes=size_bytes,
            expected_sha256=sha256,
            expected_file_version=0,  # create only, no overwrite
            project_access_revision=revision,
            idempotency_key=str(operation_uuid),
        )
        assert self.backend is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                reply = await self.backend.reserve(
                    invocation,
                    intent=self._intent(invocation, command, peer=peer, action="files.write"),
                    command=command,
                    peer=peer,
                )
        except Exception as exc:
            # The Backend SQL transaction could have committed despite
            # transport failure. Same UUID inspection is the only safe path.
            raise A6FilesUnavailable("A6_FILES_RESERVE_OUTCOME_UNKNOWN") from exc
        self._receipt(
            reply,
            permit=fresh,
            operation_uuid=operation_uuid,
            destination=normalized,
            expected_sha256=sha256,
            maximum_bytes=size_bytes,
            state="reserved",
        )
        if reply.reservation_version != 1 or reply.expires_at <= datetime.now(UTC):
            raise A6FilesUnavailable("A6_FILES_RESERVATION_UNUSABLE")
        return reply

    async def transition(
        self,
        invocation: ProjectInvocation,
        *,
        initial: ProjectPermit,
        before: FilesQuotaReceipt,
        phase: Literal["dispatch", "release", "unknown"],
    ) -> FilesQuotaReceipt:
        fresh, peer = await self._authorized(
            invocation,
            original=initial,
            action="files.write",
            operation_uuid=before.operation_uuid,
        )
        if before.status not in {"reserved", "dispatched"}:
            raise A6FilesUnavailable("A6_FILES_TRANSITION_STATE_INVALID")
        if phase in {"dispatch", "release"} and before.status != "reserved":
            raise A6FilesUnavailable("A6_FILES_DISPATCH_OR_RELEASE_STALE")
        if phase == "unknown" and before.status != "dispatched":
            raise A6FilesUnavailable("A6_FILES_UNKNOWN_REQUIRES_DISPATCH")
        command = FilesTransition(
            operation_uuid=before.operation_uuid,
            reservation_id=before.reservation_id,
            expected_version=before.reservation_version,
            destination=before.destination,
            phase=phase,
        )
        assert self.backend is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                reply = await self.backend.transition(
                    invocation,
                    intent=self._intent(invocation, command, peer=peer, action="files.write"),
                    command=command,
                    peer=peer,
                )
        except Exception as exc:
            raise A6FilesUnavailable("A6_FILES_TRANSITION_OUTCOME_UNKNOWN") from exc
        expected = cast(
            _FILE_STATE,
            {"dispatch": "dispatched", "release": "released", "unknown": "unknown"}[phase],
        )
        return self._receipt(
            reply,
            permit=fresh,
            operation_uuid=before.operation_uuid,
            destination=before.destination,
            expected_sha256=before.expected_sha256,
            maximum_bytes=before.requested_bytes,
            state=expected,
            before=before,
        )

    async def mark_unknown(
        self,
        invocation: ProjectInvocation,
        *,
        initial: ProjectPermit,
        dispatched: FilesQuotaReceipt,
    ) -> None:
        if dispatched.status != "dispatched":
            return
        # If current grant expires/revokes, Backend sweeper must freeze
        # UNKNOWN. NEVER release or reissue the write after dispatch.
        with suppress(Exception):
            await self.transition(
                invocation,
                initial=initial,
                before=dispatched,
                phase="unknown",
            )

    async def inspect(
        self,
        invocation: ProjectInvocation,
        *,
        initial: ProjectPermit,
        destination: str,
        operation_uuid: UUID,
    ) -> FilesQuotaReceipt | None:
        normalized = canonical_files_path(destination)
        fresh, peer = await self._authorized(
            invocation,
            original=initial,
            action="files.write",
            operation_uuid=operation_uuid,
        )
        command = FilesInspect(operation_uuid=operation_uuid, destination=normalized)
        assert self.backend is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                reply = await self.backend.inspect(
                    invocation,
                    intent=self._intent(invocation, command, peer=peer, action="files.write"),
                    command=command,
                    peer=peer,
                )
        except Exception as exc:
            raise A6FilesUnavailable("A6_FILES_INSPECTION_UNAVAILABLE") from exc
        if reply is None:
            # Absence of ledger row does not prove absence of an OS side effect.
            return None
        if (
            not isinstance(reply, FilesQuotaReceipt)
            or reply.project_id != fresh.project_id
            or reply.actor_id != fresh.actor_id
            or reply.session_uuid != fresh.session_uuid
            or reply.destination != normalized
            or reply.operation_uuid != operation_uuid
            or reply.owner_revision != fresh.project_access_revision
            or reply.expires_at.tzinfo is None
        ):
            raise A6FilesUnavailable("A6_FILES_INSPECTION_SCOPE_INVALID")
        return reply

    async def read_permit(
        self,
        invocation: ProjectInvocation,
        *,
        initial: ProjectPermit,
        path: str,
        operation_uuid: UUID,
        phase: Literal["read", "list", "metadata"],
        max_bytes: int,
    ) -> FilesReadPermit:
        if type(max_bytes) is not int or not 0 <= max_bytes <= 1048576:
            raise A6FilesUnavailable("A6_FILES_READ_SIZE_INVALID")
        fresh, peer = await self._authorized(
            invocation,
            original=initial,
            action="files.read",
            operation_uuid=operation_uuid,
        )
        command = FilesRead(
            operation_uuid=operation_uuid,
            path=canonical_files_path(path) if path else "",
            phase=phase,
            max_bytes=max_bytes,
        )
        if command.phase in {"read", "metadata"} and not command.path:
            raise A6FilesUnavailable("A6_FILES_READ_PATH_REQUIRED")
        assert self.backend is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                reply = await self.backend.issue_read_permit(
                    invocation,
                    intent=self._intent(invocation, command, peer=peer, action="files.read"),
                    command=command,
                    peer=peer,
                )
        except Exception as exc:
            raise A6FilesUnavailable("A6_FILES_READ_PROOF_UNAVAILABLE") from exc
        if (
            not isinstance(reply, FilesReadPermit)
            or reply.project_id != fresh.project_id
            or reply.actor_id != fresh.actor_id
            or reply.session_uuid != fresh.session_uuid
            or reply.operation_uuid != operation_uuid
            or reply.path != command.path
            or reply.action != "files.read"
            or reply.owner_revision != fresh.project_access_revision
            or reply.expires_at.tzinfo is None
            or reply.expires_at <= datetime.now(UTC)
            or reply.expires_at > fresh.expires_at
            or reply.expires_at > peer.expires_at
        ):
            raise A6FilesUnavailable("A6_FILES_READ_PERMIT_SCOPE_INVALID")
        return reply

    async def committed_observation(
        self,
        invocation: ProjectInvocation,
        *,
        initial: ProjectPermit,
        dispatched: FilesQuotaReceipt,
        inode_digest: str,
        content_sha256: str,
        size_bytes: int,
    ) -> FilesCommittedObservation:
        self.require_write_ready()
        if (
            dispatched.status != "dispatched"
            or inode_digest is None
            or _SHA.fullmatch(inode_digest) is None
            or content_sha256 != dispatched.expected_sha256
            or size_bytes != dispatched.requested_bytes
        ):
            raise A6FilesUnavailable("A6_FILES_DISPATCHED_OBSERVATION_INVALID")
        fresh, _peer = await self._authorized(
            invocation,
            original=initial,
            action="files.write",
            operation_uuid=dispatched.operation_uuid,
        )
        assert self.observer is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                proof = await self.observer.observe_committed(
                    invocation,
                    permit=fresh,
                    reservation=dispatched,
                    inode_digest=inode_digest,
                    content_sha256=content_sha256,
                    observed_bytes=size_bytes,
                )
        except Exception as exc:
            raise A6FilesUnavailable("A6_FILES_STORAGE_EVIDENCE_UNAVAILABLE") from exc
        self._validate_storage(
            proof,
            invocation=invocation,
            permit=fresh,
            reserved=dispatched,
            observed_inode=inode_digest,
            observed_content=content_sha256,
            size=size_bytes,
            absent=False,
        )
        return FilesCommittedObservation(
            operation_uuid=dispatched.operation_uuid,
            reservation_id=dispatched.reservation_id,
            expected_version=dispatched.reservation_version,
            destination=dispatched.destination,
            observed_file_version=dispatched.expected_file_version + 1,
            observed_size_bytes=size_bytes,
            observed_inode_digest=inode_digest,
            observed_content_sha256=content_sha256,
            confirmed_absent=False,
            confirmed_at=proof.confirmed_at,
            source_volume_digest=proof.source_volume_digest,
            phase="finalize",
        )

    @staticmethod
    def _validate_storage(
        proof: AttestedFilesStorage,
        *,
        invocation: ProjectInvocation,
        permit: ProjectPermit,
        reserved: FilesQuotaReceipt,
        observed_inode: str | None,
        observed_content: str | None,
        size: int,
        absent: bool,
    ) -> None:
        now = datetime.now(UTC)
        if (
            not isinstance(proof, AttestedFilesStorage)
            or proof.project_id != invocation.project_id
            or proof.session_uuid != invocation.session_uuid
            or proof.actor_id != permit.actor_id
            or proof.operation_uuid != reserved.operation_uuid
            or proof.reservation_id != reserved.reservation_id
            or proof.destination != reserved.destination
            or proof.observed_file_version
            not in {
                reserved.expected_file_version,
                reserved.expected_file_version + 1,
            }
            or proof.observed_size_bytes != size
            or proof.observed_inode_digest != observed_inode
            or proof.observed_content_sha256 != observed_content
            or proof.confirmed_absent is not absent
            or not valid_project_revision(proof.source_volume_digest)
            # The OS storage supervisor is an INDEPENDENT trusted instance,
            # not necessarily the same TLS/Unix identity as Files service.
            # Backend TrustedFilesStorageObserver must verify its own signed
            # attestation/provenance before a SQL finalize or reconciliation.
            or not isinstance(proof.storage_instance_uuid, UUID)
            or proof.storage_instance_uuid.version != 4
            or type(proof.isolated_project_uid) is not int
            or proof.isolated_project_uid <= 0
            or proof.project_mount_isolated is not True
            or not isinstance(proof.confirmed_at, datetime)
            or proof.confirmed_at.tzinfo is None
            or not now - timedelta(seconds=30) <= proof.confirmed_at <= now
        ):
            raise A6FilesUnavailable("A6_FILES_STORAGE_OBSERVATION_UNVERIFIED")

    async def complete(
        self,
        invocation: ProjectInvocation,
        *,
        initial: ProjectPermit,
        dispatched: FilesQuotaReceipt,
        command: FilesCommittedObservation,
    ) -> FilesQuotaReceipt:
        fresh, peer = await self._authorized(
            invocation,
            original=initial,
            action="files.write",
            operation_uuid=dispatched.operation_uuid,
        )
        if (
            command.phase not in {"finalize", "reconcile"}
            or command.operation_uuid != dispatched.operation_uuid
            or command.reservation_id != dispatched.reservation_id
            or command.destination != dispatched.destination
            or command.expected_version != dispatched.reservation_version
        ):
            raise A6FilesUnavailable("A6_FILES_COMPLETE_COMMAND_INVALID")
        assert self.backend is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                reply = await self.backend.complete(
                    invocation,
                    intent=self._intent(invocation, command, peer=peer, action="files.write"),
                    command=command,
                    peer=peer,
                )
        except Exception as exc:
            raise A6FilesUnavailable("A6_FILES_COMPLETE_OUTCOME_UNKNOWN") from exc
        return self._receipt(
            reply,
            permit=fresh,
            operation_uuid=dispatched.operation_uuid,
            destination=dispatched.destination,
            expected_sha256=dispatched.expected_sha256,
            maximum_bytes=dispatched.requested_bytes,
            state="committed" if command.observed_file_version else "released",
            before=dispatched,
        )

    async def reconcile_unknown(
        self,
        invocation: ProjectInvocation,
        *,
        initial: ProjectPermit,
        unknown: FilesQuotaReceipt,
    ) -> FilesQuotaReceipt:
        """Backend owner resolves UNKNOWN only from actual Files OS evidence."""
        self.require_write_ready()
        if unknown.status != "unknown" or unknown.expected_file_version != 0:
            raise A6FilesUnavailable("A6_FILES_RECONCILIATION_STATE_INVALID")
        fresh, _peer = await self._authorized(
            invocation,
            original=initial,
            action="files.write",
            operation_uuid=unknown.operation_uuid,
        )
        assert self.observer is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                proof = await self.observer.observe_unknown(
                    invocation,
                    permit=fresh,
                    reservation=unknown,
                )
        except Exception as exc:
            raise A6FilesUnavailable("A6_FILES_RECONCILIATION_PROOF_UNAVAILABLE") from exc
        if not isinstance(proof, AttestedFilesStorage):
            raise A6FilesUnavailable("A6_FILES_RECONCILIATION_PROOF_INVALID")
        changed = proof.observed_file_version == unknown.expected_file_version + 1
        absent = proof.observed_file_version == unknown.expected_file_version
        if changed:
            if proof.confirmed_absent or proof.observed_inode_digest is None:
                raise A6FilesUnavailable("A6_FILES_RECONCILIATION_INODE_REQUIRED")
            if (
                proof.observed_content_sha256 != unknown.expected_sha256
                or proof.observed_size_bytes != unknown.requested_bytes
            ):
                raise A6FilesUnavailable("A6_FILES_RECONCILIATION_CONTENT_MISMATCH")
        elif absent:
            if (
                not proof.confirmed_absent
                or proof.observed_inode_digest is not None
                or proof.observed_size_bytes != 0
            ):
                raise A6FilesUnavailable("A6_FILES_ABSENCE_NOT_PROVEN")
        else:
            raise A6FilesUnavailable("A6_FILES_RECONCILIATION_VERSION_INVALID")
        self._validate_storage(
            proof,
            invocation=invocation,
            permit=fresh,
            reserved=unknown,
            observed_inode=proof.observed_inode_digest,
            observed_content=proof.observed_content_sha256,
            size=proof.observed_size_bytes,
            absent=absent,
        )
        command = FilesCommittedObservation(
            operation_uuid=unknown.operation_uuid,
            reservation_id=unknown.reservation_id,
            expected_version=unknown.reservation_version,
            destination=unknown.destination,
            observed_file_version=proof.observed_file_version,
            observed_size_bytes=proof.observed_size_bytes,
            observed_inode_digest=proof.observed_inode_digest,
            observed_content_sha256=proof.observed_content_sha256,
            confirmed_absent=absent,
            confirmed_at=proof.confirmed_at,
            source_volume_digest=proof.source_volume_digest,
            phase="reconcile",
        )
        return await self.complete(
            invocation,
            initial=initial,
            dispatched=unknown,
            command=command,
        )
