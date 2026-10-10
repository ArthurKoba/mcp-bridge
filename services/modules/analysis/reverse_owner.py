"""Independent Files-object provenance and Reverse/Ghidra owner ledger.

No SQL FK/connection from briareus_reverse to briareus_files, no global
Authorization FileObject lookup and no optimistic Ghidra replay. A separate
freshly authenticated Files owner read verifies a committed immutable object;
Reverse owner then has its OWN command/outbox/UNKNOWN state and revision.
The native OS worker and Ghidra inventory remain physically unconfigured.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from modules.project_runtime import (
    ProjectInvocation,
    ProjectOperationScope,
    ProjectRuntimeAuthority,
    canonical_request_fingerprint,
)
from modules.project_runtime.owner_effects import OwnerEffectClient, OwnerEffectUnavailable

from .a6_native import (
    NativeImportClaimCommand,
    NativeImportInspect,
    NativeImportReceipt,
    NativeImportTransition,
)


def object_digest(value: UUID) -> str:
    if not isinstance(value, UUID) or value.version != 4:
        raise OwnerEffectUnavailable("REVERSE_FILEOBJECT_UUID_REQUIRED")
    return hashlib.sha256(b"file-object-owner-v1\x00" + value.bytes).hexdigest()


def native_digest(value: UUID) -> str:
    if not isinstance(value, UUID) or value.version != 4:
        raise OwnerEffectUnavailable("REVERSE_NATIVE_PROJECT_UUID_REQUIRED")
    return hashlib.sha256(b"native-project-owner-v1\x00" + value.bytes).hexdigest()


class CommittedFileObjectLookup(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    file_object_id: UUID
    expected_version: int = Field(ge=1)
    phase: Literal["read", "file_dispatch", "file_reconcile"] = "read"


class CommittedFileObject(BaseModel):
    """Only a separately signed Files-owner COMMITTED revision is accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    database: Literal["briareus_files"] = "briareus_files"
    project_id: UUID
    file_object_id: UUID
    version: int = Field(ge=1)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_volume_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0, le=100_000_000_000_000)
    state: Literal["committed"] = "committed"


class ReverseInspection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    found: bool
    import_receipt: NativeImportReceipt | None = None
    retry_allowed: Literal[False] = False
    outcome_unknown: bool = False


class VerifiedNativeInventory(BaseModel):
    """Ghidra attestation reference; Backend must verify the source itself."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    native_project_id: UUID
    file_object_id: UUID
    file_version: int = Field(ge=1)
    artifact_id: str = Field(min_length=1, max_length=256)
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    original_operation_uuid: UUID
    observed_at: datetime
    verifier_instance_uuid: UUID


class ReverseReconcileCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    original_operation_uuid: UUID
    native_project_id: UUID
    file_object_id: UUID
    source_file_version: int = Field(ge=1)
    import_uuid: UUID
    expected_version: int = Field(ge=1)
    verified_inventory: VerifiedNativeInventory
    phase: Literal["reconcile"] = "reconcile"


class NativeOSInventoryPort(Protocol):
    """Attests real independent Ghidra state, not caller JSON/status text."""

    async def verify_current_artifact(
        self,
        invocation: ProjectInvocation,
        *,
        record: NativeImportReceipt,
    ) -> VerifiedNativeInventory: ...


class ReverseOwnerClient:
    def __init__(
        self,
        authority: ProjectRuntimeAuthority,
        *,
        files: OwnerEffectClient,
        reverse: OwnerEffectClient,
        inventory: NativeOSInventoryPort | None = None,
    ) -> None:
        self.authority = authority
        self.files = files
        self.reverse = reverse
        self.inventory = inventory

    def _require_native_source_ready(self) -> None:
        # Native claim/dispatch/UNKNOWN/reconcile is one irreversible OS
        # protocol. A standalone signed DISPATCH endpoint is not sufficient.
        self.reverse.require_effect_lifecycle("reverse")
        self.files.require_effect_lifecycle("files")

    async def _fresh_file(
        self,
        invocation: ProjectInvocation,
        *,
        file_object_id: UUID,
        expected_version: int,
        phase: Literal["read", "file_dispatch", "file_reconcile"] = "read",
    ) -> CommittedFileObject:
        scope = invocation.operation_scope
        if scope is None or scope.action != "reverse.import":
            raise OwnerEffectUnavailable("REVERSE_IMPORT_ORIGINAL_SCOPE_REQUIRED")
        # A reverse.import grant does NOT imply files.read. Obtain a FRESH
        # signed Files read decision, same User/Project/Session/correlation,
        # but an action-specific fingerprint and owner-local Files UoW.
        args = {"file_object_id": str(file_object_id), "expected_version": expected_version}
        file_scope = ProjectOperationScope(
            project_id=scope.project_id,
            agent_session_uuid=scope.agent_session_uuid,
            request_uuid=scope.request_uuid,
            action="files.read",
            fingerprint=canonical_request_fingerprint(
                project_id=scope.project_id,
                session_uuid=scope.agent_session_uuid,
                action="files.read",
                request_uuid=scope.request_uuid,
                backend="files",
                tool="committed_object",
                arguments=args,
            ),
        )
        file_invocation = replace(invocation, operation_scope=file_scope)
        reply = await self.files.execute(
            file_invocation,
            owner="files",
            phase=phase,
            action="files.read",
            target_sha256=object_digest(file_object_id),
            payload=CommittedFileObjectLookup(
                file_object_id=file_object_id,
                expected_version=expected_version,
                phase=phase,
            ),
            expected=CommittedFileObject,
            original_operation_uuid=scope.request_uuid,
        )
        view = reply.payload
        if (
            reply.attestation.receipt.state != "committed"
            or view.project_id != invocation.project_id
            or view.file_object_id != file_object_id
            or view.version != expected_version
            or view.state != "committed"
        ):
            raise OwnerEffectUnavailable("REVERSE_FILEOBJECT_NOT_COMMITTED")
        await self.authority.require(invocation, "reverse.import")
        return view

    async def claim(
        self,
        invocation: ProjectInvocation,
        *,
        native_project_id: UUID,
        file_object_id: UUID,
        expected_file_version: int,
        auto_analyze: bool = False,
    ) -> NativeImportReceipt:
        self._require_native_source_ready()
        scope = invocation.operation_scope
        if scope is None or scope.action != "reverse.import":
            raise OwnerEffectUnavailable("REVERSE_IMPORT_SCOPE_REQUIRED")
        await self.authority.require(invocation, "reverse.import")
        source = await self._fresh_file(
            invocation,
            file_object_id=file_object_id,
            expected_version=expected_file_version,
        )
        command = NativeImportClaimCommand(
            operation_uuid=scope.request_uuid,
            native_project_id=native_project_id,
            file_object_id=file_object_id,
            source_file_version=source.version,
            source_sha256=source.source_sha256,
            size_bytes=source.size_bytes,
            auto_analyze=auto_analyze,
            idempotency_key=str(scope.request_uuid),
        )
        reply = await self.reverse.execute(
            invocation,
            owner="reverse",
            phase="claim",
            action="reverse.import",
            target_sha256=native_digest(native_project_id),
            payload=command,
            expected=NativeImportReceipt,
            original_operation_uuid=scope.request_uuid,
        )
        record = reply.payload
        if (
            reply.attestation.receipt.state != "committed"
            or record.status != "reserved"
            or record.project_id != invocation.project_id
            or record.native_project_id != native_project_id
            or record.file_object_id != source.file_object_id
            or record.source_file_version != source.version
            or record.source_sha256 != source.source_sha256
            or record.size_bytes != source.size_bytes
        ):
            raise OwnerEffectUnavailable("REVERSE_OWNER_CLAIM_INVALID", unknown=True)
        return record

    async def dispatch_intent(
        self,
        invocation: ProjectInvocation,
        *,
        reserved: NativeImportReceipt,
    ) -> NativeImportReceipt:
        """Commit owner-local DISPATCH before a separately trusted OS import.

        This does NOT import into Ghidra: absent independently accepted native
        worker/inventory C2 custody, no physical effect may be performed.
        UNKNOWN dispatch ACK requires owner inspect of ORIGINAL UUID, not
        retrying claim or creating another native Project/FileObject.
        """
        scope = invocation.operation_scope
        if (
            scope is None
            or scope.action != "reverse.import"
            or scope.request_uuid != reserved.operation_uuid
            or reserved.status != "reserved"
            or reserved.project_id != invocation.project_id
            or self.inventory is None
        ):
            raise OwnerEffectUnavailable("REVERSE_TRUSTED_DISPATCH_CONTEXT_REQUIRED")
        await self._fresh_file(
            invocation,
            file_object_id=reserved.file_object_id,
            expected_version=reserved.source_file_version,
            phase="file_dispatch",
        )
        command = NativeImportTransition(
            operation_uuid=reserved.operation_uuid,
            import_uuid=reserved.import_uuid,
            expected_version=reserved.revision,
            phase="dispatch",
        )
        result = await self.reverse.execute(
            invocation,
            owner="reverse",
            phase="dispatch",
            action="reverse.import",
            target_sha256=native_digest(reserved.native_project_id),
            payload=command,
            expected=NativeImportReceipt,
            expected_version=reserved.revision,
            original_operation_uuid=reserved.operation_uuid,
        )
        receipt = result.payload
        if (
            result.attestation.receipt.state != "committed"
            or receipt.status != "dispatched"
            or receipt.import_uuid != reserved.import_uuid
            or receipt.project_id != reserved.project_id
            or receipt.native_project_id != reserved.native_project_id
            or receipt.file_object_id != reserved.file_object_id
            or receipt.source_file_version != reserved.source_file_version
            or receipt.source_sha256 != reserved.source_sha256
            or receipt.revision != reserved.revision + 1
        ):
            raise OwnerEffectUnavailable("REVERSE_DISPATCH_CAS_INVALID", unknown=True)
        return receipt

    async def mark_unknown(
        self,
        invocation: ProjectInvocation,
        *,
        dispatched: NativeImportReceipt,
    ) -> NativeImportReceipt:
        """Freeze an uncertain native effect under the SAME owner command UUID."""
        scope = invocation.operation_scope
        if (
            scope is None
            or scope.request_uuid != dispatched.operation_uuid
            or scope.action != "reverse.import"
            or dispatched.status != "dispatched"
        ):
            raise OwnerEffectUnavailable("REVERSE_UNKNOWN_ORIGINAL_DISPATCH_REQUIRED")
        command = NativeImportTransition(
            operation_uuid=dispatched.operation_uuid,
            import_uuid=dispatched.import_uuid,
            expected_version=dispatched.revision,
            phase="unknown",
        )
        result = await self.reverse.execute(
            invocation,
            owner="reverse",
            phase="mark_unknown",
            action="reverse.import",
            target_sha256=native_digest(dispatched.native_project_id),
            payload=command,
            expected=NativeImportReceipt,
            expected_version=dispatched.revision,
            original_operation_uuid=dispatched.operation_uuid,
        )
        receipt = result.payload
        if (
            result.attestation.receipt.state != "committed"
            or receipt.status != "unknown"
            or receipt.import_uuid != dispatched.import_uuid
            or receipt.file_object_id != dispatched.file_object_id
            or receipt.revision != dispatched.revision + 1
        ):
            raise OwnerEffectUnavailable("REVERSE_UNKNOWN_CAS_INVALID", unknown=True)
        return receipt

    async def inspect(
        self,
        invocation: ProjectInvocation,
        *,
        native_project_id: UUID,
        original_operation_uuid: UUID,
    ) -> ReverseInspection:
        query = NativeImportInspect(operation_uuid=original_operation_uuid)
        reply = await self.reverse.execute(
            invocation,
            owner="reverse",
            phase="inspect",
            action="reverse.import",
            target_sha256=native_digest(native_project_id),
            payload=query,
            expected=ReverseInspection,
            original_operation_uuid=original_operation_uuid,
        )
        outcome = reply.payload
        if not outcome.found:
            if outcome.import_receipt is not None or reply.attestation.receipt.state != "committed":
                raise OwnerEffectUnavailable("REVERSE_ABSENCE_UNVERIFIED", unknown=True)
        else:
            record = outcome.import_receipt
            if (
                record is None
                or record.operation_uuid != original_operation_uuid
                or record.native_project_id != native_project_id
                or record.project_id != invocation.project_id
                or reply.attestation.receipt.state != "committed"
            ):
                raise OwnerEffectUnavailable("REVERSE_INSPECTION_SCOPE_INVALID", unknown=True)
        return outcome

    async def reconcile_verified_native(
        self, invocation: ProjectInvocation, *, record: NativeImportReceipt
    ) -> NativeImportReceipt:
        if self.inventory is None or record.status not in {"dispatched", "unknown"}:
            raise OwnerEffectUnavailable("REVERSE_TRUSTED_GHIDRA_INVENTORY_REQUIRED")
        scope = invocation.operation_scope
        if scope is None or scope.request_uuid != record.operation_uuid:
            raise OwnerEffectUnavailable("REVERSE_ORIGINAL_UUID_REQUIRED")
        current_source = await self._fresh_file(
            invocation,
            file_object_id=record.file_object_id,
            expected_version=record.source_file_version,
            phase="file_reconcile",
        )
        if current_source.source_sha256 != record.source_sha256:
            raise OwnerEffectUnavailable("REVERSE_SOURCE_CHANGED_BEFORE_RECONCILE")
        try:
            current = await self.inventory.verify_current_artifact(
                invocation,
                record=record,
            )
        except Exception as exc:
            raise OwnerEffectUnavailable("REVERSE_GHIDRA_INVENTORY_UNAVAILABLE") from exc
        if (
            not isinstance(current, VerifiedNativeInventory)
            or current.native_project_id != record.native_project_id
            or current.file_object_id != record.file_object_id
            or current.file_version != record.source_file_version
            or current.original_operation_uuid != record.operation_uuid
            or not isinstance(current.verifier_instance_uuid, UUID)
            or current.verifier_instance_uuid.version != 4
            or current.observed_at.tzinfo is None
            or current.observed_at > datetime.now(UTC)
        ):
            raise OwnerEffectUnavailable("REVERSE_GHIDRA_INVENTORY_INVALID")
        # The owner must independently validate signed OS/Ghidra inventory
        # provenance in its own SQL reconciliation UoW. This DTO alone is
        # NOT a signed attestation, and no Ghidra process is launched here.
        command = ReverseReconcileCommand(
            original_operation_uuid=record.operation_uuid,
            native_project_id=record.native_project_id,
            file_object_id=record.file_object_id,
            source_file_version=record.source_file_version,
            import_uuid=record.import_uuid,
            expected_version=record.revision,
            verified_inventory=current,
        )
        reply = await self.reverse.execute(
            invocation,
            owner="reverse",
            phase="reconcile",
            action="reverse.import",
            target_sha256=native_digest(record.native_project_id),
            payload=command,
            expected=NativeImportReceipt,
            expected_version=record.revision,
            original_operation_uuid=record.operation_uuid,
        )
        if (
            reply.attestation.receipt.state != "committed"
            or reply.payload.status != "succeeded"
            or reply.payload.import_uuid != record.import_uuid
            or reply.payload.native_project_id != record.native_project_id
            or reply.payload.source_file_version != record.source_file_version
        ):
            raise OwnerEffectUnavailable("REVERSE_RECONCILIATION_UNKNOWN", unknown=True)
        return reply.payload
