"""Reverse/Native owner import ledger; immutable Files refs, no cross-DB FK.

Native Ghidra/OS artifacts and source File bytes belong to OTHER owners and
must be verified via signed private ports before any import is dispatched.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from common.owner_contracts import (
    CurrentOwnerAuthorityPort,
    OwnerCommandDTO,
    OwnerProofAuthority,
    SignedOwnerProofs,
    TrustedOwnerServicePeerPort,
    VerifiedOwnerOperation,
    VerifiedOwnerServicePeer,
    require_online_owner_decision,
    require_signed_payload,
)
from common.owner_transactions import OwnerCommandOutcome, OwnerLocalCommandExecutor
from common.platform_db import PlatformDatabase
from common.platform_errors import AccessDenied, Conflict, InvalidInput
from projects._native_import_persistence import NativeImportRow, NativeProjectRow


@dataclass(frozen=True, slots=True)
class VerifiedFilesSourceReceipt:
    project_id: UUID
    file_object_id: UUID
    file_version: int
    content_sha256: str
    size_bytes: int
    source_revision: str
    confirmed_at: datetime


class TrustedFilesSourcePort(Protocol):
    def verify_current_file(
        self, evidence: object, *, project_id: UUID, file_object_id: UUID
    ) -> VerifiedFilesSourceReceipt:
        """Must independently validate signed Files owner revision/provenance."""
        ...


@dataclass(frozen=True, slots=True)
class VerifiedNativeImportObservation:
    import_uuid: UUID
    original_operation_uuid: UUID
    project_id: UUID
    native_project_id: UUID
    file_object_id: UUID
    owner_service_id: UUID
    outcome: Literal["succeeded", "confirmed_absent", "unknown"]
    native_artifact_id: str | None
    result_sha256: str | None
    observed_at: datetime
    native_scope_digest: str


class TrustedNativeImportObserver(Protocol):
    def verify_native_effect(
        self, evidence: object, *, peer: VerifiedOwnerServicePeer
    ) -> VerifiedNativeImportObservation:
        """Must verify signed Ghidra/OS provenance, not a caller UUID/path."""
        ...


class ReverseOwnerSource:
    def __init__(
        self,
        db: PlatformDatabase,
        commands: OwnerLocalCommandExecutor,
        authority: OwnerProofAuthority,
        current_owners: CurrentOwnerAuthorityPort,
        peer_verifier: TrustedOwnerServicePeerPort,
        files_source: TrustedFilesSourcePort,
        native_observer: TrustedNativeImportObserver,
        *,
        idempotency_hmac_key: bytes,
    ) -> None:
        if db.engine.url.database != "briareus_reverse" or commands.owner != "reverse":
            raise RuntimeError("native imports require only the Reverse owner DB")
        if (
            current_owners is None
            or peer_verifier is None
            or files_source is None
            or native_observer is None
            or len(idempotency_hmac_key) < 32
        ):
            raise RuntimeError("native import needs current authorities and Files provenance")
        self.db = db
        self.commands = commands
        self.authority = authority
        self.current_owners = current_owners
        self.peer_verifier = peer_verifier
        self.files_source = files_source
        self.native_observer = native_observer
        self._key = idempotency_hmac_key

    async def _current(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> VerifiedOwnerOperation:
        first = self.authority.require_current(request, proofs)
        live = await require_online_owner_decision(self.authority, self.current_owners, request)
        if (
            first.identity_epoch != live.identity_epoch
            or first.control_epoch != live.control_epoch
            or first.access_epoch != live.access_epoch
        ):
            raise AccessDenied("native owner permission epoch revoked")
        try:
            peer = self.peer_verifier.verify_peer(peer_evidence)
            if (
                peer.service_id != service_id
                or peer.instance_uuid != instance_uuid
                or peer.audience != "briareus:reverse"
                or peer.expires_at <= datetime.now(UTC)
            ):
                raise AccessDenied("native service instance identity mismatch")
        except Exception:
            raise AccessDenied("trusted native service peer missing") from None
        if request.target_owner != "reverse":
            raise AccessDenied("native operation addressed to foreign DB owner")
        return live

    async def reserve_import(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        files_evidence: object,
        *,
        native_project_id: UUID,
        file_object_id: UUID,
        service_id: UUID,
        instance_uuid: UUID,
        auto_analyze: bool,
        ttl_seconds: int = 900,
    ) -> OwnerCommandOutcome:
        if (
            request.operation not in {"reverse.import.reserve", "reverse.import.claim"}
            or native_project_id.version != 4
            or file_object_id.version != 4
            or not 60 <= ttl_seconds <= 3600
        ):
            raise InvalidInput("invalid signed native import selection")
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        try:
            file = self.files_source.verify_current_file(
                files_evidence, project_id=request.project_id, file_object_id=file_object_id
            )
        except Exception:
            raise AccessDenied("current signed Files version unavailable") from None
        if (
            file.project_id != request.project_id
            or file.file_object_id != file_object_id
            or file.file_version < 1
            or not 0 <= file.size_bytes <= 100_000_000_000_000
            or len(file.content_sha256) != 64
            or any(c not in "0123456789abcdef" for c in file.content_sha256)
            or file.confirmed_at.tzinfo is None
        ):
            raise AccessDenied("Files source owner provenance mismatch")
        require_signed_payload(
            request,
            {
                "native_project_id": str(native_project_id),
                "file_object_id": str(file_object_id),
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
                "auto_analyze": auto_analyze,
                "ttl_seconds": ttl_seconds,
                "file_version": file.file_version,
                "content_sha256": file.content_sha256,
                "size_bytes": file.size_bytes,
                "source_revision": file.source_revision,
            },
        )
        digest = hmac.new(self._key, request.idempotency_key.encode(), hashlib.sha256).hexdigest()

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            native = await tx.scalar(
                select(NativeProjectRow)
                .where(NativeProjectRow.id == native_project_id)
                .with_for_update()
            )
            if (
                native is None
                or native.project_id != request.project_id
                or native.owner_service_id != service_id
                or not native.enabled
            ):
                raise AccessDenied("native Project current owner not active")
            pending = await tx.scalar(
                select(NativeImportRow.import_uuid)
                .where(
                    NativeImportRow.project_id == request.project_id,
                    NativeImportRow.native_project_id == native_project_id,
                    NativeImportRow.file_object_id == file_object_id,
                    NativeImportRow.source_file_version == file.file_version,
                    NativeImportRow.status.in_(("reserved", "dispatched", "unknown")),
                )
                .limit(1)
            )
            if pending is not None:
                raise Conflict("native import source already has unresolved effect")
            row = NativeImportRow(
                import_uuid=uuid4(),
                operation_uuid=request.operation_uuid,
                project_id=request.project_id,
                native_project_id=native_project_id,
                file_object_id=file_object_id,
                source_file_version=file.file_version,
                source_content_sha256=file.content_sha256,
                source_size_bytes=file.size_bytes,
                auto_analyze=auto_analyze,
                actor_user_id=request.caller_user_id,
                agent_session_uuid=request.session_uuid,
                owner_service_id=service_id,
                idempotency_digest=digest,
                request_fingerprint=request.payload_sha256,
                status="reserved",
                version=1,
                cleanup_state="not_requested",
                expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            )
            tx.add(row)
            return {
                "import_uuid": str(row.import_uuid),
                "operation_uuid": str(row.operation_uuid),
                "native_project_id": str(row.native_project_id),
                "source_file_version": row.source_file_version,
                "status": "reserved",
                "version": 1,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="reverse.import_reserved",
            target=str(native_project_id),
        )

    async def mark_dispatched(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        import_uuid: UUID,
        original_operation_uuid: UUID,
        expected_import_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """Commit dispatch intent before invoking external Ghidra/OS import."""
        if (
            request.operation != "reverse.import.dispatch"
            or import_uuid.version != 4
            or original_operation_uuid.version != 4
            or expected_import_version < 1
        ):
            raise InvalidInput("native import dispatch requires original CAS revision")
        require_signed_payload(
            request,
            {
                "import_uuid": str(import_uuid),
                "original_operation_uuid": str(original_operation_uuid),
                "expected_import_version": expected_import_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            row = await tx.scalar(
                select(NativeImportRow)
                .where(NativeImportRow.import_uuid == import_uuid)
                .with_for_update()
            )
            if (
                row is None
                or row.project_id != request.project_id
                or row.agent_session_uuid != request.session_uuid
                or row.actor_user_id != request.caller_user_id
                or row.owner_service_id != service_id
                or row.operation_uuid != original_operation_uuid
                or row.version != expected_import_version
                or row.status != "reserved"
                or row.expires_at <= datetime.now(UTC)
            ):
                raise AccessDenied("native import intent already dispatched or revoked")
            row.status = "dispatched"
            row.dispatched_at = datetime.now(UTC)
            row.version += 1
            return {
                "import_uuid": str(row.import_uuid),
                "status": "dispatched",
                "version": row.version,
                "operation_uuid": str(row.operation_uuid),
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="reverse.import_dispatched",
            target=str(import_uuid),
        )

    async def reconcile_import(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        native_evidence: object,
        *,
        import_uuid: UUID,
        original_operation_uuid: UUID,
        expected_import_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """Only verified native effect/absence receipt settles dispatched import."""
        if (
            request.operation != "reverse.import.reconcile"
            or import_uuid.version != 4
            or original_operation_uuid.version != 4
            or expected_import_version < 1
        ):
            raise InvalidInput("native import reconciliation requires original CAS revision")
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        try:
            peer = self.peer_verifier.verify_peer(peer_evidence)
            observed = self.native_observer.verify_native_effect(native_evidence, peer=peer)
        except Exception:
            raise AccessDenied("native Ghidra/OS import provenance unavailable") from None
        if (
            observed.import_uuid != import_uuid
            or observed.original_operation_uuid != original_operation_uuid
            or observed.project_id != request.project_id
            or observed.owner_service_id != service_id
            or observed.observed_at.tzinfo is None
            or observed.observed_at > datetime.now(UTC)
            or datetime.now(UTC) - observed.observed_at > timedelta(minutes=2)
            or len(observed.native_scope_digest) != 64
            or any(c not in "0123456789abcdef" for c in observed.native_scope_digest)
        ):
            raise AccessDenied("native observation not scoped to original import")
        if observed.outcome == "succeeded":
            if (
                not observed.native_artifact_id
                or len(observed.native_artifact_id) > 256
                or observed.result_sha256 is None
                or len(observed.result_sha256) != 64
                or any(c not in "0123456789abcdef" for c in observed.result_sha256)
            ):
                raise AccessDenied("signed native success has no valid result identity")
        elif observed.native_artifact_id is not None or observed.result_sha256 is not None:
            raise AccessDenied("unconfirmed import cannot claim a native result artifact")
        require_signed_payload(
            request,
            {
                "import_uuid": str(import_uuid),
                "original_operation_uuid": str(original_operation_uuid),
                "expected_import_version": expected_import_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
                "native_observation": {
                    "native_project_id": str(observed.native_project_id),
                    "file_object_id": str(observed.file_object_id),
                    "outcome": observed.outcome,
                    "native_artifact_id": observed.native_artifact_id,
                    "result_sha256": observed.result_sha256,
                    "observed_at": observed.observed_at.isoformat(),
                    "native_scope_digest": observed.native_scope_digest,
                },
            },
        )

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            row = await tx.scalar(
                select(NativeImportRow)
                .where(NativeImportRow.import_uuid == import_uuid)
                .with_for_update()
            )
            if (
                row is None
                or row.project_id != request.project_id
                or row.operation_uuid != original_operation_uuid
                or row.agent_session_uuid != request.session_uuid
                or row.actor_user_id != request.caller_user_id
                or row.owner_service_id != service_id
                or row.native_project_id != observed.native_project_id
                or row.file_object_id != observed.file_object_id
                or row.version != expected_import_version
                or row.status not in {"dispatched", "unknown"}
            ):
                raise AccessDenied("native import source, Project or CAS revision changed")
            row.status = observed.outcome
            row.version += 1
            if observed.outcome != "unknown":
                row.resolved_at = datetime.now(UTC)
                row.native_artifact_id = observed.native_artifact_id
                row.result_sha256 = observed.result_sha256
            return {
                "import_uuid": str(row.import_uuid),
                "status": row.status,
                "version": row.version,
                "reconciliation_required": row.status == "unknown",
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="reverse.import_reconciled",
            target=str(import_uuid),
        )
