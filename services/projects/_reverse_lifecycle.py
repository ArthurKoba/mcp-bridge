"""Reverse-native safe owner-local cancel, UNKNOWN and original inspection.

The native Ghidra filesystem/artifact is an independent authority. SQL
`cancelled` is permitted ONLY before dispatch; after native dispatch any
uncertain status remains `unknown` until signed native OS observation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from common.owner_contracts import OwnerCommandDTO, SignedOwnerProofs, require_signed_payload
from common.owner_transactions import OwnerCommandOutcome
from common.platform_errors import AccessDenied, InvalidInput
from projects._native_import_persistence import NativeImportRow, NativeProjectRow
from projects._reverse_source import ReverseOwnerSource


@dataclass(frozen=True, slots=True)
class ReverseImportInspection:
    import_uuid: UUID
    original_operation_uuid: UUID
    native_project_id: UUID
    source_file_object_id: UUID
    source_file_version: int
    version: int
    status: str
    cleanup_state: str
    # Native Ghidra/OS success or absence is never inferred from SQL alone.
    native_effect_verified: bool = False
    original_reconciliation_required: bool = True


class ReverseOwnerLifecycle(ReverseOwnerSource):
    async def _import(
        self,
        tx: AsyncSession,
        *,
        request: OwnerCommandDTO,
        import_uuid: UUID,
        original_uuid: UUID,
        service_id: UUID,
    ) -> NativeImportRow:
        row = await tx.scalar(
            select(NativeImportRow)
            .where(
                NativeImportRow.import_uuid == import_uuid,
            )
            .with_for_update()
        )
        if (
            row is None
            or row.operation_uuid != original_uuid
            or row.project_id != request.project_id
            or row.actor_user_id != request.caller_user_id
            or row.agent_session_uuid != request.session_uuid
            or row.owner_service_id != service_id
        ):
            raise AccessDenied("original native import not authorized by Reverse owner")
        return row

    async def mark_unknown(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        import_uuid: UUID,
        original_operation_uuid: UUID,
        expected_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        if (
            request.operation != "reverse.import.mark_unknown"
            or any(value.version != 4 for value in (import_uuid, original_operation_uuid))
            or expected_version < 1
        ):
            raise InvalidInput("native UNKNOWN phase requires original version and UUID")
        require_signed_payload(
            request,
            {
                "import_uuid": str(import_uuid),
                "original_operation_uuid": str(original_operation_uuid),
                "expected_version": expected_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )

        async def mutate(tx: AsyncSession) -> dict[str, object]:
            row = await self._import(
                tx,
                request=request,
                import_uuid=import_uuid,
                original_uuid=original_operation_uuid,
                service_id=service_id,
            )
            if row.version != expected_version or row.status not in {"dispatched", "unknown"}:
                raise AccessDenied("not a dispatched uncertain native effect")
            row.status = "unknown"
            row.version += 1
            return {
                "import_uuid": str(row.import_uuid),
                "original_operation_uuid": str(row.operation_uuid),
                "status": "unknown",
                "version": row.version,
                "native_effect_verified": False,
                "reconciliation_required": True,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutate,
            event="reverse.import_unknown",
            target=str(import_uuid),
        )

    async def cancel_before_dispatch(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        import_uuid: UUID,
        original_operation_uuid: UUID,
        expected_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """An already-dispatched Ghidra import cannot be SQL-cancelled."""
        if (
            request.operation != "reverse.import.cancel"
            or any(value.version != 4 for value in (import_uuid, original_operation_uuid))
            or expected_version < 1
        ):
            raise InvalidInput("native cancel requires original import version")
        require_signed_payload(
            request,
            {
                "import_uuid": str(import_uuid),
                "original_operation_uuid": str(original_operation_uuid),
                "expected_version": expected_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )

        async def mutate(tx: AsyncSession) -> dict[str, object]:
            row = await self._import(
                tx,
                request=request,
                import_uuid=import_uuid,
                original_uuid=original_operation_uuid,
                service_id=service_id,
            )
            if (
                row.version != expected_version
                or row.status != "reserved"
                or row.dispatched_at is not None
            ):
                raise AccessDenied("native import already dispatched; requires OS reconciliation")
            row.status = "cancelled"
            row.version += 1
            row.resolved_at = datetime.now(UTC)
            return {
                "import_uuid": str(row.import_uuid),
                "status": "cancelled",
                "original_operation_uuid": str(row.operation_uuid),
                "version": row.version,
                "native_effect_verified": False,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutate,
            event="reverse.reservation_cancelled",
            target=str(import_uuid),
        )

    async def inspect_import(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        import_uuid: UUID,
        original_operation_uuid: UUID,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> ReverseImportInspection:
        if request.operation != "reverse.import.inspect" or any(
            value.version != 4 for value in (import_uuid, original_operation_uuid)
        ):
            raise InvalidInput("Reverse inspect requires original import UUID")
        require_signed_payload(
            request,
            {
                "import_uuid": str(import_uuid),
                "original_operation_uuid": str(original_operation_uuid),
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        async with self.db.transaction() as tx:
            row = await self._import(
                tx,
                request=request,
                import_uuid=import_uuid,
                original_uuid=original_operation_uuid,
                service_id=service_id,
            )
            native = await tx.scalar(
                select(NativeProjectRow)
                .where(
                    NativeProjectRow.id == row.native_project_id,
                )
                .with_for_update()
            )
            if native is None or native.project_id != request.project_id or not native.enabled:
                raise AccessDenied("native Project ownership disabled or changed")
            return ReverseImportInspection(
                import_uuid=row.import_uuid,
                original_operation_uuid=row.operation_uuid,
                native_project_id=row.native_project_id,
                source_file_object_id=row.file_object_id,
                source_file_version=row.source_file_version,
                version=row.version,
                status=row.status,
                cleanup_state=row.cleanup_state,
            )

    async def inspect_by_original_operation(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> ReverseImportInspection:
        """NativeImportInspect carries only original operation UUID.

        Current ownership and native Project enablement rechecked within
        Reverse-owned SQL; a row is not independent Ghidra artifact proof.
        """
        if request.operation != "reverse.import.inspect":
            raise InvalidInput("Reverse original operation inspect invalid")
        require_signed_payload(
            request,
            {
                "original_operation_uuid": str(request.operation_uuid),
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        async with self.db.transaction() as tx:
            row = await tx.scalar(
                select(NativeImportRow)
                .where(
                    NativeImportRow.operation_uuid == request.operation_uuid,
                    NativeImportRow.project_id == request.project_id,
                    NativeImportRow.owner_service_id == service_id,
                    NativeImportRow.actor_user_id == request.caller_user_id,
                    NativeImportRow.agent_session_uuid == request.session_uuid,
                )
                .with_for_update()
            )
            if row is None:
                raise AccessDenied("Reverse original import outcome unproven")
            native = await tx.scalar(
                select(NativeProjectRow)
                .where(
                    NativeProjectRow.id == row.native_project_id,
                )
                .with_for_update()
            )
            if (
                native is None
                or native.project_id != request.project_id
                or native.owner_service_id != service_id
                or not native.enabled
            ):
                raise AccessDenied("Reverse native Project current owner revoked")
            return ReverseImportInspection(
                import_uuid=row.import_uuid,
                original_operation_uuid=row.operation_uuid,
                native_project_id=row.native_project_id,
                source_file_object_id=row.file_object_id,
                source_file_version=row.source_file_version,
                version=row.version,
                status=row.status,
                cleanup_state=row.cleanup_state,
            )
