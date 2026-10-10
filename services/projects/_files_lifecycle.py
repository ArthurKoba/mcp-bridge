"""Files owner-local safe remainder: uncertain, undispatched abort, metadata.

Files bytes/OS absence require an independent native read/FD/inode observer.
A pending/reserved SQL row alone never certifies a physical file state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from common.owner_contracts import (
    OwnerCommandDTO,
    SignedOwnerProofs,
    VerifiedOwnerOperation,
    require_signed_payload,
)
from common.owner_transactions import OwnerCommandOutcome
from common.platform_errors import AccessDenied, Conflict, InvalidInput
from projects._file_quota_persistence import (
    FileObjectRow,
    FileQuotaAccountRow,
    FileQuotaReservationRow,
)
from projects._files_source import FilesOwnerSource


@dataclass(frozen=True, slots=True)
class FilesReservationInspection:
    reservation_id: UUID
    original_operation_uuid: UUID
    status: str
    version: int
    quota_reserved_bytes: int
    os_effect_verified: bool = False
    reconciliation_required: bool = True


@dataclass(frozen=True, slots=True)
class FilesMetadataInspection:
    project_id: UUID
    path_digest: str
    file_id: UUID | None
    current_file_version: int | None
    size_bytes: int | None
    content_sha256: str | None
    # DB inventory alone cannot prove a file's current native inode.
    native_file_verified: bool = False


class FilesOwnerLifecycle(FilesOwnerSource):
    async def _reservation(
        self,
        tx: AsyncSession,
        *,
        request: OwnerCommandDTO,
        reservation_id: UUID,
        original_operation_uuid: UUID,
        service_id: UUID,
    ) -> FileQuotaReservationRow:
        row = await tx.scalar(
            select(FileQuotaReservationRow)
            .where(
                FileQuotaReservationRow.reservation_id == reservation_id,
            )
            .with_for_update()
        )
        if (
            row is None
            or row.operation_uuid != original_operation_uuid
            or row.project_id != request.project_id
            or row.agent_session_uuid != request.session_uuid
            or row.actor_user_id != request.caller_user_id
            or row.owner_service_id != service_id
        ):
            raise AccessDenied("original Files reservation not found in caller's owner scope")
        return row

    async def mark_unknown(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        reservation_id: UUID,
        original_operation_uuid: UUID,
        expected_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """Freeze uncertain dispatched native write. NEVER free reserved quota."""
        if (
            request.operation != "files.write.mark_unknown"
            or any(x.version != 4 for x in (reservation_id, original_operation_uuid))
            or expected_version < 1
        ):
            raise InvalidInput("Files unknown requires exact original effect UUID/version")
        require_signed_payload(
            request,
            {
                "reservation_id": str(reservation_id),
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
            account = await tx.scalar(
                select(FileQuotaAccountRow)
                .where(
                    FileQuotaAccountRow.project_id == request.project_id,
                )
                .with_for_update()
            )
            row = await self._reservation(
                tx,
                request=request,
                reservation_id=reservation_id,
                original_operation_uuid=original_operation_uuid,
                service_id=service_id,
            )
            if (
                account is None
                or row.version != expected_version
                or row.status not in {"dispatched", "unknown"}
            ):
                raise AccessDenied("Files uncertain outcome is not safely fenced")
            row.status = "unknown"
            row.version += 1
            account.frozen = True
            account.version += 1
            account.updated_at = datetime.now(UTC)
            return {
                "reservation_id": str(row.reservation_id),
                "original_operation_uuid": str(row.operation_uuid),
                "status": "unknown",
                "version": row.version,
                "reconciliation_required": True,
                "quota_frozen": True,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutate,
            event="files.write_unknown",
            target=str(reservation_id),
        )

    async def release_undispatched(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        reservation_id: UUID,
        original_operation_uuid: UUID,
        expected_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """Release ONLY never-dispatched SQL reservation; deny uncertain OS."""
        if (
            request.operation != "files.write.release"
            or any(x.version != 4 for x in (reservation_id, original_operation_uuid))
            or expected_version < 1
        ):
            raise InvalidInput("Files release needs verified original reservation")
        require_signed_payload(
            request,
            {
                "reservation_id": str(reservation_id),
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
            account = await tx.scalar(
                select(FileQuotaAccountRow)
                .where(
                    FileQuotaAccountRow.project_id == request.project_id,
                )
                .with_for_update()
            )
            row = await self._reservation(
                tx,
                request=request,
                reservation_id=reservation_id,
                original_operation_uuid=original_operation_uuid,
                service_id=service_id,
            )
            if (
                account is None
                or account.frozen
                or row.version != expected_version
                or row.status != "reserved"
                or row.dispatched_at is not None
                or row.reserved_delta > account.reserved_bytes
            ):
                raise AccessDenied("only undispatched Files bytes can be safely released")
            row.status = "released"
            row.version += 1
            row.resolved_at = datetime.now(UTC)
            account.reserved_bytes -= row.reserved_delta
            account.version += 1
            account.updated_at = datetime.now(UTC)
            return {
                "reservation_id": str(row.reservation_id),
                "original_operation_uuid": str(row.operation_uuid),
                "status": "released",
                "version": row.version,
                "reserved_bytes": account.reserved_bytes,
                "native_effect_verified": False,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutate,
            event="files.undispatched_released",
            target=str(reservation_id),
        )

    async def inspect_reservation(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        reservation_id: UUID,
        original_operation_uuid: UUID,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> FilesReservationInspection:
        """Owner-local currently authorized DB status, not OS or execution ACK."""
        if request.operation != "files.write.inspect" or any(
            x.version != 4 for x in (reservation_id, original_operation_uuid)
        ):
            raise InvalidInput("Files inspect original UUID invalid")
        require_signed_payload(
            request,
            {
                "reservation_id": str(reservation_id),
                "original_operation_uuid": str(original_operation_uuid),
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        async with self.db.transaction() as tx:
            row = await self._reservation(
                tx,
                request=request,
                reservation_id=reservation_id,
                original_operation_uuid=original_operation_uuid,
                service_id=service_id,
            )
            account = await tx.scalar(
                select(FileQuotaAccountRow).where(
                    FileQuotaAccountRow.project_id == request.project_id,
                )
            )
            if account is None:
                raise AccessDenied("Files quota state unavailable")
            return FilesReservationInspection(
                row.reservation_id,
                row.operation_uuid,
                row.status,
                row.version,
                account.reserved_bytes,
            )

    async def inspect_file_metadata(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        path_digest: str,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> FilesMetadataInspection:
        if (
            request.operation != "files.metadata"
            or len(path_digest) != 64
            or any(c not in "0123456789abcdef" for c in path_digest)
        ):
            raise InvalidInput("Files metadata requires canonical path digest")
        require_signed_payload(
            request,
            {
                "path_digest": path_digest,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        async with self.db.transaction() as tx:
            outstanding = await tx.scalar(
                select(FileQuotaReservationRow.reservation_id)
                .where(
                    FileQuotaReservationRow.project_id == request.project_id,
                    FileQuotaReservationRow.path_digest == path_digest,
                    FileQuotaReservationRow.status.in_(("reserved", "dispatched", "unknown")),
                )
                .limit(1)
            )
            if outstanding is not None:
                raise Conflict("Files metadata is uncertain while write is unresolved")
            row = await tx.scalar(
                select(FileObjectRow).where(
                    FileObjectRow.project_id == request.project_id,
                    FileObjectRow.path_digest == path_digest,
                    FileObjectRow.deleted.is_(False),
                )
            )
            return FilesMetadataInspection(
                request.project_id,
                path_digest,
                row.id if row else None,
                row.version if row else None,
                row.size_bytes if row else None,
                row.content_sha256 if row else None,
            )

    async def list_file_index(
        self,
        decision: VerifiedOwnerOperation,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        after_file_id: UUID | None,
        limit: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """Audited Files SQL index, NEVER a native directory listing or bytes."""
        request = decision.request
        if (
            request.operation != "files.list"
            or request.target_owner != "files"
            or not 1 <= limit <= 100
            or (after_file_id is not None and after_file_id.version != 4)
        ):
            raise InvalidInput("Files SQL index cursor/scope invalid")
        require_signed_payload(
            request,
            {
                "after_file_id": str(after_file_id) if after_file_id is not None else None,
                "limit": limit,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        verified = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        if (
            verified.identity_epoch != decision.identity_epoch
            or verified.control_epoch != decision.control_epoch
            or verified.access_epoch != decision.access_epoch
        ):
            raise AccessDenied("Files current owner revisions changed before SQL metadata read")

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            unresolved = await tx.scalar(
                select(FileQuotaReservationRow.reservation_id)
                .where(
                    FileQuotaReservationRow.project_id == request.project_id,
                    FileQuotaReservationRow.status.in_(("reserved", "dispatched", "unknown")),
                )
                .limit(1)
            )
            if unresolved is not None:
                raise Conflict("File index cannot establish current state with unresolved write")
            rows = select(FileObjectRow).where(
                FileObjectRow.project_id == request.project_id,
                FileObjectRow.deleted.is_(False),
            )
            if after_file_id is not None:
                rows = rows.where(FileObjectRow.id > after_file_id)
            current = list(await tx.scalars(rows.order_by(FileObjectRow.id).limit(limit + 1)))
            return {
                "status": "recorded",
                "project_id": str(request.project_id),
                "files": [
                    {
                        "file_id": str(item.id),
                        "path_digest": item.path_digest,
                        "version": item.version,
                        "size_bytes": item.size_bytes,
                        "content_sha256": item.content_sha256,
                    }
                    for item in current[:limit]
                ],
                "has_more": len(current) > limit,
                "next_after_id": str(current[limit - 1].id) if len(current) > limit else None,
                "native_directory_verified": False,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="files.metadata_listed",
            target=str(request.project_id),
        )

    async def metadata_as_committed_read(
        self,
        decision: VerifiedOwnerOperation,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        path_digest: str,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """Owner-local signed SQL metadata; a native FD verification is separate."""
        request = decision.request
        if (
            request.operation != "files.metadata"
            or request.target_owner != "files"
            or len(path_digest) != 64
            or any(c not in "0123456789abcdef" for c in path_digest)
        ):
            raise InvalidInput("Files metadata digest or owner operation invalid")
        require_signed_payload(
            request,
            {
                "path_digest": path_digest,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        current = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        if (
            current.identity_epoch != decision.identity_epoch
            or current.control_epoch != decision.control_epoch
            or current.access_epoch != decision.access_epoch
        ):
            raise AccessDenied("Files metadata authorization changed")

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            unresolved = await tx.scalar(
                select(FileQuotaReservationRow.reservation_id)
                .where(
                    FileQuotaReservationRow.project_id == request.project_id,
                    FileQuotaReservationRow.path_digest == path_digest,
                    FileQuotaReservationRow.status.in_(("reserved", "dispatched", "unknown")),
                )
                .limit(1)
            )
            if unresolved is not None:
                raise Conflict("Files metadata cannot be read through unresolved mutation")
            row = await tx.scalar(
                select(FileObjectRow).where(
                    FileObjectRow.project_id == request.project_id,
                    FileObjectRow.path_digest == path_digest,
                    FileObjectRow.deleted.is_(False),
                )
            )
            return {
                "status": "recorded",
                "project_id": str(request.project_id),
                "path_digest": path_digest,
                "file_id": str(row.id) if row is not None else None,
                "file_version": row.version if row is not None else None,
                "size_bytes": row.size_bytes if row is not None else None,
                "content_sha256": row.content_sha256 if row is not None else None,
                "native_file_verified": False,
            }

        return await self.commands.execute_local(
            decision, proofs, mutation, event="files.metadata_read", target=path_digest
        )

    async def inspect_by_original_operation(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        path_digest: str,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> FilesReservationInspection:
        """A6 FilesInspect supplies original UUID/path, not reservation UUID.

        Lookup remains scoped to original owner SQL and status may be UNKNOWN.
        An absent quota row is not signed absence of a native write.
        """
        if (
            request.operation != "files.write.inspect"
            or len(path_digest) != 64
            or any(c not in "0123456789abcdef" for c in path_digest)
        ):
            raise InvalidInput("Files original inspect needs canonical path fingerprint")
        require_signed_payload(
            request,
            {
                "path_digest": path_digest,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        async with self.db.transaction() as tx:
            row = await tx.scalar(
                select(FileQuotaReservationRow)
                .where(
                    FileQuotaReservationRow.project_id == request.project_id,
                    FileQuotaReservationRow.operation_uuid == request.operation_uuid,
                    FileQuotaReservationRow.path_digest == path_digest,
                    FileQuotaReservationRow.owner_service_id == service_id,
                    FileQuotaReservationRow.actor_user_id == request.caller_user_id,
                    FileQuotaReservationRow.agent_session_uuid == request.session_uuid,
                )
                .with_for_update()
            )
            account = await tx.scalar(
                select(FileQuotaAccountRow).where(
                    FileQuotaAccountRow.project_id == request.project_id,
                )
            )
            if row is None or account is None:
                raise AccessDenied("original Files SQL status is unknown, not OS absence")
            return FilesReservationInspection(
                row.reservation_id,
                row.operation_uuid,
                row.status,
                row.version,
                account.reserved_bytes,
            )
