"""Files-owned quota reservation with no Control/Identity/Access SQL joins.

Every sensitive call requires current three-owner proofs and an independently
verified private Files peer. External file effects happen OUTSIDE transactions.
Unknown dispatched writes are never automatically retried or released.
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
from projects._file_quota_persistence import (
    FileObjectRow,
    FileQuotaAccountRow,
    FileQuotaReservationRow,
)


@dataclass(frozen=True, slots=True)
class VerifiedNativeFilesObservation:
    """Verified by native Files supervisor, not supplied by browser JSON."""

    reservation_id: UUID
    original_operation_uuid: UUID
    project_id: UUID
    service_id: UUID
    instance_uuid: UUID
    path_digest: str
    outcome: Literal["committed", "no_effect", "unknown"]
    observed_file_version: int
    observed_size_bytes: int
    content_sha256: str | None
    inode_digest: str | None
    confirmed_at: datetime


class TrustedFilesObservationPort(Protocol):
    def verify_observation(
        self, evidence: object, *, peer: VerifiedOwnerServicePeer
    ) -> VerifiedNativeFilesObservation:
        """Must check actual OS-root evidence and signed original effect ID."""
        ...


class FilesOwnerSource:
    def __init__(
        self,
        db: PlatformDatabase,
        commands: OwnerLocalCommandExecutor,
        authority: OwnerProofAuthority,
        current_owners: CurrentOwnerAuthorityPort,
        peer_verifier: TrustedOwnerServicePeerPort,
        observation_verifier: TrustedFilesObservationPort,
        *,
        idempotency_hmac_key: bytes,
    ) -> None:
        if db.engine.url.database != "briareus_files" or commands.owner != "files":
            raise RuntimeError("Files durable authority must use its own logical database")
        if (
            current_owners is None
            or peer_verifier is None
            or observation_verifier is None
            or len(idempotency_hmac_key) < 32
        ):
            raise RuntimeError("Files source owner requires current authority, peer and HMAC")
        self.db = db
        self.commands = commands
        self.authority = authority
        self.current_owners = current_owners
        self.peer_verifier = peer_verifier
        self.observation_verifier = observation_verifier
        self._idempotency_hmac_key = idempotency_hmac_key

    async def _current(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> VerifiedOwnerOperation:
        initial = self.authority.require_current(request, proofs)
        live = await require_online_owner_decision(self.authority, self.current_owners, request)
        if (
            initial.identity_epoch != live.identity_epoch
            or initial.control_epoch != live.control_epoch
            or initial.access_epoch != live.access_epoch
        ):
            raise AccessDenied("Files source owner revisions have changed")
        try:
            peer = self.peer_verifier.verify_peer(peer_evidence)
            if (
                peer.service_id != service_id
                or peer.instance_uuid != instance_uuid
                or peer.audience != "briareus:files"
                or peer.expires_at <= datetime.now(UTC)
            ):
                raise AccessDenied("Files service instance identity changed")
        except Exception:
            raise AccessDenied("trusted native Files service peer unavailable") from None
        if request.target_owner != "files":
            raise AccessDenied("Files operation addressed to foreign owner")
        return live

    async def reserve_write(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        service_id: UUID,
        instance_uuid: UUID,
        path_digest: str,
        content_sha256: str,
        planned_bytes: int,
        expected_file_version: int,
        ttl_seconds: int = 600,
    ) -> OwnerCommandOutcome:
        if (
            request.operation != "files.write.reserve"
            or not 0 <= planned_bytes <= 100_000_000_000_000
            or not expected_file_version >= 0
            or not 30 <= ttl_seconds <= 3600
            or service_id.version != 4
            or instance_uuid.version != 4
            or len(path_digest) != 64
            or len(content_sha256) != 64
            or any(c not in "0123456789abcdef" for c in path_digest + content_sha256)
        ):
            raise InvalidInput("Files write reservation bounds or signed identities invalid")
        require_signed_payload(
            request,
            {
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
                "path_digest": path_digest,
                "content_sha256": content_sha256,
                "planned_bytes": planned_bytes,
                "expected_file_version": expected_file_version,
                "ttl_seconds": ttl_seconds,
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        digest = hmac.new(
            self._idempotency_hmac_key, request.idempotency_key.encode(), hashlib.sha256
        ).hexdigest()

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            account = await tx.scalar(
                select(FileQuotaAccountRow)
                .where(FileQuotaAccountRow.project_id == request.project_id)
                .with_for_update()
            )
            if account is None or account.frozen:
                raise AccessDenied("Files quota unavailable or frozen for reconciliation")
            duplicate = await tx.scalar(
                select(FileQuotaReservationRow)
                .where(
                    FileQuotaReservationRow.project_id == request.project_id,
                    FileQuotaReservationRow.idempotency_digest == digest,
                )
                .with_for_update()
            )
            if duplicate is not None:
                # A previous dispatched/unknown effect is NEVER retried with
                # this key or a new UUID; status must be reconciled explicitly.
                if duplicate.operation_uuid != request.operation_uuid:
                    raise Conflict("Files key already belongs to another operation")
                raise Conflict("Files original reservation already exists; inspect status")
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
                raise Conflict("Files path has an unresolved write")
            existing = await tx.scalar(
                select(FileObjectRow)
                .where(
                    FileObjectRow.project_id == request.project_id,
                    FileObjectRow.path_digest == path_digest,
                )
                .with_for_update()
            )
            current_file_version = existing.version if existing is not None else 0
            if current_file_version != expected_file_version:
                raise Conflict("Files object revision changed")
            old_bytes = existing.size_bytes if existing is not None and not existing.deleted else 0
            needed = max(0, planned_bytes - old_bytes)
            if account.used_bytes + account.reserved_bytes + needed > account.byte_limit:
                raise Conflict("Files quota would be exceeded")
            epoch_revision = hashlib.sha256(
                f"{request.project_id}:{decision.control_epoch}:"
                f"{request.expected_control_revision}:"
                f"{request.expected_control_resource_revision}".encode()
            ).hexdigest()
            expiry = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
            reservation = FileQuotaReservationRow(
                reservation_id=uuid4(),
                operation_uuid=request.operation_uuid,
                project_id=request.project_id,
                agent_session_uuid=request.session_uuid,
                actor_user_id=request.caller_user_id,
                owner_service_id=service_id,
                path_digest=path_digest,
                idempotency_digest=digest,
                request_fingerprint=request.payload_sha256,
                expected_content_sha256=content_sha256,
                project_access_revision=epoch_revision,
                expected_file_version=expected_file_version,
                prior_bytes=old_bytes,
                planned_bytes=planned_bytes,
                reserved_delta=needed,
                status="reserved",
                version=1,
                expires_at=expiry,
            )
            tx.add(reservation)
            account.reserved_bytes += needed
            account.version += 1
            account.updated_at = datetime.now(UTC)
            return {
                "reservation_id": str(reservation.reservation_id),
                "operation_uuid": str(request.operation_uuid),
                "quota_version": account.version,
                "reserved_delta": needed,
                "status": "reserved",
                "expires_at": expiry.isoformat(),
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="files.bytes_reserved",
            target=str(request.project_id),
        )

    async def mark_dispatched(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        reservation_id: UUID,
        reservation_operation_uuid: UUID,
        expected_reservation_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """Commit the intent BEFORE R14 may perform any filesystem effect."""
        if (
            request.operation != "files.write.dispatch"
            or reservation_id.version != 4
            or reservation_operation_uuid.version != 4
            or expected_reservation_version < 1
        ):
            raise InvalidInput("Files dispatch requires original reservation identity")
        require_signed_payload(
            request,
            {
                "reservation_id": str(reservation_id),
                "reservation_operation_uuid": str(reservation_operation_uuid),
                "expected_reservation_version": expected_reservation_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            row = await tx.scalar(
                select(FileQuotaReservationRow)
                .where(FileQuotaReservationRow.reservation_id == reservation_id)
                .with_for_update()
            )
            if (
                row is None
                or row.project_id != request.project_id
                or row.agent_session_uuid != request.session_uuid
                or row.actor_user_id != request.caller_user_id
                or row.operation_uuid != reservation_operation_uuid
                or row.owner_service_id != service_id
                or row.version != expected_reservation_version
                or row.status != "reserved"
                or row.expires_at <= datetime.now(UTC)
            ):
                raise AccessDenied("Files original reservation is not dispatchable")
            row.status = "dispatched"
            row.dispatched_at = datetime.now(UTC)
            row.version += 1
            return {
                "reservation_id": str(row.reservation_id),
                "operation_uuid": str(row.operation_uuid),
                "reservation_version": row.version,
                "status": "dispatched",
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="files.write_dispatched",
            target=str(reservation_id),
        )

    async def reconcile_write(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        native_evidence: object,
        *,
        reservation_id: UUID,
        reservation_operation_uuid: UUID,
        expected_reservation_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """Only a signed Files OS observation may settle uncertain file effects."""
        if (
            request.operation not in {"files.write.reconcile", "files.write.finalize"}
            or reservation_id.version != 4
            or reservation_operation_uuid.version != 4
            or expected_reservation_version < 1
        ):
            raise InvalidInput("Files reconcile requires original stable reservation")
        decision = await self._current(
            request,
            proofs,
            peer_evidence,
            service_id=service_id,
            instance_uuid=instance_uuid,
        )
        try:
            peer = self.peer_verifier.verify_peer(peer_evidence)
            verified = self.observation_verifier.verify_observation(native_evidence, peer=peer)
        except Exception:
            raise AccessDenied("native Files receipt and OS-root attestation unavailable") from None
        if (
            verified.reservation_id != reservation_id
            or verified.original_operation_uuid != reservation_operation_uuid
            or verified.project_id != request.project_id
            or verified.service_id != service_id
            or verified.instance_uuid != instance_uuid
            or verified.observed_file_version < 0
            or not 0 <= verified.observed_size_bytes <= 100_000_000_000_000
            or verified.confirmed_at.tzinfo is None
            or not timedelta(0) <= datetime.now(UTC) - verified.confirmed_at <= timedelta(minutes=2)
            or len(verified.path_digest) != 64
            or any(c not in "0123456789abcdef" for c in verified.path_digest)
        ):
            raise AccessDenied("Files observation not current or bound to original operation")
        for digest in (verified.content_sha256, verified.inode_digest):
            if digest is not None and (
                len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
            ):
                raise AccessDenied("Files native evidence digest invalid")
        require_signed_payload(
            request,
            {
                "reservation_id": str(reservation_id),
                "reservation_operation_uuid": str(reservation_operation_uuid),
                "expected_reservation_version": expected_reservation_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
                "observation": {
                    "path_digest": verified.path_digest,
                    "outcome": verified.outcome,
                    "observed_file_version": verified.observed_file_version,
                    "observed_size_bytes": verified.observed_size_bytes,
                    "content_sha256": verified.content_sha256,
                    "inode_digest": verified.inode_digest,
                    "confirmed_at": verified.confirmed_at.isoformat(),
                },
            },
        )

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            account = await tx.scalar(
                select(FileQuotaAccountRow)
                .where(FileQuotaAccountRow.project_id == request.project_id)
                .with_for_update()
            )
            row = await tx.scalar(
                select(FileQuotaReservationRow)
                .where(FileQuotaReservationRow.reservation_id == reservation_id)
                .with_for_update()
            )
            if (
                account is None
                or row is None
                or row.project_id != request.project_id
                or row.agent_session_uuid != request.session_uuid
                or row.actor_user_id != request.caller_user_id
                or row.owner_service_id != service_id
                or row.operation_uuid != reservation_operation_uuid
                or row.version != expected_reservation_version
                or row.status not in {"dispatched", "unknown"}
                or row.path_digest != verified.path_digest
            ):
                raise AccessDenied("Files reservation cannot be reconciled at this revision")
            now = datetime.now(UTC)
            if verified.outcome == "unknown":
                # Never remove the reserved bytes or assume a failed write.
                row.status = "unknown"
                account.frozen = True
            else:
                observed = await tx.scalar(
                    select(FileObjectRow)
                    .where(
                        FileObjectRow.project_id == request.project_id,
                        FileObjectRow.path_digest == row.path_digest,
                    )
                    .with_for_update()
                )
                prior_version = observed.version if observed is not None else 0
                if prior_version != row.expected_file_version:
                    raise Conflict("Files known-good file version changed during reconciliation")
                if verified.outcome == "committed":
                    if (
                        verified.observed_file_version != row.expected_file_version + 1
                        or verified.observed_size_bytes != row.planned_bytes
                        or verified.content_sha256 != row.expected_content_sha256
                        or verified.inode_digest is None
                    ):
                        raise AccessDenied("native Files write proof contradicts original intent")
                    new_used = account.used_bytes - row.prior_bytes + verified.observed_size_bytes
                    if new_used < 0 or new_used > account.byte_limit:
                        raise Conflict("Files committed byte reconciliation violates quota")
                    if observed is None:
                        observed = FileObjectRow(
                            id=uuid4(),
                            project_id=request.project_id,
                            path_digest=row.path_digest,
                            version=1,
                            size_bytes=verified.observed_size_bytes,
                            inode_digest=verified.inode_digest,
                            content_sha256=verified.content_sha256,
                            deleted=False,
                            confirmed_at=verified.confirmed_at,
                        )
                        tx.add(observed)
                    else:
                        observed.version = verified.observed_file_version
                        observed.size_bytes = verified.observed_size_bytes
                        observed.inode_digest = verified.inode_digest
                        observed.content_sha256 = verified.content_sha256
                        observed.deleted = False
                        observed.confirmed_at = verified.confirmed_at
                    account.used_bytes = new_used
                    row.status = "committed"
                else:
                    if (
                        verified.outcome != "no_effect"
                        or verified.observed_file_version != row.expected_file_version
                        or verified.observed_size_bytes != row.prior_bytes
                        or (
                            observed is not None
                            and (
                                observed.inode_digest is None
                                or verified.inode_digest != observed.inode_digest
                                or verified.content_sha256 != observed.content_sha256
                            )
                        )
                        or (
                            observed is None
                            and (
                                verified.inode_digest is not None
                                or verified.content_sha256 is not None
                            )
                        )
                    ):
                        raise AccessDenied("native Files no-effect evidence contradicts prior file")
                    row.status = "released"
                if account.reserved_bytes < row.reserved_delta:
                    raise Conflict("Files byte reservation accounting underflow")
                account.reserved_bytes -= row.reserved_delta
                row.resolved_at = now
                row.observed_file_version = verified.observed_file_version
                row.observed_size_bytes = verified.observed_size_bytes
                row.observed_inode_digest = verified.inode_digest
            row.version += 1
            account.version += 1
            account.updated_at = now
            return {
                "reservation_id": str(row.reservation_id),
                "reservation_version": row.version,
                "quota_version": account.version,
                "status": row.status,
                "reserved_bytes": account.reserved_bytes,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="files.write_reconciled",
            target=str(reservation_id),
        )

    async def configure_quota(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        service_id: UUID,
        instance_uuid: UUID,
        byte_limit: int,
        expected_quota_version: int | None,
    ) -> OwnerCommandOutcome:
        """Identity-superuser-authorized quota changes, no Control SQL join."""
        if (
            request.operation != "files.quota.configure"
            or not 0 <= byte_limit <= 100_000_000_000_000
            or (expected_quota_version is not None and expected_quota_version < 1)
        ):
            raise InvalidInput("Files quota policy command invalid")
        require_signed_payload(
            request,
            {
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
                "byte_limit": byte_limit,
                "expected_quota_version": expected_quota_version,
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        if decision.actor_role != "superuser":
            raise AccessDenied("current verified Identity superuser required")

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            row = await tx.scalar(
                select(FileQuotaAccountRow)
                .where(FileQuotaAccountRow.project_id == request.project_id)
                .with_for_update()
            )
            if row is None:
                if expected_quota_version is not None:
                    raise Conflict("Files quota account does not exist at expected revision")
                row = FileQuotaAccountRow(
                    project_id=request.project_id,
                    byte_limit=byte_limit,
                    used_bytes=0,
                    reserved_bytes=0,
                    frozen=False,
                    version=1,
                )
                tx.add(row)
            else:
                if row.version != expected_quota_version:
                    raise Conflict("Files quota owner revision mismatch")
                row.byte_limit = byte_limit
                if row.used_bytes + row.reserved_bytes > byte_limit:
                    row.frozen = True
                row.version += 1
                row.updated_at = datetime.now(UTC)
            return {
                "project_id": str(request.project_id),
                "quota_version": row.version,
                "byte_limit": row.byte_limit,
                "frozen": row.frozen,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="files.quota_configured",
            target=str(request.project_id),
        )
