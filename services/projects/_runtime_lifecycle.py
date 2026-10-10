"""Runtime owner-local job completion, uncertainty, undispatched cancel and inspect.

SQL can prove reservation/dispatch/revision, never native process execution.
Native finish/failure is stored only with an independently verified OS owner
observation and the ORIGINAL persisted lease nonce. No busy retries, no new
idempotency key, no fabricated cgroup status when the supervisor is absent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from common.owner_contracts import OwnerCommandDTO, SignedOwnerProofs, require_signed_payload
from common.owner_transactions import OwnerCommandOutcome
from common.platform_errors import AccessDenied, InvalidInput
from projects._runtime_persistence import RuntimeJobRow, RuntimeSessionRow
from projects._runtime_source import RuntimeOwnerSource


@dataclass(frozen=True, slots=True)
class RuntimeJobInspection:
    job_uuid: UUID
    runtime_session_uuid: UUID
    original_queue_operation: str
    original_lease_nonce: UUID
    status: str
    version: int
    hard_expires_at: datetime
    result_digest: str | None
    # A database row is a reported state; it does not attest OS liveness.
    native_process_verified: bool = False
    reconciliation_required: bool = True


class RuntimeOwnerLifecycle(RuntimeOwnerSource):
    async def _job(
        self,
        tx: AsyncSession,
        *,
        request: OwnerCommandDTO,
        job_uuid: UUID,
        runtime_session_uuid: UUID,
        original_nonce: UUID,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> RuntimeJobRow:
        row = await tx.scalar(
            select(RuntimeJobRow)
            .where(
                RuntimeJobRow.job_uuid == job_uuid,
            )
            .with_for_update()
        )
        session = await tx.scalar(
            select(RuntimeSessionRow)
            .where(
                RuntimeSessionRow.runtime_session_uuid == runtime_session_uuid,
            )
            .with_for_update()
        )
        if (
            row is None
            or session is None
            or row.runtime_session_uuid != runtime_session_uuid
            or row.project_id != request.project_id
            or row.actor_user_id != request.caller_user_id
            or row.agent_session_uuid != request.session_uuid
            or row.owner_service_id != service_id
            or row.lease_nonce != original_nonce
            or session.project_id != request.project_id
            or session.actor_user_id != request.caller_user_id
            or session.agent_session_uuid != request.session_uuid
            or session.owner_service_id != service_id
            or session.owner_instance != instance_uuid
        ):
            raise AccessDenied("Runtime original job/lease scope is not authoritative")
        return row

    async def mark_job_unknown(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        job_uuid: UUID,
        runtime_session_uuid: UUID,
        original_lease_nonce: UUID,
        expected_job_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        if (
            request.operation != "runtime.job.mark_unknown"
            or any(
                value.version != 4
                for value in (job_uuid, runtime_session_uuid, original_lease_nonce)
            )
            or expected_job_version < 1
        ):
            raise InvalidInput("Runtime unknown requires original Job/nonce/CAS")
        require_signed_payload(
            request,
            {
                "job_uuid": str(job_uuid),
                "runtime_session_uuid": str(runtime_session_uuid),
                "original_lease_nonce": str(original_lease_nonce),
                "expected_job_version": expected_job_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )

        async def mutate(tx: AsyncSession) -> dict[str, object]:
            row = await self._job(
                tx,
                request=request,
                job_uuid=job_uuid,
                runtime_session_uuid=runtime_session_uuid,
                original_nonce=original_lease_nonce,
                service_id=service_id,
                instance_uuid=instance_uuid,
            )
            if row.status not in {"running", "unknown"} or row.version != expected_job_version:
                raise AccessDenied("Runtime UNKNOWN cannot undo or replay a completed Job")
            row.status = "unknown"
            row.version += 1
            return {
                "job_uuid": str(row.job_uuid),
                "status": "unknown",
                "version": row.version,
                "original_lease_nonce": str(original_lease_nonce),
                "reconciliation_required": True,
                "native_process_verified": False,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutate,
            event="runtime.job_unknown",
            target=str(job_uuid),
        )

    async def cancel_undispatched_job(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        job_uuid: UUID,
        runtime_session_uuid: UUID,
        original_lease_nonce: UUID,
        expected_job_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        if (
            request.operation != "runtime.job.cancel"
            or any(
                value.version != 4
                for value in (job_uuid, runtime_session_uuid, original_lease_nonce)
            )
            or expected_job_version < 1
        ):
            raise InvalidInput("Runtime cancel requires an undispatched Job CAS")
        require_signed_payload(
            request,
            {
                "job_uuid": str(job_uuid),
                "runtime_session_uuid": str(runtime_session_uuid),
                "original_lease_nonce": str(original_lease_nonce),
                "expected_job_version": expected_job_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )

        async def mutate(tx: AsyncSession) -> dict[str, object]:
            row = await self._job(
                tx,
                request=request,
                job_uuid=job_uuid,
                runtime_session_uuid=runtime_session_uuid,
                original_nonce=original_lease_nonce,
                service_id=service_id,
                instance_uuid=instance_uuid,
            )
            if (
                row.version != expected_job_version
                or row.status != "queued"
                or row.started_at is not None
            ):
                raise AccessDenied("dispatched native Runtime Job cannot be SQL-cancelled")
            row.status = "cancelled"
            row.version += 1
            row.resolved_at = datetime.now(UTC)
            return {
                "job_uuid": str(row.job_uuid),
                "status": "cancelled",
                "version": row.version,
                "native_process_verified": False,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutate,
            event="runtime.undispatched_cancelled",
            target=str(job_uuid),
        )

    async def reconcile_native_job(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        native_evidence: object,
        *,
        job_uuid: UUID,
        runtime_session_uuid: UUID,
        original_lease_nonce: UUID,
        expected_job_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        if (
            request.operation != "runtime.job.reconcile"
            or any(
                value.version != 4
                for value in (job_uuid, runtime_session_uuid, original_lease_nonce)
            )
            or expected_job_version < 1
        ):
            raise InvalidInput("Runtime native reconcile must bind original Job nonce")
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        try:
            peer = self.peer_verifier.verify_peer(peer_evidence)
            native = self.job_observer.verify_job_effect(native_evidence, peer=peer)
        except Exception:
            raise AccessDenied("signed Runtime native supervisor evidence unavailable") from None
        if (
            native.job_uuid != job_uuid
            or native.runtime_session_uuid != runtime_session_uuid
            or native.project_id != request.project_id
            or native.owner_service_id != service_id
            or native.owner_instance != instance_uuid
            or native.lease_nonce != original_lease_nonce
            or native.observed_at.tzinfo is None
            or native.observed_at > datetime.now(UTC)
            or datetime.now(UTC) - native.observed_at > timedelta(minutes=2)
            or len(native.native_scope_digest) != 64
            or any(c not in "0123456789abcdef" for c in native.native_scope_digest)
            or (
                native.outcome == "succeeded"
                and (
                    native.result_sha256 is None
                    or len(native.result_sha256) != 64
                    or any(c not in "0123456789abcdef" for c in native.result_sha256)
                )
            )
            or (native.outcome != "succeeded" and native.result_sha256 is not None)
        ):
            raise AccessDenied("Runtime native observation contradicts original job/lease")
        require_signed_payload(
            request,
            {
                "job_uuid": str(job_uuid),
                "runtime_session_uuid": str(runtime_session_uuid),
                "original_lease_nonce": str(original_lease_nonce),
                "expected_job_version": expected_job_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
                "native_observation": {
                    "outcome": native.outcome,
                    "result_sha256": native.result_sha256,
                    "native_scope_digest": native.native_scope_digest,
                    "observed_at": native.observed_at.isoformat(),
                },
            },
        )

        async def mutate(tx: AsyncSession) -> dict[str, object]:
            row = await self._job(
                tx,
                request=request,
                job_uuid=job_uuid,
                runtime_session_uuid=runtime_session_uuid,
                original_nonce=original_lease_nonce,
                service_id=service_id,
                instance_uuid=instance_uuid,
            )
            if row.version != expected_job_version or row.status not in {"running", "unknown"}:
                raise AccessDenied("Runtime original Job outcome not pending reconciliation")
            if native.observed_at < row.created_at:
                raise AccessDenied("Runtime OS observation predates original job")
            row.status = native.outcome
            row.version += 1
            if native.outcome != "unknown":
                row.resolved_at = datetime.now(UTC)
                row.result_digest = native.result_sha256
            return {
                "job_uuid": str(row.job_uuid),
                "status": row.status,
                "version": row.version,
                "result_digest": row.result_digest,
                "reconciliation_required": row.status == "unknown",
                "native_process_verified": native.outcome != "unknown",
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutate,
            event="runtime.native_job_reconciled",
            target=str(job_uuid),
        )

    async def inspect_job(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        job_uuid: UUID,
        runtime_session_uuid: UUID,
        original_lease_nonce: UUID,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> RuntimeJobInspection:
        if request.operation != "runtime.job.inspect" or any(
            value.version != 4 for value in (job_uuid, runtime_session_uuid, original_lease_nonce)
        ):
            raise InvalidInput("Runtime inspect requires original job UUID/lease")
        require_signed_payload(
            request,
            {
                "job_uuid": str(job_uuid),
                "runtime_session_uuid": str(runtime_session_uuid),
                "original_lease_nonce": str(original_lease_nonce),
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        async with self.db.transaction() as tx:
            row = await self._job(
                tx,
                request=request,
                job_uuid=job_uuid,
                runtime_session_uuid=runtime_session_uuid,
                original_nonce=original_lease_nonce,
                service_id=service_id,
                instance_uuid=instance_uuid,
            )
            return RuntimeJobInspection(
                job_uuid=row.job_uuid,
                runtime_session_uuid=row.runtime_session_uuid,
                original_queue_operation=row.operation,
                original_lease_nonce=original_lease_nonce,
                status=row.status,
                version=row.version,
                hard_expires_at=row.hard_expires_at,
                result_digest=row.result_digest,
            )
