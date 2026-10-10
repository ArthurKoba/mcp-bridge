"""Runtime durable lease authority, separate from Control/Access and native OS.

Never starts a process, allocates a filesystem root or infers OS cleanup from
SQL status. R14 independently verifies native ownership before effectful calls.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, cast
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
from projects._runtime_persistence import RuntimeJobRow, RuntimeSessionRow

Kind = Literal["files", "terminal", "web_managed", "web_remote", "reverse"]
_ALLOWED_KINDS: frozenset[str] = frozenset(
    {"files", "terminal", "web_managed", "web_remote", "reverse"}
)


@dataclass(frozen=True, slots=True)
class OwnerRuntimeLeaseClaim:
    runtime_session_uuid: UUID
    owner_service_id: UUID
    owner_instance: UUID
    project_id: UUID
    caller_user_id: UUID
    agent_session_uuid: UUID
    lease_nonce: UUID
    kind: Kind
    version: int
    lease_expires_at: datetime
    hard_expires_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedRuntimeStopped:
    runtime_session_uuid: UUID
    project_id: UUID
    previous_owner_service_id: UUID
    previous_instance_uuid: UUID
    lease_nonce: UUID
    observed_stopped_at: datetime
    native_scope_digest: str


class TrustedRuntimeCleanupVerifier(Protocol):
    def verify_stopped(
        self, evidence: object, *, supervisor_peer: VerifiedOwnerServicePeer
    ) -> VerifiedRuntimeStopped:
        """Must verify signed OS process/cgroup-owner evidence, not row status."""
        ...


@dataclass(frozen=True, slots=True)
class VerifiedRuntimeJobObservation:
    job_uuid: UUID
    runtime_session_uuid: UUID
    project_id: UUID
    owner_service_id: UUID
    owner_instance: UUID
    lease_nonce: UUID
    outcome: Literal["succeeded", "failed", "unknown"]
    result_sha256: str | None
    native_scope_digest: str
    observed_at: datetime


class TrustedRuntimeJobObserver(Protocol):
    def verify_job_effect(
        self, evidence: object, *, peer: VerifiedOwnerServicePeer
    ) -> VerifiedRuntimeJobObservation:
        """Only native OS process-owner proof can settle an external job."""
        ...


class TrustedOwnerRuntimeLeaseSigner(Protocol):
    def sign(self, claim: OwnerRuntimeLeaseClaim) -> str:
        """Produce verified-release Ed25519 JWS for a fenced owner lease."""
        ...


class RuntimeOwnerSource:
    def __init__(
        self,
        db: PlatformDatabase,
        commands: OwnerLocalCommandExecutor,
        authority: OwnerProofAuthority,
        current_owners: CurrentOwnerAuthorityPort,
        peer_verifier: TrustedOwnerServicePeerPort,
        lease_signer: TrustedOwnerRuntimeLeaseSigner,
        cleanup_verifier: TrustedRuntimeCleanupVerifier,
        job_observer: TrustedRuntimeJobObserver,
        *,
        idempotency_hmac_key: bytes,
    ) -> None:
        if db.engine.url.database != "briareus_runtime" or commands.owner != "runtime":
            raise RuntimeError("Runtime must have an independent durable owner database")
        if (
            current_owners is None
            or peer_verifier is None
            or lease_signer is None
            or cleanup_verifier is None
            or job_observer is None
            or len(idempotency_hmac_key) < 32
        ):
            raise RuntimeError("Runtime current owner proof, peer and lease signer required")
        self.db = db
        self.commands = commands
        self.authority = authority
        self.current_owners = current_owners
        self.peer_verifier = peer_verifier
        self.lease_signer = lease_signer
        self.cleanup_verifier = cleanup_verifier
        self.job_observer = job_observer
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
        initial = self.authority.require_current(request, proofs)
        live = await require_online_owner_decision(self.authority, self.current_owners, request)
        if (
            initial.identity_epoch != live.identity_epoch
            or initial.control_epoch != live.control_epoch
            or initial.access_epoch != live.access_epoch
        ):
            raise AccessDenied("Runtime owner authorization epoch changed")
        try:
            peer = self.peer_verifier.verify_peer(peer_evidence)
            if (
                peer.service_id != service_id
                or peer.instance_uuid != instance_uuid
                or peer.audience != "briareus:runtime"
                or peer.expires_at <= datetime.now(UTC)
            ):
                raise AccessDenied("Runtime service peer identity mismatch")
        except Exception:
            raise AccessDenied("verified native Runtime service peer required") from None
        if request.target_owner != "runtime":
            raise AccessDenied("wrong owner for Runtime effect")
        return live

    def _receipt(self, row: RuntimeSessionRow) -> str:
        if row.status != "active" or row.lease_expires_at <= datetime.now(UTC):
            raise AccessDenied("Runtime owner lease expired or revoked")
        if row.kind not in _ALLOWED_KINDS:
            raise AccessDenied("unrecognized Runtime session kind")
        claim = OwnerRuntimeLeaseClaim(
            runtime_session_uuid=row.runtime_session_uuid,
            project_id=row.project_id,
            caller_user_id=row.actor_user_id,
            agent_session_uuid=row.agent_session_uuid,
            owner_service_id=row.owner_service_id,
            owner_instance=row.owner_instance,
            lease_nonce=row.lease_nonce,
            kind=cast(Kind, row.kind),
            version=row.version,
            lease_expires_at=row.lease_expires_at,
            hard_expires_at=row.hard_expires_at,
        )
        return self.lease_signer.sign(claim)

    async def open_runtime(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        runtime_session_uuid: UUID,
        service_id: UUID,
        instance_uuid: UUID,
        kind: Kind,
        idle_ttl_seconds: int,
        hard_ttl_seconds: int,
    ) -> OwnerCommandOutcome:
        if (
            request.operation != "runtime.session.open"
            or runtime_session_uuid.version != 4
            or kind not in _ALLOWED_KINDS
            or not 30 <= idle_ttl_seconds <= 86400
            or not idle_ttl_seconds <= hard_ttl_seconds <= 86400
        ):
            raise InvalidInput("Runtime lease type or TTL invalid")
        require_signed_payload(
            request,
            {
                "runtime_session_uuid": str(runtime_session_uuid),
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
                "kind": kind,
                "idle_ttl_seconds": idle_ttl_seconds,
                "hard_ttl_seconds": hard_ttl_seconds,
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        digest = hmac.new(self._key, request.idempotency_key.encode(), hashlib.sha256).hexdigest()

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            if await tx.get(RuntimeSessionRow, runtime_session_uuid) is not None:
                raise Conflict("Runtime session identity already allocated")
            now = datetime.now(UTC)
            hard = now + timedelta(seconds=hard_ttl_seconds)
            row = RuntimeSessionRow(
                runtime_session_uuid=runtime_session_uuid,
                project_id=request.project_id,
                agent_session_uuid=request.session_uuid,
                actor_user_id=request.caller_user_id,
                kind=kind,
                owner_service_id=service_id,
                owner_instance=instance_uuid,
                open_idempotency_digest=digest,
                open_request_fingerprint=request.payload_sha256,
                lease_nonce=uuid4(),
                status="active",
                version=1,
                cleanup_state="not_needed",
                idle_ttl_seconds=idle_ttl_seconds,
                created_at=now,
                last_heartbeat_at=now,
                idle_expires_at=now + timedelta(seconds=idle_ttl_seconds),
                hard_expires_at=hard,
                lease_expires_at=min(now + timedelta(seconds=30), hard),
            )
            tx.add(row)
            return {
                "runtime_session_uuid": str(row.runtime_session_uuid),
                "lease_nonce": str(row.lease_nonce),
                "lease_version": row.version,
                "lease_expires_at": row.lease_expires_at.isoformat(),
                "owner_jws": self._receipt(row),
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="runtime.session_opened",
            target=str(runtime_session_uuid),
        )

    async def renew_runtime(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        runtime_session_uuid: UUID,
        expected_version: int,
        expected_lease_nonce: UUID,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        if (
            request.operation != "runtime.session.renew"
            or runtime_session_uuid.version != 4
            or expected_lease_nonce.version != 4
            or expected_version < 1
        ):
            raise InvalidInput("Runtime lease renewal requires version and nonce")
        require_signed_payload(
            request,
            {
                "runtime_session_uuid": str(runtime_session_uuid),
                "expected_version": expected_version,
                "expected_lease_nonce": str(expected_lease_nonce),
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            row = await tx.scalar(
                select(RuntimeSessionRow)
                .where(RuntimeSessionRow.runtime_session_uuid == runtime_session_uuid)
                .with_for_update()
            )
            now = datetime.now(UTC)
            if (
                row is None
                or row.project_id != request.project_id
                or row.agent_session_uuid != request.session_uuid
                or row.actor_user_id != request.caller_user_id
                or row.owner_service_id != service_id
                or row.owner_instance != instance_uuid
                or row.version != expected_version
                or row.lease_nonce != expected_lease_nonce
                or row.status != "active"
                or row.idle_expires_at <= now
                or row.hard_expires_at <= now
                or row.lease_expires_at <= now
            ):
                raise AccessDenied("Runtime session lease expired, revoked or replaced")
            row.version += 1
            row.lease_nonce = uuid4()
            row.last_heartbeat_at = now
            row.idle_expires_at = min(
                now + timedelta(seconds=row.idle_ttl_seconds), row.hard_expires_at
            )
            row.lease_expires_at = min(now + timedelta(seconds=30), row.hard_expires_at)
            return {
                "runtime_session_uuid": str(row.runtime_session_uuid),
                "lease_nonce": str(row.lease_nonce),
                "lease_version": row.version,
                "lease_expires_at": row.lease_expires_at.isoformat(),
                "owner_jws": self._receipt(row),
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="runtime.lease_renewed",
            target=str(runtime_session_uuid),
        )

    async def revoke_runtime(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        runtime_session_uuid: UUID,
        expected_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        if (
            request.operation != "runtime.session.revoke"
            or runtime_session_uuid.version != 4
            or expected_version < 1
        ):
            raise InvalidInput("Runtime revoke needs original owner revision")
        require_signed_payload(
            request,
            {
                "runtime_session_uuid": str(runtime_session_uuid),
                "expected_version": expected_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            row = await tx.scalar(
                select(RuntimeSessionRow)
                .where(RuntimeSessionRow.runtime_session_uuid == runtime_session_uuid)
                .with_for_update()
            )
            if (
                row is None
                or row.project_id != request.project_id
                or row.agent_session_uuid != request.session_uuid
                or row.actor_user_id != request.caller_user_id
                or row.owner_service_id != service_id
                or row.owner_instance != instance_uuid
                or row.version != expected_version
                or row.status != "active"
            ):
                raise AccessDenied("Runtime lease already replaced or revoked")
            now = datetime.now(UTC)
            row.status = "revoked"
            row.cleanup_state = "pending"
            # Keep last nonce for attested native cleanup. Current version and
            # revoked status fence every previously signed owner lease JWS.
            row.version += 1
            row.lease_expires_at = now
            row.ended_at = now
            return {
                "runtime_session_uuid": str(row.runtime_session_uuid),
                "lease_version": row.version,
                "status": row.status,
                "cleanup_state": "pending",  # OS process is NOT proven stopped
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="runtime.cleanup_requested",
            target=str(runtime_session_uuid),
        )

    async def confirm_cleanup(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        native_evidence: object,
        *,
        runtime_session_uuid: UUID,
        previous_lease_nonce: UUID,
        expected_version: int,
        previous_service_id: UUID,
        previous_instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """Only independently signed supervisor proof can close OS cleanup."""
        if (
            request.operation != "runtime.cleanup.confirm"
            or runtime_session_uuid.version != 4
            or previous_lease_nonce.version != 4
            or expected_version < 1
        ):
            raise InvalidInput("Runtime cleanup requires original lease revision and nonce")
        initial = self.authority.require_current(request, proofs)
        live = await require_online_owner_decision(self.authority, self.current_owners, request)
        if (
            initial.identity_epoch != live.identity_epoch
            or initial.control_epoch != live.control_epoch
            or initial.access_epoch != live.access_epoch
        ):
            raise AccessDenied("Runtime cleanup rights changed")
        try:
            supervisor = self.peer_verifier.verify_peer(peer_evidence)
            if supervisor.audience != "briareus:runtime":
                raise AccessDenied("Runtime cleanup supervisor has wrong audience")
            evidence = self.cleanup_verifier.verify_stopped(
                native_evidence, supervisor_peer=supervisor
            )
        except Exception:
            raise AccessDenied("trusted Runtime OS cleanup attestation absent") from None
        if (
            evidence.runtime_session_uuid != runtime_session_uuid
            or evidence.project_id != request.project_id
            or evidence.previous_owner_service_id != previous_service_id
            or evidence.previous_instance_uuid != previous_instance_uuid
            or evidence.lease_nonce != previous_lease_nonce
            or evidence.observed_stopped_at.tzinfo is None
            or evidence.observed_stopped_at > datetime.now(UTC)
            or datetime.now(UTC) - evidence.observed_stopped_at > timedelta(minutes=2)
            or len(evidence.native_scope_digest) != 64
            or any(c not in "0123456789abcdef" for c in evidence.native_scope_digest)
        ):
            raise AccessDenied("native Runtime cleanup evidence is not current or scoped")
        require_signed_payload(
            request,
            {
                "runtime_session_uuid": str(runtime_session_uuid),
                "previous_lease_nonce": str(previous_lease_nonce),
                "expected_version": expected_version,
                "previous_service_id": str(previous_service_id),
                "previous_instance_uuid": str(previous_instance_uuid),
                "supervisor_service_id": str(supervisor.service_id),
                "supervisor_instance_uuid": str(supervisor.instance_uuid),
                "observed_stopped_at": evidence.observed_stopped_at.isoformat(),
                "native_scope_digest": evidence.native_scope_digest,
            },
        )

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            row = await tx.scalar(
                select(RuntimeSessionRow)
                .where(RuntimeSessionRow.runtime_session_uuid == runtime_session_uuid)
                .with_for_update()
            )
            if (
                row is None
                or row.project_id != request.project_id
                or row.agent_session_uuid != request.session_uuid
                or row.owner_service_id != previous_service_id
                or row.owner_instance != previous_instance_uuid
                or row.lease_nonce != previous_lease_nonce
                or row.version != expected_version
                or row.status not in {"revoked", "lost", "expired", "closed"}
                or row.cleanup_state not in {"pending", "unknown"}
            ):
                raise AccessDenied("Runtime previous owner/lease not pending cleanup")
            if evidence.observed_stopped_at < row.created_at:
                raise AccessDenied("Runtime stop evidence predates the owned session")
            row.status = "closed"
            row.cleanup_state = "confirmed"
            row.lease_expires_at = min(row.lease_expires_at, datetime.now(UTC))
            row.version += 1
            row.ended_at = evidence.observed_stopped_at
            return {
                "runtime_session_uuid": str(row.runtime_session_uuid),
                "cleanup_state": row.cleanup_state,
                "status": row.status,
                "version": row.version,
                "confirmed_stopped_at": evidence.observed_stopped_at.isoformat(),
            }

        return await self.commands.execute_local(
            live,
            proofs,
            mutation,
            event="runtime.cleanup_confirmed",
            target=str(runtime_session_uuid),
        )

    async def queue_job(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        runtime_session_uuid: UUID,
        expected_lease_version: int,
        expected_lease_nonce: UUID,
        service_id: UUID,
        instance_uuid: UUID,
        payload_sha256: str,
        hard_ttl_seconds: int = 900,
    ) -> OwnerCommandOutcome:
        """Durably reserve a native effect; never execute OS side effect here."""
        kind_ops = {
            "terminal": "runtime.terminal.job.queue",
            "web_managed": "runtime.web.job.queue",
            "web_remote": "runtime.web.job.queue",
            "reverse": "runtime.reverse.job.queue",
        }
        if (
            request.operation not in kind_ops.values()
            or runtime_session_uuid.version != 4
            or expected_lease_nonce.version != 4
            or expected_lease_version < 1
            or not 1 <= hard_ttl_seconds <= 3600
            or len(payload_sha256) != 64
            or any(c not in "0123456789abcdef" for c in payload_sha256)
        ):
            raise InvalidInput("Runtime job intent invalid or not an allowed owner operation")
        require_signed_payload(
            request,
            {
                "runtime_session_uuid": str(runtime_session_uuid),
                "expected_lease_version": expected_lease_version,
                "expected_lease_nonce": str(expected_lease_nonce),
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
                "payload_sha256": payload_sha256,
                "hard_ttl_seconds": hard_ttl_seconds,
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )
        digest = hmac.new(self._key, request.idempotency_key.encode(), hashlib.sha256).hexdigest()

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            session = await tx.scalar(
                select(RuntimeSessionRow)
                .where(RuntimeSessionRow.runtime_session_uuid == runtime_session_uuid)
                .with_for_update()
            )
            now = datetime.now(UTC)
            if (
                session is None
                or session.project_id != request.project_id
                or session.agent_session_uuid != request.session_uuid
                or session.actor_user_id != request.caller_user_id
                or session.owner_service_id != service_id
                or session.owner_instance != instance_uuid
                or session.version != expected_lease_version
                or session.lease_nonce != expected_lease_nonce
                or session.status != "active"
                or session.hard_expires_at <= now
                or session.lease_expires_at <= now
                or session.idle_expires_at <= now
                or kind_ops.get(session.kind) != request.operation
            ):
                raise AccessDenied("Runtime job requires matching active owner lease and kind")
            # A different in-flight or UNKNOWN native job in the same owner
            # scope cannot be silently overwritten by a new operation UUID.
            active_job = await tx.scalar(
                select(RuntimeJobRow.job_uuid)
                .where(
                    RuntimeJobRow.runtime_session_uuid == runtime_session_uuid,
                    RuntimeJobRow.status.in_(("queued", "running", "unknown")),
                )
                .limit(1)
                .with_for_update()
            )
            if active_job is not None:
                raise Conflict("Runtime has an unresolved native effect; reconcile original UUID")
            job = RuntimeJobRow(
                job_uuid=request.operation_uuid,
                runtime_session_uuid=runtime_session_uuid,
                # runtime_0002 was added exactly to preserve original nonce;
                # a newly queued job must NEVER have an inferred NULL nonce.
                lease_nonce=expected_lease_nonce,
                project_id=request.project_id,
                owner_service_id=service_id,
                actor_user_id=request.caller_user_id,
                agent_session_uuid=request.session_uuid,
                idempotency_digest=digest,
                request_fingerprint=request.payload_sha256,
                operation=request.operation,
                status="queued",
                version=1,
                created_at=now,
                hard_expires_at=min(
                    session.hard_expires_at, now + timedelta(seconds=hard_ttl_seconds)
                ),
            )
            tx.add(job)
            return {
                "job_uuid": str(job.job_uuid),
                "runtime_session_uuid": str(runtime_session_uuid),
                "status": "queued",
                "job_version": 1,
                "lease_nonce": str(expected_lease_nonce),
                "hard_expires_at": job.hard_expires_at.isoformat(),
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="runtime.job_queued",
            target=str(runtime_session_uuid),
        )

    async def dispatch_job(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        peer_evidence: object,
        *,
        job_uuid: UUID,
        runtime_session_uuid: UUID,
        expected_lease_nonce: UUID,
        expected_job_version: int,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        if (
            request.operation
            not in {
                "runtime.terminal.job.dispatch",
                "runtime.web.job.dispatch",
                "runtime.reverse.job.dispatch",
            }
            or job_uuid.version != 4
            or runtime_session_uuid.version != 4
            or expected_lease_nonce.version != 4
            or expected_job_version < 1
        ):
            raise InvalidInput("Runtime dispatch requires original CAS job and lease")
        require_signed_payload(
            request,
            {
                "job_uuid": str(job_uuid),
                "runtime_session_uuid": str(runtime_session_uuid),
                "expected_lease_nonce": str(expected_lease_nonce),
                "expected_job_version": expected_job_version,
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )
        decision = await self._current(
            request, proofs, peer_evidence, service_id=service_id, instance_uuid=instance_uuid
        )

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            session = await tx.scalar(
                select(RuntimeSessionRow)
                .where(RuntimeSessionRow.runtime_session_uuid == runtime_session_uuid)
                .with_for_update()
            )
            job = await tx.scalar(
                select(RuntimeJobRow).where(RuntimeJobRow.job_uuid == job_uuid).with_for_update()
            )
            now = datetime.now(UTC)
            if (
                session is None
                or job is None
                or session.project_id != request.project_id
                or session.agent_session_uuid != request.session_uuid
                or session.owner_service_id != service_id
                or session.owner_instance != instance_uuid
                or session.lease_nonce != expected_lease_nonce
                or session.status != "active"
                or session.lease_expires_at <= now
                or job.runtime_session_uuid != runtime_session_uuid
                or job.project_id != request.project_id
                or job.agent_session_uuid != request.session_uuid
                or job.owner_service_id != service_id
                or job.lease_nonce != expected_lease_nonce
                or job.version != expected_job_version
                or job.status != "queued"
                or job.hard_expires_at <= now
                or request.operation != job.operation.replace(".queue", ".dispatch")
            ):
                raise AccessDenied("Runtime job already dispatched or lease fenced")
            job.status = "running"
            job.version += 1
            job.started_at = now
            return {
                "job_uuid": str(job.job_uuid),
                "status": "running",
                "job_version": job.version,
                "lease_nonce": str(session.lease_nonce),
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="runtime.job_dispatched",
            target=str(job_uuid),
        )
