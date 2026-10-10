"""Briareus execution-owner signed RuntimeSession/Job source (unmounted).

`briareus_runtime` alone persists leases/jobs/outbox. A9 Ed25519 signed
RuntimeLeaseReceipt proves the committed owner/nonces but is NOT OS custody.
Before an ACTIVE SQL lease, require an independently verified restricted UID,
mount namespace, cgroup-v2 hard TTL and owner-bound worker preflight. This
module never creates host subprocesses or terminates a PID. Missing C2 owner
port/supervisor denies without mutating SQL or inventing a replacement lease.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from common.owner_runtime_signing import RuntimeOwnerJwsClaims
from modules.project_runtime import (
    ProjectAction,
    ProjectInvocation,
    ProjectRuntimeAuthority,
)
from modules.project_runtime.a6_runtime import (
    RuntimeJobCommand,
    RuntimeJobReceipt,
    RuntimeJobTransition,
    RuntimeLeaseCommand,
    RuntimeOpenCommand,
)
from modules.project_runtime.a9_signed_lease import (
    RuntimeLeaseReceipt,
    SignedRuntimeLeaseReceipt,
)
from modules.project_runtime.owner_effects import (
    OwnerEffectClient,
    OwnerEffectUnavailable,
)
from modules.project_runtime.runtime_owner_lease import (
    RuntimeOwnerLeaseKeyPort,
    verify_current_runtime_owner_lease,
)

ExecutionKind = Literal["files", "terminal", "web_managed", "web_remote", "reverse"]
_KIND: dict[ExecutionKind, tuple[ProjectAction, Literal["files", "terminal", "web", "reverse"]]] = {
    "files": ("files.write", "files"),
    "terminal": ("terminal.attach", "terminal"),
    "web_managed": ("web.internal", "web"),
    "web_remote": ("web.remote", "web"),
    "reverse": ("reverse.import", "reverse"),
}


def lease_target(runtime_uuid: UUID) -> str:
    if not isinstance(runtime_uuid, UUID) or runtime_uuid.version != 4:
        raise OwnerEffectUnavailable("EXECUTION_RUNTIME_UUID_REQUIRED")
    return hashlib.sha256(b"execution-session-v1\x00" + runtime_uuid.bytes).hexdigest()


class ExecutionOpenReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    signed_lease: SignedRuntimeLeaseReceipt
    owner_database: Literal["briareus_runtime"] = "briareus_runtime"


class ExecutionInspect(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    original_operation_uuid: UUID
    runtime_session_uuid: UUID
    expected_revision: int = Field(ge=0)
    phase: Literal["inspect"] = "inspect"


class ExecutionInspectReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    found: bool
    signed_lease: SignedRuntimeLeaseReceipt | None
    outcome_unknown: bool
    retry_allowed: Literal[False] = False


@dataclass(frozen=True, slots=True)
class TrustedExecutionConfinement:
    """OS supervisor attestation snapshot, NEVER a caller-provided payload."""

    project_id: UUID
    agent_session_uuid: UUID
    runtime_session_uuid: UUID
    cgroup_owner_instance: UUID
    private_project_uid: int
    restricted_mount_namespace: bool
    cgroup_v2_process_tree_hard_ttl: bool
    no_host_privileges: bool
    expires_at: datetime


class VerifiedJobTreeEvidence(BaseModel):
    """From an independently signed and verified C2 worker, NOT user JSON.

    The Execution owner checks the ORIGINAL signed OS evidence again inside
    the job state UoW. Hashes are opaque fingerprints, not raw command/logs.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    project_id: UUID
    agent_session_uuid: UUID
    runtime_session_uuid: UUID
    job_uuid: UUID
    owner_instance_uuid: UUID
    lease_nonce: UUID
    cgroup_v2_tree_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    attested_os_proof_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime
    stage: Literal["running", "succeeded", "failed"]
    tree_restricted: Literal[True] = True
    hard_ttl_enforced: Literal[True] = True


class VerifiedExecutionStoppedEvidence(BaseModel):
    """Signed kernel process-tree STOP, as validated by a trusted C2 port.

    A SQL `revoked` / `expired` row, PID/PGID or boolean in public JSON cannot
    prove descendants were terminated. The signed *actual* supervisor receipt
    must bind original RuntimeSession nonce/owner instance and a cgroup tree
    digest, plus the verified supervisor's own registered service identity.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    project_id: UUID
    agent_session_uuid: UUID
    runtime_session_uuid: UUID
    previous_service_id: UUID
    previous_instance_uuid: UUID
    lease_nonce: UUID
    supervisor_service_id: UUID
    supervisor_instance_uuid: UUID
    native_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_os_proof_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_stopped_at: datetime
    cgroup_process_tree_empty: Literal[True] = True


class ExecutionConfirmCleanupCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    runtime_session_uuid: UUID
    previous_lease_nonce: UUID
    expected_version: int = Field(ge=1)
    previous_service_id: UUID
    previous_instance_uuid: UUID
    supervisor_service_id: UUID
    supervisor_instance_uuid: UUID
    observed_stopped_at: datetime
    native_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_os_proof_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class VerifiedExecutionJobCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    command: RuntimeJobTransition
    os_evidence: VerifiedJobTreeEvidence


class TrustedExecutionSupervisorPort(Protocol):
    """Verify actual signed kernel/runtime attestation before ACTIVE owner.

    Runtime may not fabricate this with PID/PGID/cwd or bool-only JSON. The
    real supervisor must verify namespace/mount/uid/cgroup membership and
    sign the proof bound to the recipient, Project, Session and runtime UUID.
    """

    async def attest_prepared(
        self,
        invocation: ProjectInvocation,
        *,
        runtime_session_uuid: UUID,
        kind: ExecutionKind,
    ) -> TrustedExecutionConfinement: ...

    async def attest_stopped(
        self,
        invocation: ProjectInvocation,
        *,
        previous: SignedRuntimeLeaseReceipt,
    ) -> VerifiedExecutionStoppedEvidence: ...

    async def attest_job_event(
        self,
        invocation: ProjectInvocation,
        *,
        runtime_session_uuid: UUID,
        job_uuid: UUID,
        lease_nonce: UUID,
        stage: Literal["running", "succeeded", "failed"],
    ) -> VerifiedJobTreeEvidence: ...


class ExecutionOwnerRuntime:
    """Backend-independent durable execution receipts, no process spawn."""

    def __init__(
        self,
        authority: ProjectRuntimeAuthority,
        effects: OwnerEffectClient,
        *,
        owner_lease_keys: RuntimeOwnerLeaseKeyPort | None = None,
        supervisor: TrustedExecutionSupervisorPort | None = None,
    ) -> None:
        self.authority = authority
        self.effects = effects
        self.owner_lease_keys = owner_lease_keys
        self.supervisor = supervisor

    async def verify_split_owner_lease(
        self,
        invocation: ProjectInvocation,
        *,
        attestation_jws: str,
        runtime_session_uuid: UUID,
        lease_nonce: UUID,
        expected_version: int,
        kind: ExecutionKind,
    ) -> RuntimeOwnerJwsClaims:
        """Check split Runtime owner SQL nonce; never infer OS process proof.

        Legacy A9 `briareus-authorization` lease signatures are not an
        alternate signer for this source. No real job/cleanup is initiated.
        """
        return await verify_current_runtime_owner_lease(
            invocation,
            authority=self.authority,
            effects=self.effects,
            keys=self.owner_lease_keys,
            attestation_jws=attestation_jws,
            runtime_session_uuid=runtime_session_uuid,
            lease_nonce=lease_nonce,
            expected_version=expected_version,
            kind=kind,
        )

    async def _confined(
        self,
        invocation: ProjectInvocation,
        *,
        kind: ExecutionKind,
        runtime_session_uuid: UUID,
    ) -> TrustedExecutionConfinement:
        # An accepted isolated OS supervisor alone is insufficient while A12
        # has not accepted the owner-local signed cleanup/reconnect/job phases.
        self.effects.require_effect_lifecycle("execution")
        if self.supervisor is None or self.owner_lease_keys is None:
            raise OwnerEffectUnavailable("EXECUTION_TRUSTED_OS_AND_SIGNER_REQUIRED")
        action, _ = _KIND[kind]
        await self.authority.require(invocation, action)
        try:
            async with asyncio.timeout(10):
                fact = await self.supervisor.attest_prepared(
                    invocation,
                    runtime_session_uuid=runtime_session_uuid,
                    kind=kind,
                )
        except Exception as exc:
            raise OwnerEffectUnavailable("EXECUTION_OS_C2_SUPERVISOR_UNAVAILABLE") from exc
        if (
            not isinstance(fact, TrustedExecutionConfinement)
            or fact.project_id != invocation.project_id
            or fact.agent_session_uuid != invocation.session_uuid
            or fact.runtime_session_uuid != runtime_session_uuid
            or not isinstance(fact.cgroup_owner_instance, UUID)
            or fact.cgroup_owner_instance.version != 4
            or type(fact.private_project_uid) is not int
            or fact.private_project_uid <= 0
            or not fact.restricted_mount_namespace
            or not fact.cgroup_v2_process_tree_hard_ttl
            or not fact.no_host_privileges
            or fact.expires_at.tzinfo is None
            or fact.expires_at <= datetime.now(UTC)
        ):
            raise OwnerEffectUnavailable("EXECUTION_OS_C2_ATTESTATION_INVALID")
        return fact

    async def _verify_lease(
        self,
        invocation: ProjectInvocation,
        signed: SignedRuntimeLeaseReceipt,
        *,
        kind: ExecutionKind,
    ) -> RuntimeLeaseReceipt:
        """Historical A9 Authorization-global JWS is not Runtime ownership.

        No old issuer can be promoted to a split-owner process capability.
        New commands require a separately signed Runtime owner lease plus
        complete owner phases and independently attested C2 OS state.
        """
        _ = (invocation, signed, kind)
        raise OwnerEffectUnavailable("EXECUTION_A9_GLOBAL_LEASE_RETIRED")

    async def open_intent(
        self,
        invocation: ProjectInvocation,
        *,
        kind: ExecutionKind,
        runtime_session_uuid: UUID,
        idle_seconds: int,
        hard_seconds: int,
    ) -> SignedRuntimeLeaseReceipt:
        """Signed owner SQL active after independent OS-ready proof, no exec."""
        if kind not in _KIND or type(idle_seconds) is not int or type(hard_seconds) is not int:
            raise OwnerEffectUnavailable("EXECUTION_OPEN_PARAMETERS_INVALID")
        if not 30 <= idle_seconds <= hard_seconds <= 86400 or hard_seconds < 60:
            raise OwnerEffectUnavailable("EXECUTION_OPEN_TTL_INVALID")
        scope = invocation.operation_scope
        if scope is None:
            raise OwnerEffectUnavailable("EXECUTION_OPERATION_SCOPE_REQUIRED")
        prepared = await self._confined(
            invocation,
            kind=kind,
            runtime_session_uuid=runtime_session_uuid,
        )
        peer = await self.effects._recipient(invocation)
        if prepared.cgroup_owner_instance != peer.instance_uuid:
            raise OwnerEffectUnavailable("EXECUTION_OS_PEER_INSTANCE_MISMATCH")
        action, _ = _KIND[kind]
        command = RuntimeOpenCommand(
            operation_uuid=scope.request_uuid,
            runtime_session_uuid=runtime_session_uuid,
            instance_uuid=peer.instance_uuid,
            kind=kind,
            idle_seconds=idle_seconds,
            hard_seconds=hard_seconds,
            idempotency_key=str(scope.request_uuid),
        )
        result = await self.effects.execute(
            invocation,
            owner="execution",
            phase="open",
            action=action,
            target_sha256=lease_target(runtime_session_uuid),
            payload=command,
            expected=ExecutionOpenReceipt,
            original_operation_uuid=scope.request_uuid,
        )
        lease = await self._verify_lease(
            invocation,
            result.payload.signed_lease,
            kind=kind,
        )
        if (
            result.attestation.receipt.state != "committed"
            or lease.state != "active"
            or lease.owner_instance_uuid != peer.instance_uuid
            or lease.lease_expires_at > prepared.expires_at
        ):
            raise OwnerEffectUnavailable("EXECUTION_OPEN_RESULT_UNSAFE", unknown=True)
        return result.payload.signed_lease

    async def heartbeat(
        self,
        invocation: ProjectInvocation,
        *,
        prior: SignedRuntimeLeaseReceipt,
    ) -> SignedRuntimeLeaseReceipt:
        """One signed CAS heartbeat with current attested OS owner and nonce.

        This method cannot keep a lease alive without a real C2 supervisor,
        pinned issuer JWS and fresh Identity+Control+Access versions inside
        the Execution owner SQL transaction. It NEVER adopts an OS PID.
        """
        kind = prior.lease.kind
        before = await self._verify_lease(invocation, prior, kind=kind)
        if before.state != "active":
            raise OwnerEffectUnavailable("EXECUTION_HEARTBEAT_ACTIVE_LEASE_REQUIRED")
        confined = await self._confined(
            invocation,
            kind=kind,
            runtime_session_uuid=before.runtime_session_uuid,
        )
        if confined.cgroup_owner_instance != before.owner_instance_uuid:
            raise OwnerEffectUnavailable("EXECUTION_HEARTBEAT_OS_OWNER_STALE")
        scope = invocation.operation_scope
        if scope is None:
            raise OwnerEffectUnavailable("EXECUTION_HEARTBEAT_OPERATION_SCOPE_REQUIRED")
        action, _ = _KIND[kind]
        command = RuntimeLeaseCommand(
            operation_uuid=scope.request_uuid,
            runtime_session_uuid=before.runtime_session_uuid,
            expected_version=before.revision,
            lease_nonce=before.lease_nonce,
            phase="heartbeat",
        )
        result = await self.effects.execute(
            invocation,
            owner="execution",
            phase="heartbeat",
            action=action,
            target_sha256=lease_target(before.runtime_session_uuid),
            payload=command,
            expected=ExecutionOpenReceipt,
            expected_version=before.revision,
            original_operation_uuid=scope.request_uuid,
        )
        after = await self._verify_lease(
            invocation,
            result.payload.signed_lease,
            kind=kind,
        )
        if (
            result.attestation.receipt.state != "committed"
            or after.state != "active"
            or after.revision != before.revision + 1
            or after.lease_nonce != before.lease_nonce
            or after.owner_service_id != before.owner_service_id
            or after.owner_instance_uuid != before.owner_instance_uuid
            or after.hard_expires_at != before.hard_expires_at
            or after.lease_expires_at > after.hard_expires_at
        ):
            raise OwnerEffectUnavailable("EXECUTION_HEARTBEAT_OWNER_CAS_INVALID", unknown=True)
        return result.payload.signed_lease

    async def inspect(
        self,
        invocation: ProjectInvocation,
        *,
        kind: ExecutionKind,
        runtime_session_uuid: UUID,
        original_operation_uuid: UUID,
        expected_revision: int = 0,
    ) -> ExecutionInspectReceipt:
        action, _ = _KIND[kind]
        query = ExecutionInspect(
            original_operation_uuid=original_operation_uuid,
            runtime_session_uuid=runtime_session_uuid,
            expected_revision=expected_revision,
        )
        reply = await self.effects.execute(
            invocation,
            owner="execution",
            phase="inspect",
            action=action,
            target_sha256=lease_target(runtime_session_uuid),
            payload=query,
            expected=ExecutionInspectReceipt,
            original_operation_uuid=original_operation_uuid,
        )
        result = reply.payload
        if not result.found:
            if result.signed_lease is not None or reply.attestation.receipt.state != "committed":
                raise OwnerEffectUnavailable(
                    "EXECUTION_INSPECTION_ABSENCE_UNVERIFIED", unknown=True
                )
        else:
            if result.signed_lease is None:
                raise OwnerEffectUnavailable("EXECUTION_INSPECTION_LEASE_MISSING", unknown=True)
            await self._verify_lease(invocation, result.signed_lease, kind=kind)
        # Absent durable row NEVER proves a prior process had no side effect.
        return result

    async def revoke(
        self,
        invocation: ProjectInvocation,
        *,
        prior: SignedRuntimeLeaseReceipt,
    ) -> SignedRuntimeLeaseReceipt:
        kind = prior.lease.kind
        verified = await self._verify_lease(invocation, prior, kind=kind)
        scope = invocation.operation_scope
        if scope is None:
            raise OwnerEffectUnavailable("EXECUTION_REVOKE_SCOPE_REQUIRED")
        action, _ = _KIND[kind]
        command = RuntimeLeaseCommand(
            operation_uuid=scope.request_uuid,
            runtime_session_uuid=verified.runtime_session_uuid,
            expected_version=verified.revision,
            lease_nonce=verified.lease_nonce,
            phase="revoke",
        )
        reply = await self.effects.execute(
            invocation,
            owner="execution",
            phase="revoke",
            action=action,
            target_sha256=lease_target(verified.runtime_session_uuid),
            payload=command,
            expected=ExecutionOpenReceipt,
            expected_version=verified.revision,
            original_operation_uuid=scope.request_uuid,
        )
        renewed = await self._verify_lease(
            invocation,
            reply.payload.signed_lease,
            kind=kind,
        )
        if (
            renewed.state not in {"revoked", "closed", "expired"}
            or renewed.lease_nonce != verified.lease_nonce
            or renewed.revision not in {verified.revision, verified.revision + 1}
        ):
            raise OwnerEffectUnavailable("EXECUTION_REVOKE_SQL_STATE_INVALID", unknown=True)
        # OS kill-tree is SEPARATE, requires signed observed-stop attestation.
        return reply.payload.signed_lease

    async def confirm_cleanup_intent(
        self,
        invocation: ProjectInvocation,
        *,
        previous: SignedRuntimeLeaseReceipt,
    ) -> SignedRuntimeLeaseReceipt:
        """Request SQL cleanup confirmation ONLY from a verified OS stop proof.

        The current A11 owner has `runtime.cleanup.confirm` but it requires
        independent C2 `TrustedRuntimeCleanupVerifier` with actual signed
        evidence, and A12 has not accepted its recipient-bound result JWS.
        The typed source therefore remains fail-closed until the exact whole
        owner lease/cleanup/UNKNOWN contract is approved; no PID or OS kill.
        """
        self.effects.require_effect_lifecycle("execution")
        if self.supervisor is None:
            raise OwnerEffectUnavailable("EXECUTION_C2_STOP_OBSERVER_REQUIRED")
        kind = previous.lease.kind
        prior = await self._verify_lease(invocation, previous, kind=kind)
        if prior.state not in {"revoked", "expired", "lost", "closed"}:
            raise OwnerEffectUnavailable("EXECUTION_ACTIVE_LEASE_CANNOT_CONFIRM_CLEANUP")
        scope = invocation.operation_scope
        if scope is None or scope.action != _KIND[kind][0]:
            raise OwnerEffectUnavailable("EXECUTION_CLEANUP_ORIGINAL_SCOPE_REQUIRED")
        try:
            async with asyncio.timeout(10):
                proof = await self.supervisor.attest_stopped(
                    invocation,
                    previous=previous,
                )
        except Exception as exc:
            raise OwnerEffectUnavailable("EXECUTION_NATIVE_STOP_EVIDENCE_UNAVAILABLE") from exc
        now = datetime.now(UTC)
        if (
            not isinstance(proof, VerifiedExecutionStoppedEvidence)
            or proof.project_id != prior.project_id
            or proof.agent_session_uuid != prior.agent_session_uuid
            or proof.runtime_session_uuid != prior.runtime_session_uuid
            or proof.previous_service_id != prior.owner_service_id
            or proof.previous_instance_uuid != prior.owner_instance_uuid
            or proof.lease_nonce != prior.lease_nonce
            or proof.observed_stopped_at.tzinfo is None
            or proof.observed_stopped_at > now
            or (now - proof.observed_stopped_at).total_seconds() > 120
            or not all(
                isinstance(value, UUID) and value.version == 4
                for value in (proof.supervisor_service_id, proof.supervisor_instance_uuid)
            )
            or proof.cgroup_process_tree_empty is not True
        ):
            raise OwnerEffectUnavailable("EXECUTION_C2_STOP_PROOF_INVALID")
        command = ExecutionConfirmCleanupCommand(
            runtime_session_uuid=prior.runtime_session_uuid,
            previous_lease_nonce=prior.lease_nonce,
            expected_version=prior.revision,
            previous_service_id=prior.owner_service_id,
            previous_instance_uuid=prior.owner_instance_uuid,
            supervisor_service_id=proof.supervisor_service_id,
            supervisor_instance_uuid=proof.supervisor_instance_uuid,
            observed_stopped_at=proof.observed_stopped_at,
            native_scope_digest=proof.native_scope_digest,
            signed_os_proof_sha256=proof.signed_os_proof_sha256,
        )
        result = await self.effects.execute(
            invocation,
            owner="execution",
            phase="confirm_cleanup",
            action=_KIND[kind][0],
            target_sha256=lease_target(prior.runtime_session_uuid),
            payload=command,
            expected=ExecutionOpenReceipt,
            expected_version=prior.revision,
            original_operation_uuid=scope.request_uuid,
        )
        # A12 still needs to accept the signed owner-result JWS for this
        # operation and the refreshed Runtime owner-specific lease signer.
        renewed = await self._verify_lease(
            invocation,
            result.payload.signed_lease,
            kind=kind,
        )
        if (
            result.attestation.receipt.state != "committed"
            or renewed.cleanup_state != "confirmed"
            or renewed.lease_nonce != prior.lease_nonce
            or renewed.owner_service_id != prior.owner_service_id
            or renewed.owner_instance_uuid != prior.owner_instance_uuid
            or renewed.revision != prior.revision + 1
        ):
            raise OwnerEffectUnavailable("EXECUTION_CLEANUP_SIGNED_ACK_UNKNOWN", unknown=True)
        return result.payload.signed_lease

    async def queue_job(
        self,
        invocation: ProjectInvocation,
        *,
        lease: SignedRuntimeLeaseReceipt,
        request_fingerprint: str,
        hard_seconds: int,
    ) -> RuntimeJobReceipt:
        kind = lease.lease.kind
        prior = await self._verify_lease(invocation, lease, kind=kind)
        if prior.state != "active" or kind != "terminal":
            raise OwnerEffectUnavailable("EXECUTION_JOB_CURRENT_ACTIVE_TERMINAL_REQUIRED")
        await self._confined(
            invocation,
            kind=kind,
            runtime_session_uuid=prior.runtime_session_uuid,
        )
        scope = invocation.operation_scope
        if scope is None:
            raise OwnerEffectUnavailable("EXECUTION_JOB_SCOPE_REQUIRED")
        command = RuntimeJobCommand(
            operation_uuid=scope.request_uuid,
            runtime_session_uuid=prior.runtime_session_uuid,
            runtime_version=prior.revision,
            lease_nonce=prior.lease_nonce,
            idempotency_key=str(scope.request_uuid),
            request_fingerprint=request_fingerprint,
            hard_seconds=hard_seconds,
        )
        reply = await self.effects.execute(
            invocation,
            owner="execution",
            phase="queue_job",
            action="terminal.attach",
            target_sha256=lease_target(prior.runtime_session_uuid),
            payload=command,
            expected=RuntimeJobReceipt,
            expected_version=prior.revision,
            original_operation_uuid=scope.request_uuid,
        )
        if (
            reply.attestation.receipt.state != "committed"
            or reply.payload.status != "queued"
            or reply.payload.runtime_session_uuid != prior.runtime_session_uuid
            or reply.payload.project_id != prior.project_id
        ):
            raise OwnerEffectUnavailable("EXECUTION_JOB_RESERVATION_INVALID", unknown=True)
        # Not a process launch. OS worker/process-tree and cleanup proof are
        # separate C2 gates and cannot be inferred from a QUEUED SQL job.
        return reply.payload

    async def record_verified_job_event(
        self,
        invocation: ProjectInvocation,
        *,
        lease: SignedRuntimeLeaseReceipt,
        job: RuntimeJobReceipt,
        stage: Literal["running", "succeeded", "failed"],
        result_digest: str | None = None,
    ) -> RuntimeJobReceipt:
        """Persist a verified *observed* OS tree transition; never launch OS.

        Independent C2 supervisor must have observed a process-tree state
        bound to this Project/Session/lease nonce and *specific* job UUID.
        Backend owner must authenticate/verify the same OS proof under its
        own transaction before accepting running/succeeded/failed SQL state.
        A returned `queued` DB row is NEVER evidence of a started worker.
        """
        if self.supervisor is None:
            raise OwnerEffectUnavailable("EXECUTION_JOB_OS_SUPERVISOR_REQUIRED")
        if lease.lease.kind != "terminal":
            raise OwnerEffectUnavailable("EXECUTION_JOB_TERMINAL_ONLY")
        prior = await self._verify_lease(invocation, lease, kind="terminal")
        if (
            prior.state != "active"
            or not isinstance(job, RuntimeJobReceipt)
            or job.runtime_session_uuid != prior.runtime_session_uuid
            or job.project_id != prior.project_id
            or job.hard_expires_at.tzinfo is None
            or job.hard_expires_at <= datetime.now(UTC)
            or (stage == "running" and job.status != "queued")
            or (stage in {"succeeded", "failed"} and job.status != "running")
            or (
                stage == "succeeded"
                and (
                    not isinstance(result_digest, str)
                    or len(result_digest) != 64
                    or any(c not in "0123456789abcdef" for c in result_digest)
                )
            )
        ):
            raise OwnerEffectUnavailable("EXECUTION_JOB_STATE_OR_TTL_INVALID")
        os_owner = await self._confined(
            invocation,
            kind="terminal",
            runtime_session_uuid=prior.runtime_session_uuid,
        )
        if os_owner.cgroup_owner_instance != prior.owner_instance_uuid:
            raise OwnerEffectUnavailable("EXECUTION_JOB_OS_OWNER_STALE")
        try:
            async with asyncio.timeout(10):
                evidence = await self.supervisor.attest_job_event(
                    invocation,
                    runtime_session_uuid=prior.runtime_session_uuid,
                    job_uuid=job.job_uuid,
                    lease_nonce=prior.lease_nonce,
                    stage=stage,
                )
        except Exception as exc:
            raise OwnerEffectUnavailable("EXECUTION_JOB_OS_EVENT_UNAVAILABLE") from exc
        if (
            not isinstance(evidence, VerifiedJobTreeEvidence)
            or evidence.project_id != invocation.project_id
            or evidence.agent_session_uuid != invocation.session_uuid
            or evidence.runtime_session_uuid != prior.runtime_session_uuid
            or evidence.job_uuid != job.job_uuid
            or evidence.lease_nonce != prior.lease_nonce
            or evidence.owner_instance_uuid != prior.owner_instance_uuid
            or evidence.stage != stage
            or evidence.observed_at.tzinfo is None
            or evidence.observed_at > datetime.now(UTC)
            or (datetime.now(UTC) - evidence.observed_at).total_seconds() > 30
            or evidence.tree_restricted is not True
            or evidence.hard_ttl_enforced is not True
        ):
            raise OwnerEffectUnavailable("EXECUTION_JOB_OS_EVENT_INVALID")
        scope = invocation.operation_scope
        if scope is None:
            raise OwnerEffectUnavailable("EXECUTION_JOB_ORIGINAL_SCOPE_REQUIRED")
        inner = RuntimeJobTransition(
            operation_uuid=scope.request_uuid,
            runtime_session_uuid=prior.runtime_session_uuid,
            runtime_version=prior.revision,
            lease_nonce=prior.lease_nonce,
            job_uuid=job.job_uuid,
            expected_job_version=job.revision,
            target=stage,
            result_digest=result_digest,
        )
        phase: Literal["start_job", "finish_job", "fail_job"] = (
            "start_job"
            if stage == "running"
            else "finish_job"
            if stage == "succeeded"
            else "fail_job"
        )
        reply = await self.effects.execute(
            invocation,
            owner="execution",
            phase=phase,
            action="terminal.attach",
            target_sha256=lease_target(prior.runtime_session_uuid),
            payload=VerifiedExecutionJobCommand(command=inner, os_evidence=evidence),
            expected=RuntimeJobReceipt,
            expected_version=job.revision,
            original_operation_uuid=scope.request_uuid,
        )
        result = reply.payload
        expected_status = stage
        if (
            reply.attestation.receipt.state != "committed"
            or result.status != expected_status
            or result.job_uuid != job.job_uuid
            or result.runtime_session_uuid != prior.runtime_session_uuid
            or result.project_id != prior.project_id
            or result.revision != job.revision + 1
        ):
            raise OwnerEffectUnavailable("EXECUTION_JOB_CAS_OR_STATUS_INVALID", unknown=True)
        return result
