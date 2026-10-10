"""Private OS confinement attestation contract for future Project worker owner.

A shared Terminal cwd or process-group PID is NOT a security boundary. This
application port may only be backed by an approved worker supervisor with
per-Project namespace/UID/cgroup and hard TTL enforcement. There is no shell
executor, subprocess or root fallback in this file. No public tool mounts it.
"""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from modules.project_runtime import ProjectInvocation, ProjectPermit, ProjectRuntimeAuthority


class ProjectIsolationUnavailable(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ProjectIsolationAttestation:
    platform_project_id: UUID
    agent_session_uuid: UUID
    actor_id: UUID
    runtime_session_uuid: UUID
    supervisor_instance_uuid: UUID
    project_unix_uid: int
    supervisor_unix_uid: int
    namespace_isolated: bool
    private_mounts_enforced: bool
    cgroup_v2_enforced: bool
    process_tree_hard_ttl_enforced: bool
    no_privileged_host_access: bool
    resource_policy_revision: str
    valid_until: datetime


class ProjectIsolationSupervisorPort(Protocol):
    """Backend/OS-owned worker attestation with per-call ownership check."""

    async def attest(
        self,
        invocation: ProjectInvocation,
        *,
        runtime_session_uuid: UUID,
        permit: ProjectPermit,
    ) -> ProjectIsolationAttestation: ...


class ProjectIsolationInspector:
    """Verifies an attestation; it does NOT prove the kernel policy by itself."""

    def __init__(
        self,
        authority: ProjectRuntimeAuthority,
        supervisor: ProjectIsolationSupervisorPort | None = None,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
            raise ValueError("OS isolation attestation timeout invalid")
        self.authority = authority
        self._supervisor = supervisor
        self.timeout_seconds = timeout_seconds

    async def attest(
        self,
        invocation: ProjectInvocation,
        *,
        runtime_session_uuid: UUID,
    ) -> ProjectIsolationAttestation:
        if not isinstance(runtime_session_uuid, UUID) or runtime_session_uuid.version != 4:
            raise ProjectIsolationUnavailable("PROJECT_RUNTIME_SESSION_UUID_INVALID")
        if self._supervisor is None:
            raise ProjectIsolationUnavailable("PROJECT_OS_SUPERVISOR_UNAVAILABLE")
        permit = await self.authority.require(invocation, "terminal.attach")
        try:
            async with asyncio.timeout(self.timeout_seconds):
                proof = await self._supervisor.attest(
                    invocation, runtime_session_uuid=runtime_session_uuid, permit=permit
                )
        except Exception as exc:
            raise ProjectIsolationUnavailable("PROJECT_OS_SUPERVISOR_UNAVAILABLE") from exc
        if (
            not isinstance(proof, ProjectIsolationAttestation)
            or proof.platform_project_id != permit.project_id
            or proof.agent_session_uuid != permit.session_uuid
            or proof.actor_id != permit.actor_id
            or proof.runtime_session_uuid != runtime_session_uuid
            or not isinstance(proof.supervisor_instance_uuid, UUID)
            or proof.supervisor_instance_uuid.version != 4
            or type(proof.project_unix_uid) is not int
            or type(proof.supervisor_unix_uid) is not int
            or proof.project_unix_uid <= 0
            or proof.project_unix_uid == proof.supervisor_unix_uid
            or not all(
                (
                    proof.namespace_isolated is True,
                    proof.private_mounts_enforced is True,
                    proof.cgroup_v2_enforced is True,
                    proof.process_tree_hard_ttl_enforced is True,
                    proof.no_privileged_host_access is True,
                )
            )
            or not proof.resource_policy_revision
            or len(proof.resource_policy_revision) > 128
            or not isinstance(proof.valid_until, datetime)
            or proof.valid_until.tzinfo is None
            or proof.valid_until <= datetime.now(UTC)
            or proof.valid_until > permit.expires_at
        ):
            raise ProjectIsolationUnavailable("PROJECT_OS_ATTESTATION_INVALID")
        # Membership/AgentSession may have been revoked during supervisor
        # resolution. Recheck before returning attestation metadata.
        refreshed = await self.authority.require(invocation, "terminal.attach")
        if (
            refreshed.project_id != permit.project_id
            or refreshed.actor_id != permit.actor_id
            or refreshed.session_uuid != permit.session_uuid
            or refreshed.project_access_revision != permit.project_access_revision
            or refreshed.decision_version != permit.decision_version
            or proof.valid_until > refreshed.expires_at
            or refreshed.project_owner_scope != permit.project_owner_scope
            or refreshed.project_owner_id != permit.project_owner_id
            or refreshed.owner_fence != permit.owner_fence
        ):
            raise ProjectIsolationUnavailable("PROJECT_OS_PROJECT_ACCESS_STALE")
        return proof
