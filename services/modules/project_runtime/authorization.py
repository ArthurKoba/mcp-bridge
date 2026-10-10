"""Unmounted authorization consumer port for future project-runtime adapters.

An opaque UUID or a value supplied by a tool caller is NEVER a permission.
Only an injected, service-authenticated implementation of ProjectAccessPort may
return a permit. Until C1-B/C2 supply that implementation, requests fail closed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import UUID

_REVISION_PATTERN = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)


def valid_project_revision(value: object) -> bool:
    """Accepted A4 `project_permit.decision_version` SHA-256 hex identity."""
    return isinstance(value, str) and _REVISION_PATTERN.fullmatch(value) is not None


ProjectAction = Literal[
    "files.read",
    "files.write",
    "files.manage",
    "terminal.attach",
    "web.internal",
    "web.remote",
    "reverse.import",
    "reverse.read",
    "svc.read",
    "svc.write",
    "infrastructure.read",
    "resources.use",
]


@dataclass(frozen=True, slots=True)
class ProjectOperationScope:
    """Trusted in-process preflight identity, NOT authorization by itself.

    Gateway derives this from a validated, canonical Pydantic request BEFORE
    any A5 signed proof is requested. Backend MUST independently authenticate
    the service+delegated human and consume matching single-use JWT JTIs.
    """

    project_id: UUID
    agent_session_uuid: UUID
    action: ProjectAction
    request_uuid: UUID
    fingerprint: str
    resource_id: UUID | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.project_id, UUID)
            or not isinstance(self.agent_session_uuid, UUID)
            or self.agent_session_uuid.version != 4
            or not isinstance(self.request_uuid, UUID)
            or self.request_uuid.version != 4
            or not valid_project_revision(self.fingerprint)
            or (self.resource_id is not None and not isinstance(self.resource_id, UUID))
        ):
            raise ProjectAccessDenied("PROJECT_OPERATION_SCOPE_INVALID")


def canonical_request_fingerprint(
    *,
    project_id: UUID,
    session_uuid: UUID,
    action: ProjectAction,
    request_uuid: UUID,
    backend: str,
    tool: str,
    arguments: Mapping[str, object],
) -> str:
    """Domain-separated digest of the *normalized* concrete private command.

    A digest is a binding label, NOT an HMAC/signed authorization proof. Any
    future C1-B2 transport must pass this exact digest as its independently
    routed `expected_fingerprint` to Backend A5's verifier.
    """
    if (
        not isinstance(request_uuid, UUID)
        or request_uuid.version != 4
        or not isinstance(session_uuid, UUID)
        or session_uuid.version != 4
        or not isinstance(project_id, UUID)
        or not isinstance(backend, str)
        or not isinstance(tool, str)
        or not isinstance(arguments, dict)
    ):
        raise ProjectAccessDenied("PROJECT_OPERATION_FINGERPRINT_INVALID")
    try:
        encoded = json.dumps(
            [
                "private-project-op-v1",
                str(project_id),
                str(session_uuid),
                str(request_uuid),
                action,
                backend,
                tool,
                arguments,
            ],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProjectAccessDenied("PROJECT_OPERATION_FINGERPRINT_INVALID") from exc
    if len(encoded) > 600000:
        raise ProjectAccessDenied("PROJECT_OPERATION_FINGERPRINT_TOO_LARGE")
    return hashlib.sha256(encoded).hexdigest()


class ProjectAccessDenied(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ProjectInvocation:
    """Opaque caller evidence must be validated again by ProjectAccessPort."""

    project_id: UUID
    session_uuid: UUID
    caller_evidence: object
    # A service-to-service attestation is distinct from the User's OAuth/
    # local-login credential. No raw caller/agent UUID is service identity.
    service_evidence: object | None = None
    operation_scope: ProjectOperationScope | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, UUID):
            raise ProjectAccessDenied("PROJECT_ID_INVALID")
        if not isinstance(self.session_uuid, UUID) or self.session_uuid.version != 4:
            raise ProjectAccessDenied("SESSION_UUID_INVALID")
        if self.caller_evidence is None:
            raise ProjectAccessDenied("CALLER_REQUIRED")
        if self.service_evidence is None:
            raise ProjectAccessDenied("PROJECT_SERVICE_IDENTITY_REQUIRED")
        if self.operation_scope is not None and (
            not isinstance(self.operation_scope, ProjectOperationScope)
            or self.operation_scope.project_id != self.project_id
            or self.operation_scope.agent_session_uuid != self.session_uuid
        ):
            raise ProjectAccessDenied("PROJECT_OPERATION_SCOPE_INVALID")


@dataclass(frozen=True, slots=True)
class ProjectOwnerFence:
    """Opaque, owner-issued version triple; NOT a cross-DB SQL transaction.

    Each independently trusted source must recheck Identity activity,
    Control Project/Team membership and Access Session revocation at the
    actual effect boundary. Projections/events are never these proofs.
    """

    identity_version: int
    identity_revocation_epoch: int
    identity_authority_epoch: UUID
    control_state_version: int
    control_revision: str
    control_scope_epoch: int
    control_authority_epoch: UUID
    access_session_version: int
    access_revocation_epoch: int
    access_authority_epoch: UUID

    def valid(self) -> bool:
        return (
            type(self.identity_version) is int
            and self.identity_version >= 1
            and type(self.identity_revocation_epoch) is int
            and self.identity_revocation_epoch >= 0
            and isinstance(self.identity_authority_epoch, UUID)
            and self.identity_authority_epoch.version == 4
            and type(self.control_state_version) is int
            and self.control_state_version >= 1
            and valid_project_revision(self.control_revision)
            and type(self.control_scope_epoch) is int
            and self.control_scope_epoch >= 0
            and isinstance(self.control_authority_epoch, UUID)
            and self.control_authority_epoch.version == 4
            and type(self.access_session_version) is int
            and self.access_session_version >= 1
            and type(self.access_revocation_epoch) is int
            and self.access_revocation_epoch >= 0
            and isinstance(self.access_authority_epoch, UUID)
            and self.access_authority_epoch.version == 4
        )


@dataclass(frozen=True, slots=True)
class ProjectPermit:
    """Internal result issued ONLY by an authenticated backend authorization port."""

    project_id: UUID
    actor_id: UUID
    session_uuid: UUID
    action: ProjectAction
    expires_at: datetime
    decision_version: int
    project_access_revision: str | None = None
    project_owner_scope: Literal["team", "project"] | None = None
    project_owner_id: UUID | None = None
    owner_fence: ProjectOwnerFence | None = None


class ProjectAccessPort(Protocol):
    async def authorize(
        self, invocation: ProjectInvocation, action: ProjectAction
    ) -> ProjectPermit: ...


class ProjectRuntimeAuthority:
    """Validates the backend decision before any private Project resource use.

    C1-B/C2 must bind a real port. No permissive in-process fallback exists.
    The permit is not a durable grant and must be refreshed before each action.
    """

    def __init__(
        self,
        port: ProjectAccessPort | None = None,
        *,
        operation_timeout_seconds: float = 10.0,
    ) -> None:
        if not math.isfinite(operation_timeout_seconds) or not 0 < operation_timeout_seconds <= 300:
            raise ValueError("Project authorization timeout must be finite and positive")
        self._operation_timeout_seconds = operation_timeout_seconds
        self._port = port

    async def require(self, invocation: ProjectInvocation, action: ProjectAction) -> ProjectPermit:
        if self._port is None:
            raise ProjectAccessDenied("PROJECT_AUTHORIZATION_UNAVAILABLE")
        try:
            async with asyncio.timeout(self._operation_timeout_seconds):
                permit = await self._port.authorize(invocation, action)
        except ProjectAccessDenied:
            raise
        except Exception as exc:
            raise ProjectAccessDenied("PROJECT_AUTHORIZATION_UNAVAILABLE") from exc
        if not isinstance(permit, ProjectPermit):
            raise ProjectAccessDenied("PROJECT_AUTHORIZATION_INVALID")
        if (
            permit.project_id != invocation.project_id
            or permit.session_uuid != invocation.session_uuid
            or permit.action != action
            or not isinstance(permit.actor_id, UUID)
            or type(permit.decision_version) is not int
            or permit.decision_version < 1
            # The previous single Authorization-global snapshot does not
            # authorize any new split-owner Project operation. All three
            # authoritative stores must independently attest source versions.
            or not isinstance(permit.owner_fence, ProjectOwnerFence)
            or not permit.owner_fence.valid()
            or permit.decision_version != permit.owner_fence.access_session_version
            or permit.project_access_revision != permit.owner_fence.control_revision
            or (
                permit.project_access_revision is not None
                and not valid_project_revision(permit.project_access_revision)
            )
            or (
                (permit.project_owner_scope is None) != (permit.project_owner_id is None)
                or (
                    permit.project_owner_scope is not None
                    and (
                        permit.project_owner_scope not in {"team", "project"}
                        or not isinstance(permit.project_owner_id, UUID)
                        or (
                            permit.project_owner_scope == "project"
                            and permit.project_owner_id != invocation.project_id
                        )
                    )
                )
            )
            or not isinstance(permit.expires_at, datetime)
            or permit.expires_at.tzinfo is None
            or permit.expires_at <= datetime.now(UTC)
        ):
            raise ProjectAccessDenied("PROJECT_AUTHORIZATION_INVALID")
        return permit
