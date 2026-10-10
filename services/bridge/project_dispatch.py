"""Unmounted Briareus Project dispatch, signed A6 actions only.

C1-B/C2 must provide a verified principal/session/grants transport and typed
backend identity. This is a private composition root, NOT a public MCP tool.
"""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import UUID, uuid4

from common.models import JsonObject
from modules.project_runtime import (
    ProjectAction,
    ProjectInvocation,
    ProjectOperationScope,
    ProjectPermit,
    ProjectRuntimeAuthority,
    canonical_request_fingerprint,
)

# C2-UNMOUNTED source registry; operation cannot be selected by untrusted
# MCP arguments or by an accidentally permissive classifier implementation.
# Exactly one bounded mutation is staged: Files upload under A6 signed quota.
_PRIVATE_TOOL_ACTIONS: dict[tuple[str, str], ProjectAction] = {
    ("files", "list"): "files.read",
    ("files", "info"): "files.read",
    ("files", "read_base64"): "files.read",
    ("files", "sha256"): "files.read",
    ("files", "upload_base64"): "files.write",
    ("files", "write_status"): "files.write",
    ("github", "connections"): "svc.read",
    ("gitlab", "connections"): "svc.read",
    ("observability", "connections"): "infrastructure.read",
    ("variables", "metadata"): "resources.use",
}
_MUTATING_ACTIONS: frozenset[ProjectAction] = frozenset(
    {
        "files.write",
        "files.manage",
        "terminal.attach",
        "web.internal",
        "web.remote",
        "reverse.import",
        "svc.write",
    }
)
_FORBIDDEN_KEYS = frozenset(
    {
        "project_key",
        "session_uuid",
        "api_key",
        "api_token",
        "password",
        "secret",
        "bearer",
        "caller_evidence",
        "service_evidence",
        "authorization",
        "access_token",
        "refresh_token",
        "private_key",
        "credential",
    }
)


class ProjectGatewayDispatchUnavailable(Exception):
    """Stable internal error code; never includes private backend messages."""

    def __init__(self, code: str, *, operation_uuid: UUID | None = None) -> None:
        self.code = code
        self.operation_uuid = operation_uuid
        # If an externally meaningful write may have committed, callers must
        # inspect its SAME UUID instead of retrying or creating a new key.
        self.outcome_unknown = code in {
            "PROJECT_FILE_OUTCOME_UNKNOWN",
            "PROJECT_BACKEND_OUTCOME_UNKNOWN",
        }
        super().__init__(code)


def _deny_raw_credentials(
    value: object, *, depth: int = 0, budget: list[int] | None = None
) -> None:
    """Bound hostile nested JSON size and ban reserved credential/identity keys."""
    if depth > 12:
        raise ProjectGatewayDispatchUnavailable("PROJECT_ARGUMENTS_TOO_DEEP")
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > 2048:
        raise ProjectGatewayDispatchUnavailable("PROJECT_ARGUMENTS_TOO_LARGE")
    if isinstance(value, dict):
        if len(value) > 128:
            raise ProjectGatewayDispatchUnavailable("PROJECT_ARGUMENTS_TOO_LARGE")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128 or key.casefold() in _FORBIDDEN_KEYS:
                raise ProjectGatewayDispatchUnavailable("PROJECT_ARGUMENTS_FORBIDDEN")
            _deny_raw_credentials(item, depth=depth + 1, budget=budget)
    elif isinstance(value, list):
        if len(value) > 2048:
            raise ProjectGatewayDispatchUnavailable("PROJECT_ARGUMENTS_TOO_LARGE")
        for item in value:
            _deny_raw_credentials(item, depth=depth + 1, budget=budget)
    elif isinstance(value, str):
        if len(value) > 350000:
            raise ProjectGatewayDispatchUnavailable("PROJECT_ARGUMENTS_TOO_LARGE")
    elif not isinstance(value, (type(None), bool, int, float)):
        raise ProjectGatewayDispatchUnavailable("PROJECT_ARGUMENTS_INVALID")


OwnerServiceName = Literal["identity", "access", "control", "catalog"]
_OWNER_STORE: dict[OwnerServiceName, str] = {
    "identity": "briareus_identity",
    "access": "briareus_access",
    "control": "briareus_platform",
    "catalog": "briareus_resources",
}


@dataclass(frozen=True, slots=True)
class VerifiedOwnerReadiness:
    """Recipient-bound read-only health, NOT bearer authorization.

    `ProjectOwnerReadinessPort` must independently check actual pinned owner
    signature, service transport, DB identity/role, exact installed migration
    head and bounded readiness timestamp. This object alone proves nothing.
    """

    owner: OwnerServiceName
    database: str
    schema_head: str
    database_role: str
    owner_service_id: UUID
    expires_at: datetime


class ProjectOwnerReadinessPort(Protocol):
    """Require distinct verified current schema+role of EACH initial owner.

    Backend A11+Deployment must define signed C2 transport/head contracts.
    Neither Data PostgreSQL health nor historical global A10 migration counts.
    No gateway SQL/Alembic DDL, no cached "ready" or env boolean fallback.
    """

    async def require_current_owner_schema(
        self,
        invocation: ProjectInvocation,
        *,
        owner: OwnerServiceName,
    ) -> VerifiedOwnerReadiness: ...


@dataclass(frozen=True, slots=True)
class ExpectedOwnerSchema:
    """Accepted signed RELEASE manifest, never supplied by the DB itself."""

    owner: OwnerServiceName
    database: str
    expected_head: str
    expected_role: str
    expected_service_id: UUID


class ProjectOwnerReleaseManifestPort(Protocol):
    """Version-locked artifact from reviewed A11+D4 release, not ENV/SQL.

    The installed owner's own self-reported head/version cannot determine
    which migration release is authorized. A separate trusted release manifest
    must pin DB identity, role, exact accepted Alembic head and issuer ID.
    Without it gateway refuses the complete protected Project operation.
    """

    async def expected_schema(self, owner: OwnerServiceName) -> ExpectedOwnerSchema: ...


class ProjectToolClassifier(Protocol):
    async def classify(self, backend: str, tool: str) -> ProjectAction | None: ...


@dataclass(frozen=True, slots=True)
class AuthorizedToolForward:
    backend: str
    tool: str
    arguments: JsonObject
    permit: ProjectPermit
    request_uuid: UUID
    invocation: ProjectInvocation


class AuthenticatedProjectForwarder(Protocol):
    async def normalize(self, *, backend: str, tool: str, arguments: JsonObject) -> JsonObject: ...

    async def forward(self, request: AuthorizedToolForward) -> JsonObject: ...


class ProjectGatewayDispatch:
    """A private allowlisted entry requiring real per-call Project authorization.

    Upstream service must independently validate service identity and its
    actor/Project context. A Python permit alone is never a wire credential.
    """

    def __init__(
        self,
        authority: ProjectRuntimeAuthority,
        *,
        classifier: ProjectToolClassifier | None = None,
        forwarder: AuthenticatedProjectForwarder | None = None,
        readiness: ProjectOwnerReadinessPort | None = None,
        release_manifest: ProjectOwnerReleaseManifestPort | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
            raise ValueError("Project dispatch timeout out of bounds")
        self.authority = authority
        self.timeout_seconds = timeout_seconds
        self._classifier = classifier
        self._forwarder = forwarder
        self._readiness = readiness
        self._release_manifest = release_manifest

    async def dispatch(
        self,
        invocation: ProjectInvocation,
        *,
        backend: str,
        tool: str,
        arguments: JsonObject | None = None,
        request_uuid: UUID | None = None,
    ) -> JsonObject:
        if self._classifier is None or self._forwarder is None:
            raise ProjectGatewayDispatchUnavailable("PROJECT_DISPATCH_NOT_CONFIGURED")
        if self._readiness is None or self._release_manifest is None:
            raise ProjectGatewayDispatchUnavailable("PROJECT_OWNER_SCHEMAS_NOT_READY")
        expected_action = _PRIVATE_TOOL_ACTIONS.get((backend, tool))
        if expected_action is None:
            # Native Ghidra and arbitrary internal backends are NOT public.
            raise ProjectGatewayDispatchUnavailable("PROJECT_BACKEND_NOT_PUBLIC")
        forwarded = arguments if arguments is not None else {}
        if not isinstance(forwarded, dict):
            raise ProjectGatewayDispatchUnavailable("PROJECT_ARGUMENTS_INVALID")
        _deny_raw_credentials(forwarded)
        forwarded_to_effect = False
        try:
            # Gateway has ZERO SQL/migration privileges. Four independent
            # initial authoritative DBs must each be on its own accepted
            # owner-specific head and role; no former briareus_dev global head
            # is an acceptable migration/readiness shortcut.
            try:
                async with asyncio.timeout(min(self.timeout_seconds, 10.0)):
                    for name in ("identity", "access", "control", "catalog"):
                        expected = await self._release_manifest.expected_schema(name)
                        snapshot = await self._readiness.require_current_owner_schema(
                            invocation,
                            owner=name,
                        )
                        if (
                            not isinstance(snapshot, VerifiedOwnerReadiness)
                            or snapshot.owner != name
                            or snapshot.database != _OWNER_STORE[name]
                            or not isinstance(expected, ExpectedOwnerSchema)
                            or expected.owner != name
                            or expected.database != snapshot.database
                            or not isinstance(expected.expected_head, str)
                            or not isinstance(expected.expected_role, str)
                            or not isinstance(snapshot.schema_head, str)
                            or not isinstance(snapshot.database_role, str)
                            or snapshot.schema_head != expected.expected_head
                            or snapshot.database_role != expected.expected_role
                            or not 1 <= len(snapshot.schema_head) <= 128
                            or not 1 <= len(snapshot.database_role) <= 128
                            or not isinstance(snapshot.owner_service_id, UUID)
                            or snapshot.owner_service_id.version != 4
                            or snapshot.owner_service_id != expected.expected_service_id
                            or not isinstance(snapshot.expires_at, datetime)
                            or snapshot.expires_at.tzinfo is None
                            or snapshot.expires_at <= datetime.now(UTC)
                        ):
                            raise ProjectGatewayDispatchUnavailable(
                                "PROJECT_OWNER_SCHEMA_REVISION_INVALID"
                            )
            except Exception as exc:
                # No owner-verified current head => deny BEFORE normalization,
                # classifier, signed operation or any File/worker/provider
                # side effect. Do not show SQL/transport error or auto-retry.
                raise ProjectGatewayDispatchUnavailable("PROJECT_OWNER_SCHEMA_UNAVAILABLE") from exc
            async with asyncio.timeout(self.timeout_seconds):
                action = await self._classifier.classify(backend, tool)
                if action is None or action != expected_action:
                    raise ProjectGatewayDispatchUnavailable("PROJECT_TOOL_NOT_AUTHORIZED")
                if request_uuid is not None and (
                    not isinstance(request_uuid, UUID) or request_uuid.version != 4
                ):
                    raise ProjectGatewayDispatchUnavailable("PROJECT_REQUEST_UUID_INVALID")
                if request_uuid is None and action in _MUTATING_ACTIONS:
                    raise ProjectGatewayDispatchUnavailable("PROJECT_IDEMPOTENCY_KEY_REQUIRED")
                operation_uuid = request_uuid if request_uuid is not None else uuid4()
                prepared = await self._forwarder.normalize(
                    backend=backend, tool=tool, arguments=forwarded
                )
                _deny_raw_credentials(prepared)
                # A6 SQL idempotency key and signed operation UUID must equal
                # the canonical upload UUID in the validated payload.
                if action == "files.write" and prepared.get("operation_uuid") != str(
                    operation_uuid
                ):
                    raise ProjectGatewayDispatchUnavailable("PROJECT_REQUEST_UUID_MISMATCH")
                scope = ProjectOperationScope(
                    project_id=invocation.project_id,
                    agent_session_uuid=invocation.session_uuid,
                    action=action,
                    request_uuid=operation_uuid,
                    fingerprint=canonical_request_fingerprint(
                        project_id=invocation.project_id,
                        session_uuid=invocation.session_uuid,
                        action=action,
                        request_uuid=operation_uuid,
                        backend=backend,
                        tool=tool,
                        arguments=prepared,
                    ),
                )
                scoped = replace(invocation, operation_scope=scope)
                permit = await self.authority.require(scoped, action)
                # Never retry a write after a transport timeout: its outcome
                # must be recovered from Backend's durable idempotency ledger.
                request = AuthorizedToolForward(
                    backend, tool, prepared, permit, operation_uuid, scoped
                )
                forwarded_to_effect = True
                return await self._forwarder.forward(request)
        except TimeoutError as exc:
            if not forwarded_to_effect:
                raise ProjectGatewayDispatchUnavailable(
                    "PROJECT_AUTHORIZATION_SCHEMA_UNAVAILABLE"
                ) from exc
            # Only an already-dispatched write is an UNKNOWN SIDE EFFECT.
            # Read-only status queries should not masquerade as new writes.
            if backend == "files" and tool == "upload_base64":
                raise ProjectGatewayDispatchUnavailable(
                    "PROJECT_FILE_OUTCOME_UNKNOWN", operation_uuid=request_uuid
                ) from exc
            if backend == "files" and tool == "write_status":
                raise ProjectGatewayDispatchUnavailable(
                    "PROJECT_FILE_STATUS_UNAVAILABLE", operation_uuid=request_uuid
                ) from exc
            raise ProjectGatewayDispatchUnavailable("PROJECT_BACKEND_TIMEOUT") from exc
        except ProjectGatewayDispatchUnavailable:
            raise
        except Exception as exc:
            # Internal provider/files exceptions may carry private paths,
            # HTTP headers or SDK tokens; do not echo them into MCP metadata.
            raise ProjectGatewayDispatchUnavailable("PROJECT_BACKEND_ERROR") from exc
