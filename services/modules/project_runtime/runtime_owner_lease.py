"""Read-only verifier of A11 Runtime-owner lease JWS (NOT legacy A9).

The signed lease certifies an owner-local SQL nonce/version, not a running
process, child cleanup, browser consent, a fresh grant, or a new command.
Release trust and real C2 peer must be resolved outside an MCP request.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from common.owner_contracts import OwnerAuthorityUnavailable
from common.owner_runtime_signing import RuntimeOwnerJwsClaims, verify_owner_runtime_lease

from .authorization import (
    ProjectAccessDenied,
    ProjectAction,
    ProjectInvocation,
    ProjectRuntimeAuthority,
)
from .owner_authorization import VerifiedOwnerRecipient
from .owner_effects import OwnerEffectClient, OwnerEffectUnavailable

RuntimeOwnerKind = Literal["files", "terminal", "web_managed", "web_remote", "reverse"]


@dataclass(frozen=True, slots=True)
class PinnedRuntimeOwnerLeaseKey:
    """Trusted-release identity, never caller token/JWKS/ENV discovery."""

    issuer: str
    public_key: Ed25519PublicKey
    service_id: UUID
    instance_uuid: UUID
    expires_at: datetime


class RuntimeOwnerLeaseKeyPort(Protocol):
    async def pinned_runtime_lease_key(
        self, *, recipient: VerifiedOwnerRecipient
    ) -> PinnedRuntimeOwnerLeaseKey: ...


async def verify_current_runtime_owner_lease(
    invocation: ProjectInvocation,
    *,
    authority: ProjectRuntimeAuthority,
    effects: OwnerEffectClient,
    keys: RuntimeOwnerLeaseKeyPort | None,
    attestation_jws: str,
    runtime_session_uuid: UUID,
    lease_nonce: UUID,
    expected_version: int,
    kind: RuntimeOwnerKind,
) -> RuntimeOwnerJwsClaims:
    """Verify accepted split Runtime-owner JWS and current three-owner grant.

    This pure source adapter deliberately does not create a process/lease or
    certify an OS effect. It must be paired with a separately signed original
    owner command receipt and independently trusted supervisor observation.
    """
    action_by_kind: dict[RuntimeOwnerKind, ProjectAction] = {
        "files": "files.write",
        "terminal": "terminal.attach",
        "web_managed": "web.internal",
        "web_remote": "web.remote",
        "reverse": "reverse.import",
    }
    action = action_by_kind.get(kind)
    if (
        action is None
        or keys is None
        or type(expected_version) is not int
        or expected_version < 1
        or not all(
            isinstance(x, UUID) and x.version == 4 for x in (runtime_session_uuid, lease_nonce)
        )
    ):
        raise OwnerEffectUnavailable("RUNTIME_OWNER_SIGNED_LEASE_EXPECTATIONS_REQUIRED")
    initial = await authority.require(invocation, action)
    peer = await effects._recipient(invocation)
    try:
        async with asyncio.timeout(min(5, effects.timeout_seconds)):
            trusted = await keys.pinned_runtime_lease_key(recipient=peer)
    except Exception as exc:
        raise OwnerEffectUnavailable("RUNTIME_OWNER_RELEASE_PIN_UNAVAILABLE") from exc
    now = datetime.now(UTC)
    if (
        not isinstance(trusted, PinnedRuntimeOwnerLeaseKey)
        or not isinstance(trusted.public_key, Ed25519PublicKey)
        or not trusted.issuer.startswith("briareus:")
        or trusted.service_id != peer.service_id
        or trusted.instance_uuid != peer.instance_uuid
        or trusted.expires_at.tzinfo is None
        or not now < trusted.expires_at <= peer.expires_at
    ):
        raise OwnerEffectUnavailable("RUNTIME_OWNER_RELEASE_PIN_INVALID")
    try:
        signed = verify_owner_runtime_lease(
            attestation_jws,
            pinned_public_key=trusted.public_key,
            trusted_issuer=trusted.issuer,
            expected_runtime_session_uuid=runtime_session_uuid,
            expected_project_id=initial.project_id,
            expected_actor_user_id=initial.actor_id,
            expected_agent_session_uuid=initial.session_uuid,
            expected_service_id=peer.service_id,
            expected_instance_uuid=peer.instance_uuid,
            expected_lease_nonce=lease_nonce,
            expected_version=expected_version,
        )
    except OwnerAuthorityUnavailable as exc:
        raise OwnerEffectUnavailable("RUNTIME_OWNER_SIGNED_LEASE_UNVERIFIED", unknown=True) from exc
    if signed.kind != kind or signed.exp <= int(now.timestamp()):
        raise OwnerEffectUnavailable("RUNTIME_OWNER_LEASE_KIND_OR_TTL_STALE", unknown=True)
    refreshed = await authority.require(invocation, action)
    if (
        refreshed.project_id != initial.project_id
        or refreshed.actor_id != initial.actor_id
        or refreshed.session_uuid != initial.session_uuid
        or refreshed.owner_fence != initial.owner_fence
        or refreshed.project_access_revision != initial.project_access_revision
        or refreshed.project_owner_id != initial.project_owner_id
        or refreshed.project_owner_scope != initial.project_owner_scope
        or refreshed.expires_at <= datetime.now(UTC)
    ):
        raise ProjectAccessDenied("RUNTIME_OWNER_LEASE_GRANT_REVOKED")
    return signed
