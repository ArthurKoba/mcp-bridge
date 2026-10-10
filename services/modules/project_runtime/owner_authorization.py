"""Private split-owner Identity + Control + Access source authentication.

This contract is a deliberately UNMOUNTED Runtime consumer boundary while
Backend A11 independently defines its wire DTOs and per-owner signers. The
only issuer of an executable decision is the actual trusted owner transaction:
three signed, short-lived snapshots with fenced versions are EXPECTED STATE,
not portable bearer tokens and not a distributed PostgreSQL transaction.

An unavailable owner, missing C2 verified recipient, stale JWS or pending
Project transfer closes ALL protected effects before Files/Execution/Catalog.
A global Authorization SQL Session or async websocket projection is never a
fallback. No service private key or Team secret is accepted as a tool value.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .authorization import (
    ProjectAccessDenied,
    ProjectAccessPort,
    ProjectAction,
    ProjectInvocation,
    ProjectOwnerFence,
    ProjectPermit,
    valid_project_revision,
)

OwnerName = Literal["identity", "platform", "access"]
_OWNER_DATABASE = {
    "identity": "briareus_identity",
    "platform": "briareus_platform",
    "access": "briareus_access",
}


def _uuid4(value: object) -> bool:
    return isinstance(value, UUID) and value.version == 4


def _key_fingerprint(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(
        key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()


class OwnerDecision(BaseModel):
    """Strict signed ONE-owner decision; no raw secret/credential/user data.

    Owner-specific fields are intentionally distinct. A11 may replace this
    *private candidate wire contract* during independently accepted fan-in.
    No endpoint is assumed or generated from these DTO fields.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    protocol: Literal["split-owner-effect-v1"] = "split-owner-effect-v1"
    owner: OwnerName
    database: Literal["briareus_identity", "briareus_platform", "briareus_access"]
    recipient_service_id: UUID
    recipient_instance_uuid: UUID
    project_id: UUID
    actor_id: UUID
    session_uuid: UUID
    operation_uuid: UUID
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    action: ProjectAction
    state_version: int = Field(ge=1)
    revoke_epoch: int = Field(ge=0)
    authority_epoch: UUID
    active: bool
    expires_at: datetime
    # Control alone is authoritative for actual Team/Project owner, Project
    # access revision and allowed action. No Access read projection can mint it.
    project_revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    owner_scope: Literal["team", "project"] | None = None
    owner_id: UUID | None = None
    granted_actions: tuple[ProjectAction, ...] = ()
    # Access alone is authoritative for AgentSession grant/hard expiry.
    session_hard_expires_at: datetime | None = None
    transfer_pending: bool = False

    @model_validator(mode="after")
    def check_owner_state(self) -> OwnerDecision:
        if (
            self.database != _OWNER_DATABASE[self.owner]
            or not all(
                _uuid4(value)
                for value in (
                    self.recipient_service_id,
                    self.recipient_instance_uuid,
                    self.session_uuid,
                    self.operation_uuid,
                )
            )
            or not isinstance(self.project_id, UUID)
            or not isinstance(self.actor_id, UUID)
            or not isinstance(self.expires_at, datetime)
            or self.expires_at.tzinfo is None
            or not _uuid4(self.authority_epoch)
            or len(set(self.granted_actions)) != len(self.granted_actions)
        ):
            raise ValueError("invalid owner decision scope")
        if self.owner == "identity":
            if (
                self.project_revision is not None
                or self.owner_scope is not None
                or self.owner_id is not None
                or self.granted_actions
                or self.session_hard_expires_at is not None
                or self.transfer_pending
            ):
                raise ValueError("Identity cannot mint Project or Session grants")
        elif self.owner == "platform":
            if (
                not valid_project_revision(self.project_revision)
                or self.owner_scope not in {"team", "project"}
                or self.owner_id is None
                or (self.owner_scope == "project" and self.owner_id != self.project_id)
                or self.session_hard_expires_at is not None
            ):
                raise ValueError("Control Project ownership invalid")
        elif (
            self.project_revision is not None
            or self.owner_scope is not None
            or self.owner_id is not None
            or self.session_hard_expires_at is None
            or self.session_hard_expires_at.tzinfo is None
            or self.transfer_pending
        ):
            raise ValueError("Access cannot assert Control ownership")
        return self


class SignedOwnerDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    decision: OwnerDecision
    attestation_jws: str = Field(min_length=100, max_length=8192)


@dataclass(frozen=True, slots=True)
class VerifiedOwnerRecipient:
    service_id: UUID
    instance_uuid: UUID
    expires_at: datetime
    transport: Literal["mtls", "unix-peer"]


class OwnerRecipientPort(Protocol):
    """C2 independently verifies exact TLS/Unix peer, never an MCP header."""

    async def verified_recipient(self, evidence: object) -> VerifiedOwnerRecipient: ...


class OwnerPublicKeyPort(Protocol):
    """Pins each distinct database owner's signer outside untrusted JSON."""

    async def pinned_owner_key(
        self,
        owner: OwnerName,
        *,
        recipient: VerifiedOwnerRecipient,
    ) -> Ed25519PublicKey: ...


class OwnerAuthorizationPort(Protocol):
    """One owner-local SQL transaction with its own signed, fresh outcome.

    A11 must authenticate the service plus human/caller, original operation
    body/hash, recipient, Identity/Control/Access dependency revision and
    consume owner-local assertion JTI before signing the current answer.
    The decision is not accepted merely because an HTTP request succeeded.
    Every call is fresh; no cached grant, generic global SQL session, or
    event/projection used for privileged effects.
    """

    async def decide(
        self,
        owner: OwnerName,
        invocation: ProjectInvocation,
        *,
        action: ProjectAction,
        recipient: VerifiedOwnerRecipient,
    ) -> SignedOwnerDecision: ...


class SplitOwnerSourceAuthorization(ProjectAccessPort):
    """Version-fenced 3-owner permit consumer, fail-closed on absent ports.

    Denies if either current Identity revocation, Control membership/Project
    ownership, or Access Session approval disagrees. A second Identity+Control
    check catches changes while another owner was consulted. It does not
    pretend five separate owner reads form an atomic DB transaction; the
    durable Files/Runtime/Reverse/Catalog writer must check the SAME epochs
    again in its own owner-local committed transaction at effect time.
    """

    def __init__(
        self,
        *,
        recipients: OwnerRecipientPort | None = None,
        sources: OwnerAuthorizationPort | None = None,
        trusted_keys: OwnerPublicKeyPort | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 15:
            raise ValueError("split-owner authorization timeout invalid")
        self.recipients = recipients
        self.sources = sources
        self.trusted_keys = trusted_keys
        self.timeout_seconds = timeout_seconds

    async def _fetch(
        self,
        owner: OwnerName,
        invocation: ProjectInvocation,
        action: ProjectAction,
        recipient: VerifiedOwnerRecipient,
    ) -> OwnerDecision:
        assert self.sources is not None and self.trusted_keys is not None
        try:
            async with asyncio.timeout(self.timeout_seconds):
                signed = await self.sources.decide(
                    owner,
                    invocation,
                    action=action,
                    recipient=recipient,
                )
                key = await self.trusted_keys.pinned_owner_key(
                    owner,
                    recipient=recipient,
                )
            if not isinstance(signed, SignedOwnerDecision) or not isinstance(key, Ed25519PublicKey):
                raise ProjectAccessDenied("OWNER_SIGNATURE_UNAVAILABLE")
            header = jwt.get_unverified_header(signed.attestation_jws)
            if (
                header.get("alg") != "EdDSA"
                or header.get("typ") != "briareus-owner-effect+jwt"
                or header.get("kid") != _key_fingerprint(key)
                or header.get("crit")
            ):
                raise ProjectAccessDenied("OWNER_SIGNER_UNTRUSTED")
            claims = jwt.decode(
                signed.attestation_jws,
                key,
                algorithms=["EdDSA"],
                audience=f"owner-effect:{recipient.service_id}",
                issuer=f"briareus-{owner}",
                leeway=0,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                        "purpose",
                        "decision",
                    ]
                },
            )
            jti = UUID(claims["jti"])
            decoded = OwnerDecision.model_validate_json(
                json.dumps(claims["decision"], sort_keys=True, separators=(",", ":"))
            )
            expected = invocation.operation_scope
            now = datetime.now(UTC)
            if (
                not _uuid4(jti)
                or claims["purpose"] != "split-owner-effect-v1"
                or type(claims["iat"]) is not int
                or type(claims["exp"]) is not int
                or not 0 < claims["exp"] - claims["iat"] <= 15
                or decoded != signed.decision
                or expected is None
                or decoded.owner != owner
                or decoded.database != _OWNER_DATABASE[owner]
                or decoded.project_id != invocation.project_id
                or decoded.session_uuid != invocation.session_uuid
                or decoded.operation_uuid != expected.request_uuid
                or decoded.request_sha256 != expected.fingerprint
                or decoded.action != action
                or decoded.recipient_service_id != recipient.service_id
                or decoded.recipient_instance_uuid != recipient.instance_uuid
                or decoded.expires_at <= now
                or decoded.expires_at > recipient.expires_at
                or decoded.expires_at > datetime.fromtimestamp(claims["exp"], UTC)
                or not decoded.active
                or decoded.transfer_pending
            ):
                raise ProjectAccessDenied("OWNER_DECISION_STALE_OR_INVALID")
            return decoded
        except ProjectAccessDenied:
            raise
        except (jwt.PyJWTError, ValidationError, ValueError, TypeError, KeyError) as exc:
            raise ProjectAccessDenied("OWNER_SIGNATURE_INVALID") from exc
        except Exception as exc:
            raise ProjectAccessDenied("OWNER_CURRENT_AUTHORITY_UNAVAILABLE") from exc

    async def authorize(
        self,
        invocation: ProjectInvocation,
        action: ProjectAction,
    ) -> ProjectPermit:
        if (
            self.recipients is None
            or self.sources is None
            or self.trusted_keys is None
            or invocation.service_evidence is None
            or invocation.caller_evidence is None
            or invocation.operation_scope is None
            or invocation.operation_scope.action != action
        ):
            raise ProjectAccessDenied("SPLIT_OWNER_SERVICE_PORTS_REQUIRED")
        try:
            async with asyncio.timeout(self.timeout_seconds):
                recipient = await self.recipients.verified_recipient(invocation.service_evidence)
        except Exception as exc:
            raise ProjectAccessDenied("SPLIT_OWNER_C2_PEER_UNAVAILABLE") from exc
        if (
            not isinstance(recipient, VerifiedOwnerRecipient)
            or not _uuid4(recipient.service_id)
            or not _uuid4(recipient.instance_uuid)
            or recipient.transport not in {"mtls", "unix-peer"}
            or recipient.expires_at.tzinfo is None
            or recipient.expires_at <= datetime.now(UTC)
        ):
            raise ProjectAccessDenied("SPLIT_OWNER_C2_PEER_INVALID")
        identity = await self._fetch("identity", invocation, action, recipient)
        control = await self._fetch("platform", invocation, action, recipient)
        access = await self._fetch("access", invocation, action, recipient)
        # No optimistic role inheritance: Team permission can only come from
        # Control owner, not a personal Project or alias string.
        if (
            identity.actor_id != control.actor_id
            or identity.actor_id != access.actor_id
            or action not in control.granted_actions
            or action not in access.granted_actions
            or access.session_hard_expires_at is None
            or access.session_hard_expires_at <= datetime.now(UTC)
        ):
            raise ProjectAccessDenied("SPLIT_OWNER_PRIVILEGE_OR_SESSION_REVOKED")
        # Verify no Identity/Control change while reading Access. This is an
        # expected-state fence for Files/Execution owner-local write, not a
        # guarantee that separate DB transactions were globally atomic.
        fresh_identity = await self._fetch("identity", invocation, action, recipient)
        fresh_control = await self._fetch("platform", invocation, action, recipient)
        if (
            fresh_identity.actor_id != identity.actor_id
            or fresh_identity.state_version != identity.state_version
            or fresh_identity.revoke_epoch != identity.revoke_epoch
            or fresh_identity.authority_epoch != identity.authority_epoch
            or fresh_identity.active != identity.active
            or fresh_control.actor_id != control.actor_id
            or fresh_control.state_version != control.state_version
            or fresh_control.revoke_epoch != control.revoke_epoch
            or fresh_control.authority_epoch != control.authority_epoch
            or fresh_control.project_revision != control.project_revision
            or fresh_control.owner_scope != control.owner_scope
            or fresh_control.owner_id != control.owner_id
            or fresh_control.granted_actions != control.granted_actions
            or fresh_control.transfer_pending != control.transfer_pending
        ):
            # A new JWS has a new JTI/expiry; only AUTHORITATIVE owner
            # state/epochs must remain unchanged across the Access read.
            raise ProjectAccessDenied("SPLIT_OWNER_REVOCATION_DURING_REQUEST")
        revision = control.project_revision
        if not isinstance(revision, str):
            raise ProjectAccessDenied("SPLIT_OWNER_PROJECT_REVISION_REQUIRED")
        fence = ProjectOwnerFence(
            identity_version=identity.state_version,
            identity_revocation_epoch=identity.revoke_epoch,
            identity_authority_epoch=identity.authority_epoch,
            control_state_version=control.state_version,
            control_revision=revision,
            control_scope_epoch=control.revoke_epoch,
            control_authority_epoch=control.authority_epoch,
            access_session_version=access.state_version,
            access_revocation_epoch=access.revoke_epoch,
            access_authority_epoch=access.authority_epoch,
        )
        if not fence.valid():
            raise ProjectAccessDenied("SPLIT_OWNER_REVISION_INVALID")
        expires = min(
            identity.expires_at,
            control.expires_at,
            access.expires_at,
            recipient.expires_at,
            access.session_hard_expires_at,
            datetime.now(UTC) + timedelta(seconds=5),
        )
        if expires <= datetime.now(UTC):
            raise ProjectAccessDenied("SPLIT_OWNER_PROOFS_EXPIRED")
        return ProjectPermit(
            project_id=invocation.project_id,
            actor_id=identity.actor_id,
            session_uuid=invocation.session_uuid,
            action=action,
            expires_at=expires,
            decision_version=access.state_version,
            project_access_revision=revision,
            project_owner_scope=control.owner_scope,
            project_owner_id=control.owner_id,
            owner_fence=fence,
        )
