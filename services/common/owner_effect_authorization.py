"""Canonical R13-compatible v1 signed Identity/Control/Access owner decisions.

PRIVATE source DTO, not C1-B2/C2 transport authority. A signed claim is
produced only after owner-local authoritative SQL + independently verified
human delegation/service peer. No Project ID or event projection is a grant.

Wire parity: Runtime `modules/project_runtime/owner_authorization.OwnerDecision`
(accepted R13 source, now awaiting R14 independent integration review).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, model_validator

from common.owner_contracts import OwnerAuthorityUnavailable, VerifiedOwnerServicePeer
from common.platform_db import OWNER_DB_NAMES

SourceOwner = Literal["identity", "platform", "access"]
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

_DECISION_TTL_SECONDS = 15
_ISSUER = {
    "identity": "briareus-identity",
    "platform": "briareus-platform",
    "access": "briareus-access",
}
_JWT_TYPE = "briareus-owner-effect+jwt"
_PURPOSE = "split-owner-effect-v1"


def _v4(value: UUID) -> bool:
    return isinstance(value, UUID) and value.version == 4


def _hash(payload: object) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_project_access_revision(
    *,
    project_id: UUID,
    project_version: int,
    resource_revision: int,
    owner_user_id: UUID | None,
    owner_team_id: UUID | None,
    team_version: int | None,
    team_resource_revision: int | None,
    membership_revision: int | None,
    actor_user_id: UUID,
    identity_credential_revision: int,
    role: str,
    lifecycle_status: str,
) -> str:
    """Canonical owner-local current Project SHA; NO queued permission view.

    A Team membership change, Project transfer, User role/credential revision,
    Project lifecycle or resource rotation changes this revision. Consumers
    compare exact SHA with a NEW Control-signed version before every effect.
    """
    if (owner_user_id is None) == (owner_team_id is None):
        raise OwnerAuthorityUnavailable("Control exclusive Project owner is invalid")
    if any(x.version != 4 for x in (project_id, actor_user_id)):
        raise OwnerAuthorityUnavailable("Control Project/actor UUID not valid")
    if project_version < 1 or resource_revision < 0 or identity_credential_revision < 1:
        raise OwnerAuthorityUnavailable("Control revision invalid")
    return _hash(
        [
            "briareus-control-project-revision-v1",
            str(project_id),
            project_version,
            resource_revision,
            str(owner_user_id) if owner_user_id else None,
            str(owner_team_id) if owner_team_id else None,
            team_version,
            team_resource_revision,
            membership_revision,
            str(actor_user_id),
            identity_credential_revision,
            role,
            lifecycle_status,
        ]
    )


def derive_source_epoch(owner: SourceOwner, *components: object) -> UUID:
    """Stable signed owner fencing UUID derived from current DB state.

    Not a bearer, not a randomly regenerated value on each proof. When any
    originating source row version/revocation changes, the epoch changes.
    """
    if not components or any(value is None for value in components):
        raise OwnerAuthorityUnavailable("incomplete authoritative owner epoch")
    raw = bytearray(bytes.fromhex(_hash(("briareus-owner-state-v1", owner, components)))[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return UUID(bytes=bytes(raw))


class OwnerEffectIntent(BaseModel):
    """Original ProjectOperationScope + authenticated recipient (not bearer)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    project_id: UUID
    actor_id: UUID
    session_uuid: UUID
    operation_uuid: UUID
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    action: ProjectAction
    recipient_service_id: UUID
    recipient_instance_uuid: UUID

    @model_validator(mode="after")
    def valid_identity(self) -> OwnerEffectIntent:
        if not all(
            _v4(v)
            for v in (
                self.project_id,
                self.actor_id,
                self.session_uuid,
                self.operation_uuid,
                self.recipient_service_id,
                self.recipient_instance_uuid,
            )
        ):
            raise ValueError("effect scope UUID must be real UUIDv4")
        return self


class OwnerDecision(BaseModel):
    """Exact Runtime R13 private v1 Pydantic field names and wire values."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    protocol: Literal["split-owner-effect-v1"] = "split-owner-effect-v1"
    owner: SourceOwner
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
    project_revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    owner_scope: Literal["team", "project"] | None = None
    owner_id: UUID | None = None
    granted_actions: tuple[ProjectAction, ...] = ()
    session_hard_expires_at: datetime | None = None
    transfer_pending: bool = False

    @model_validator(mode="after")
    def owner_provenance(self) -> OwnerDecision:
        if (
            self.database != OWNER_DB_NAMES[self.owner]
            or not all(
                _v4(value)
                for value in (
                    self.project_id,
                    self.actor_id,
                    self.session_uuid,
                    self.operation_uuid,
                    self.recipient_service_id,
                    self.recipient_instance_uuid,
                    self.authority_epoch,
                )
            )
            or self.expires_at.tzinfo is None
            or len(self.granted_actions) != len(set(self.granted_actions))
        ):
            raise ValueError("owner decision provenance mismatch")
        if self.owner == "identity":
            if (
                self.project_revision is not None
                or self.owner_scope is not None
                or self.owner_id is not None
                or self.granted_actions
                or self.session_hard_expires_at is not None
                or self.transfer_pending
            ):
                raise ValueError("Identity cannot assert Project/Session privileges")
        elif self.owner == "platform":
            if (
                self.project_revision is None
                or self.owner_scope is None
                or self.owner_id is None
                or not _v4(self.owner_id)
                or (self.owner_scope == "project" and self.owner_id != self.project_id)
                or self.session_hard_expires_at is not None
            ):
                raise ValueError("Control ownership/Project SHA missing")
        elif (
            self.project_revision is not None
            or self.owner_scope is not None
            or self.owner_id is not None
            or self.session_hard_expires_at is None
            or self.session_hard_expires_at.tzinfo is None
            or self.transfer_pending
        ):
            raise ValueError("Access cannot assert Project ownership")
        return self


class SignedOwnerDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    decision: OwnerDecision
    attestation_jws: str = Field(min_length=100, max_length=8192)


@dataclass(frozen=True, slots=True)
class OwnerEffectAuthoritySnapshot:
    """Produced only by validated source SQL reader in its OWN database."""

    owner: SourceOwner
    intent: OwnerEffectIntent
    state_version: int
    revoke_epoch: int
    authority_epoch: UUID
    active: bool
    issued_from_owner_db: str
    project_revision: str | None = None
    owner_scope: Literal["team", "project"] | None = None
    owner_id: UUID | None = None
    granted_actions: tuple[ProjectAction, ...] = ()
    session_hard_expires_at: datetime | None = None
    transfer_pending: bool = False
    # Physical human delegation and Access hard-expiry can shorten JWT TTL.
    source_expires_at: datetime | None = None


class OwnerEffectDecisionSigner:
    """Independent source-private signer pinned by service release/C2 verifier."""

    def __init__(self, *, owner: SourceOwner, private_key_pem: SecretStr) -> None:
        try:
            key = serialization.load_pem_private_key(
                private_key_pem.get_secret_value().encode(), password=None
            )
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("issuer signing key must be Ed25519")
        except (TypeError, ValueError):
            raise ValueError("invalid owner Ed25519 private key") from None
        self.owner = owner
        self.key = key
        self.kid = hashlib.sha256(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).hexdigest()

    def sign(
        self,
        snapshot: OwnerEffectAuthoritySnapshot,
        *,
        recipient: VerifiedOwnerServicePeer,
    ) -> SignedOwnerDecision:
        intent = snapshot.intent
        now = datetime.now(UTC)
        if (
            snapshot.owner != self.owner
            or snapshot.issued_from_owner_db != OWNER_DB_NAMES[self.owner]
            or recipient.service_id != intent.recipient_service_id
            or recipient.instance_uuid != intent.recipient_instance_uuid
            or recipient.expires_at <= now
            or not snapshot.active
            or snapshot.state_version < 1
            or snapshot.revoke_epoch < 0
            or not _v4(snapshot.authority_epoch)
        ):
            raise OwnerAuthorityUnavailable("owner-local issuer/recipient not current")
        if snapshot.source_expires_at is not None and (
            snapshot.source_expires_at.tzinfo is None or snapshot.source_expires_at <= now
        ):
            raise OwnerAuthorityUnavailable("current owner source delegation expired")
        candidate_expiry = min(
            now + timedelta(seconds=_DECISION_TTL_SECONDS),
            recipient.expires_at,
            snapshot.source_expires_at or recipient.expires_at,
            snapshot.session_hard_expires_at or recipient.expires_at,
        )
        # Runtime's signed-JWT consumer requires decision.expires_at <= the
        # INTEGER JWT exp claim; round DOWN before constructing either.
        expires = datetime.fromtimestamp(int(candidate_expiry.timestamp()), UTC)
        if expires <= now or int(expires.timestamp()) <= int(now.timestamp()):
            raise OwnerAuthorityUnavailable("owner source proof has expired")
        decision = OwnerDecision(
            owner=self.owner,
            database=cast(
                Literal["briareus_identity", "briareus_platform", "briareus_access"],
                OWNER_DB_NAMES[self.owner],
            ),
            recipient_service_id=intent.recipient_service_id,
            recipient_instance_uuid=intent.recipient_instance_uuid,
            project_id=intent.project_id,
            actor_id=intent.actor_id,
            session_uuid=intent.session_uuid,
            operation_uuid=intent.operation_uuid,
            request_sha256=intent.request_sha256,
            action=intent.action,
            state_version=snapshot.state_version,
            revoke_epoch=snapshot.revoke_epoch,
            authority_epoch=snapshot.authority_epoch,
            active=snapshot.active,
            expires_at=expires,
            project_revision=snapshot.project_revision,
            owner_scope=snapshot.owner_scope,
            owner_id=snapshot.owner_id,
            granted_actions=snapshot.granted_actions,
            session_hard_expires_at=snapshot.session_hard_expires_at,
            transfer_pending=snapshot.transfer_pending,
        )
        if self.owner != "identity" and intent.action not in snapshot.granted_actions:
            raise OwnerAuthorityUnavailable("current owner action not explicitly granted")
        claims = {
            "iss": _ISSUER[self.owner],
            "aud": f"owner-effect:{recipient.service_id}",
            "purpose": _PURPOSE,
            "jti": str(uuid4()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires.timestamp()),
            "decision": decision.model_dump(mode="json"),
        }
        token = jwt.encode(
            claims,
            self.key,
            algorithm="EdDSA",
            headers={
                "typ": _JWT_TYPE,
                "kid": self.kid,
            },
        )
        return SignedOwnerDecision(decision=decision, attestation_jws=token)


class CurrentEffectDecisionPort(Protocol):
    """Owner-only C2 current proof, not a cached JWT or WS projection."""

    async def fresh(
        self, owner: SourceOwner, *, intent: OwnerEffectIntent, recipient: VerifiedOwnerServicePeer
    ) -> SignedOwnerDecision: ...


class TrustedDecisionReplayFence(Protocol):
    """Physical C2 JTI single-consumer nonce store; no in-memory fallback."""

    async def consume_once(
        self,
        *,
        owner: SourceOwner,
        jti: UUID,
        recipient_service_id: UUID,
        recipient_instance_uuid: UUID,
        expires_at: datetime,
    ) -> None:
        """Atomically reject used JTI until expiry; fail closed on outage."""
        ...


class PinnedEffectOwnerPublicKeys(Protocol):
    """Release-pinned distinct keys; never obtained from token headers."""

    def owner_key(self, owner: SourceOwner) -> Ed25519PublicKey: ...


def verify_owner_effect_decision(
    signed: SignedOwnerDecision,
    *,
    owner: SourceOwner,
    pinned_key: Ed25519PublicKey,
    intent: OwnerEffectIntent,
    recipient: VerifiedOwnerServicePeer,
) -> OwnerDecision:
    """Exact private R13 v1 signature and semantic check, not a grant by itself."""
    if not isinstance(signed, SignedOwnerDecision) or recipient.expires_at <= datetime.now(UTC):
        raise OwnerAuthorityUnavailable("signed owner decision or recipient unavailable")
    try:
        header = jwt.get_unverified_header(signed.attestation_jws)
        key_id = hashlib.sha256(
            pinned_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).hexdigest()
        if (
            header.get("alg") != "EdDSA"
            or header.get("typ") != _JWT_TYPE
            or header.get("kid") != key_id
            or header.get("crit")
        ):
            raise OwnerAuthorityUnavailable("owner key or JOSE header not pinned")
        claims = jwt.decode(
            signed.attestation_jws,
            pinned_key,
            algorithms=["EdDSA"],
            audience=f"owner-effect:{recipient.service_id}",
            issuer=_ISSUER[owner],
            leeway=0,
            options={"require": ["iss", "aud", "iat", "nbf", "exp", "jti", "purpose", "decision"]},
        )
        decision = OwnerDecision.model_validate_json(
            json.dumps(claims["decision"], sort_keys=True, separators=(",", ":"), allow_nan=False)
        )
        now = datetime.now(UTC)
        if (
            UUID(claims["jti"]).version != 4
            or claims["purpose"] != _PURPOSE
            or type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or not 0 < claims["exp"] - claims["iat"] <= _DECISION_TTL_SECONDS
            or decision != signed.decision
            or decision.owner != owner
            or decision.recipient_service_id != recipient.service_id
            or decision.recipient_instance_uuid != recipient.instance_uuid
            or decision.project_id != intent.project_id
            or decision.actor_id != intent.actor_id
            or decision.session_uuid != intent.session_uuid
            or decision.operation_uuid != intent.operation_uuid
            or decision.request_sha256 != intent.request_sha256
            or decision.action != intent.action
            or decision.expires_at <= now
            or decision.expires_at > recipient.expires_at
            or decision.expires_at > datetime.fromtimestamp(claims["exp"], UTC)
            or not decision.active
            or decision.transfer_pending
        ):
            raise OwnerAuthorityUnavailable("signed owner effect proof scope changed")
        return decision
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, ValidationError):
        raise OwnerAuthorityUnavailable("signed owner effect decision rejected") from None


async def verify_and_consume_effect_decision(
    signed: SignedOwnerDecision,
    *,
    owner: SourceOwner,
    pinned_key: Ed25519PublicKey,
    intent: OwnerEffectIntent,
    recipient: VerifiedOwnerServicePeer,
    replay_fence: TrustedDecisionReplayFence | None,
) -> OwnerDecision:
    """Effect-use verification: JWS plus durable single-use C2 JTI fence.

    The pure verifier alone is for comparing repeated current source reads;
    it does NOT grant executing an effect without a consumed nonce.
    """
    if replay_fence is None:
        raise OwnerAuthorityUnavailable("trusted current owner JTI replay fence unavailable")
    decision = verify_owner_effect_decision(
        signed,
        owner=owner,
        pinned_key=pinned_key,
        intent=intent,
        recipient=recipient,
    )
    try:
        claims = jwt.decode(
            signed.attestation_jws,
            pinned_key,
            algorithms=["EdDSA"],
            audience=f"owner-effect:{recipient.service_id}",
            issuer=_ISSUER[owner],
            leeway=0,
        )
        jti = UUID(claims["jti"])
        if jti.version != 4:
            raise OwnerAuthorityUnavailable("owner nonce is not UUIDv4")
        import asyncio

        async with asyncio.timeout(3):
            await replay_fence.consume_once(
                owner=owner,
                jti=jti,
                recipient_service_id=recipient.service_id,
                recipient_instance_uuid=recipient.instance_uuid,
                expires_at=decision.expires_at,
            )
    except Exception:
        raise OwnerAuthorityUnavailable(
            "owner decision JTI reused or replay guard unavailable"
        ) from None
    return decision
