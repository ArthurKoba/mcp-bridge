"""Language-neutral signed owner DB decisions, not permissions from projections.

The operation DTO travels over a separately authenticated private TLS/Unix
service peer. JWT verification here is necessary but not a substitute for that
peer: the public business API remains unmounted until C1-B2/C2 acceptance.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

import jwt
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from common.platform_db import OWNER_DB_NAMES, OwnerName

RequiredAuthority = Literal["identity", "platform", "access"]


class OwnerCommandDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    operation_uuid: UUID
    caller_user_id: UUID
    project_id: UUID
    session_uuid: UUID
    target_owner: OwnerName
    operation: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=128)
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_identity_revision: int = Field(ge=1)
    expected_control_revision: int = Field(ge=1)
    expected_control_resource_revision: int = Field(ge=0)
    expected_team_id: UUID | None = None
    expected_team_revision: int | None = Field(default=None, ge=1)
    expected_team_resource_revision: int | None = Field(default=None, ge=0)
    expected_access_revision: int = Field(ge=1)

    @field_validator("expected_team_id")
    @classmethod
    def _team_uuid(cls, value: UUID | None) -> UUID | None:
        if value is not None and value.version != 4:
            raise ValueError("Team scope identifier must be UUIDv4")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def _original_key(cls, value: str) -> str:
        # Preserve accepted HTTP Idempotency-Key contract across owner DBs.
        if not value.isascii() or not value.isprintable():
            raise ValueError("Idempotency-Key must be printable ASCII")
        return value

    @field_validator("operation_uuid", "caller_user_id", "project_id", "session_uuid")
    @classmethod
    def _v4(cls, value: UUID) -> UUID:
        if value.version != 4:
            raise ValueError("operation and authority identifiers must be UUIDv4")
        return value


class SignedOwnerProofs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    identity: SecretStr
    platform: SecretStr
    access: SecretStr


class OwnerProofClaims(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    iss: str
    aud: str
    sub: str
    owner: RequiredAuthority
    owner_database: str
    operation_uuid: UUID
    caller_user_id: UUID
    project_id: UUID
    session_uuid: UUID
    operation: str
    idempotency_key: str
    payload_sha256: str
    active: bool
    role: Literal["user", "superuser"] | None = None
    capabilities: tuple[str, ...] = ()
    owner_revision: int = Field(ge=1)
    control_resource_revision: int | None = None
    project_lifecycle: Literal["active", "deleting", "deleted"] | None = None
    team_id: UUID | None = None
    team_revision: int | None = None
    team_resource_revision: int | None = None
    authority_epoch: UUID
    iat: int
    nbf: int
    exp: int


@dataclass(frozen=True, slots=True)
class TrustedOwnerPin:
    owner: RequiredAuthority
    kid: str
    public_key_pem: bytes
    issuer: str
    # Pins are configured by the trusted release/peer supervisor, NEVER by
    # HTTP body, provider variable, public UI, or untrusted JWT headers.


@dataclass(frozen=True, slots=True)
class VerifiedOwnerOperation:
    request: OwnerCommandDTO
    identity_epoch: UUID
    control_epoch: UUID
    access_epoch: UUID
    actor_role: Literal["user", "superuser"]
    verified_at: datetime


class OwnerAuthorityUnavailable(RuntimeError):
    """Security-sensitive effect cannot proceed without CURRENT source proof."""


class OwnerProofAuthority:
    def __init__(self, pins: tuple[TrustedOwnerPin, ...], *, audience: str) -> None:
        if not audience or not audience.startswith("briareus:"):
            raise ValueError("recipient must have approved private service audience")
        if {pin.owner for pin in pins} != {"identity", "platform", "access"} or len(pins) != 3:
            raise ValueError("one pinned signer required per authoritative owner")
        if any(not pin.kid or not pin.issuer or not pin.public_key_pem for pin in pins):
            raise ValueError("invalid pinned owner key provenance")
        self._pins = {pin.owner: pin for pin in pins}
        self._audience = audience

    def _verify(
        self, token: SecretStr, owner: RequiredAuthority, request: OwnerCommandDTO, now: datetime
    ) -> OwnerProofClaims:
        pin = self._pins[owner]
        try:
            header = jwt.get_unverified_header(token.get_secret_value())
            if (
                header.get("alg") != "EdDSA"
                or header.get("kid") != pin.kid
                or header.get("crit")
                or header.get("typ") not in {"JWT", None}
            ):
                raise OwnerAuthorityUnavailable("owner signing key not pinned")
            payload = jwt.decode(
                token.get_secret_value(),
                pin.public_key_pem,
                algorithms=["EdDSA"],
                audience=self._audience,
                issuer=pin.issuer,
                options={"require": ["iss", "aud", "sub", "exp", "nbf", "iat"]},
                leeway=0,
            )
            # JWT transports JSON strings for UUIDs and arrays for tuples.
            # Strict Python validation rejects valid UUID text, whereas strict
            # JSON validation preserves the wire contract without leniency.
            claims = OwnerProofClaims.model_validate_json(
                json.dumps(payload, separators=(",", ":"), allow_nan=False)
            )
            if (
                claims.owner != owner
                or claims.owner_database != OWNER_DB_NAMES[owner]
                or claims.operation_uuid != request.operation_uuid
                or claims.caller_user_id != request.caller_user_id
                or claims.project_id != request.project_id
                or claims.session_uuid != request.session_uuid
                or claims.operation != request.operation
                or claims.idempotency_key != request.idempotency_key
                or claims.payload_sha256 != request.payload_sha256
                or claims.team_id != request.expected_team_id
                or not claims.active
                or claims.aud != self._audience
                or claims.sub != str(request.caller_user_id)
            ):
                raise OwnerAuthorityUnavailable("signed owner scope mismatch")
            expected = {
                "identity": request.expected_identity_revision,
                "platform": request.expected_control_revision,
                "access": request.expected_access_revision,
            }[owner]
            if owner != "identity" and request.operation not in claims.capabilities:
                raise OwnerAuthorityUnavailable("owning authority did not attest this operation")
            if owner == "platform" and claims.project_lifecycle != (
                "deleting" if request.operation == "project.delete.confirm" else "active"
            ):
                raise OwnerAuthorityUnavailable("Control Project lifecycle is not authorized")
            if owner == "platform" and (
                claims.team_id != request.expected_team_id
                or claims.control_resource_revision != request.expected_control_resource_revision
                or claims.team_revision != request.expected_team_revision
                or claims.team_resource_revision != request.expected_team_resource_revision
            ):
                raise OwnerAuthorityUnavailable("signed Control resource/Team revisions differ")
            if claims.owner_revision != expected:
                raise OwnerAuthorityUnavailable("owner revision changed")
            # Sensitive effect needs a fresh proof; a queued read model, stale
            # JWT or expired Account/Team grant is never sufficient.
            issued = datetime.fromtimestamp(claims.iat, UTC)
            expires = datetime.fromtimestamp(claims.exp, UTC)
            not_before = datetime.fromtimestamp(claims.nbf, UTC)
            if (
                issued > now
                or not_before > now
                or expires <= now
                or now - issued > timedelta(seconds=15)
                or expires - issued > timedelta(seconds=30)
                or claims.authority_epoch.version != 4
            ):
                raise OwnerAuthorityUnavailable("owner proof stale or invalid")
            return claims
        except (jwt.PyJWTError, ValidationError, ValueError, TypeError, KeyError) as exc:
            raise OwnerAuthorityUnavailable("signed owner proof not verified") from exc

    def require_bootstrap_sources(
        self,
        request: OwnerCommandDTO,
        *,
        identity: SecretStr,
        platform: SecretStr,
    ) -> tuple[OwnerProofClaims, OwnerProofClaims]:
        """AgentSession creation has no existing Session to authorize itself.

        The *current* Identity and Control issuers must BOTH independently
        approve the exact new normal Session UUID/Project/operation. Access
        will separately bind the service caller and own ServiceKey SQL.
        This does not grant an elevated Session or bypass original dedupe.
        """
        if request.operation != "session.open" or request.target_owner != "access":
            raise OwnerAuthorityUnavailable("only normal AgentSession bootstrap is permitted")
        now = datetime.now(UTC)
        user = self._verify(identity, "identity", request, now)
        project = self._verify(platform, "platform", request, now)
        if user.role not in {"user", "superuser"} or "session.open" not in project.capabilities:
            raise OwnerAuthorityUnavailable("fresh Identity+Control Session bootstrap denied")
        return user, project

    def require_current(
        self, request: OwnerCommandDTO, signed: SignedOwnerProofs
    ) -> VerifiedOwnerOperation:
        if self._audience != f"briareus:{request.target_owner}":
            raise OwnerAuthorityUnavailable("owner recipient does not match signed audience")
        now = datetime.now(UTC)
        user = self._verify(signed.identity, "identity", request, now)
        scope = self._verify(signed.platform, "platform", request, now)
        grant = self._verify(signed.access, "access", request, now)
        if user.role not in {"user", "superuser"}:
            raise OwnerAuthorityUnavailable("Identity did not attest the current role")
        return VerifiedOwnerOperation(
            request,
            user.authority_epoch,
            scope.authority_epoch,
            grant.authority_epoch,
            user.role,
            now,
        )


def require_signed_payload(request: OwnerCommandDTO, payload: dict[str, object]) -> None:
    """The exact business parameters MUST match all three signed authority claims."""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != request.payload_sha256:
        raise OwnerAuthorityUnavailable("business payload differs from signed request")


@dataclass(frozen=True, slots=True)
class VerifiedOwnerServicePeer:
    """Produced by trusted mTLS/Unix peer verifier, not by request headers."""

    service_id: UUID
    instance_uuid: UUID
    audience: str
    signing_key_id: UUID
    transport: Literal["mtls", "unix-peer"]
    expires_at: datetime

    def __post_init__(self) -> None:
        if (
            self.service_id.version != 4
            or self.instance_uuid.version != 4
            or self.signing_key_id.version != 4
            or not self.audience.startswith("briareus:")
            or self.expires_at.tzinfo is None
            or self.expires_at <= datetime.now(UTC)
            or self.transport not in {"mtls", "unix-peer"}
        ):
            raise OwnerAuthorityUnavailable("service peer identity was not attested")


class TrustedOwnerServicePeerPort(Protocol):
    """Inject only an independently approved certificate/OS peer attestor."""

    def verify_peer(self, evidence: object) -> VerifiedOwnerServicePeer: ...


class CurrentOwnerAuthorityPort(Protocol):
    """Actual C2 peer-attested RPC to all three source owners, never cache only.

    Source implementation has no default adapter: a missing physical verified
    peer is DENY. No replay queue or cached JWT may mint a current owner proof.
    """

    async def fetch_current(self, command: OwnerCommandDTO) -> SignedOwnerProofs: ...


async def require_online_owner_decision(
    verifier: OwnerProofAuthority,
    source: CurrentOwnerAuthorityPort,
    command: OwnerCommandDTO,
) -> VerifiedOwnerOperation:
    try:
        async with asyncio.timeout(3):
            signed = await source.fetch_current(command)
        return verifier.require_current(command, signed)
    except Exception:
        raise OwnerAuthorityUnavailable(
            "current Identity/Control/Access source unavailable; protected effect denied"
        ) from None
