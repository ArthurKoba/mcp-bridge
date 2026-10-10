"""Bounded Ed25519 Runtime owner lease provenance for source-only owner storage.

An owner lease JWS is NOT proof of OS cleanup, Project permission or active
AgentSession grant. The target process MUST independently attest the private
service peer and recheck current Identity/Control/Access before any effect.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from common.owner_contracts import OwnerAuthorityUnavailable

_LEASE_TYPE = "briareus.owner-runtime-lease+jwt"
_LEASE_PURPOSE = "briareus-runtime-owner-lease-v1"


class RuntimeOwnerJwsClaims(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    iss: str
    aud: str
    sub: str
    purpose: str
    jti: UUID
    runtime_session_uuid: UUID
    project_id: UUID
    caller_user_id: UUID
    agent_session_uuid: UUID
    service_id: UUID
    instance_uuid: UUID
    lease_nonce: UUID
    lease_version: int = Field(ge=1)
    kind: str = Field(pattern=r"^(files|terminal|web_managed|web_remote|reverse)$")
    lease_expires_at: datetime
    hard_expires_at: datetime
    iat: int
    nbf: int
    exp: int


def _public_key_fingerprint(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(
        key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()


class RuntimeOwnerLeaseSigner:
    """Injected by trusted release; no key loaded from HTTP/Frontend input."""

    def __init__(self, *, key_pem: SecretStr, issuer: str) -> None:
        if not issuer.startswith("briareus:") or len(issuer) > 128:
            raise ValueError("Runtime owner signer issuer must be release scoped")
        try:
            key = serialization.load_pem_private_key(
                key_pem.get_secret_value().encode(),
                password=None,
            )
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("Runtime owner signing key is not Ed25519")
        except (TypeError, ValueError):
            raise ValueError("invalid trusted Runtime owner key") from None
        self._key = key
        self._issuer = issuer
        self._kid = _public_key_fingerprint(key.public_key())

    def sign(self, claim: object) -> str:
        """Sign a fenced in-process source-only owner lease after SQL commit.

        The payload is structurally validated instead of blindly serializing
        an arbitrary dataclass from a caller request body.
        """
        from projects._runtime_source import OwnerRuntimeLeaseClaim

        if not isinstance(claim, OwnerRuntimeLeaseClaim):
            raise OwnerAuthorityUnavailable("trusted Runtime ledger lease required")
        now = datetime.now(UTC)
        if (
            claim.runtime_session_uuid.version != 4
            or claim.project_id.version != 4
            or claim.caller_user_id.version != 4
            or claim.agent_session_uuid.version != 4
            or claim.owner_service_id.version != 4
            or claim.owner_instance.version != 4
            or claim.lease_nonce.version != 4
            or claim.version < 1
            or claim.lease_expires_at.tzinfo is None
            or claim.hard_expires_at.tzinfo is None
            or claim.lease_expires_at <= now
            or claim.hard_expires_at < claim.lease_expires_at
        ):
            raise OwnerAuthorityUnavailable("unsigned Runtime owner lease is not active")
        expires = min(now + timedelta(seconds=20), claim.lease_expires_at)
        if int(expires.timestamp()) <= int(now.timestamp()):
            raise OwnerAuthorityUnavailable("Runtime owner lease has insufficient signable TTL")
        claims = {
            "iss": self._issuer,
            "aud": f"briareus:runtime:{claim.owner_service_id}",
            "sub": str(claim.runtime_session_uuid),
            "purpose": _LEASE_PURPOSE,
            "jti": str(uuid4()),
            "runtime_session_uuid": str(claim.runtime_session_uuid),
            "project_id": str(claim.project_id),
            "caller_user_id": str(claim.caller_user_id),
            "agent_session_uuid": str(claim.agent_session_uuid),
            "service_id": str(claim.owner_service_id),
            "instance_uuid": str(claim.owner_instance),
            "lease_nonce": str(claim.lease_nonce),
            "lease_version": claim.version,
            "kind": claim.kind,
            "lease_expires_at": claim.lease_expires_at.isoformat(),
            "hard_expires_at": claim.hard_expires_at.isoformat(),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires.timestamp()),
        }
        return jwt.encode(
            claims,
            self._key,
            algorithm="EdDSA",
            headers={"typ": _LEASE_TYPE, "kid": self._kid},
        )


def verify_owner_runtime_lease(
    token: str,
    *,
    pinned_public_key: Ed25519PublicKey,
    trusted_issuer: str,
    expected_runtime_session_uuid: UUID,
    expected_project_id: UUID,
    expected_actor_user_id: UUID,
    expected_agent_session_uuid: UUID,
    expected_service_id: UUID,
    expected_instance_uuid: UUID,
    expected_lease_nonce: UUID,
    expected_version: int,
) -> RuntimeOwnerJwsClaims:
    """Pure JWS verify only; a valid old signed lease still needs live recheck."""
    expected = (
        expected_runtime_session_uuid,
        expected_project_id,
        expected_actor_user_id,
        expected_agent_session_uuid,
        expected_service_id,
        expected_instance_uuid,
        expected_lease_nonce,
    )
    if any(value.version != 4 for value in expected) or expected_version < 1:
        raise OwnerAuthorityUnavailable("expected native Runtime owner IDs invalid")
    if not token or len(token) > 8192:
        raise OwnerAuthorityUnavailable("Runtime owner JWS is absent or oversized")
    try:
        header = jwt.get_unverified_header(token)
        if (
            header.get("alg") != "EdDSA"
            or header.get("typ") != _LEASE_TYPE
            or header.get("kid") != _public_key_fingerprint(pinned_public_key)
            or header.get("crit")
        ):
            raise OwnerAuthorityUnavailable("Runtime signer identity/algorithm not pinned")
        raw = jwt.decode(
            token,
            pinned_public_key,
            algorithms=["EdDSA"],
            issuer=trusted_issuer,
            audience=f"briareus:runtime:{expected_service_id}",
            leeway=0,
            options={
                "require": [
                    "iss",
                    "aud",
                    "sub",
                    "purpose",
                    "jti",
                    "iat",
                    "nbf",
                    "exp",
                    "lease_nonce",
                    "lease_version",
                    "lease_expires_at",
                ]
            },
        )
        claims = RuntimeOwnerJwsClaims.model_validate_json(
            json.dumps(raw, separators=(",", ":"), allow_nan=False)
        )
        now = datetime.now(UTC)
        if (
            claims.iss != trusted_issuer
            or claims.aud != f"briareus:runtime:{expected_service_id}"
            or claims.purpose != _LEASE_PURPOSE
            or claims.jti.version != 4
            or claims.sub != str(expected_runtime_session_uuid)
            or claims.runtime_session_uuid != expected_runtime_session_uuid
            or claims.project_id != expected_project_id
            or claims.caller_user_id != expected_actor_user_id
            or claims.agent_session_uuid != expected_agent_session_uuid
            or claims.service_id != expected_service_id
            or claims.instance_uuid != expected_instance_uuid
            or claims.lease_nonce != expected_lease_nonce
            or claims.lease_version != expected_version
            or claims.lease_expires_at.tzinfo is None
            or claims.hard_expires_at.tzinfo is None
            or claims.lease_expires_at <= now
            or claims.hard_expires_at < claims.lease_expires_at
            or claims.exp - claims.iat > 20
            or claims.iat > int(now.timestamp())
            or claims.exp > int(claims.lease_expires_at.timestamp())
        ):
            raise OwnerAuthorityUnavailable("Runtime owner JWS differs from expected source")
        return claims
    except (jwt.PyJWTError, ValidationError, ValueError, TypeError, KeyError):
        raise OwnerAuthorityUnavailable(
            "trusted Runtime owner lease could not be verified"
        ) from None
