"""Private recipient-pinned original-command proofs for a BFF source aggregate.

Only independently verified per-owner Ed25519 status can contribute to BFF
confirmed. A caller's Operation-UUID header, local DB row, transport 200 or
WS event does not itself constitute an original command acknowledgment.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from common.owner_contracts import OwnerAuthorityUnavailable

BffOwner = Literal["identity", "access", "control", "catalog"]
Phase = Literal["pending", "unknown", "reconciling", "confirmed", "denied"]

_ISSUER: dict[BffOwner, str] = {
    "identity": "briareus-identity",
    "access": "briareus-access",
    "control": "briareus-platform",
    "catalog": "briareus-resources",
}
_PURPOSE = "briareus-bff-original-owner-v1"
_TYP = "briareus-bff-owner+jwt"


class SignedOriginalOwnerStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    owner: BffOwner
    actor_user_id: UUID
    operation_uuid: UUID
    original_idempotency_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    binding_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_revision: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")
    phase: Phase
    issued_at: datetime
    expires_at: datetime
    recipient_service_id: UUID
    recipient_instance_uuid: UUID

    @model_validator(mode="after")
    def validate_owner_status(self) -> SignedOriginalOwnerStatus:
        now = datetime.now(UTC)
        ids = (
            self.actor_user_id,
            self.operation_uuid,
            self.recipient_service_id,
            self.recipient_instance_uuid,
        )
        if (
            any(value.version != 4 for value in ids)
            or self.issued_at.tzinfo is None
            or self.expires_at.tzinfo is None
            or self.issued_at > now
            or self.expires_at <= now
            or self.expires_at - self.issued_at > timedelta(seconds=15)
        ):
            raise ValueError("owner signed BFF original receipt is not current")
        return self


class OriginalOwnerSignedEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    receipt: SignedOriginalOwnerStatus
    attestation_jws: str = Field(min_length=100, max_length=8192)


class PinnedBffOwnerKeys(Protocol):
    def public_key(self, owner: BffOwner) -> Ed25519PublicKey:
        """Release-pinned key belonging ONLY to the named source owner."""
        ...


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def canonical_original_identity(operation_uuid: UUID, key: str) -> str:
    """The ONE agreed frontend/backend/runtime original-key identity.

    Runtime v1 requires operation_uuid == idempotency_uuid; the signed owner
    source stores the original printable Idempotency-Key. Require canonical
    UUIDv4 key text identical to Operation-UUID rather than invent a mapping
    or mint another hidden key. Old two-distinct-UUID commands remain UNKNOWN.
    """
    if operation_uuid.version != 4 or not isinstance(key, str):
        raise OwnerAuthorityUnavailable("original signed Operation-UUID must be v4")
    if key != str(operation_uuid):
        raise OwnerAuthorityUnavailable(
            "Operation-UUID and Idempotency-Key are different original operations"
        )
    return hashlib.sha256(key.encode("ascii")).hexdigest()


def verify_source_owner_status(
    envelope: OriginalOwnerSignedEnvelope,
    *,
    owner: BffOwner,
    key: Ed25519PublicKey,
    actor_user_id: UUID,
    operation_uuid: UUID,
    key_sha256: str,
    scope_sha256: str,
    binding_sha256: str,
    expected_revision: str,
    recipient_service_id: UUID,
    recipient_instance_uuid: UUID,
) -> SignedOriginalOwnerStatus:
    """Verify ORIGINAL source JWS and recipient binding, not a client echo."""
    try:
        headers = jwt.get_unverified_header(envelope.attestation_jws)
        kid = hashlib.sha256(
            key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        if (
            headers.get("alg") != "EdDSA"
            or headers.get("typ") != _TYP
            or headers.get("kid") != kid
            or headers.get("crit")
        ):
            raise OwnerAuthorityUnavailable("BFF owner JWS key/algorithm mismatch")
        claims = jwt.decode(
            envelope.attestation_jws,
            key,
            algorithms=["EdDSA"],
            issuer=_ISSUER[owner],
            audience=f"briareus:admin-bff:{recipient_service_id}",
            leeway=0,
            options={"require": ["iss", "aud", "iat", "nbf", "exp", "jti", "purpose", "receipt"]},
        )
        receipt = SignedOriginalOwnerStatus.model_validate_json(
            json.dumps(
                claims["receipt"],
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
        now = datetime.now(UTC)
        if (
            UUID(claims["jti"]).version != 4
            or type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or not 0 < claims["exp"] - claims["iat"] <= 15
            or claims["purpose"] != _PURPOSE
            or receipt != envelope.receipt
            or receipt.owner != owner
            or receipt.actor_user_id != actor_user_id
            or receipt.operation_uuid != operation_uuid
            or receipt.original_idempotency_key_sha256 != key_sha256
            or receipt.scope_sha256 != scope_sha256
            or receipt.binding_sha256 != binding_sha256
            or receipt.owner_revision != expected_revision
            or receipt.recipient_service_id != recipient_service_id
            or receipt.recipient_instance_uuid != recipient_instance_uuid
            or receipt.expires_at <= now
            or receipt.expires_at > datetime.fromtimestamp(claims["exp"], UTC)
        ):
            raise OwnerAuthorityUnavailable("BFF original source owner status mismatch")
        return receipt
    except (jwt.PyJWTError, ValidationError, ValueError, TypeError, KeyError):
        raise OwnerAuthorityUnavailable(
            "BFF original signed source owner receipt rejected"
        ) from None
