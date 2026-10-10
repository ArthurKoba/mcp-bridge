"""Verify A12 source-only owner-effect status v2, never infer OS success.

The owner signs statuses of ORIGINAL durable command rows with its own
release-pinned Ed25519 key; missing rows, lost ACK, wrong Project/Session,
changed owner revisions and unverified recipient always remain UNKNOWN.
This module does not discover the signing key, mutate SQL or expose MCP tools.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .a11_owner_wire import A11OwnerCommandDTO
from .owner_authorization import VerifiedOwnerRecipient
from .owner_effects import OwnerEffectCommand, OwnerEffectUnavailable


class OwnerEffectStatusV2(BaseModel):
    """Field-exact Backend A12 `owner_effect_status.OwnerEffectStatusV2`."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    protocol: Literal["owner-effect-status-v2"] = "owner-effect-status-v2"
    owner: Literal["catalog", "files", "execution", "reverse"]
    owner_database: Literal[
        "briareus_resources", "briareus_files", "briareus_runtime", "briareus_reverse"
    ]
    recipient_service_id: UUID
    recipient_instance_uuid: UUID
    project_id: UUID
    actor_id: UUID
    agent_session_uuid: UUID
    operation_uuid: UUID
    idempotency_uuid: UUID
    phase: str = Field(min_length=1, max_length=48)
    action: str = Field(min_length=1, max_length=64)
    original_idempotency_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_revision: int = Field(ge=1)
    state: Literal["UNKNOWN", "COMMITTED", "DENIED"]
    result_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime
    expires_at: datetime
    reconciliation_required: bool = True
    retry_with_new_key_allowed: Literal[False] = False


class SignedOwnerEffectStatusV2(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    status: OwnerEffectStatusV2
    attestation_jws: str = Field(min_length=100, max_length=8192)


def verify_signed_owner_status_v2(
    signed: SignedOwnerEffectStatusV2,
    *,
    pinned_key: Ed25519PublicKey,
    command: OwnerEffectCommand,
    source_command: A11OwnerCommandDTO,
    recipient: VerifiedOwnerRecipient,
) -> OwnerEffectStatusV2:
    """Authenticate exact original operation and finite signed status.

    COMMITTED means owner-local SQL command state + independent target CAS,
    not that native/Ghidra/Terminal/Browser side effects were successful.
    DENIED and UNKNOWN both prohibit replay under a newly minted UUID/key.
    A12 status must never turn an ABSENT SQL row into safe-to-retry evidence.
    """
    try:
        if (
            not isinstance(signed, SignedOwnerEffectStatusV2)
            or not isinstance(command, OwnerEffectCommand)
            or not isinstance(source_command, A11OwnerCommandDTO)
            or not isinstance(recipient, VerifiedOwnerRecipient)
            or not isinstance(pinned_key, Ed25519PublicKey)
            or recipient.expires_at.tzinfo is None
            or recipient.expires_at <= datetime.now(UTC)
        ):
            raise OwnerEffectUnavailable("A12_OWNER_STATUS_TRUSTED_INPUT_REQUIRED", unknown=True)
        raw_key = pinned_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        header = jwt.get_unverified_header(signed.attestation_jws)
        if (
            header.get("alg") != "EdDSA"
            or header.get("typ") != "briareus-owner-effect-status+jwt"
            or header.get("kid") != hashlib.sha256(raw_key).hexdigest()
            or header.get("crit")
        ):
            raise OwnerEffectUnavailable("A12_OWNER_STATUS_SIGNER_UNTRUSTED", unknown=True)
        owner_signer = {
            "catalog": "resources",
            "files": "files",
            "execution": "runtime",
            "reverse": "reverse",
        }[command.owner]
        claims = jwt.decode(
            signed.attestation_jws,
            pinned_key,
            algorithms=["EdDSA"],
            audience=f"owner-effect:{recipient.service_id}",
            issuer=f"briareus-{owner_signer}",
            options={
                "require": [
                    "iss",
                    "aud",
                    "iat",
                    "nbf",
                    "exp",
                    "jti",
                    "purpose",
                    "status",
                ]
            },
            leeway=0,
        )
        status = OwnerEffectStatusV2.model_validate_json(
            json.dumps(claims["status"], separators=(",", ":"), allow_nan=False)
        )
        now = datetime.now(UTC)
        if (
            UUID(claims["jti"]).version != 4
            or claims["purpose"] != "owner-effect-status-v2"
            or type(claims["iat"]) is not int
            or type(claims["nbf"]) is not int
            or type(claims["exp"]) is not int
            or not 0 < claims["exp"] - claims["iat"] <= 30
            or status != signed.status
            or status.owner != command.owner
            or status.owner_database != command.owner_database
            or status.recipient_service_id != recipient.service_id
            or status.recipient_instance_uuid != recipient.instance_uuid
            or status.project_id != command.project_id
            or status.actor_id != command.actor_id
            or status.agent_session_uuid != command.agent_session_uuid
            or status.operation_uuid != command.operation_uuid
            or status.idempotency_uuid != command.idempotency_uuid
            or source_command.operation_uuid != command.operation_uuid
            or source_command.target_owner != owner_signer
            or source_command.caller_user_id != command.actor_id
            or source_command.project_id != command.project_id
            or source_command.session_uuid != command.agent_session_uuid
            or source_command.expected_identity_revision != command.fence.identity_version
            or source_command.expected_control_revision != command.fence.control_state_version
            or source_command.expected_access_revision != command.fence.access_session_version
            or status.phase != command.phase
            or status.action != command.action
            or status.request_sha256 != command.request_sha256
            or status.target_sha256 != command.target_sha256
            or status.payload_sha256 != command.payload_sha256
            or status.owner_revision < max(1, command.expected_version)
            or status.original_idempotency_key_sha256
            != hashlib.sha256(source_command.idempotency_key.encode("ascii")).hexdigest()
            or status.observed_at.tzinfo is None
            or status.observed_at > now
            or status.expires_at.tzinfo is None
            or status.expires_at <= now
            or status.expires_at > recipient.expires_at
            or status.expires_at > datetime.fromtimestamp(claims["exp"], UTC)
            or (status.state == "COMMITTED") != (status.result_sha256 is not None)
            or (status.state != "COMMITTED" and not status.reconciliation_required)
            or status.retry_with_new_key_allowed is not False
        ):
            raise OwnerEffectUnavailable("A12_OWNER_STATUS_SCOPE_OR_CAS_INVALID", unknown=True)
        return status
    except OwnerEffectUnavailable:
        raise
    except (
        jwt.PyJWTError,
        ValidationError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ) as exc:
        raise OwnerEffectUnavailable("A12_OWNER_STATUS_VERIFICATION_UNKNOWN", unknown=True) from exc
