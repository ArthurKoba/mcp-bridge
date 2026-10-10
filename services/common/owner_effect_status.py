"""Versioned owner status v2 JWS for UNKNOWN/COMMITTED/DENIED.

This is an A12 private R14 convergence PROPOSAL: Runtime R13 v1 does not
accept DENIED in EffectState. An absent command is not proof of failure or
permission to create a new UUID/idempotency key. Only persisted owner-local
command rows can be attested; no event stream, HTTP 200, or cache authority.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Literal, cast
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select

from common.owner_contracts import (
    OwnerAuthorityUnavailable,
    OwnerCommandDTO,
    SignedOwnerProofs,
    VerifiedOwnerServicePeer,
    require_online_owner_decision,
)
from common.owner_effect_authorization import _hash
from common.owner_effect_phase_map import require_exact_owner_operation
from common.owner_effect_receipts import (
    OwnerEffectCommand,
    OwnerEffectReceiptAttestor,
    require_fresh_effect_fence,
)


class OwnerEffectStatusV2(BaseModel):
    """Strict signed UNKNOWN cannot be relabeled as COMMITTED by any caller."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
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
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    status: OwnerEffectStatusV2
    attestation_jws: str = Field(min_length=100, max_length=8192)


class OwnerEffectStatusAttestor(OwnerEffectReceiptAttestor):
    async def status(
        self,
        *,
        command: OwnerEffectCommand,
        source_command: OwnerCommandDTO,
        source_proofs: SignedOwnerProofs,
        recipient: VerifiedOwnerServicePeer,
    ) -> SignedOwnerEffectStatusV2:
        """Durably inspect original row. `NOT_FOUND` is NOT signed as DENIED.

        New phase/status DTO is separate from an A11 `OwnerCommandOutcome`.
        Runtime R14 must explicitly accept this v2 type before use.
        """
        original = self._proofs.require_current(source_command, source_proofs)
        current = await require_online_owner_decision(self._proofs, self._current, source_command)
        if (
            original.identity_epoch != current.identity_epoch
            or original.control_epoch != current.control_epoch
            or original.access_epoch != current.access_epoch
        ):
            raise OwnerAuthorityUnavailable("owner status current identity/grant revoked")
        if (
            command.owner != self.owner
            or source_command.operation_uuid != command.operation_uuid
            or source_command.idempotency_key != str(command.operation_uuid)
            or source_command.caller_user_id != command.actor_id
            or source_command.project_id != command.project_id
            or source_command.session_uuid != command.agent_session_uuid
            or recipient.service_id != command.recipient_service_id
            or recipient.instance_uuid != command.recipient_instance_uuid
            or recipient.expires_at <= datetime.now(UTC)
        ):
            raise OwnerAuthorityUnavailable("owner effect status scope/original UUID mismatch")
        if (
            source_command.target_owner
            != {
                "catalog": "resources",
                "files": "files",
                "execution": "runtime",
                "reverse": "reverse",
            }[self.owner]
        ):
            raise OwnerAuthorityUnavailable("owner status operation/phase mismatch")
        require_exact_owner_operation(
            owner=self.owner,
            phase=command.phase,
            payload_type=command.payload_type,
            operation=source_command.operation,
        )
        await require_fresh_effect_fence(
            command=command,
            recipient=recipient,
            decisions=self._effect_decisions,
            keys=self._effect_keys,
        )
        async with self.database.transaction() as tx:
            row = await tx.scalar(
                select(self._row)
                .where(
                    self._row.operation_uuid == command.operation_uuid,
                    self._row.actor_scope == str(command.actor_id),
                    self._row.project_scope == str(command.project_id),
                    self._row.operation == source_command.operation,
                    self._row.key == source_command.idempotency_key,
                )
                .with_for_update()
            )
            if row is None:
                raise OwnerAuthorityUnavailable("original durable command absent; effect UNKNOWN")
            if row.fingerprint != source_command.payload_sha256:
                raise OwnerAuthorityUnavailable("owner status fingerprint changed")
            original_result: dict[str, object] | None = None
            if row.encrypted_outcome is not None:
                try:
                    recovered = json.loads(self._cipher.decrypt(row.encrypted_outcome.encode()))
                    if not isinstance(recovered, dict):
                        raise ValueError("original result is not a JSON object")
                    original_result = recovered
                except Exception:
                    raise OwnerAuthorityUnavailable(
                        "owner source status encryption unavailable"
                    ) from None
            target = await self._cas.verify_current_target(
                tx,
                command=command,
                source_command=source_command,
                stored_result=original_result,
            )
            from common.owner_effect_receipts import VerifiedOwnerTargetObservation

            if (
                not isinstance(target, VerifiedOwnerTargetObservation)
                or target.operation_uuid != command.operation_uuid
                or target.target_sha256 != command.target_sha256
                or target.owner_revision < max(1, command.expected_version)
            ):
                raise OwnerAuthorityUnavailable("signed owner status target not currently verified")
            state_map = {
                "pending": "UNKNOWN",
                "unknown": "UNKNOWN",
                "completed": "COMMITTED",
                "reconciled": "COMMITTED",
                "denied": "DENIED",
            }
            state = state_map.get(row.state)
            if state is None:
                raise OwnerAuthorityUnavailable("unsupported owner command state")
            result_hash = None
            if state == "COMMITTED":
                if row.encrypted_outcome is None:
                    raise OwnerAuthorityUnavailable(
                        "committed owner result has no encrypted outcome"
                    )
                try:
                    decoded = json.loads(self._cipher.decrypt(row.encrypted_outcome.encode()))
                except Exception:
                    raise OwnerAuthorityUnavailable(
                        "stored owner result cannot authenticate"
                    ) from None
                if not isinstance(decoded, dict):
                    raise OwnerAuthorityUnavailable("stored committed owner result not an object")
                # Status-only COMMITTED is NOT native effect completion proof;
                # target CAS is independently mandatory to sign an effect ACK.
                result_hash = _hash(decoded)
            now = datetime.now(UTC)
        final = await require_online_owner_decision(self._proofs, self._current, source_command)
        if (
            final.identity_epoch != current.identity_epoch
            or final.control_epoch != current.control_epoch
            or final.access_epoch != current.access_epoch
        ):
            raise OwnerAuthorityUnavailable("owner status source revoked before signature")
        expires = datetime.fromtimestamp(
            int(min(now + timedelta(seconds=30), recipient.expires_at).timestamp()), UTC
        )
        if expires <= datetime.now(UTC):
            raise OwnerAuthorityUnavailable("owner status expires before trusted recipient")
        await require_fresh_effect_fence(
            command=command,
            recipient=recipient,
            decisions=self._effect_decisions,
            keys=self._effect_keys,
        )
        import hashlib

        key_digest = hashlib.sha256(source_command.idempotency_key.encode()).hexdigest()
        outcome = OwnerEffectStatusV2(
            owner=command.owner,
            owner_database=command.owner_database,
            recipient_service_id=recipient.service_id,
            recipient_instance_uuid=recipient.instance_uuid,
            project_id=command.project_id,
            actor_id=command.actor_id,
            agent_session_uuid=command.agent_session_uuid,
            operation_uuid=command.operation_uuid,
            idempotency_uuid=command.idempotency_uuid,
            phase=command.phase,
            action=command.action,
            original_idempotency_key_sha256=key_digest,
            request_sha256=command.request_sha256,
            target_sha256=command.target_sha256,
            payload_sha256=command.payload_sha256,
            owner_revision=target.owner_revision,
            state=cast(Literal["UNKNOWN", "COMMITTED", "DENIED"], state),
            result_sha256=result_hash,
            observed_at=now,
            expires_at=expires,
            reconciliation_required=state != "COMMITTED",
        )
        claims = {
            "iss": f"briareus-{source_command.target_owner}",
            "aud": f"owner-effect:{recipient.service_id}",
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires.timestamp()),
            "jti": str(uuid4()),
            "purpose": "owner-effect-status-v2",
            "status": outcome.model_dump(mode="json"),
        }
        jws = jwt.encode(
            claims,
            self._key,
            algorithm="EdDSA",
            headers={"typ": "briareus-owner-effect-status+jwt", "kid": self._kid},
        )
        return SignedOwnerEffectStatusV2(status=outcome, attestation_jws=jws)


def verify_owner_effect_status_v2(
    signed: SignedOwnerEffectStatusV2,
    *,
    pinned_key: Ed25519PublicKey,
    command: OwnerEffectCommand,
    recipient: VerifiedOwnerServicePeer,
    original_idempotency_key: str,
) -> OwnerEffectStatusV2:
    """Strict pure JWS verification for Runtime R14's proposed V2 reader.

    It proves ONLY a durable owner-observed STATUS, not a native effect nor
    permission to retry with a new key. Consumers still require current
    source-owner revocation and an independently verified recipient peer.
    """
    import hashlib

    if not original_idempotency_key or not original_idempotency_key.isascii():
        raise OwnerAuthorityUnavailable("original effect Idempotency-Key unavailable")
    try:
        header = jwt.get_unverified_header(signed.attestation_jws)
        kid = hashlib.sha256(
            pinned_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).hexdigest()
        if (
            header.get("alg") != "EdDSA"
            or header.get("typ") != "briareus-owner-effect-status+jwt"
            or header.get("kid") != kid
            or header.get("crit")
        ):
            raise OwnerAuthorityUnavailable("owner status signer key not pinned")
        issuer = {
            "catalog": "resources",
            "files": "files",
            "execution": "runtime",
            "reverse": "reverse",
        }[command.owner]
        claims = jwt.decode(
            signed.attestation_jws,
            pinned_key,
            algorithms=["EdDSA"],
            issuer=f"briareus-{issuer}",
            audience=f"owner-effect:{recipient.service_id}",
            options={"require": ["iss", "aud", "iat", "nbf", "exp", "jti", "purpose", "status"]},
            leeway=0,
        )
        body = OwnerEffectStatusV2.model_validate_json(
            json.dumps(claims["status"], sort_keys=True, separators=(",", ":"), allow_nan=False)
        )
        observed = datetime.now(UTC)
        if (
            body != signed.status
            or UUID(claims["jti"]).version != 4
            or claims["purpose"] != "owner-effect-status-v2"
            or type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or not 0 < claims["exp"] - claims["iat"] <= 30
            or body.owner != command.owner
            or body.owner_database != command.owner_database
            or body.recipient_service_id != recipient.service_id
            or body.recipient_instance_uuid != recipient.instance_uuid
            or body.project_id != command.project_id
            or body.actor_id != command.actor_id
            or body.agent_session_uuid != command.agent_session_uuid
            or body.operation_uuid != command.operation_uuid
            or body.idempotency_uuid != command.idempotency_uuid
            or body.phase != command.phase
            or body.action != command.action
            or body.request_sha256 != command.request_sha256
            or body.target_sha256 != command.target_sha256
            or body.payload_sha256 != command.payload_sha256
            or body.original_idempotency_key_sha256
            != hashlib.sha256(original_idempotency_key.encode()).hexdigest()
            or body.owner_revision < max(1, command.expected_version)
            or body.observed_at.tzinfo is None
            or body.observed_at > observed
            or body.expires_at <= observed
            or body.expires_at > recipient.expires_at
            or body.expires_at > datetime.fromtimestamp(claims["exp"], UTC)
            or body.retry_with_new_key_allowed is not False
            or (body.state != "COMMITTED" and body.result_sha256 is not None)
        ):
            raise OwnerAuthorityUnavailable("original owner effect signed status mismatched")
        return body
    except (jwt.PyJWTError, ValidationError, ValueError, TypeError, KeyError):
        raise OwnerAuthorityUnavailable("owner signed status v2 could not verify") from None
