"""Read current ORIGINAL owner SQL and emit an Ed25519 source-only BFF status.

C2 issuer, private verified admin actor and recipient are REQUIRED adapters.
The signer NEVER signs unverified caller-provided phase, target or revision.
All public routes remain unmounted until independently accepted C1-B2/C2.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import import_module
from typing import Protocol
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr
from sqlalchemy import select

from common.owner_bff_signed import (
    BffOwner,
    OriginalOwnerSignedEnvelope,
    Phase,
    SignedOriginalOwnerStatus,
    canonical_original_identity,
)
from common.owner_contracts import OwnerAuthorityUnavailable
from common.platform_db import PlatformDatabase

_SOURCE_TO_DB: dict[BffOwner, str] = {
    "identity": "briareus_identity",
    "access": "briareus_access",
    "control": "briareus_platform",
    "catalog": "briareus_resources",
}
_SOURCE_LEDGER: dict[BffOwner, tuple[str, str]] = {
    "identity": ("identity._owner_ledger", "OwnerCommandRow"),
    "access": ("authorization._platform_persistence", "IdempotencyRow"),
    "control": ("projects._control_ledger", "OwnerCommandRow"),
    "catalog": ("projects._catalog_ledger", "OwnerCommandRow"),
}
_SOURCE_ISSUER: dict[BffOwner, str] = {
    "identity": "briareus-identity",
    "access": "briareus-access",
    "control": "briareus-platform",
    "catalog": "briareus-resources",
}


@dataclass(frozen=True, slots=True)
class CurrentOriginalBffSourceGrant:
    """Trusted C2 result: current owner approval of original SQL scope/binding."""

    actor_user_id: UUID
    operation_uuid: UUID
    original_key: str
    original_operation: str
    original_project_scope: str
    scope_sha256: str
    binding_sha256: str
    owner_revision: str
    recipient_service_id: UUID
    recipient_instance_uuid: UUID
    expires_at: datetime


class TrustedOriginalBffGrantPort(Protocol):
    async def current(
        self,
        *,
        owner: BffOwner,
        actor_user_id: UUID,
        operation_uuid: UUID,
        original_key: str,
        original_operation: str,
        scope_sha256: str,
        binding_sha256: str,
        recipient_service_id: UUID,
        recipient_instance_uuid: UUID,
        source_evidence: object,
    ) -> CurrentOriginalBffSourceGrant:
        """Must verify current User and owner target after original delegation."""
        ...


class BffOriginalOwnerSigner:
    def __init__(
        self,
        *,
        owner: BffOwner,
        db: PlatformDatabase,
        private_key_pem: SecretStr,
        grants: TrustedOriginalBffGrantPort,
    ) -> None:
        if db.engine.url.database != _SOURCE_TO_DB[owner] or grants is None:
            raise RuntimeError("BFF signer must use the originating owner SQL and live C2")
        try:
            signing = serialization.load_pem_private_key(
                private_key_pem.get_secret_value().encode(),
                password=None,
            )
            if not isinstance(signing, Ed25519PrivateKey):
                raise ValueError("BFF source signer is not Ed25519")
        except (ValueError, TypeError):
            raise ValueError("invalid release-custodied BFF source signer key") from None
        self.owner = owner
        self.db = db
        self.grants = grants
        self.key = signing
        self.kid = hashlib.sha256(
            signing.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        module, model = _SOURCE_LEDGER[owner]
        self.row_type = getattr(import_module(module), model)

    async def sign_original(
        self,
        *,
        actor_user_id: UUID,
        operation_uuid: UUID,
        original_key: str,
        original_operation: str,
        scope_sha256: str,
        binding_sha256: str,
        recipient_service_id: UUID,
        recipient_instance_uuid: UUID,
        source_evidence: object,
    ) -> OriginalOwnerSignedEnvelope:
        key_sha = canonical_original_identity(operation_uuid, original_key)
        if (
            actor_user_id.version != 4
            or recipient_service_id.version != 4
            or recipient_instance_uuid.version != 4
            or not original_operation
            or len(original_operation) > 128
        ):
            raise OwnerAuthorityUnavailable("invalid signed original BFF selector")

        async def live() -> CurrentOriginalBffSourceGrant:
            try:
                async with asyncio.timeout(3):
                    grant = await self.grants.current(
                        owner=self.owner,
                        actor_user_id=actor_user_id,
                        operation_uuid=operation_uuid,
                        original_key=original_key,
                        original_operation=original_operation,
                        scope_sha256=scope_sha256,
                        binding_sha256=binding_sha256,
                        recipient_service_id=recipient_service_id,
                        recipient_instance_uuid=recipient_instance_uuid,
                        source_evidence=source_evidence,
                    )
            except Exception:
                raise OwnerAuthorityUnavailable(
                    "owner current original scope unavailable"
                ) from None
            now = datetime.now(UTC)
            if (
                not isinstance(grant, CurrentOriginalBffSourceGrant)
                or grant.actor_user_id != actor_user_id
                or grant.operation_uuid != operation_uuid
                or grant.original_key != original_key
                or grant.original_operation != original_operation
                or grant.scope_sha256 != scope_sha256
                or grant.binding_sha256 != binding_sha256
                or grant.recipient_service_id != recipient_service_id
                or grant.recipient_instance_uuid != recipient_instance_uuid
                or not grant.original_project_scope
                or not 1 <= len(grant.owner_revision) <= 160
                or grant.expires_at.tzinfo is None
                or not now < grant.expires_at <= now + timedelta(seconds=15)
            ):
                raise OwnerAuthorityUnavailable("original signed owner grant changed")
            return grant

        initial = await live()
        async with self.db.transaction() as tx:
            clauses = [
                self.row_type.actor_scope == str(actor_user_id),
                self.row_type.project_scope == initial.original_project_scope,
                self.row_type.operation == original_operation,
                self.row_type.key == original_key,
            ]
            if self.owner != "access":
                clauses.append(self.row_type.operation_uuid == operation_uuid)
            row = await tx.scalar(select(self.row_type).where(*clauses).with_for_update())
            if row is None:
                raise OwnerAuthorityUnavailable("original owner command not durably found")
            if self.owner == "access":
                # Historical Access ledger has no operation_uuid column.
                # Only an exact canonical UUIDv4 original key can bind its
                # row to the caller's Operation-UUID without inference.
                status = row.status
                encrypted = row.response_ciphertext
            else:
                status = row.state
                encrypted = row.encrypted_outcome
            phase: Phase
            if status in {"pending", "unknown"}:
                phase = "unknown"
            elif status == "denied":
                phase = "denied"
            elif status in {"completed", "reconciled"} and encrypted is not None:
                # Only this originating database's own row is completed.
                # ALL source owners must independently sign for aggregate.
                phase = "confirmed"
            else:
                raise OwnerAuthorityUnavailable("original owner effect state is not verified")
        final = await live()
        if (
            final.original_project_scope != initial.original_project_scope
            or final.owner_revision != initial.owner_revision
            or final.scope_sha256 != initial.scope_sha256
            or final.binding_sha256 != initial.binding_sha256
        ):
            raise OwnerAuthorityUnavailable("original grant revoked before BFF status signature")
        now = datetime.now(UTC)
        expires = datetime.fromtimestamp(
            int(
                min(
                    now + timedelta(seconds=15),
                    final.expires_at,
                ).timestamp()
            ),
            UTC,
        )
        if expires <= now:
            raise OwnerAuthorityUnavailable("BFF original source signature has expired")
        status_receipt = SignedOriginalOwnerStatus(
            owner=self.owner,
            actor_user_id=actor_user_id,
            operation_uuid=operation_uuid,
            original_idempotency_key_sha256=key_sha,
            scope_sha256=scope_sha256,
            binding_sha256=binding_sha256,
            owner_revision=final.owner_revision,
            phase=phase,
            issued_at=now,
            expires_at=expires,
            recipient_service_id=recipient_service_id,
            recipient_instance_uuid=recipient_instance_uuid,
        )
        jws = jwt.encode(
            {
                "iss": _SOURCE_ISSUER[self.owner],
                "aud": f"briareus:admin-bff:{recipient_service_id}",
                "iat": int(now.timestamp()),
                "nbf": int(now.timestamp()),
                "exp": int(expires.timestamp()),
                "jti": str(uuid4()),
                "purpose": "briareus-bff-original-owner-v1",
                "receipt": status_receipt.model_dump(mode="json"),
            },
            self.key,
            algorithm="EdDSA",
            headers={"typ": "briareus-bff-owner+jwt", "kid": self.kid},
        )
        return OriginalOwnerSignedEnvelope(receipt=status_receipt, attestation_jws=jws)
