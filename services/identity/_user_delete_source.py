"""Identity-owned deleted-User tombstone under independently signed owner impact.

A cross-owner operation is NOT one ACID transaction. This source only
tombstones a User after a trusted private issuer has attested zero remaining
Control Team/Project ownership and zero active Access AgentSessions at the
same revocation fence. When that future C2 issuer does not exist, deletion
fails closed instead of orphaning durable Catalog/Files/Runtime resources.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from common.owner_contracts import OwnerAuthorityUnavailable
from common.owner_transactions import OwnerCommandOutcome
from common.platform_db import PlatformDatabase
from common.platform_errors import AccessDenied, Conflict, LastSuperuser
from identity._owner_ledger import OwnerAuditRow, OwnerCommandRow, OwnerOutboxRow
from identity._persistence import UserRow
from identity._repository import IdentityRepository


class SignedUserDeletionIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    operation_uuid: UUID
    actor_user_id: UUID
    target_user_id: UUID
    idempotency_key: str = Field(min_length=1, max_length=128)
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    actor_credential_version: int = Field(ge=1)
    target_credential_version: int = Field(ge=1)
    confirmed: bool = True

    @field_validator("operation_uuid", "actor_user_id", "target_user_id")
    @classmethod
    def uuid4(cls, value: UUID) -> UUID:
        if value.version != 4:
            raise ValueError("Identity global command IDs must be UUIDv4")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def original_key(cls, value: str) -> str:
        if not value.isascii() or not value.isprintable():
            raise ValueError("printable original Idempotency-Key required")
        return value


@dataclass(frozen=True, slots=True)
class VerifiedDeletionImpact:
    actor_user_id: UUID
    target_user_id: UUID
    operation_uuid: UUID
    issuer_owner: str
    no_owned_teams: bool
    no_owned_projects: bool
    no_active_agent_sessions: bool
    no_pending_owner_effects: bool
    current_revocation_epoch: UUID
    observed_at: datetime


class TrustedIdentityDeleteSource(Protocol):
    async def verify_current(
        self,
        command: SignedUserDeletionIntent,
        *,
        caller_evidence: object,
    ) -> tuple[VerifiedDeletionImpact, VerifiedDeletionImpact]:
        """Return separately pinned Control and Access current impact.

        Must re-attest original admin actor plus Target User and revocation
        fence. No browser-supplied impact, cached WS event or unsigned HTTP.
        """
        ...


class IdentityUserDeleteSource:
    def __init__(
        self,
        db: PlatformDatabase,
        *,
        verifier: TrustedIdentityDeleteSource,
        encryption_key: SecretStr,
    ) -> None:
        if db.engine.url.database != "briareus_identity" or verifier is None:
            raise RuntimeError("deleted User source must be isolated Identity/C2")
        self.db = db
        self.verifier = verifier
        self.cipher = Fernet(encryption_key.get_secret_value().encode())
        self.repo = IdentityRepository()

    @staticmethod
    def _impact(
        command: SignedUserDeletionIntent,
        receipts: tuple[VerifiedDeletionImpact, VerifiedDeletionImpact],
    ) -> tuple[UUID, UUID]:
        now = datetime.now(UTC)
        if len(receipts) != 2 or {item.issuer_owner for item in receipts} != {"platform", "access"}:
            raise OwnerAuthorityUnavailable("current Control+Access deletion evidence required")
        for item in receipts:
            if (
                item.actor_user_id != command.actor_user_id
                or item.target_user_id != command.target_user_id
                or item.operation_uuid != command.operation_uuid
                or item.current_revocation_epoch.version != 4
                or item.observed_at.tzinfo is None
                or not timedelta(0) <= now - item.observed_at <= timedelta(seconds=5)
                or not item.no_owned_teams
                or not item.no_owned_projects
                or not item.no_active_agent_sessions
                or not item.no_pending_owner_effects
            ):
                raise OwnerAuthorityUnavailable("owner deletion impact not current/empty")
        return receipts[0].current_revocation_epoch, receipts[1].current_revocation_epoch

    async def delete(
        self,
        command: SignedUserDeletionIntent,
        *,
        caller_evidence: object,
    ) -> OwnerCommandOutcome:
        import hashlib

        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "actor_user_id": str(command.actor_user_id),
                    "target_user_id": str(command.target_user_id),
                    "confirmed": command.confirmed,
                },
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        if fingerprint != command.payload_sha256 or not command.confirmed:
            raise AccessDenied("Identity deletion signed payload/confirmation invalid")

        async def verified_impact() -> tuple[UUID, UUID]:
            try:
                async with asyncio.timeout(3):
                    signed = await self.verifier.verify_current(
                        command,
                        caller_evidence=caller_evidence,
                    )
                return self._impact(command, signed)
            except Exception:
                raise OwnerAuthorityUnavailable(
                    "signed fresh Control+Access deletion impact unavailable"
                ) from None

        start_epochs = await verified_impact()
        try:
            async with self.db.transaction() as tx:
                await tx.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:scope,0))"),
                    {"scope": f"briareus:identity:{command.operation_uuid}"},
                )
                rows = list(
                    await tx.scalars(
                        select(OwnerCommandRow)
                        .where(
                            OwnerCommandRow.operation_uuid == command.operation_uuid,
                        )
                        .with_for_update()
                    )
                )
                for row in rows:
                    if (
                        row.actor_scope != str(command.actor_user_id)
                        or row.project_scope != f"user:{command.target_user_id}"
                        or row.key != command.idempotency_key
                    ):
                        raise Conflict("original User deletion scope/key conflict")
                old = await tx.scalar(
                    select(OwnerCommandRow)
                    .where(
                        OwnerCommandRow.actor_scope == str(command.actor_user_id),
                        OwnerCommandRow.project_scope == f"user:{command.target_user_id}",
                        OwnerCommandRow.operation == "identity.user.delete",
                        OwnerCommandRow.key == command.idempotency_key,
                    )
                    .with_for_update()
                )
                if old is not None:
                    if (
                        old.operation_uuid != command.operation_uuid
                        or old.fingerprint != fingerprint
                    ):
                        raise Conflict("User deletion original Idempotency-Key changed")
                    if old.state != "completed" or old.encrypted_outcome is None:
                        return OwnerCommandOutcome(command.operation_uuid, "UNKNOWN", None)
                    try:
                        old_result = json.loads(self.cipher.decrypt(old.encrypted_outcome.encode()))
                        if not isinstance(old_result, dict):
                            raise ValueError("stored outcome not an object")
                    except (InvalidToken, ValueError, TypeError, UnicodeDecodeError):
                        raise Conflict(
                            "Identity encrypted original deletion outcome unverified"
                        ) from None
                    return OwnerCommandOutcome(command.operation_uuid, "COMMITTED", old_result)
                await self.repo.lock_bootstrap(tx)
                actor = await tx.scalar(
                    select(UserRow)
                    .where(
                        UserRow.id == command.actor_user_id,
                    )
                    .with_for_update()
                )
                target = await tx.scalar(
                    select(UserRow)
                    .where(
                        UserRow.id == command.target_user_id,
                    )
                    .with_for_update()
                )
                if (
                    actor is None
                    or not actor.enabled
                    or actor.deleted_at is not None
                    or actor.role != "superuser"
                    or actor.credential_version != command.actor_credential_version
                    or target is None
                    or not target.enabled
                    or target.deleted_at is not None
                    or target.credential_version != command.target_credential_version
                ):
                    raise AccessDenied("Identity actor/target role or credential revoked")
                if (
                    target.role == "superuser"
                    and len(await self.repo.list_active_superusers(tx)) <= 1
                ):
                    raise LastSuperuser("cannot delete the last active superuser")
                row = OwnerCommandRow(
                    operation_uuid=command.operation_uuid,
                    actor_scope=str(command.actor_user_id),
                    project_scope=f"user:{command.target_user_id}",
                    operation="identity.user.delete",
                    key=command.idempotency_key,
                    fingerprint=fingerprint,
                    expected_owner_revision=str(target.credential_version),
                    state="pending",
                    expires_at=datetime.now(UTC) + timedelta(days=7),
                )
                tx.add(row)
                await tx.flush()
                # Remote epoch checks are not globally atomic with this SQL
                # transaction; only an accepted durable C2 fenced issuer can
                # allow live deletion. Absence or mismatch stops source effect.
                if await verified_impact() != start_epochs:
                    raise OwnerAuthorityUnavailable("deletion impact revoked before commit")
                now = datetime.now(UTC)
                target.deleted_at = now
                target.enabled = False
                target.credential_version += 1
                target.browser_telemetry_opt_in = False
                target.updated_at = now
                await tx.execute(
                    text(
                        "UPDATE identity.invitations SET revoked_at=:revoked "
                        "WHERE revoked_at IS NULL AND used_at IS NULL "
                        "AND (created_by_user_id=:target OR target_user_id=:target)"
                    ),
                    {"revoked": now, "target": command.target_user_id},
                )
                result: dict[str, object] = {
                    "user_id": str(target.id),
                    "deleted": True,
                    "credential_version": target.credential_version,
                    "reconciliation_required": True,
                }
                row.state = "completed"
                row.updated_at = now
                row.encrypted_outcome = self.cipher.encrypt(
                    json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
                ).decode()
                tx.add(
                    OwnerOutboxRow(
                        operation_uuid=command.operation_uuid,
                        event_name="identity.user_deleted",
                        owner_revision=str(target.credential_version),
                        event_payload={
                            "user_id": str(target.id),
                            "credential_version": target.credential_version,
                        },
                    )
                )
                tx.add(
                    OwnerAuditRow(
                        operation_uuid=command.operation_uuid,
                        actor_user_id=command.actor_user_id,
                        project_id=None,
                        action="identity.user_deleted",
                        object_id=str(target.id),
                        owner_revision=str(target.credential_version),
                        details={"recipient_user_id": str(target.id)},
                    )
                )
                return OwnerCommandOutcome(command.operation_uuid, "COMMITTED", result)
        except IntegrityError:
            raise Conflict("Identity original deletion conflict; inspect same UUID/key") from None
