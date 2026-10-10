"""One-database-only idempotent commands with immutable outbox and audit.

Only locally transactional SQL changes belong inside the supplied mutation.
Remote providers/files/processes use a separate UNKNOWN/reconcile protocol.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import import_module
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from common.owner_contracts import (
    CurrentOwnerAuthorityPort,
    OwnerCommandDTO,
    OwnerProofAuthority,
    SignedOwnerProofs,
    VerifiedOwnerOperation,
    require_online_owner_decision,
)
from common.platform_db import OWNER_DB_NAMES, OwnerName, PlatformDatabase

_OWNED_LEDGERS: dict[OwnerName, str] = {
    "identity": "identity._owner_ledger",
    "platform": "projects._control_ledger",
    "resources": "projects._catalog_ledger",
    "files": "projects._files_ledger",
    "runtime": "projects._execution_ledger",
    "reverse": "projects._reverse_ledger",
}


class OwnerCommandRejected(RuntimeError):
    """Unknown command result is not an invitation to replay a side effect."""


@dataclass(frozen=True, slots=True)
class OwnerCommandOutcome:
    operation_uuid: UUID
    state: str
    result: dict[str, object] | None


class OwnerLocalCommandExecutor:
    def __init__(
        self,
        db: PlatformDatabase,
        owner: OwnerName,
        *,
        encryption_key: SecretStr,
        source_authority: OwnerProofAuthority,
        current_owners: CurrentOwnerAuthorityPort,
    ) -> None:
        if owner not in _OWNED_LEDGERS or db.engine.url.database != OWNER_DB_NAMES[owner]:
            raise OwnerCommandRejected("source-owned database mismatch or inactive ledger")
        if not encryption_key.get_secret_value():
            raise ValueError("encrypted command outcome requires injected owner secret")
        if source_authority is None or current_owners is None:
            raise OwnerCommandRejected("signed owner proof verifier is mandatory")
        self.source_authority = source_authority
        self.current_owners = current_owners
        self.db = db
        self.owner = owner
        self.crypt = Fernet(encryption_key.get_secret_value().encode())
        module = import_module(_OWNED_LEDGERS[owner])
        self.commands = module.OwnerCommandRow
        self.outbox = module.OwnerOutboxRow
        self.audit = module.OwnerAuditRow

    async def execute_local(
        self,
        decision: VerifiedOwnerOperation,
        proofs: SignedOwnerProofs,
        mutation: Callable[[AsyncSession], Awaitable[dict[str, object]]],
        *,
        event: str,
        target: str,
    ) -> OwnerCommandOutcome:
        request: OwnerCommandDTO = decision.request
        initial = self.source_authority.require_current(request, proofs)
        fresh = await require_online_owner_decision(
            self.source_authority, self.current_owners, request
        )
        if (
            initial.identity_epoch != fresh.identity_epoch
            or initial.control_epoch != fresh.control_epoch
            or initial.access_epoch != fresh.access_epoch
        ):
            raise OwnerCommandRejected("source epochs changed before owner transaction")
        if (
            decision.identity_epoch != fresh.identity_epoch
            or decision.control_epoch != fresh.control_epoch
            or decision.access_epoch != fresh.access_epoch
            or decision.actor_role != fresh.actor_role
        ):
            raise OwnerCommandRejected("owner proofs differ from signed source attestations")
        if request.target_owner != self.owner:
            raise OwnerCommandRejected("command sent to wrong data owner")
        if datetime.now(UTC) - decision.verified_at > timedelta(seconds=5):
            raise OwnerCommandRejected("owner authority expired before command commit")
        if not event or len(event) > 128 or len(target) > 128:
            raise OwnerCommandRejected("invalid bounded audit event")
        actor_scope = str(request.caller_user_id)
        project_scope = str(request.project_id)
        try:
            async with self.db.transaction() as tx:
                # Each phase is a separate command row, but ALL phases MUST
                # retain the original UUID/actor/Project/Idempotency-Key.
                # A PostgreSQL transaction-scoped lock serializes simultaneous
                # first-phase attempts without a shared global transaction or
                # a new owner-roots table. It is released on commit/rollback.
                await tx.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                    {"scope": f"briareus:{self.owner}:{request.operation_uuid}"},
                )
                same_original = list(
                    await tx.scalars(
                        select(self.commands)
                        .where(
                            self.commands.operation_uuid == request.operation_uuid,
                        )
                        .with_for_update()
                    )
                )
                for original in same_original:
                    if (
                        original.actor_scope != actor_scope
                        or original.project_scope != project_scope
                        or original.key != request.idempotency_key
                    ):
                        raise OwnerCommandRejected(
                            "original UUID cannot cross owner scope or original key"
                        )
                    if original.operation != request.operation and original.state not in {
                        "completed",
                        "reconciled",
                    }:
                        raise OwnerCommandRejected(
                            "next phase is blocked by unresolved original owner command"
                        )
                row = await tx.scalar(
                    select(self.commands)
                    .where(
                        self.commands.actor_scope == actor_scope,
                        self.commands.project_scope == project_scope,
                        self.commands.operation == request.operation,
                        self.commands.key == request.idempotency_key,
                    )
                    .with_for_update()
                )
                if row is not None:
                    if (
                        row.fingerprint != request.payload_sha256
                        or row.operation_uuid != request.operation_uuid
                    ):
                        raise OwnerCommandRejected(
                            "idempotency key was reused with different effect"
                        )
                    if row.state in {"pending", "unknown"}:
                        return OwnerCommandOutcome(row.operation_uuid, "UNKNOWN", None)
                    if (
                        row.state not in {"completed", "reconciled"}
                        or row.encrypted_outcome is None
                    ):
                        raise OwnerCommandRejected("owner command is not replayable")
                    try:
                        replay = json.loads(self.crypt.decrypt(row.encrypted_outcome.encode()))
                        if not isinstance(replay, dict):
                            raise ValueError("non-object result")
                    except (InvalidToken, ValueError, TypeError, UnicodeDecodeError) as exc:
                        raise OwnerCommandRejected(
                            "stored command outcome cannot be authenticated"
                        ) from exc
                    return OwnerCommandOutcome(row.operation_uuid, "COMMITTED", replay)
                row = self.commands(
                    operation_uuid=request.operation_uuid,
                    actor_scope=actor_scope,
                    project_scope=project_scope,
                    operation=request.operation,
                    key=request.idempotency_key,
                    fingerprint=request.payload_sha256,
                    expected_owner_revision=str(request.expected_control_revision),
                    state="pending",
                    expires_at=datetime.now(UTC) + timedelta(days=7),
                )
                tx.add(row)
                await tx.flush()
                result = await mutation(tx)
                # Any exception rolls back command, business rows, audit and outbox.
                if datetime.now(UTC) - decision.verified_at > timedelta(seconds=5):
                    raise OwnerCommandRejected("owner attestation expired during local transaction")
                final = await require_online_owner_decision(
                    self.source_authority, self.current_owners, request
                )
                if (
                    final.identity_epoch != fresh.identity_epoch
                    or final.control_epoch != fresh.control_epoch
                    or final.access_epoch != fresh.access_epoch
                    or final.actor_role != fresh.actor_role
                ):
                    raise OwnerCommandRejected(
                        "source owner revision invalidated during transaction"
                    )
                row.state = "completed"
                row.updated_at = datetime.now(UTC)
                row.encrypted_outcome = self.crypt.encrypt(
                    json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
                ).decode()
                tx.add(
                    self.outbox(
                        operation_uuid=request.operation_uuid,
                        event_name=event,
                        owner_revision=row.expected_owner_revision,
                        event_payload={
                            "operation_uuid": str(request.operation_uuid),
                            "project_id": project_scope,
                            "event": event,
                        },
                    )
                )
                tx.add(
                    self.audit(
                        operation_uuid=request.operation_uuid,
                        actor_user_id=request.caller_user_id,
                        project_id=request.project_id,
                        action=event,
                        object_id=target,
                        owner_revision=row.expected_owner_revision,
                        details={"operation_uuid": str(request.operation_uuid)},
                    )
                )
                return OwnerCommandOutcome(request.operation_uuid, "COMMITTED", result)
        except IntegrityError:
            # Competing concurrent INSERTs for the same idempotency key are
            # serialized by PostgreSQL UNIQUE. The losing transaction is
            # rolled back; read a fresh authorized outcome using the ORIGINAL
            # operation UUID/key. An unrelated business UNIQUE error still
            # propagates if the owner command does not exist.
            collision = await self.status(request, proofs)
            if collision is None:
                raise
            return collision

    async def status(
        self, request: OwnerCommandDTO, proofs: SignedOwnerProofs
    ) -> OwnerCommandOutcome | None:
        """Owner-only command status after FRESH three-owner authority.

        Does not disclose a result across a revoked User/Project/AgentSession.
        In-flight and UNKNOWN are not silently retried or reported successful.
        """
        if request.target_owner != self.owner:
            raise OwnerCommandRejected("command status recipient is not the durable owner")
        initial = self.source_authority.require_current(request, proofs)
        current = await require_online_owner_decision(
            self.source_authority, self.current_owners, request
        )
        if (
            initial.identity_epoch != current.identity_epoch
            or initial.control_epoch != current.control_epoch
            or initial.access_epoch != current.access_epoch
        ):
            raise OwnerCommandRejected("command result source authorization was revoked")
        async with self.db.transaction() as tx:
            row = await tx.scalar(
                select(self.commands)
                .where(
                    self.commands.operation_uuid == request.operation_uuid,
                    self.commands.actor_scope == str(request.caller_user_id),
                    self.commands.project_scope == str(request.project_id),
                    self.commands.operation == request.operation,
                    self.commands.key == request.idempotency_key,
                )
                .with_for_update()
            )
            if row is None:
                return None
            if row.fingerprint != request.payload_sha256:
                raise OwnerCommandRejected("command status request fingerprint mismatch")
            if row.state in {"pending", "unknown"}:
                return OwnerCommandOutcome(row.operation_uuid, "UNKNOWN", None)
            if row.state == "denied":
                return OwnerCommandOutcome(row.operation_uuid, "DENIED", None)
            if row.state not in {"completed", "reconciled"} or row.encrypted_outcome is None:
                raise OwnerCommandRejected("command outcome is not reconciled")
            try:
                outcome = json.loads(self.crypt.decrypt(row.encrypted_outcome.encode()))
                if not isinstance(outcome, dict):
                    raise ValueError("stored result is not an object")
            except (InvalidToken, ValueError, TypeError, UnicodeDecodeError):
                raise OwnerCommandRejected(
                    "encrypted owner command result is unavailable"
                ) from None
            return OwnerCommandOutcome(row.operation_uuid, "COMMITTED", outcome)
