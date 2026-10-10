"""Control-local projection of verified per-owner outbox events.

These rows are NEVER permission evidence. Every browser/WS resume/poll/ACK
requires a newly verified Identity+Control current reader from private C2.
No global SQL join or Authorization-owned outbox foreign key is used.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID, uuid4

from sqlalchemy import select

from authorization._scoped_events_persistence import (
    ScopeCursorRow,
    ScopeDeliveryReceiptRow,
    ScopeEventRow,
)
from common.platform_db import PlatformDatabase
from common.platform_errors import AccessDenied, Conflict, InvalidInput

ScopeKind = Literal["user", "team", "project"]
_SourceOwner = Literal["identity", "access", "platform", "resources", "files", "runtime", "reverse"]
_ALLOWED_DETAIL_KEYS = frozenset(
    {
        "project_id",
        "team_id",
        "owner_scope",
        "owner_id",
        "resource_id",
        "resource_version",
        "owner_resource_revision",
        "quota_revision",
        "reservation_revision",
        "runtime_revision",
        "job_version",
        "job_status",
        "native_project_id",
        "native_import_version",
        "source_file_version",
        "session_version",
        "approved",
        "enabled",
        "reconciliation_required",
        "cleanup_required",
        "over_limit",
        "lifecycle_status",
        "scope_epoch",
    }
)


@dataclass(frozen=True, slots=True)
class VerifiedOwnerOutboxEvent:
    source_owner: _SourceOwner
    source_outbox_id: UUID
    operation_uuid: UUID
    scope_kind: ScopeKind
    scope_id: UUID
    event_type: str
    actor_user_id: UUID | None
    detail: dict[str, object]
    produced_at: datetime


class TrustedScopedOutboxEvidence(Protocol):
    def verify(self, evidence: object) -> VerifiedOwnerOutboxEvent:
        """Check issuer peer/JWS, durable source outbox and original scope."""
        ...


class CurrentScopedReaderPort(Protocol):
    async def require_current(
        self, *, user_id: UUID, scope_kind: ScopeKind, scope_id: UUID
    ) -> None:
        """Re-attest live User and Team/Project membership; no projection rights."""
        ...


@dataclass(frozen=True, slots=True)
class VerifiedScopedSubscriber:
    subscriber_id: UUID
    actor_user_id: UUID
    scope_kind: ScopeKind
    scope_id: UUID
    expires_at: datetime


class TrustedScopedSubscriberPort(Protocol):
    def verify_subscriber(self, evidence: object) -> VerifiedScopedSubscriber:
        """Must verify bearer/current scope and subscriber from transport."""
        ...


@dataclass(frozen=True, slots=True)
class OwnerScopeOffset:
    scope_kind: ScopeKind
    scope_id: UUID
    epoch: UUID
    sequence: int


@dataclass(frozen=True, slots=True)
class OwnerScopeEvent:
    event_uuid: UUID
    source_outbox_id: UUID
    event_type: str
    safe_payload: dict[str, object]
    created_at: datetime
    offset: OwnerScopeOffset


class ScopedOwnerProjection:
    def __init__(
        self,
        db: PlatformDatabase,
        source: TrustedScopedOutboxEvidence,
        current_reader: CurrentScopedReaderPort,
        subscriber_verifier: TrustedScopedSubscriberPort,
    ) -> None:
        if (
            db.engine.url.database != "briareus_platform"
            or source is None
            or current_reader is None
            or subscriber_verifier is None
        ):
            raise RuntimeError("scope projection must have signed origin and current Control")
        self.db = db
        self.source = source
        self.current_reader = current_reader
        self.subscriber_verifier = subscriber_verifier

    @staticmethod
    def _safe(details: dict[str, object]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in details.items():
            if key not in _ALLOWED_DETAIL_KEYS:
                continue
            if (
                isinstance(value, bool)
                or (isinstance(value, int) and 0 <= value < 2**63)
                or (isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value))
            ):
                result[key] = value
        return result

    async def ingest(self, evidence: object) -> OwnerScopeOffset:
        try:
            event = self.source.verify(evidence)
        except Exception:
            raise AccessDenied("signed durable source-owner outbox receipt required") from None
        if (
            not isinstance(event, VerifiedOwnerOutboxEvent)
            or event.source_outbox_id.version != 4
            or event.operation_uuid.version != 4
            or event.scope_id.version != 4
            or event.scope_kind not in {"user", "team", "project"}
            or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", event.event_type)
            or event.produced_at.tzinfo is None
            or event.produced_at > datetime.now(UTC) + timedelta(minutes=1)
        ):
            raise AccessDenied("source outbox scope/revision claim invalid")
        async with self.db.transaction() as tx:
            old = await tx.scalar(
                select(ScopeEventRow).where(
                    ScopeEventRow.scope_kind == event.scope_kind,
                    ScopeEventRow.scope_id == event.scope_id,
                    ScopeEventRow.source_outbox_id == event.source_outbox_id,
                )
            )
            if old is not None:
                return OwnerScopeOffset(event.scope_kind, event.scope_id, old.epoch, old.sequence)
            cursor = await tx.scalar(
                select(ScopeCursorRow)
                .where(
                    ScopeCursorRow.scope_kind == event.scope_kind,
                    ScopeCursorRow.scope_id == event.scope_id,
                )
                .with_for_update()
            )
            if cursor is None:
                cursor = ScopeCursorRow(
                    scope_kind=event.scope_kind,
                    scope_id=event.scope_id,
                    epoch=uuid4(),
                    revision=0,
                )
                tx.add(cursor)
                await tx.flush()
            cursor.revision += 1
            cursor.updated_at = datetime.now(UTC)
            if event.event_type in {
                "identity.suspended",
                "identity.deleted",
                "identity.role_changed",
                "team.member_removed",
                "team.owner_transferred",
                "session.revoked",
                "project.delete_preparing",
                "project.delete_finalized",
            }:
                cursor.epoch = uuid4()
            tx.add(
                ScopeEventRow(
                    event_id=uuid4(),
                    scope_kind=event.scope_kind,
                    scope_id=event.scope_id,
                    sequence=cursor.revision,
                    epoch=cursor.epoch,
                    source_outbox_id=event.source_outbox_id,
                    event_type=event.event_type,
                    actor_user_id=event.actor_user_id,
                    safe_payload=self._safe(event.detail),
                    created_at=datetime.now(UTC),
                    expires_at=datetime.now(UTC) + timedelta(days=7),
                )
            )
            return OwnerScopeOffset(event.scope_kind, event.scope_id, cursor.epoch, cursor.revision)

    async def read(
        self,
        *,
        actor_user_id: UUID,
        scope_kind: ScopeKind,
        scope_id: UUID,
        epoch: UUID | None,
        after_sequence: int,
        limit: int = 64,
    ) -> tuple[OwnerScopeEvent, ...]:
        if (
            actor_user_id.version != 4
            or scope_id.version != 4
            or (epoch is not None and epoch.version != 4)
            or after_sequence < 0
            or not 1 <= limit <= 128
        ):
            raise InvalidInput("scoped event cursor bounds invalid")
        # Native OAuth/session/grant proof MUST be checked again for every
        # resumed poll; an old projected member event grants no access.
        try:
            import asyncio

            async with asyncio.timeout(3):
                await self.current_reader.require_current(
                    user_id=actor_user_id, scope_kind=scope_kind, scope_id=scope_id
                )
        except Exception:
            raise AccessDenied("realtime scope no longer authorized") from None
        async with self.db.transaction() as tx:
            cursor = await tx.scalar(
                select(ScopeCursorRow).where(
                    ScopeCursorRow.scope_kind == scope_kind,
                    ScopeCursorRow.scope_id == scope_id,
                )
            )
            if cursor is None:
                return ()
            if epoch is not None and cursor.epoch != epoch:
                raise Conflict("scope epoch rotated; caller must reauthorize and resynchronize")
            rows = await tx.scalars(
                select(ScopeEventRow)
                .where(
                    ScopeEventRow.scope_kind == scope_kind,
                    ScopeEventRow.scope_id == scope_id,
                    ScopeEventRow.sequence > after_sequence,
                    ScopeEventRow.expires_at > datetime.now(UTC),
                )
                .order_by(ScopeEventRow.sequence)
                .limit(limit)
            )
            return tuple(
                OwnerScopeEvent(
                    event_uuid=row.event_id,
                    source_outbox_id=row.source_outbox_id,
                    event_type=row.event_type,
                    safe_payload=row.safe_payload,
                    created_at=row.created_at,
                    offset=OwnerScopeOffset(scope_kind, scope_id, row.epoch, row.sequence),
                )
                for row in rows
            )

    async def acknowledge(
        self,
        *,
        subscriber_evidence: object,
        scope_kind: ScopeKind,
        scope_id: UUID,
        epoch: UUID,
        sequence: int,
    ) -> int:
        """Durable ACK after authenticated scope read; Valkey Pub/Sub != ACK."""
        try:
            subscriber = self.subscriber_verifier.verify_subscriber(subscriber_evidence)
        except Exception:
            raise AccessDenied("trusted scoped subscriber evidence required") from None
        if (
            subscriber.subscriber_id.version != 4
            or subscriber.actor_user_id.version != 4
            or subscriber.scope_kind != scope_kind
            or subscriber.scope_id != scope_id
            or scope_id.version != 4
            or epoch.version != 4
            or subscriber.expires_at.tzinfo is None
            or subscriber.expires_at <= datetime.now(UTC)
            or sequence < 0
        ):
            raise AccessDenied("subscriber scope/epoch identity is not verified")
        try:
            import asyncio

            async with asyncio.timeout(3):
                await self.current_reader.require_current(
                    user_id=subscriber.actor_user_id,
                    scope_kind=scope_kind,
                    scope_id=scope_id,
                )
        except Exception:
            raise AccessDenied("subscriber current Team/Project grant revoked") from None
        async with self.db.transaction() as tx:
            cursor = await tx.scalar(
                select(ScopeCursorRow)
                .where(
                    ScopeCursorRow.scope_kind == scope_kind,
                    ScopeCursorRow.scope_id == scope_id,
                )
                .with_for_update()
            )
            if cursor is None or cursor.epoch != epoch or sequence > cursor.revision:
                raise Conflict("subscriber ACK cannot advance past signed scope cursor")
            row = await tx.scalar(
                select(ScopeDeliveryReceiptRow)
                .where(
                    ScopeDeliveryReceiptRow.subscriber_id == subscriber.subscriber_id,
                    ScopeDeliveryReceiptRow.scope_kind == scope_kind,
                    ScopeDeliveryReceiptRow.scope_id == scope_id,
                )
                .with_for_update()
            )
            if row is None:
                row = ScopeDeliveryReceiptRow(
                    id=uuid4(),
                    subscriber_id=subscriber.subscriber_id,
                    scope_kind=scope_kind,
                    scope_id=scope_id,
                    epoch=epoch,
                    ack_sequence=sequence,
                )
                tx.add(row)
            else:
                if row.epoch != epoch:
                    # A new scope epoch invalidates previously acknowledged
                    # reader offsets. The caller must re-authorize a snapshot.
                    raise Conflict("subscriber scope epoch rotated")
                row.ack_sequence = max(row.ack_sequence, sequence)
                row.updated_at = datetime.now(UTC)
            return row.ack_sequence
