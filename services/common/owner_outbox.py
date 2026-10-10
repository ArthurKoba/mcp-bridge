"""Durable per-owner event claim/retry/ACK, never cross-owner SQL.

The sink is private and must acknowledge only after durable idempotent receipt.
An unclear external effect MUST be reconciled by the original operation UUID;
retry of an event is safe only for a consumer that deduplicates the event ID.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import import_module
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from common.platform_db import OWNER_DB_NAMES, OwnerName, PlatformDatabase

_OWNER_LEDGERS: dict[OwnerName, str] = {
    "identity": "identity._owner_ledger",
    "platform": "projects._control_ledger",
    "resources": "projects._catalog_ledger",
    "files": "projects._files_ledger",
    "runtime": "projects._execution_ledger",
    "reverse": "projects._reverse_ledger",
}


@dataclass(frozen=True, slots=True)
class OwnerEventClaim:
    owner: OwnerName
    event_uuid: UUID
    claim_uuid: UUID
    operation_uuid: UUID
    event_name: str
    owner_revision: str
    payload: dict[str, object]


class DurableOwnerEventSink(Protocol):
    async def deliver(self, event: OwnerEventClaim) -> bool:
        """True ONLY after durable dedupe+ACK by authenticated consumer."""
        ...


class OwnerOutboxDispatcher:
    def __init__(
        self, database: PlatformDatabase, owner: OwnerName, sink: DurableOwnerEventSink
    ) -> None:
        if (
            owner not in _OWNER_LEDGERS
            or database.engine.url.database != OWNER_DB_NAMES[owner]
            or sink is None
        ):
            raise ValueError("outbox must be bound to one durable owner and trusted sink")
        self.db = database
        self.owner = owner
        self.row_type = import_module(_OWNER_LEDGERS[owner]).OwnerOutboxRow
        self.sink = sink

    async def _claim(self, session: AsyncSession, limit: int) -> list[OwnerEventClaim]:
        now = datetime.now(UTC)
        rows = await session.scalars(
            select(self.row_type)
            .where(
                self.row_type.delivered_at.is_(None),
                self.row_type.available_at <= now,
                (self.row_type.claimed_until.is_(None) | (self.row_type.claimed_until <= now)),
            )
            .order_by(self.row_type.available_at, self.row_type.id)
            .with_for_update(skip_locked=True)
            .limit(limit)
        )
        result: list[OwnerEventClaim] = []
        for item in rows:
            claim_uuid = uuid4()
            item.delivery_claim_uuid = claim_uuid
            item.claimed_until = now + timedelta(seconds=60)
            item.attempts += 1
            result.append(
                OwnerEventClaim(
                    self.owner,
                    item.id,
                    claim_uuid,
                    item.operation_uuid,
                    item.event_name,
                    item.owner_revision,
                    item.event_payload,
                )
            )
        return result

    async def _complete(
        self, session: AsyncSession, event: OwnerEventClaim, *, acknowledged: bool
    ) -> bool:
        row = await session.scalar(
            select(self.row_type).where(self.row_type.id == event.event_uuid).with_for_update()
        )
        if (
            row is None
            or row.delivery_claim_uuid != event.claim_uuid
            or row.operation_uuid != event.operation_uuid
            or row.delivered_at is not None
        ):
            return False
        row.delivery_claim_uuid = None
        row.claimed_until = None
        if acknowledged:
            row.delivered_at = datetime.now(UTC)
        else:
            # Idempotent downstream consumer and durable deduplication are
            # mandatory before enabling this publisher in a real service.
            row.available_at = datetime.now(UTC) + timedelta(
                seconds=min(300, 2 ** min(row.attempts, 8))
            )
        return acknowledged

    async def dispatch_once(self, *, limit: int = 64) -> int:
        if not 1 <= limit <= 256:
            raise ValueError("outbox dispatch batch must be in 1..256")
        async with self.db.transaction() as tx:
            claims = await self._claim(tx, limit)
        count = 0
        for claim in claims:
            try:
                acknowledged = bool(await self.sink.deliver(claim))
            except Exception:
                # No external exception/request body may leak into audit or
                # operator output; leave as unacknowledged with bounded retry.
                acknowledged = False
            async with self.db.transaction() as tx:
                if await self._complete(tx, claim, acknowledged=acknowledged):
                    count += 1
        return count
