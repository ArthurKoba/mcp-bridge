"""Durable per-scope sequence and permission epochs for private realtime ports.

Every ScopeEvent cursor is locked/advanced within a transaction, avoiding
PostgreSQL sequence commit-order gaps for a single scope. A Team-owned Project
subscribes to two INDEPENDENT streams, never a flattened global topic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import ControlBase


def _now() -> datetime:
    return datetime.now(UTC)


class ScopeCursorRow(ControlBase):
    __tablename__ = "scope_cursors"
    __table_args__ = (
        CheckConstraint(
            "scope_kind IN ('user','team','project')",
            name="ck_scope_cursor_kind",
        ),
        CheckConstraint(
            "revision >= 0",
            name="ck_scope_cursor_revision",
        ),
        {"schema": "control"},
    )
    scope_kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(primary_key=True)
    epoch: Mapped[UUID] = mapped_column(default=uuid4)
    revision: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ScopeEventRow(ControlBase):
    __tablename__ = "scope_events"
    __table_args__ = (
        CheckConstraint(
            "scope_kind IN ('user','team','project')",
            name="ck_scope_event_kind",
        ),
        CheckConstraint("sequence >= 1", name="ck_scope_event_sequence"),
        UniqueConstraint("scope_kind", "scope_id", "sequence", name="uq_scope_event_sequence"),
        UniqueConstraint(
            "scope_kind", "scope_id", "source_outbox_id", name="uq_scope_outbox_ingest"
        ),
        Index("ix_scope_event_delivery", "scope_kind", "scope_id", "sequence"),
        Index("ix_scope_event_retention", "expires_at"),
        {"schema": "control"},
    )
    event_id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scope_kind: Mapped[str] = mapped_column(String(16))
    scope_id: Mapped[UUID] = mapped_column(nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger)
    epoch: Mapped[UUID] = mapped_column()
    source_outbox_id: Mapped[UUID] = mapped_column()
    event_type: Mapped[str] = mapped_column(String(128))
    actor_user_id: Mapped[UUID | None] = mapped_column()
    safe_payload: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ScopeDeliveryReceiptRow(ControlBase):
    """Durable C2 consumer ACK; no Valkey Pub/Sub delivery claim."""

    __tablename__ = "scope_delivery_receipts"
    __table_args__ = (
        UniqueConstraint(
            "subscriber_id", "scope_kind", "scope_id", name="uq_scope_subscriber_cursor"
        ),
        CheckConstraint("ack_sequence >= 0", name="ck_scope_ack_revision"),
        {"schema": "control"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    subscriber_id: Mapped[UUID] = mapped_column(nullable=False)
    scope_kind: Mapped[str] = mapped_column(String(16))
    scope_id: Mapped[UUID] = mapped_column()
    epoch: Mapped[UUID] = mapped_column()
    ack_sequence: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
