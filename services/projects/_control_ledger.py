"""Durable platform command, outbox and audit owned only by its logical DB.

A foreign authenticated operation UUID is opaque; no cross-owner SQL join or FK.
No counter, read projection or unsigned UUID may authorize a sensitive effect.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import ControlBase


def _now() -> datetime:
    return datetime.now(UTC)


class OwnerCommandRow(ControlBase):
    __tablename__ = "commands"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending','completed','unknown','reconciled','denied')",
            name="ck_platform_command_state",
        ),
        UniqueConstraint(
            "actor_scope", "project_scope", "operation", "key", name="uq_platform_command_key"
        ),
        UniqueConstraint("operation_uuid", "operation", name="uq_platform_command_uuid_phase"),
        Index("ix_platform_command_reconcile", "state", "updated_at"),
        {"schema": "control"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operation_uuid: Mapped[UUID] = mapped_column(default=uuid4)
    actor_scope: Mapped[str] = mapped_column(String(64))
    project_scope: Mapped[str] = mapped_column(String(64))
    operation: Mapped[str] = mapped_column(String(128))
    key: Mapped[str] = mapped_column(String(128))
    fingerprint: Mapped[str] = mapped_column(String(64))
    expected_owner_revision: Mapped[str] = mapped_column(String(128))
    state: Mapped[str] = mapped_column(String(16), default="pending")
    encrypted_outcome: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OwnerOutboxRow(ControlBase):
    __tablename__ = "outbox"
    __table_args__ = (
        UniqueConstraint("operation_uuid", "event_name", name="uq_platform_outbox_effect"),
        Index("ix_platform_outbox_pending", "delivered_at", "available_at"),
        {"schema": "control"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operation_uuid: Mapped[UUID] = mapped_column()
    event_name: Mapped[str] = mapped_column(String(128))
    owner_revision: Mapped[str] = mapped_column(String(128))
    event_payload: Mapped[dict[str, object]] = mapped_column(JSONB)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    delivery_claim_uuid: Mapped[UUID | None] = mapped_column()
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    claimed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class OwnerAuditRow(ControlBase):
    __tablename__ = "audit"
    __table_args__ = (
        Index("ix_platform_audit_actor_time", "actor_user_id", "created_at"),
        {"schema": "control"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operation_uuid: Mapped[UUID] = mapped_column()
    actor_user_id: Mapped[UUID | None] = mapped_column()
    project_id: Mapped[UUID | None] = mapped_column()
    action: Mapped[str] = mapped_column(String(128))
    object_id: Mapped[str] = mapped_column(String(128))
    owner_revision: Mapped[str] = mapped_column(String(128))
    details: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
