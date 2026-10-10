"""Fresh Authorization command ledger and immutable security audit."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import AccessBase, CatalogBase


class IdempotencyRow(AccessBase):
    __tablename__ = "commands"
    __table_args__ = (
        CheckConstraint("status IN ('pending','completed')", name="ck_idempotency_status"),
        UniqueConstraint(
            "actor_scope",
            "project_scope",
            "operation",
            "key",
            name="uq_authorization_command_idempotency",
        ),
        Index("ix_authorization_command_expiry", "expires_at"),
        {"schema": "access"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    actor_scope: Mapped[str] = mapped_column(String(64))
    project_scope: Mapped[str] = mapped_column(String(64))
    operation: Mapped[str] = mapped_column(String(128))
    key: Mapped[str] = mapped_column(String(128))
    fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="pending")
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_ciphertext: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SecurityAuditRow(AccessBase):
    __tablename__ = "audit"
    __table_args__ = (
        Index("ix_authorization_audit_actor_time", "actor_id", "created_at"),
        {"schema": "access"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    actor_id: Mapped[UUID | None] = mapped_column()
    project_id: Mapped[UUID | None] = mapped_column()
    action: Mapped[str] = mapped_column(String(128))
    object_id: Mapped[str] = mapped_column(String(128))
    details: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class OutboxRow(AccessBase):
    __tablename__ = "outbox"
    __table_args__ = (
        Index("ix_auth_outbox_pending", "published_at", "created_at"),
        {"schema": "access"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    event_name: Mapped[str] = mapped_column(String(128))
    event_payload: Mapped[dict[str, object]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claim_id: Mapped[UUID | None] = mapped_column()
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class ExternalOperationRow(CatalogBase):
    """One irreversible provider effect per explicit operation identity.

    A recorded 'dispatched' or 'unknown' outcome MUST NOT auto-execute again.
    """

    __tablename__ = "external_operations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('reserved', 'dispatched', 'succeeded', 'unknown')",
            name="ck_external_operation_status",
        ),
        UniqueConstraint(
            "actor_id",
            "project_id",
            "operation",
            "idempotency_digest",
            name="uq_external_operation_identity",
        ),
        UniqueConstraint(
            "project_id",
            "service_id",
            "instance_uuid",
            "operation_uuid",
            name="uq_external_service_operation",
        ),
        Index("ix_external_unknown", "status", "created_at"),
        Index(
            "uq_external_uncertain_effect",
            "project_id",
            "resource_id",
            "operation",
            "request_fingerprint",
            unique=True,
            postgresql_where=text("status IN ('dispatched','unknown')"),
        ),
        {"schema": "resources"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    actor_id: Mapped[UUID] = mapped_column()
    project_id: Mapped[UUID] = mapped_column()
    session_uuid: Mapped[UUID] = mapped_column()
    resource_id: Mapped[UUID] = mapped_column(
        ForeignKey("resources.integrations.id", ondelete="RESTRICT")
    )
    resource_version: Mapped[int] = mapped_column(Integer)
    service_id: Mapped[UUID] = mapped_column(nullable=False)
    instance_uuid: Mapped[UUID] = mapped_column(nullable=False)
    operation_uuid: Mapped[UUID] = mapped_column(nullable=False)
    operation: Mapped[str] = mapped_column(String(128))
    idempotency_digest: Mapped[str] = mapped_column(String(64))
    request_fingerprint: Mapped[str] = mapped_column(String(64))
    result_sha256: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="reserved")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
