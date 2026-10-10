"""Project-owned runtime lease + job records; never OS process metadata.

A runtime_session_uuid is a distinct UUIDv4, not an AgentSession UUID or a
Terminal/Ghidra/Browser native ID. The runtime process owner is an opaque
authenticated service_id + instance_id with a fenced, expiring lease.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import RuntimeBase


def _now() -> datetime:
    return datetime.now(UTC)


class RuntimeSessionRow(RuntimeBase):
    __tablename__ = "sessions"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('files','terminal','web_managed','web_remote','reverse')",
            name="ck_runtime_kind",
        ),
        CheckConstraint(
            "status IN ('active','lost','expired','revoked','closed')",
            name="ck_runtime_status",
        ),
        CheckConstraint(
            "cleanup_state IN ('not_needed','pending','confirmed','unknown')",
            name="ck_runtime_cleanup_state",
        ),
        CheckConstraint(
            "version >= 1 AND idle_ttl_seconds >= 30 AND idle_ttl_seconds <= 86400",
            name="ck_runtime_lease_revision",
        ),
        CheckConstraint(
            "hard_expires_at > created_at AND lease_expires_at <= hard_expires_at",
            name="ck_runtime_hard_lease",
        ),
        CheckConstraint(
            "substr(cast(runtime_session_uuid AS text), 15, 1) = '4'",
            name="ck_runtime_session_uuid_v4",
        ),
        UniqueConstraint("runtime_session_uuid", "project_id", name="uq_runtime_project_session"),
        UniqueConstraint(
            "project_id",
            "owner_service_id",
            "actor_user_id",
            "agent_session_uuid",
            "kind",
            "open_idempotency_digest",
            name="uq_runtime_session_open_dedup",
        ),
        Index("ix_runtime_expiry", "status", "idle_expires_at", "hard_expires_at"),
        Index("ix_runtime_owner", "project_id", "owner_service_id", "status"),
        {"schema": "runtime"},
    )
    runtime_session_uuid: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column()
    agent_session_uuid: Mapped[UUID] = mapped_column()
    actor_user_id: Mapped[UUID] = mapped_column()
    kind: Mapped[str] = mapped_column(String(20))
    owner_service_id: Mapped[UUID] = mapped_column()
    owner_instance: Mapped[UUID] = mapped_column(nullable=False)
    open_idempotency_digest: Mapped[str] = mapped_column(String(64))
    open_request_fingerprint: Mapped[str] = mapped_column(String(64))
    lease_nonce: Mapped[UUID] = mapped_column(default=uuid4)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(16), default="active")
    cleanup_state: Mapped[str] = mapped_column(String(16), default="not_needed")
    idle_ttl_seconds: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    hard_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RuntimeJobRow(RuntimeBase):
    __tablename__ = "jobs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["runtime_session_uuid", "project_id"],
            ["runtime.sessions.runtime_session_uuid", "runtime.sessions.project_id"],
            name="fk_runtime_job_project_session",
        ),
        CheckConstraint(
            "status IN ('queued','running','succeeded','failed','unknown','cancelled')",
            name="ck_runtime_job_status",
        ),
        CheckConstraint("version >= 1", name="ck_runtime_job_version"),
        UniqueConstraint(
            "project_id",
            "runtime_session_uuid",
            "idempotency_digest",
            name="uq_runtime_job_idempotency",
        ),
        Index("ix_runtime_job_pending", "status", "hard_expires_at"),
        Index(
            "uq_runtime_uncertain_effect",
            "runtime_session_uuid",
            "request_fingerprint",
            unique=True,
            postgresql_where=text("status IN ('queued','running','unknown')"),
        ),
        {"schema": "runtime"},
    )
    job_uuid: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    runtime_session_uuid: Mapped[UUID] = mapped_column(nullable=False)
    # Additive runtime_0002; legacy versioned jobs cannot infer their original
    # lease nonce. A NULL remains unreconcilable until independently attested.
    lease_nonce: Mapped[UUID | None] = mapped_column(nullable=True)
    project_id: Mapped[UUID] = mapped_column()
    owner_service_id: Mapped[UUID] = mapped_column(nullable=False)
    actor_user_id: Mapped[UUID] = mapped_column()
    agent_session_uuid: Mapped[UUID] = mapped_column()
    idempotency_digest: Mapped[str] = mapped_column(String(64))
    request_fingerprint: Mapped[str] = mapped_column(String(64))
    operation: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="queued")
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hard_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    result_digest: Mapped[str | None] = mapped_column(String(64))
