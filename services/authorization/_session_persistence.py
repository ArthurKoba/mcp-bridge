"""New Project AgentSessions, independent of OAuth/chat/client surfaces."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import AccessBase


class ProjectAgentSessionRow(AccessBase):
    __tablename__ = "agent_sessions"
    __table_args__ = (
        CheckConstraint(
            "substr(cast(session_uuid AS text), 15, 1) = '4'",
            name="ck_agent_session_uuid_v4",
        ),
        CheckConstraint(
            "elevation_policy IN ('fixed','requestable')",
            name="ck_agent_session_elevation_policy",
        ),
        CheckConstraint(
            "status IN ('active','revoked')",
            name="ck_agent_session_status",
        ),
        Index("ix_agent_session_project_active", "project_id", "status"),
        {"schema": "sessions"},
    )
    session_uuid: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column()
    created_by_principal_id: Mapped[UUID] = mapped_column()
    is_elevated: Mapped[bool] = mapped_column(Boolean, default=False)
    elevation_policy: Mapped[str] = mapped_column(String(16), default="requestable")
    label: Mapped[str | None] = mapped_column(String(128))
    grants: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="active")
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    hard_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SessionApprovalRow(AccessBase):
    __tablename__ = "approvals"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','approved','rejected')",
            name="ck_session_approval_status",
        ),
        CheckConstraint("version >= 1", name="ck_session_approval_version"),
        Index("ix_session_approval_status", "project_id", "status"),
        {"schema": "sessions"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    session_uuid: Mapped[UUID] = mapped_column(
        ForeignKey("sessions.agent_sessions.session_uuid", ondelete="RESTRICT")
    )
    project_id: Mapped[UUID] = mapped_column()
    requested_by_user_id: Mapped[UUID] = mapped_column()
    requested_grants: Mapped[dict[str, object]] = mapped_column(JSONB)
    requested_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    version: Mapped[int] = mapped_column(Integer, default=1)
    resolved_by_user_id: Mapped[UUID | None] = mapped_column()
    issued_session_uuid: Mapped[UUID | None] = mapped_column(
        ForeignKey("sessions.agent_sessions.session_uuid", ondelete="RESTRICT")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
