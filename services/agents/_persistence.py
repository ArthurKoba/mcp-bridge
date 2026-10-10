"""AgentIdentity persistence scoped by PlatformProjectId."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import ControlBase


class AgentIdentityRow(ControlBase):
    __tablename__ = "identities"
    __table_args__ = (
        UniqueConstraint("id", "project_id", name="uq_agent_project_identity"),
        ForeignKeyConstraint(
            ["parent_agent_id", "project_id"],
            ["agents.identities.id", "agents.identities.project_id"],
            name="fk_agent_parent_same_project",
        ),
        Index("ix_agent_project_enabled", "project_id", "enabled"),
        {"schema": "agents"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.projects.id", ondelete="RESTRICT")
    )
    parent_agent_id: Mapped[UUID | None] = mapped_column(nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
