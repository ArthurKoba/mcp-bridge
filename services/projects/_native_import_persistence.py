"""Project-owned Reverse import intent; native Ghidra assets live elsewhere.

Native identifiers are opaque and NEVER interchangeable with Project UUID or
Project Files path. No operation in this schema deletes a native artifact.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
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

from common.platform_db import ReverseBase


def _now() -> datetime:
    return datetime.now(UTC)


class NativeProjectRow(ReverseBase):
    __tablename__ = "native_projects"
    __table_args__ = (
        UniqueConstraint("project_id", "native_project_key", name="uq_reverse_project_native"),
        UniqueConstraint("id", "project_id", name="uq_reverse_native_project_scoped"),
        Index("ix_native_project_project", "project_id", "enabled"),
        {"schema": "reverse"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column()
    native_project_key: Mapped[str] = mapped_column(String(256))
    owner_service_id: Mapped[UUID] = mapped_column()
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class NativeImportRow(ReverseBase):
    __tablename__ = "native_imports"
    __table_args__ = (
        ForeignKeyConstraint(
            ["native_project_id", "project_id"],
            ["reverse.native_projects.id", "reverse.native_projects.project_id"],
            name="fk_native_import_project_owner",
        ),
        CheckConstraint(
            "status IN ('reserved','dispatched','succeeded','unknown',"
            "'confirmed_absent','cancelled')",
            name="ck_native_import_status",
        ),
        CheckConstraint(
            "cleanup_state IN ('not_requested','requested','confirmed')",
            name="ck_native_import_cleanup_state",
        ),
        CheckConstraint(
            "version >= 1 AND source_file_version >= 1 AND source_size_bytes >= 0",
            name="ck_native_import_version",
        ),
        CheckConstraint(
            "(status = 'succeeded' AND native_artifact_id IS NOT NULL) OR (status <> 'succeeded')",
            name="ck_native_import_success_id",
        ),
        UniqueConstraint("project_id", "idempotency_digest", name="uq_native_import_idempotency"),
        UniqueConstraint("project_id", "operation_uuid", name="uq_native_import_operation_uuid"),
        CheckConstraint(
            "substr(cast(operation_uuid AS text), 15, 1) = '4'",
            name="ck_native_import_operation_uuid_v4",
        ),
        Index(
            "uq_native_artifact_in_project",
            "native_project_id",
            "native_artifact_id",
            unique=True,
            postgresql_where=text("native_artifact_id IS NOT NULL"),
        ),
        Index("ix_native_import_uncertain", "status", "created_at"),
        Index(
            "uq_native_uncertain_effect",
            "project_id",
            "native_project_id",
            "file_object_id",
            "source_file_version",
            "request_fingerprint",
            unique=True,
            postgresql_where=text("status IN ('dispatched','unknown')"),
        ),
        {"schema": "reverse"},
    )
    import_uuid: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operation_uuid: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column()
    native_project_id: Mapped[UUID] = mapped_column(nullable=False)
    file_object_id: Mapped[UUID] = mapped_column(nullable=False)
    source_file_version: Mapped[int] = mapped_column(Integer)
    source_content_sha256: Mapped[str] = mapped_column(String(64))
    source_size_bytes: Mapped[int] = mapped_column(Integer)
    auto_analyze: Mapped[bool] = mapped_column(Boolean)
    actor_user_id: Mapped[UUID] = mapped_column()
    agent_session_uuid: Mapped[UUID] = mapped_column()
    owner_service_id: Mapped[UUID] = mapped_column()
    idempotency_digest: Mapped[str] = mapped_column(String(64))
    request_fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="reserved")
    version: Mapped[int] = mapped_column(Integer, default=1)
    native_artifact_id: Mapped[str | None] = mapped_column(String(256))
    result_sha256: Mapped[str | None] = mapped_column(String(64))
    cleanup_state: Mapped[str] = mapped_column(String(20), default="not_requested")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
