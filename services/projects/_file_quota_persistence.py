"""Backend owned Project byte accounting; Files owns actual bytes and paths.

FileQuota tracks authoritative committed observations and bytes reserved for
in-flight writes. External filesystem effects NEVER happen in a SQL transaction.
An unknown upload must be observed/reconciled before freeing its reservation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import FilesBase


def _now() -> datetime:
    return datetime.now(UTC)


class FileQuotaAccountRow(FilesBase):
    __tablename__ = "quota_accounts"
    __table_args__ = (
        CheckConstraint(
            "byte_limit >= 0 AND used_bytes >= 0 AND reserved_bytes >= 0",
            name="ck_file_quota_nonnegative",
        ),
        CheckConstraint("version >= 1", name="ck_file_quota_version"),
        {"schema": "files"},
    )
    project_id: Mapped[UUID] = mapped_column(primary_key=True)
    byte_limit: Mapped[int] = mapped_column(BigInteger)
    used_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    reserved_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    frozen: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class FileObjectRow(FilesBase):
    __tablename__ = "file_objects"
    __table_args__ = (
        UniqueConstraint("project_id", "path_digest", name="uq_file_object_project_path"),
        UniqueConstraint("id", "project_id", name="uq_file_object_project_identity"),
        CheckConstraint("size_bytes >= 0 AND version >= 1", name="ck_file_object_revision"),
        Index("ix_file_object_project_deleted", "project_id", "deleted"),
        {"schema": "files"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column()
    path_digest: Mapped[str] = mapped_column(String(64))
    inode_digest: Mapped[str | None] = mapped_column(String(64))
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    version: Mapped[int] = mapped_column(Integer, default=1)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class FileQuotaReservationRow(FilesBase):
    __tablename__ = "quota_reservations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('reserved','dispatched','committed','released','unknown')",
            name="ck_file_quota_reservation_state",
        ),
        CheckConstraint(
            "prior_bytes >= 0 AND planned_bytes >= 0 AND reserved_delta >= 0",
            name="ck_file_reservation_size",
        ),
        CheckConstraint(
            "version >= 1 AND expected_file_version >= 0", name="ck_file_reservation_version"
        ),
        UniqueConstraint("project_id", "idempotency_digest", name="uq_file_quota_idempotency"),
        UniqueConstraint("project_id", "operation_uuid", name="uq_file_quota_operation_uuid"),
        CheckConstraint(
            "substr(cast(operation_uuid AS text), 15, 1) = '4'",
            name="ck_file_operation_uuid_v4",
        ),
        Index(
            "uq_file_active_path",
            "project_id",
            "path_digest",
            unique=True,
            postgresql_where=text("status IN ('reserved','dispatched','unknown')"),
        ),
        Index("ix_quota_reservation_expiry", "status", "expires_at"),
        {"schema": "files"},
    )
    reservation_id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operation_uuid: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column()
    agent_session_uuid: Mapped[UUID] = mapped_column()
    actor_user_id: Mapped[UUID] = mapped_column()
    owner_service_id: Mapped[UUID] = mapped_column()
    path_digest: Mapped[str] = mapped_column(String(64))
    idempotency_digest: Mapped[str] = mapped_column(String(64))
    request_fingerprint: Mapped[str] = mapped_column(String(64))
    expected_content_sha256: Mapped[str] = mapped_column(String(64))
    project_access_revision: Mapped[str] = mapped_column(String(64))
    expected_file_version: Mapped[int] = mapped_column(Integer)
    prior_bytes: Mapped[int] = mapped_column(BigInteger)
    planned_bytes: Mapped[int] = mapped_column(BigInteger)
    reserved_delta: Mapped[int] = mapped_column(BigInteger)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(16), default="reserved")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_inode_digest: Mapped[str | None] = mapped_column(String(64))
    observed_file_version: Mapped[int | None] = mapped_column(Integer)
    observed_size_bytes: Mapped[int | None] = mapped_column(BigInteger)
