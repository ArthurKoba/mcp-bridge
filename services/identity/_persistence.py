"""Identity SQL ownership: fresh schema, not the historical users table."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import IdentityBase


def now_utc() -> datetime:
    return datetime.now(UTC)


class UserRow(IdentityBase):
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_identity_user_active_role", "enabled", "role"),
        CheckConstraint("role IN ('user','superuser')", name="ck_identity_role"),
        {"schema": "identity"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_digest: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(24), default="user")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    credential_version: Mapped[int] = mapped_column(Integer, default=1)
    # Strictly opt-in; missing consent never authorizes browser event upload.
    browser_telemetry_opt_in: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BootstrapRow(IdentityBase):
    __tablename__ = "bootstrap"
    __table_args__ = {"schema": "identity"}  # noqa: RUF012
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    first_superuser_claimed: Mapped[bool] = mapped_column(Boolean, default=False)


class LoginAttemptRow(IdentityBase):
    """Persistent fail-closed backoff for verified local login sources."""

    __tablename__ = "login_attempts"
    __table_args__ = {"schema": "identity"}  # noqa: RUF012

    bucket_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    last_failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AdminTokenRevocationRow(IdentityBase):
    """Revoked signed Admin token jti digests; no bearer is persisted."""

    __tablename__ = "admin_token_revocations"
    __table_args__ = (
        Index("ix_admin_revocation_expires_at", "expires_at"),
        {"schema": "identity"},
    )

    jti_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("identity.users.id", ondelete="RESTRICT"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class InvitationRow(IdentityBase):
    __tablename__ = "invitations"
    __table_args__ = (
        Index("ix_identity_invitation_pending", "kind", "used_at", "revoked_at"),
        {"schema": "identity"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(24))
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("identity.users.id", ondelete="RESTRICT"), nullable=True
    )
    target_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("identity.users.id", ondelete="RESTRICT"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
