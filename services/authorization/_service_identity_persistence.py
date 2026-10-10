"""Backend authority for asymmetric runtime identities and one-use assertions.

These are greenfield tables; no OAuth chat session or legacy client grants are
converted to service credentials. Each service stores its own private key.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import AccessBase


def _now() -> datetime:
    return datetime.now(UTC)


class ServiceKeyRow(AccessBase):
    __tablename__ = "service_keys"
    __table_args__ = (
        CheckConstraint("key_version >= 1", name="ck_service_key_version"),
        UniqueConstraint(
            "service_id",
            "audience",
            "key_version",
            name="uq_service_identity_audience_revision",
        ),
        UniqueConstraint("public_key_fingerprint", name="uq_service_public_key"),
        Index("ix_service_key_audience_enabled", "audience", "enabled"),
        {"schema": "authorization"},
    )
    key_id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    service_id: Mapped[UUID] = mapped_column(nullable=False)
    service_name: Mapped[str] = mapped_column(String(80))
    audience: Mapped[str] = mapped_column(String(64))
    key_version: Mapped[int] = mapped_column(Integer)
    public_key_b64: Mapped[str] = mapped_column(String(64))
    public_key_fingerprint: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    issued_by_user_id: Mapped[UUID] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ConsumedAssertionRow(AccessBase):
    __tablename__ = "consumed_assertions"
    __table_args__ = (
        CheckConstraint("kind IN ('service','delegation')", name="ck_assertion_kind"),
        UniqueConstraint(
            "kind",
            "issuer_id",
            "jti_digest",
            name="uq_assertion_single_use",
        ),
        Index("ix_assertion_expiry", "expires_at"),
        {"schema": "authorization"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    kind: Mapped[str] = mapped_column(String(16))
    issuer_id: Mapped[UUID] = mapped_column(nullable=False)
    jti_digest: Mapped[str] = mapped_column(String(64))
    project_id: Mapped[UUID] = mapped_column()
    session_uuid: Mapped[UUID] = mapped_column(
        ForeignKey("sessions.agent_sessions.session_uuid", ondelete="RESTRICT")
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
