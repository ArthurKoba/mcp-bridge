from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import BigInteger, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AgentSessionRecord(Base):
    __tablename__ = "agent_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    uid: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    oauth_client_id: Mapped[str] = mapped_column(String(128), index=True)
    oauth_session_id: Mapped[str] = mapped_column(String(36), index=True)
    surface_id: Mapped[int] = mapped_column(Integer, index=True)
    access_level: Mapped[str] = mapped_column(String(32), default="read_only", index=True)
    account_scope: Mapped[str] = mapped_column(String(16), default="none")
    account_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    label: Mapped[str] = mapped_column(String(256), default="")
    expires_at: Mapped[int] = mapped_column(BigInteger, default=0, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SurfaceControlRecord(Base):
    __tablename__ = "surface_controls"
    __table_args__ = (UniqueConstraint("user_id", "surface_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    surface_id: Mapped[int] = mapped_column(Integer, index=True)
    mode: Mapped[str] = mapped_column(String(32), default="session_enforced")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class AccessRequestRecord(Base):
    __tablename__ = "access_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    requested_access_level: Mapped[str] = mapped_column(String(32), default="")
    requested_account_scope: Mapped[str] = mapped_column(String(16), default="none")
    requested_account_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    requested_expires_at: Mapped[int] = mapped_column(BigInteger, default=0)
    resolved_access_level: Mapped[str] = mapped_column(String(32), default="")
    resolved_account_scope: Mapped[str] = mapped_column(String(16), default="none")
    resolved_account_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    resolved_expires_at: Mapped[int] = mapped_column(BigInteger, default=0)
    resolved_by_user_id: Mapped[str] = mapped_column(String(36), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OAuthContextBlockRecord(Base):
    __tablename__ = "oauth_context_blocks"

    oauth_session_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    reason: Mapped[str] = mapped_column(String(64), default="session_abuse")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class SecurityEventRecord(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    oauth_session_id: Mapped[str] = mapped_column(String(36), default="", index=True)
    session_id: Mapped[str] = mapped_column(String(36), default="", index=True)
    surface_id: Mapped[int] = mapped_column(Integer, index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )


class AccessDatabase:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        database: str,
        username: str,
        password: str,
    ) -> None:
        url = URL.create(
            "postgresql+asyncpg",
            username=username,
            password=password,
            host=host,
            port=port,
            database=database,
        )
        self.engine: AsyncEngine = create_async_engine(url, pool_pre_ping=True)
        self.sessions: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
        )

    async def ensure_schema(self) -> bool:
        """Retired. Only independently reviewed owner Alembic may create DDL."""
        raise RuntimeError("legacy schema initializer disabled; use reviewed owner migrations")

    async def dispose(self) -> None:
        await self.engine.dispose()
