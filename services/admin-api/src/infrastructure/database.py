from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
)
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


class GitHubAccountRecord(Base):
    __tablename__ = "github_accounts"
    __allow_unmapped__ = True

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alias: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    auth_type: Mapped[str] = mapped_column(String(32))
    app_id: Mapped[str] = mapped_column(String(512), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    encrypted_credential: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    _credential_input: str = ""

    @property
    def credential_input(self) -> str:
        return ""

    @credential_input.setter
    def credential_input(self, value: str) -> None:
        self._credential_input = value


class GitLabAccountRecord(Base):
    __tablename__ = "gitlab_accounts"
    __allow_unmapped__ = True

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alias: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    auth_type: Mapped[str] = mapped_column(String(32))
    base_url: Mapped[str] = mapped_column(String(2048), default="https://gitlab.com")
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    ca_cert_pem: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    encrypted_credential: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    _credential_input: str = ""

    @property
    def credential_input(self) -> str:
        return ""

    @credential_input.setter
    def credential_input(self, value: str) -> None:
        self._credential_input = value


class SigNozAccountRecord(Base):
    __tablename__ = "signoz_accounts"
    __allow_unmapped__ = True

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alias: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    auth_type: Mapped[str] = mapped_column(String(32), default="signoz_api_key")
    base_url: Mapped[str] = mapped_column(String(2048))
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    ca_cert_pem: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    encrypted_credential: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    _credential_input: str = ""

    @property
    def credential_input(self) -> str:
        return ""

    @credential_input.setter
    def credential_input(self, value: str) -> None:
        self._credential_input = value


class CoolifyAccountRecord(Base):
    __tablename__ = "coolify_accounts"
    __allow_unmapped__ = True

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alias: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    auth_type: Mapped[str] = mapped_column(String(32), default="coolify_api_token")
    base_url: Mapped[str] = mapped_column(String(2048))
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    ca_cert_pem: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    encrypted_credential: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    _credential_input: str = ""

    @property
    def credential_input(self) -> str:
        return ""

    @credential_input.setter
    def credential_input(self, value: str) -> None:
        self._credential_input = value


class InvocationRecord(Base):
    __tablename__ = "invocations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    request_id: Mapped[str] = mapped_column(String(128), default="", index=True)
    module: Mapped[str] = mapped_column(String(64), index=True)
    tool: Mapped[str] = mapped_column(String(256), index=True)
    account_id: Mapped[str] = mapped_column(String(128), default="", index=True)
    provider: Mapped[str] = mapped_column(String(32), default="", index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    duration_ms: Mapped[float] = mapped_column(Float)
    error_type: Mapped[str] = mapped_column(String(256), default="")
    arguments_json: Mapped[str] = mapped_column(Text, default="")
    result_json: Mapped[str] = mapped_column(Text, default="")
    error_message: Mapped[str] = mapped_column(Text, default="")
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, default=lambda: datetime.now(UTC)
    )


class OAuthSessionRecord(Base):
    __tablename__ = "oauth_sessions"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(512), default="", index=True)
    client_name: Mapped[str] = mapped_column(String(512), default="")
    resource: Mapped[str] = mapped_column(String(2048), default="", index=True)
    login: Mapped[str] = mapped_column(String(256), default="", index=True)
    subject: Mapped[str] = mapped_column(String(512), default="")
    scopes_json: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    last_event: Mapped[str] = mapped_column(String(64), default="", index=True)
    access_jti: Mapped[str] = mapped_column(String(256), default="", index=True)
    refresh_jti: Mapped[str] = mapped_column(String(256), default="", index=True)
    previous_refresh_jti: Mapped[str] = mapped_column(String(256), default="", index=True)
    access_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    refresh_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_refresh_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_type: Mapped[str] = mapped_column(String(256), default="")
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, default=lambda: datetime.now(UTC)
    )


class CachedSnapshotRecord(Base):
    __tablename__ = "cached_snapshots"

    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    parameters_json: Mapped[str] = mapped_column(Text, default="{}")
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    refresh_after_seconds: Mapped[int] = mapped_column(Integer, default=300)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    attempted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    error_type: Mapped[str] = mapped_column(String(256), default="")
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class AdminConfigRecord(Base):
    __tablename__ = "admin_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    logging_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    logging_capture_payloads: Mapped[bool] = mapped_column(Boolean, default=True)
    logging_retention_days: Mapped[int] = mapped_column(Integer, default=30)
    logging_max_records: Mapped[int] = mapped_column(Integer, default=10_000)
    maintenance_interval_minutes: Mapped[int] = mapped_column(Integer, default=60)


class RuntimeSettingsRecord(Base):
    __tablename__ = "runtime_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    terminal_max_exec_timeout_seconds: Mapped[int] = mapped_column(Integer, default=21_600)
    terminal_max_job_runtime_seconds: Mapped[int] = mapped_column(Integer, default=43_200)


class McpRuntimeSettingsRecord(Base):
    __tablename__ = "mcp_runtime_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    call_timeout_seconds: Mapped[int] = mapped_column(Integer, default=5)


class GitHubRuntimeSettingsRecord(Base):
    __tablename__ = "github_runtime_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    local_first_guidance: Mapped[bool] = mapped_column(Boolean, default=True)
    local_git_transport_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    remote_source_mutations_enabled: Mapped[bool] = mapped_column(Boolean, default=False)


class GitLabRuntimeSettingsRecord(Base):
    __tablename__ = "gitlab_runtime_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    local_first_guidance: Mapped[bool] = mapped_column(Boolean, default=True)
    local_git_transport_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    remote_source_mutations_enabled: Mapped[bool] = mapped_column(Boolean, default=False)


class BrowserRuntimeSettingsRecord(Base):
    __tablename__ = "browser_runtime_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    external_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    external_mcp_url: Mapped[str] = mapped_column(String(2048), default="")
    call_timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)
    auto_disconnect_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    idle_timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)
    profile_dir_name: Mapped[str] = mapped_column(String(128), default="Default")
    encrypted_extension_token: Mapped[str] = mapped_column(Text, default="")


class DatabaseManager:
    """Own the PostgreSQL async engine and session factory for Admin API."""

    def __init__(
        self,
        *,
        host: str = "postgres",
        port: int = 5432,
        database: str = "mcp-bridge",
        username: str,
        password: str,
    ) -> None:
        database_url = URL.create(
            "postgresql+asyncpg",
            username=username,
            password=password,
            host=host,
            port=port,
            database=database,
        )
        self.engine: AsyncEngine = create_async_engine(
            database_url,
            pool_pre_ping=True,
        )
        self.sessions: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
        )

    async def ensure_schema(self) -> bool:
        """Retired. Only independently reviewed owner Alembic may create DDL."""
        raise RuntimeError("legacy schema initializer disabled; use reviewed owner migrations")

    async def dispose(self) -> None:
        await self.engine.dispose()
