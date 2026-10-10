"""Briareus greenfield PostgreSQL connection; no legacy DSN or crypto settings.

Only the deployment-provided POSTGRES_PASSWORD is a required secret. Host,
database name, port and username follow the one selected Compose topology.
No DB connection is opened by constructing the settings or SQLAlchemy metadata.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from sqlalchemy import MetaData, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from common.platform_errors import Conflict, PersistenceTimeout
from common.settings import ProcessSettings

_LOCK_TIMEOUT_MS = 3000
_STATEMENT_TIMEOUT_MS = 30000
_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z", re.ASCII)
_HOST = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\Z", re.ASCII)


class PlatformDatabaseSettings(ProcessSettings):
    """DB-only contract: credentials, topology and no unrelated app options."""

    postgres_host: str = Field("briareus-postgres", validation_alias="POSTGRES_HOST")
    postgres_port: int = Field(5432, ge=1, le=65535, validation_alias="POSTGRES_PORT")
    postgres_db: str = Field(validation_alias="POSTGRES_DB")
    postgres_user: str = Field(validation_alias="POSTGRES_USER")
    postgres_password: SecretStr = Field(validation_alias="POSTGRES_PASSWORD")

    @field_validator("postgres_host")
    @classmethod
    def _host(cls, value: str) -> str:
        if not _HOST.fullmatch(value) or len(value) > 253:
            raise ValueError("POSTGRES_HOST must be an internal DNS host")
        return value

    @field_validator("postgres_db", "postgres_user")
    @classmethod
    def _identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("PostgreSQL database/user must be canonical identifiers")
        return value

    @field_validator("postgres_password")
    @classmethod
    def _password(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not raw or raw.isspace() or raw.startswith(("{{", "${")) or len(raw) > 8192:
            raise ValueError("POSTGRES_PASSWORD must resolve to a nonempty secret")
        return value

    @property
    def url(self) -> URL:
        """SQLAlchemy quotes credentials safely; no second DATABASE_URL input."""
        return URL.create(
            "postgresql+asyncpg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )


class PlatformBase(DeclarativeBase):
    metadata = MetaData()


# Separate SQLAlchemy registries: models owned by different logical databases
# must never share one MetaData or rely on a cross-database foreign key.
class IdentityBase(DeclarativeBase):
    metadata = MetaData()


class AccessBase(DeclarativeBase):
    metadata = MetaData()


class ControlBase(DeclarativeBase):
    metadata = MetaData()


class CatalogBase(DeclarativeBase):
    metadata = MetaData()


class FilesBase(DeclarativeBase):
    metadata = MetaData()


class RuntimeBase(DeclarativeBase):
    metadata = MetaData()


class ReverseBase(DeclarativeBase):
    metadata = MetaData()


class IngestBase(DeclarativeBase):
    metadata = MetaData()


OwnerName = Literal[
    "identity", "access", "platform", "resources", "files", "runtime", "reverse", "ingest"
]
OWNER_DB_NAMES: dict[OwnerName, str] = {
    "identity": "briareus_identity",
    "access": "briareus_access",
    "platform": "briareus_platform",
    "resources": "briareus_resources",
    "files": "briareus_files",
    "runtime": "briareus_runtime",
    "reverse": "briareus_reverse",
    "ingest": "briareus_ingest",
}


class OwnerDatabaseSettings(PlatformDatabaseSettings):
    """Single-owner SQL connection; never accepts an obsolete shared database."""

    owner: OwnerName

    @model_validator(mode="after")
    def _owner_database(self) -> OwnerDatabaseSettings:
        if self.postgres_db != OWNER_DB_NAMES[self.owner]:
            raise ValueError("POSTGRES_DB does not match this durable owner's logical database")
        if self.postgres_user in {"briareus", "postgres", "root"}:
            raise ValueError("POSTGRES_USER cannot be the shared/platform/admin principal")
        return self


class PlatformDatabase:
    def __init__(self, settings: PlatformDatabaseSettings) -> None:
        self.engine: AsyncEngine = create_async_engine(settings.url, pool_pre_ping=True)
        self.sessions: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False, autoflush=False
        )

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[AsyncSession]:
        """Bounded one-command transaction, errors preserve retry semantics."""
        try:
            async with self.sessions() as session, session.begin():
                await session.execute(
                    text("SELECT set_config('lock_timeout', :value, true)"),
                    {"value": f"{_LOCK_TIMEOUT_MS}ms"},
                )
                await session.execute(
                    text("SELECT set_config('statement_timeout', :value, true)"),
                    {"value": f"{_STATEMENT_TIMEOUT_MS}ms"},
                )
                yield session
        except DBAPIError as exc:
            sqlstate = getattr(exc.orig, "sqlstate", None)
            if sqlstate in {"55P03", "40P01", "40001"}:
                raise Conflict(
                    "transaction concurrency conflict; retry with the same key"
                ) from None
            if sqlstate == "57014":
                raise PersistenceTimeout("database operation deadline exceeded") from None
            raise

    async def close(self) -> None:
        await self.engine.dispose()
