"""Optional distinct per-owner migrator principal; never global DBA access.

D4's currently staged 4-owner Compose provides only per-owner runtime roles.
For rollout with least privilege, D4 may independently supply the two
MIGRATION_POSTGRES_* runtime secret refs for a *different* per-owner DDL
principal. This is an optional paired configuration, not a manual schema job,
privilege escalation, shared Postgres admin or public enable-migration toggle.
"""

from __future__ import annotations

from pydantic import Field, SecretStr, model_validator

from common.platform_db import OwnerDatabaseSettings
from common.settings import ProcessSettings


class OwnerMigrationCredentials(ProcessSettings):
    migration_user: str | None = Field(default=None, validation_alias="MIGRATION_POSTGRES_USER")
    migration_password: SecretStr | None = Field(
        default=None, validation_alias="MIGRATION_POSTGRES_PASSWORD"
    )

    @model_validator(mode="after")
    def validate_pair(self) -> OwnerMigrationCredentials:
        if (self.migration_user is None) != (self.migration_password is None):
            raise ValueError("migration principal and password must be provided together")
        if self.migration_user is not None:
            if self.migration_user in {"postgres", "briareus", "root"}:
                raise ValueError("database superuser/shared principal cannot migrate an owner")
            from common.platform_db import _IDENTIFIER

            if _IDENTIFIER.fullmatch(self.migration_user) is None:
                raise ValueError("migration principal must be a valid dedicated SQL role")
            assert self.migration_password is not None
            value = self.migration_password.get_secret_value()
            if not value or value.isspace() or len(value) > 8192 or value.startswith(("{{", "${")):
                raise ValueError("migration role password must be independently secret")
        return self


def owner_migrator(
    runtime: OwnerDatabaseSettings,
    credentials: OwnerMigrationCredentials,
) -> OwnerDatabaseSettings | None:
    """Return distinct same-DB migrator settings or None for scoped MVP role."""
    if credentials.migration_user is None:
        return None
    if credentials.migration_user == runtime.postgres_user:
        raise ValueError("distinct migrator role cannot equal owner runtime role")
    assert credentials.migration_password is not None
    return OwnerDatabaseSettings(
        owner=runtime.owner,
        postgres_host=runtime.postgres_host,
        postgres_port=runtime.postgres_port,
        postgres_db=runtime.postgres_db,
        postgres_user=credentials.migration_user,
        postgres_password=credentials.migration_password,
    )
