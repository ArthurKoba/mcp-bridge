"""Owner-locked Alembic environment; no manual/offline invocation."""

from common.owner_migrations import run_owner_alembic_env

run_owner_alembic_env("identity")
