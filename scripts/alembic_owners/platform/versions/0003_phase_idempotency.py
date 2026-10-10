"""Owner-local multi-phase original UUID idempotency; no content migration.

A single original UUID/Idempotency-Key must span distinct source-owned
phase operations. The old UNIQUE(operation_uuid) blocked legal sequential
reserve/dispatch/reconcile. New UNIQUE(operation_uuid,operation) preserves
each phase identity, and the owner executor serializes original UUID across
phases using PostgreSQL xact advisory lock and checks original key/scope.

LIVE DDL remains HELD pending D4 owner DBA/backup/rollback review.
"""

from __future__ import annotations

from alembic import op

revision = "platform_0003"
down_revision = "platform_0002"
branch_labels = None
depends_on = None
source_signature = "ba83ac5b77a755f02b4b034f43eed17742ab26ffa4d0dcd2e3004530b3e6d0dd"


def upgrade() -> None:
    # Transactional owner DB DDL only; never modify another logical DB.
    op.drop_constraint("uq_platform_command_uuid", "commands", schema="projects", type_="unique")
    op.create_unique_constraint(
        "uq_platform_command_uuid_phase",
        "commands",
        ["operation_uuid", "operation"],
        schema="projects",
    )


def downgrade() -> None:
    # A live multi-phase UUID can no longer satisfy old UNIQUE(UUID).
    # Downgrade would discard data or fail: intentional forward-only guard.
    raise RuntimeError("owner multi-phase idempotency schema is forward-only")
