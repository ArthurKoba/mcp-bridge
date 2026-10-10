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

revision = "reverse_0002"
down_revision = "reverse_0001"
branch_labels = None
depends_on = None
source_signature = "3a6b282442ca5b5842ca14ff174b30d3574b37d229cf92240e78b51310894d19"


def upgrade() -> None:
    # Transactional owner DB DDL only; never modify another logical DB.
    op.drop_constraint("uq_reverse_command_uuid", "commands", schema="reverse", type_="unique")
    op.create_unique_constraint(
        "uq_reverse_command_uuid_phase",
        "commands",
        ["operation_uuid", "operation"],
        schema="reverse",
    )


def downgrade() -> None:
    # A live multi-phase UUID can no longer satisfy old UNIQUE(UUID).
    # Downgrade would discard data or fail: intentional forward-only guard.
    raise RuntimeError("owner multi-phase idempotency schema is forward-only")
