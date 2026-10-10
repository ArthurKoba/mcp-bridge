"""Runtime-owned job lease nonce fence; append-only nullable column.

Old source-created jobs without an original nonce cannot be reconciled by
inference from an active lease; they remain UNKNOWN until native proof.
"""

from __future__ import annotations

from alembic import op

revision = "runtime_0002"
down_revision = "runtime_0001"
branch_labels = None
depends_on = None
source_signature = "27d61748555c275ca1a09c29b5faba52343cdb85624b9825778661372b7c9136"


def upgrade() -> None:
    op.execute("ALTER TABLE runtime.jobs ADD COLUMN lease_nonce UUID")


def downgrade() -> None:
    raise RuntimeError("Runtime original job nonce cannot be downgraded automatically")
