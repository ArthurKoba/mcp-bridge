"""A11 Control-owned Project deletion fence; additive and data-preserving.

The published A11 platform_0001 stays frozen; no global DB rewrite/import.
A live upgrade is separately held for D4 role/backup/release acceptance.
"""

from __future__ import annotations

from alembic import op

revision = "platform_0002"
down_revision = "platform_0001"
branch_labels = None
depends_on = None
source_signature = "88c00bda99826e83ce432675a1c4231f7f047e0c68571dc849e180132d997005"


def upgrade() -> None:
    op.execute(
        "ALTER TABLE projects.projects "
        "ADD COLUMN lifecycle_status VARCHAR(12) NOT NULL DEFAULT 'active'"
    )
    op.execute(
        "ALTER TABLE projects.projects "
        "ADD CONSTRAINT ck_project_lifecycle_status "
        "CHECK (lifecycle_status IN ('active','deleting','deleted'))"
    )


def downgrade() -> None:
    raise RuntimeError("Project lifecycle fence is forward-only without a reviewed rollback")
