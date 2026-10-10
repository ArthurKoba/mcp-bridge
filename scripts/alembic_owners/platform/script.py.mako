"""${message}"""
from alembic import op
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}
def upgrade():
    raise RuntimeError("Runtime autogeneration forbidden: author reviewed DDL")
def downgrade():
    raise RuntimeError("Destructive automatic downgrades forbidden")
