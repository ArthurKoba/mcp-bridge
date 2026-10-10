# ruff: noqa: E501
"""Frozen fresh ingest schema; independent logical database.

This is NEVER an upgrade of the historical global A10 0001/0002.
Changes must use a new reviewed revision, never regenerate installed baseline.
"""

from __future__ import annotations

from alembic import op

revision = "ingest_0001"
down_revision = None
branch_labels = None
depends_on = None
source_signature = "88c8db8381bfdf26e72f1aa33bd6915a48ef22b2e48164b14aa9bc80614ce77c"

_DDL: tuple[str, ...] = (
    'CREATE SCHEMA "ingest"',
    "CREATE TABLE ingest.browser_telemetry_budgets (\n\tuser_id UUID NOT NULL, \n\tscope_kind VARCHAR(16) NOT NULL, \n\tscope_id UUID NOT NULL, \n\tminute_start TIMESTAMP WITH TIME ZONE NOT NULL, \n\tevent_count INTEGER NOT NULL, \n\tbyte_count INTEGER NOT NULL, \n\tPRIMARY KEY (user_id, scope_kind, scope_id, minute_start), \n\tCONSTRAINT ck_browser_telemetry_scope CHECK (scope_kind IN ('user','project')), \n\tCONSTRAINT ck_browser_telemetry_budget CHECK (event_count >= 0 AND event_count <= 180 AND byte_count >= 0 AND byte_count <= 262144)\n)",
)


def upgrade() -> None:
    for statement in _DDL:
        op.get_bind().exec_driver_sql(statement)


def downgrade() -> None:
    raise RuntimeError("No destructive owner-schema downgrade without independent approval")
