# ruff: noqa: E501
"""Frozen fresh reverse schema; independent logical database.

This is NEVER an upgrade of the historical global A10 0001/0002.
Changes must use a new reviewed revision, never regenerate installed baseline.
"""

from __future__ import annotations

from alembic import op

revision = "reverse_0001"
down_revision = None
branch_labels = None
depends_on = None
source_signature = "7876512ca2e5b8a47ba7f1dccd13ede9a58378fea4133de400e8e9ff884fe517"

_DDL: tuple[str, ...] = (
    'CREATE SCHEMA "reverse"',
    "CREATE TABLE reverse.audit (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tactor_user_id UUID, \n\tproject_id UUID, \n\taction VARCHAR(128) NOT NULL, \n\tobject_id VARCHAR(128) NOT NULL, \n\towner_revision VARCHAR(128) NOT NULL, \n\tdetails JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id)\n)",
    "CREATE INDEX ix_reverse_audit_actor_time ON reverse.audit (actor_user_id, created_at)",
    "CREATE TABLE reverse.commands (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tactor_scope VARCHAR(64) NOT NULL, \n\tproject_scope VARCHAR(64) NOT NULL, \n\toperation VARCHAR(128) NOT NULL, \n\tkey VARCHAR(128) NOT NULL, \n\tfingerprint VARCHAR(64) NOT NULL, \n\texpected_owner_revision VARCHAR(128) NOT NULL, \n\tstate VARCHAR(16) NOT NULL, \n\tencrypted_outcome TEXT, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT ck_reverse_command_state CHECK (state IN ('pending','completed','unknown','reconciled','denied')), \n\tCONSTRAINT uq_reverse_command_key UNIQUE (actor_scope, project_scope, operation, key), \n\tCONSTRAINT uq_reverse_command_uuid UNIQUE (operation_uuid)\n)",
    "CREATE INDEX ix_reverse_command_reconcile ON reverse.commands (state, updated_at)",
    "CREATE TABLE reverse.native_projects (\n\tid UUID NOT NULL, \n\tproject_id UUID NOT NULL, \n\tnative_project_key VARCHAR(256) NOT NULL, \n\towner_service_id UUID NOT NULL, \n\tenabled BOOLEAN NOT NULL, \n\tversion INTEGER NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_reverse_project_native UNIQUE (project_id, native_project_key), \n\tCONSTRAINT uq_reverse_native_project_scoped UNIQUE (id, project_id)\n)",
    "CREATE INDEX ix_native_project_project ON reverse.native_projects (project_id, enabled)",
    "CREATE TABLE reverse.outbox (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tevent_name VARCHAR(128) NOT NULL, \n\towner_revision VARCHAR(128) NOT NULL, \n\tevent_payload JSONB NOT NULL, \n\tattempts INTEGER NOT NULL, \n\tdelivery_claim_uuid UUID, \n\tavailable_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tclaimed_until TIMESTAMP WITH TIME ZONE, \n\tdelivered_at TIMESTAMP WITH TIME ZONE, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_reverse_outbox_effect UNIQUE (operation_uuid, event_name)\n)",
    "CREATE INDEX ix_reverse_outbox_pending ON reverse.outbox (delivered_at, available_at)",
    "CREATE TABLE reverse.native_imports (\n\timport_uuid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tproject_id UUID NOT NULL, \n\tnative_project_id UUID NOT NULL, \n\tfile_object_id UUID NOT NULL, \n\tsource_file_version INTEGER NOT NULL, \n\tsource_content_sha256 VARCHAR(64) NOT NULL, \n\tsource_size_bytes INTEGER NOT NULL, \n\tauto_analyze BOOLEAN NOT NULL, \n\tactor_user_id UUID NOT NULL, \n\tagent_session_uuid UUID NOT NULL, \n\towner_service_id UUID NOT NULL, \n\tidempotency_digest VARCHAR(64) NOT NULL, \n\trequest_fingerprint VARCHAR(64) NOT NULL, \n\tstatus VARCHAR(24) NOT NULL, \n\tversion INTEGER NOT NULL, \n\tnative_artifact_id VARCHAR(256), \n\tresult_sha256 VARCHAR(64), \n\tcleanup_state VARCHAR(20) NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tdispatched_at TIMESTAMP WITH TIME ZONE, \n\tresolved_at TIMESTAMP WITH TIME ZONE, \n\tPRIMARY KEY (import_uuid), \n\tCONSTRAINT fk_native_import_project_owner FOREIGN KEY(native_project_id, project_id) REFERENCES reverse.native_projects (id, project_id), \n\tCONSTRAINT ck_native_import_status CHECK (status IN ('reserved','dispatched','succeeded','unknown','confirmed_absent','cancelled')), \n\tCONSTRAINT ck_native_import_cleanup_state CHECK (cleanup_state IN ('not_requested','requested','confirmed')), \n\tCONSTRAINT ck_native_import_version CHECK (version >= 1 AND source_file_version >= 1 AND source_size_bytes >= 0), \n\tCONSTRAINT ck_native_import_success_id CHECK ((status = 'succeeded' AND native_artifact_id IS NOT NULL) OR (status <> 'succeeded')), \n\tCONSTRAINT uq_native_import_idempotency UNIQUE (project_id, idempotency_digest), \n\tCONSTRAINT uq_native_import_operation_uuid UNIQUE (project_id, operation_uuid), \n\tCONSTRAINT ck_native_import_operation_uuid_v4 CHECK (substr(cast(operation_uuid AS text), 15, 1) = '4')\n)",
    "CREATE INDEX ix_native_import_uncertain ON reverse.native_imports (status, created_at)",
    "CREATE UNIQUE INDEX uq_native_artifact_in_project ON reverse.native_imports (native_project_id, native_artifact_id) WHERE native_artifact_id IS NOT NULL",
    "CREATE UNIQUE INDEX uq_native_uncertain_effect ON reverse.native_imports (project_id, native_project_id, file_object_id, source_file_version, request_fingerprint) WHERE status IN ('dispatched','unknown')",
)


def upgrade() -> None:
    for statement in _DDL:
        op.get_bind().exec_driver_sql(statement)


def downgrade() -> None:
    raise RuntimeError("No destructive owner-schema downgrade without independent approval")
