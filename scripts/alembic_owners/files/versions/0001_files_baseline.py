# ruff: noqa: E501
"""Frozen fresh files schema; independent logical database.

This is NEVER an upgrade of the historical global A10 0001/0002.
Changes must use a new reviewed revision, never regenerate installed baseline.
"""

from __future__ import annotations

from alembic import op

revision = "files_0001"
down_revision = None
branch_labels = None
depends_on = None
source_signature = "395244365a0bd125869329b31554e285d8313f3f8253bd6596006c73421a1679"

_DDL: tuple[str, ...] = (
    'CREATE SCHEMA "files"',
    "CREATE TABLE files.audit (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tactor_user_id UUID, \n\tproject_id UUID, \n\taction VARCHAR(128) NOT NULL, \n\tobject_id VARCHAR(128) NOT NULL, \n\towner_revision VARCHAR(128) NOT NULL, \n\tdetails JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id)\n)",
    "CREATE INDEX ix_files_audit_actor_time ON files.audit (actor_user_id, created_at)",
    "CREATE TABLE files.commands (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tactor_scope VARCHAR(64) NOT NULL, \n\tproject_scope VARCHAR(64) NOT NULL, \n\toperation VARCHAR(128) NOT NULL, \n\tkey VARCHAR(128) NOT NULL, \n\tfingerprint VARCHAR(64) NOT NULL, \n\texpected_owner_revision VARCHAR(128) NOT NULL, \n\tstate VARCHAR(16) NOT NULL, \n\tencrypted_outcome TEXT, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT ck_files_command_state CHECK (state IN ('pending','completed','unknown','reconciled','denied')), \n\tCONSTRAINT uq_files_command_key UNIQUE (actor_scope, project_scope, operation, key), \n\tCONSTRAINT uq_files_command_uuid UNIQUE (operation_uuid)\n)",
    "CREATE INDEX ix_files_command_reconcile ON files.commands (state, updated_at)",
    "CREATE TABLE files.file_objects (\n\tid UUID NOT NULL, \n\tproject_id UUID NOT NULL, \n\tpath_digest VARCHAR(64) NOT NULL, \n\tinode_digest VARCHAR(64), \n\tcontent_sha256 VARCHAR(64), \n\tsize_bytes BIGINT NOT NULL, \n\tversion INTEGER NOT NULL, \n\tdeleted BOOLEAN NOT NULL, \n\tconfirmed_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_file_object_project_path UNIQUE (project_id, path_digest), \n\tCONSTRAINT uq_file_object_project_identity UNIQUE (id, project_id), \n\tCONSTRAINT ck_file_object_revision CHECK (size_bytes >= 0 AND version >= 1)\n)",
    "CREATE INDEX ix_file_object_project_deleted ON files.file_objects (project_id, deleted)",
    "CREATE TABLE files.outbox (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tevent_name VARCHAR(128) NOT NULL, \n\towner_revision VARCHAR(128) NOT NULL, \n\tevent_payload JSONB NOT NULL, \n\tattempts INTEGER NOT NULL, \n\tdelivery_claim_uuid UUID, \n\tavailable_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tclaimed_until TIMESTAMP WITH TIME ZONE, \n\tdelivered_at TIMESTAMP WITH TIME ZONE, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_files_outbox_effect UNIQUE (operation_uuid, event_name)\n)",
    "CREATE INDEX ix_files_outbox_pending ON files.outbox (delivered_at, available_at)",
    "CREATE TABLE files.quota_accounts (\n\tproject_id UUID NOT NULL, \n\tbyte_limit BIGINT NOT NULL, \n\tused_bytes BIGINT NOT NULL, \n\treserved_bytes BIGINT NOT NULL, \n\tfrozen BOOLEAN NOT NULL, \n\tversion INTEGER NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (project_id), \n\tCONSTRAINT ck_file_quota_nonnegative CHECK (byte_limit >= 0 AND used_bytes >= 0 AND reserved_bytes >= 0), \n\tCONSTRAINT ck_file_quota_version CHECK (version >= 1)\n)",
    "CREATE TABLE files.quota_reservations (\n\treservation_id UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tproject_id UUID NOT NULL, \n\tagent_session_uuid UUID NOT NULL, \n\tactor_user_id UUID NOT NULL, \n\towner_service_id UUID NOT NULL, \n\tpath_digest VARCHAR(64) NOT NULL, \n\tidempotency_digest VARCHAR(64) NOT NULL, \n\trequest_fingerprint VARCHAR(64) NOT NULL, \n\texpected_content_sha256 VARCHAR(64) NOT NULL, \n\tproject_access_revision VARCHAR(64) NOT NULL, \n\texpected_file_version INTEGER NOT NULL, \n\tprior_bytes BIGINT NOT NULL, \n\tplanned_bytes BIGINT NOT NULL, \n\treserved_delta BIGINT NOT NULL, \n\tversion INTEGER NOT NULL, \n\tstatus VARCHAR(16) NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tdispatched_at TIMESTAMP WITH TIME ZONE, \n\texpires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tresolved_at TIMESTAMP WITH TIME ZONE, \n\tobserved_inode_digest VARCHAR(64), \n\tobserved_file_version INTEGER, \n\tobserved_size_bytes BIGINT, \n\tPRIMARY KEY (reservation_id), \n\tCONSTRAINT ck_file_quota_reservation_state CHECK (status IN ('reserved','dispatched','committed','released','unknown')), \n\tCONSTRAINT ck_file_reservation_size CHECK (prior_bytes >= 0 AND planned_bytes >= 0 AND reserved_delta >= 0), \n\tCONSTRAINT ck_file_reservation_version CHECK (version >= 1 AND expected_file_version >= 0), \n\tCONSTRAINT uq_file_quota_idempotency UNIQUE (project_id, idempotency_digest), \n\tCONSTRAINT uq_file_quota_operation_uuid UNIQUE (project_id, operation_uuid), \n\tCONSTRAINT ck_file_operation_uuid_v4 CHECK (substr(cast(operation_uuid AS text), 15, 1) = '4')\n)",
    "CREATE INDEX ix_quota_reservation_expiry ON files.quota_reservations (status, expires_at)",
    "CREATE UNIQUE INDEX uq_file_active_path ON files.quota_reservations (project_id, path_digest) WHERE status IN ('reserved','dispatched','unknown')",
)


def upgrade() -> None:
    for statement in _DDL:
        op.get_bind().exec_driver_sql(statement)


def downgrade() -> None:
    raise RuntimeError("No destructive owner-schema downgrade without independent approval")
