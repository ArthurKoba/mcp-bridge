# ruff: noqa: E501
"""Frozen fresh runtime schema; independent logical database.

This is NEVER an upgrade of the historical global A10 0001/0002.
Changes must use a new reviewed revision, never regenerate installed baseline.
"""

from __future__ import annotations

from alembic import op

revision = "runtime_0001"
down_revision = None
branch_labels = None
depends_on = None
source_signature = "acc05a7994ad166610ad02b4c189f7c776df53a4a922bd75fa12ed64d7b46b75"

_DDL: tuple[str, ...] = (
    'CREATE SCHEMA "runtime"',
    "CREATE TABLE runtime.audit (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tactor_user_id UUID, \n\tproject_id UUID, \n\taction VARCHAR(128) NOT NULL, \n\tobject_id VARCHAR(128) NOT NULL, \n\towner_revision VARCHAR(128) NOT NULL, \n\tdetails JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id)\n)",
    "CREATE INDEX ix_runtime_audit_actor_time ON runtime.audit (actor_user_id, created_at)",
    "CREATE TABLE runtime.commands (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tactor_scope VARCHAR(64) NOT NULL, \n\tproject_scope VARCHAR(64) NOT NULL, \n\toperation VARCHAR(128) NOT NULL, \n\tkey VARCHAR(128) NOT NULL, \n\tfingerprint VARCHAR(64) NOT NULL, \n\texpected_owner_revision VARCHAR(128) NOT NULL, \n\tstate VARCHAR(16) NOT NULL, \n\tencrypted_outcome TEXT, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT ck_runtime_command_state CHECK (state IN ('pending','completed','unknown','reconciled','denied')), \n\tCONSTRAINT uq_runtime_command_key UNIQUE (actor_scope, project_scope, operation, key), \n\tCONSTRAINT uq_runtime_command_uuid UNIQUE (operation_uuid)\n)",
    "CREATE INDEX ix_runtime_command_reconcile ON runtime.commands (state, updated_at)",
    "CREATE TABLE runtime.outbox (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tevent_name VARCHAR(128) NOT NULL, \n\towner_revision VARCHAR(128) NOT NULL, \n\tevent_payload JSONB NOT NULL, \n\tattempts INTEGER NOT NULL, \n\tdelivery_claim_uuid UUID, \n\tavailable_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tclaimed_until TIMESTAMP WITH TIME ZONE, \n\tdelivered_at TIMESTAMP WITH TIME ZONE, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_runtime_outbox_effect UNIQUE (operation_uuid, event_name)\n)",
    "CREATE INDEX ix_runtime_outbox_pending ON runtime.outbox (delivered_at, available_at)",
    "CREATE TABLE runtime.sessions (\n\truntime_session_uuid UUID NOT NULL, \n\tproject_id UUID NOT NULL, \n\tagent_session_uuid UUID NOT NULL, \n\tactor_user_id UUID NOT NULL, \n\tkind VARCHAR(20) NOT NULL, \n\towner_service_id UUID NOT NULL, \n\towner_instance UUID NOT NULL, \n\topen_idempotency_digest VARCHAR(64) NOT NULL, \n\topen_request_fingerprint VARCHAR(64) NOT NULL, \n\tlease_nonce UUID NOT NULL, \n\tversion INTEGER NOT NULL, \n\tstatus VARCHAR(16) NOT NULL, \n\tcleanup_state VARCHAR(16) NOT NULL, \n\tidle_ttl_seconds INTEGER NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tlast_heartbeat_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tidle_expires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\thard_expires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tlease_expires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tended_at TIMESTAMP WITH TIME ZONE, \n\tPRIMARY KEY (runtime_session_uuid), \n\tCONSTRAINT ck_runtime_kind CHECK (kind IN ('files','terminal','web_managed','web_remote','reverse')), \n\tCONSTRAINT ck_runtime_status CHECK (status IN ('active','lost','expired','revoked','closed')), \n\tCONSTRAINT ck_runtime_cleanup_state CHECK (cleanup_state IN ('not_needed','pending','confirmed','unknown')), \n\tCONSTRAINT ck_runtime_lease_revision CHECK (version >= 1 AND idle_ttl_seconds >= 30 AND idle_ttl_seconds <= 86400), \n\tCONSTRAINT ck_runtime_hard_lease CHECK (hard_expires_at > created_at AND lease_expires_at <= hard_expires_at), \n\tCONSTRAINT ck_runtime_session_uuid_v4 CHECK (substr(cast(runtime_session_uuid AS text), 15, 1) = '4'), \n\tCONSTRAINT uq_runtime_project_session UNIQUE (runtime_session_uuid, project_id), \n\tCONSTRAINT uq_runtime_session_open_dedup UNIQUE (project_id, owner_service_id, actor_user_id, agent_session_uuid, kind, open_idempotency_digest)\n)",
    "CREATE INDEX ix_runtime_expiry ON runtime.sessions (status, idle_expires_at, hard_expires_at)",
    "CREATE INDEX ix_runtime_owner ON runtime.sessions (project_id, owner_service_id, status)",
    "CREATE TABLE runtime.jobs (\n\tjob_uuid UUID NOT NULL, \n\truntime_session_uuid UUID NOT NULL, \n\tproject_id UUID NOT NULL, \n\towner_service_id UUID NOT NULL, \n\tactor_user_id UUID NOT NULL, \n\tagent_session_uuid UUID NOT NULL, \n\tidempotency_digest VARCHAR(64) NOT NULL, \n\trequest_fingerprint VARCHAR(64) NOT NULL, \n\toperation VARCHAR(128) NOT NULL, \n\tstatus VARCHAR(16) NOT NULL, \n\tversion INTEGER NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tstarted_at TIMESTAMP WITH TIME ZONE, \n\tresolved_at TIMESTAMP WITH TIME ZONE, \n\thard_expires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tresult_digest VARCHAR(64), \n\tPRIMARY KEY (job_uuid), \n\tCONSTRAINT fk_runtime_job_project_session FOREIGN KEY(runtime_session_uuid, project_id) REFERENCES runtime.sessions (runtime_session_uuid, project_id), \n\tCONSTRAINT ck_runtime_job_status CHECK (status IN ('queued','running','succeeded','failed','unknown','cancelled')), \n\tCONSTRAINT ck_runtime_job_version CHECK (version >= 1), \n\tCONSTRAINT uq_runtime_job_idempotency UNIQUE (project_id, runtime_session_uuid, idempotency_digest)\n)",
    "CREATE INDEX ix_runtime_job_pending ON runtime.jobs (status, hard_expires_at)",
    "CREATE UNIQUE INDEX uq_runtime_uncertain_effect ON runtime.jobs (runtime_session_uuid, request_fingerprint) WHERE status IN ('queued','running','unknown')",
)


def upgrade() -> None:
    for statement in _DDL:
        op.get_bind().exec_driver_sql(statement)


def downgrade() -> None:
    raise RuntimeError("No destructive owner-schema downgrade without independent approval")
