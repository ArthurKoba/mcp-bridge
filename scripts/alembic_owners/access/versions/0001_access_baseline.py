# ruff: noqa: E501
"""Frozen fresh access schema; independent logical database.

This is NEVER an upgrade of the historical global A10 0001/0002.
Changes must use a new reviewed revision, never regenerate installed baseline.
"""

from __future__ import annotations

from alembic import op

revision = "access_0001"
down_revision = None
branch_labels = None
depends_on = None
source_signature = "b9db1f587cb5412d7d08616acac58468d910c9a535bc9b7de77a5570a1652b2c"

_DDL: tuple[str, ...] = (
    'CREATE SCHEMA "access"',
    'CREATE SCHEMA "authorization"',
    'CREATE SCHEMA "sessions"',
    "CREATE TABLE access.audit (\n\tid UUID NOT NULL, \n\tactor_id UUID, \n\tproject_id UUID, \n\taction VARCHAR(128) NOT NULL, \n\tobject_id VARCHAR(128) NOT NULL, \n\tdetails JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id)\n)",
    "CREATE INDEX ix_authorization_audit_actor_time ON access.audit (actor_id, created_at)",
    "CREATE TABLE access.commands (\n\tid UUID NOT NULL, \n\tactor_scope VARCHAR(64) NOT NULL, \n\tproject_scope VARCHAR(64) NOT NULL, \n\toperation VARCHAR(128) NOT NULL, \n\tkey VARCHAR(128) NOT NULL, \n\tfingerprint VARCHAR(64) NOT NULL, \n\tstatus VARCHAR(24) NOT NULL, \n\tresponse_status INTEGER, \n\tresponse_ciphertext TEXT, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT ck_idempotency_status CHECK (status IN ('pending','completed')), \n\tCONSTRAINT uq_authorization_command_idempotency UNIQUE (actor_scope, project_scope, operation, key)\n)",
    "CREATE INDEX ix_authorization_command_expiry ON access.commands (expires_at)",
    "CREATE TABLE access.outbox (\n\tid UUID NOT NULL, \n\tevent_name VARCHAR(128) NOT NULL, \n\tevent_payload JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tpublished_at TIMESTAMP WITH TIME ZONE, \n\tclaim_id UUID, \n\tlocked_until TIMESTAMP WITH TIME ZONE, \n\tattempts INTEGER NOT NULL, \n\tPRIMARY KEY (id)\n)",
    "CREATE INDEX ix_auth_outbox_pending ON access.outbox (published_at, created_at)",
    'CREATE TABLE "authorization".service_keys (\n\tkey_id UUID NOT NULL, \n\tservice_id UUID NOT NULL, \n\tservice_name VARCHAR(80) NOT NULL, \n\taudience VARCHAR(64) NOT NULL, \n\tkey_version INTEGER NOT NULL, \n\tpublic_key_b64 VARCHAR(64) NOT NULL, \n\tpublic_key_fingerprint VARCHAR(64) NOT NULL, \n\tenabled BOOLEAN NOT NULL, \n\tissued_by_user_id UUID NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\trevoked_at TIMESTAMP WITH TIME ZONE, \n\tPRIMARY KEY (key_id), \n\tCONSTRAINT ck_service_key_version CHECK (key_version >= 1), \n\tCONSTRAINT uq_service_identity_audience_revision UNIQUE (service_id, audience, key_version), \n\tCONSTRAINT uq_service_public_key UNIQUE (public_key_fingerprint)\n)',
    'CREATE INDEX ix_service_key_audience_enabled ON "authorization".service_keys (audience, enabled)',
    "CREATE TABLE sessions.agent_sessions (\n\tsession_uuid UUID NOT NULL, \n\tproject_id UUID NOT NULL, \n\tcreated_by_principal_id UUID NOT NULL, \n\tis_elevated BOOLEAN NOT NULL, \n\televation_policy VARCHAR(16) NOT NULL, \n\tlabel VARCHAR(128), \n\tgrants JSONB NOT NULL, \n\tstatus VARCHAR(16) NOT NULL, \n\tversion INTEGER NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\thard_expires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\trevoked_at TIMESTAMP WITH TIME ZONE, \n\tPRIMARY KEY (session_uuid), \n\tCONSTRAINT ck_agent_session_uuid_v4 CHECK (substr(cast(session_uuid AS text), 15, 1) = '4'), \n\tCONSTRAINT ck_agent_session_elevation_policy CHECK (elevation_policy IN ('fixed','requestable')), \n\tCONSTRAINT ck_agent_session_status CHECK (status IN ('active','revoked'))\n)",
    "CREATE INDEX ix_agent_session_project_active ON sessions.agent_sessions (project_id, status)",
    "CREATE TABLE \"authorization\".consumed_assertions (\n\tid UUID NOT NULL, \n\tkind VARCHAR(16) NOT NULL, \n\tissuer_id UUID NOT NULL, \n\tjti_digest VARCHAR(64) NOT NULL, \n\tproject_id UUID NOT NULL, \n\tsession_uuid UUID NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT ck_assertion_kind CHECK (kind IN ('service','delegation')), \n\tCONSTRAINT uq_assertion_single_use UNIQUE (kind, issuer_id, jti_digest), \n\tFOREIGN KEY(session_uuid) REFERENCES sessions.agent_sessions (session_uuid) ON DELETE RESTRICT\n)",
    'CREATE INDEX ix_assertion_expiry ON "authorization".consumed_assertions (expires_at)',
    "CREATE TABLE sessions.approvals (\n\tid UUID NOT NULL, \n\tsession_uuid UUID NOT NULL, \n\tproject_id UUID NOT NULL, \n\trequested_by_user_id UUID NOT NULL, \n\trequested_grants JSONB NOT NULL, \n\trequested_expires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tstatus VARCHAR(16) NOT NULL, \n\tversion INTEGER NOT NULL, \n\tresolved_by_user_id UUID, \n\tissued_session_uuid UUID, \n\tresolved_at TIMESTAMP WITH TIME ZONE, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT ck_session_approval_status CHECK (status IN ('pending','approved','rejected')), \n\tCONSTRAINT ck_session_approval_version CHECK (version >= 1), \n\tFOREIGN KEY(session_uuid) REFERENCES sessions.agent_sessions (session_uuid) ON DELETE RESTRICT, \n\tFOREIGN KEY(issued_session_uuid) REFERENCES sessions.agent_sessions (session_uuid) ON DELETE RESTRICT\n)",
    "CREATE INDEX ix_session_approval_status ON sessions.approvals (project_id, status)",
)


def upgrade() -> None:
    for statement in _DDL:
        op.get_bind().exec_driver_sql(statement)


def downgrade() -> None:
    raise RuntimeError("No destructive owner-schema downgrade without independent approval")
