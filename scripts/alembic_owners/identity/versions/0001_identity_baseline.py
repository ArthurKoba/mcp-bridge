# ruff: noqa: E501
"""Frozen fresh identity schema; independent logical database.

This is NEVER an upgrade of the historical global A10 0001/0002.
Changes must use a new reviewed revision, never regenerate installed baseline.
"""

from __future__ import annotations

from alembic import op

revision = "identity_0001"
down_revision = None
branch_labels = None
depends_on = None
source_signature = "ee13ba6b4266a325be4f5860e3a321c43662e2409bfcd88f69ccf9969f8466eb"

_DDL: tuple[str, ...] = (
    'CREATE SCHEMA "identity"',
    "CREATE TABLE identity.audit (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tactor_user_id UUID, \n\tproject_id UUID, \n\taction VARCHAR(128) NOT NULL, \n\tobject_id VARCHAR(128) NOT NULL, \n\towner_revision VARCHAR(128) NOT NULL, \n\tdetails JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id)\n)",
    "CREATE INDEX ix_identity_audit_actor_time ON identity.audit (actor_user_id, created_at)",
    "CREATE TABLE identity.bootstrap (\n\tid SERIAL NOT NULL, \n\tfirst_superuser_claimed BOOLEAN NOT NULL, \n\tPRIMARY KEY (id)\n)",
    "CREATE TABLE identity.commands (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tactor_scope VARCHAR(64) NOT NULL, \n\tproject_scope VARCHAR(64) NOT NULL, \n\toperation VARCHAR(128) NOT NULL, \n\tkey VARCHAR(128) NOT NULL, \n\tfingerprint VARCHAR(64) NOT NULL, \n\texpected_owner_revision VARCHAR(128) NOT NULL, \n\tstate VARCHAR(16) NOT NULL, \n\tencrypted_outcome TEXT, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT ck_identity_command_state CHECK (state IN ('pending','completed','unknown','reconciled','denied')), \n\tCONSTRAINT uq_identity_command_key UNIQUE (actor_scope, project_scope, operation, key), \n\tCONSTRAINT uq_identity_command_uuid UNIQUE (operation_uuid)\n)",
    "CREATE INDEX ix_identity_command_reconcile ON identity.commands (state, updated_at)",
    "CREATE TABLE identity.login_attempts (\n\tbucket_key VARCHAR(64) NOT NULL, \n\tfailures INTEGER NOT NULL, \n\tlast_failed_at TIMESTAMP WITH TIME ZONE, \n\tblocked_until TIMESTAMP WITH TIME ZONE, \n\tPRIMARY KEY (bucket_key)\n)",
    "CREATE TABLE identity.outbox (\n\tid UUID NOT NULL, \n\toperation_uuid UUID NOT NULL, \n\tevent_name VARCHAR(128) NOT NULL, \n\towner_revision VARCHAR(128) NOT NULL, \n\tevent_payload JSONB NOT NULL, \n\tattempts INTEGER NOT NULL, \n\tdelivery_claim_uuid UUID, \n\tavailable_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tclaimed_until TIMESTAMP WITH TIME ZONE, \n\tdelivered_at TIMESTAMP WITH TIME ZONE, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_identity_outbox_effect UNIQUE (operation_uuid, event_name)\n)",
    "CREATE INDEX ix_identity_outbox_pending ON identity.outbox (delivered_at, available_at)",
    "CREATE TABLE identity.users (\n\tid UUID NOT NULL, \n\tusername VARCHAR(128) NOT NULL, \n\tpassword_digest TEXT NOT NULL, \n\trole VARCHAR(24) NOT NULL, \n\tenabled BOOLEAN NOT NULL, \n\tcredential_version INTEGER NOT NULL, \n\tbrowser_telemetry_opt_in BOOLEAN DEFAULT 'false' NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tdeleted_at TIMESTAMP WITH TIME ZONE, \n\tPRIMARY KEY (id), \n\tCONSTRAINT ck_identity_role CHECK (role IN ('user','superuser'))\n)",
    "CREATE INDEX ix_identity_user_active_role ON identity.users (enabled, role)",
    "CREATE UNIQUE INDEX ix_identity_users_username ON identity.users (username)",
    "CREATE TABLE identity.admin_token_revocations (\n\tjti_digest VARCHAR(64) NOT NULL, \n\tuser_id UUID NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\trevoked_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (jti_digest), \n\tFOREIGN KEY(user_id) REFERENCES identity.users (id) ON DELETE RESTRICT\n)",
    "CREATE INDEX ix_admin_revocation_expires_at ON identity.admin_token_revocations (expires_at)",
    "CREATE TABLE identity.invitations (\n\tid UUID NOT NULL, \n\ttoken_digest VARCHAR(64) NOT NULL, \n\tkind VARCHAR(24) NOT NULL, \n\tcreated_by_user_id UUID, \n\ttarget_user_id UUID, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE, \n\tused_at TIMESTAMP WITH TIME ZONE, \n\trevoked_at TIMESTAMP WITH TIME ZONE, \n\tPRIMARY KEY (id), \n\tUNIQUE (token_digest), \n\tFOREIGN KEY(created_by_user_id) REFERENCES identity.users (id) ON DELETE RESTRICT, \n\tFOREIGN KEY(target_user_id) REFERENCES identity.users (id) ON DELETE RESTRICT\n)",
    "CREATE INDEX ix_identity_invitation_pending ON identity.invitations (kind, used_at, revoked_at)",
)


def upgrade() -> None:
    for statement in _DDL:
        op.get_bind().exec_driver_sql(statement)


def downgrade() -> None:
    raise RuntimeError("No destructive owner-schema downgrade without independent approval")
