"""Privacy-bounded owner startup incident classification (D11 source contract).

Only fixed allowlisted strings/SQLSTATE appear in stdout, exception reason and
telemetry. NEVER pass DBAPIError, orig exception, repr, args, SQL statement,
bind parameters, DSN or secret to a logger, operator or a public endpoint.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

Phase = Literal[
    "settings",
    "db_create",
    "connect",
    "migration_lock",
    "alembic_upgrade",
    "owner_schema_verify",
    "ingress_attestation",
]
Reason = Literal[
    "database_missing",
    "role_or_database_login_invalid",
    "password_rejected",
    "connection_unavailable",
    "database_permission_denied",
    "schema_object_missing",
    "schema_conflict",
    "owner_database_or_role_mismatch",
    "migration_graph_rejected",
    "migration_state_unverified",
    "migration_lock_timeout",
    "startup_deadline",
    "ingress_unverified",
    "settings_rejected",
    "database_error_unknown",
    "startup_unknown",
]
_EXCEPTION_TYPES = frozenset(
    {
        "OperationalError",
        "InterfaceError",
        "DatabaseError",
        "ProgrammingError",
        "IntegrityError",
        "DataError",
        "DBAPIError",
        "TimeoutError",
        "OSError",
        "ConnectionError",
        "ConnectionRefusedError",
        "gaierror",
        "ValidationError",
        "OwnerSchemaRejected",
        "OwnerDatabaseConnectionUnavailable",
        "RuntimeError",
        "ValueError",
    }
)
_SQLSTATE = re.compile(r"[A-Z0-9]{5}\Z", re.ASCII)
_AUTH_STATES = {"28000", "28P01"}
_PERMANENT_STATES = {
    "3D000",
    "28000",
    "28P01",
    "42501",
    "42P01",
    "42P07",
    "42710",
    "3F000",
    "42703",
    "23505",
}
_SCHEMA_REASONS: dict[str, Reason] = {
    "owner PostgreSQL database or principal mismatch": "owner_database_or_role_mismatch",
    "foreign namespace in owner database": "schema_conflict",
    "unexpected legacy or cross-owner database object": "schema_conflict",
    "nonempty unversioned owner database": "schema_conflict",
    "unknown or newer owner migration version": "migration_state_unverified",
    "invalid owner revision-table cardinality": "migration_state_unverified",
    "owner column nullability differs from reviewed metadata": "migration_state_unverified",
    "owner column type differs from reviewed metadata": "migration_state_unverified",
    "owner index columns/uniqueness differ": "migration_state_unverified",
    "owner partial-index predicate absent or unexpected": "migration_state_unverified",
    "owner migration history missing from installed image": "migration_graph_rejected",
    "unexpected owner Alembic heads or branching": "migration_graph_rejected",
    "owner migration baseline missing from reviewed graph": "migration_graph_rejected",
    "owner migration graph has a foreign ancestor": "migration_graph_rejected",
    "branched/merged owner schema history is forbidden": "migration_graph_rejected",
    "unknown intermediate owner schema revision": "migration_graph_rejected",
    "frozen owner 0001 baseline was modified": "migration_graph_rejected",
    "pre-A13 owner migration history was altered": "migration_graph_rejected",
    "current ORM source differs from reviewed owner head": "migration_graph_rejected",
    "owner startup migration lock timeout": "migration_lock_timeout",
    "owner startup deadline exceeded": "startup_deadline",
    "owner revision mismatch": "migration_state_unverified",
    "owner column inventory mismatch": "migration_state_unverified",
    "owner primary-key contract changed": "migration_state_unverified",
    "owner CHECK constraints missing": "migration_state_unverified",
    "owner UNIQUE contract differs from reviewed head": "migration_state_unverified",
    "owner index inventory mismatch": "migration_state_unverified",
    "owner foreign-key verification failed": "migration_state_unverified",
    "owner read-only schema verification unavailable": "migration_state_unverified",
}


def safe_sqlstate(error: BaseException) -> str | None:
    """Look through trusted SQLAlchemy/asyncpg wrapping without leaking values."""
    queue: list[BaseException] = [error]
    seen: set[int] = set()
    for _ in range(7):
        if not queue:
            break
        current = queue.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        for field in ("sqlstate", "pgcode", "sql_state"):
            code = getattr(current, field, None)
            if isinstance(code, str) and _SQLSTATE.fullmatch(code) is not None:
                return code
        queue.extend(
            child
            for child in (getattr(current, "orig", None), current.__cause__, current.__context__)
            if isinstance(child, BaseException)
        )
    return None


def is_permanent_connection_failure(error: BaseException) -> bool:
    return safe_sqlstate(error) in _PERMANENT_STATES


@dataclass(frozen=True, slots=True)
class OwnerStartupDiagnostic:
    phase: Phase
    reason: Reason
    exception_type: str
    sqlstate: str | None


def safe_owner_startup_diagnostic(
    *,
    phase: Phase,
    error: BaseException,
) -> OwnerStartupDiagnostic:
    sqlstate = safe_sqlstate(error)
    if sqlstate == "3D000":
        reason: Reason = "database_missing"
    elif sqlstate == "28000":
        reason = "role_or_database_login_invalid"
    elif sqlstate == "28P01":
        reason = "password_rejected"
    elif sqlstate == "42501":
        reason = "database_permission_denied"
    elif sqlstate in {"42P01", "42703", "3F000"}:
        reason = "schema_object_missing"
    elif sqlstate in {"42P07", "42710", "23505"}:
        reason = "schema_conflict"
    elif (
        (sqlstate is not None and sqlstate.startswith("08"))
        or isinstance(error, (ConnectionError, TimeoutError, OSError))
        or type(error).__name__ == "OwnerDatabaseConnectionUnavailable"
    ):
        reason = "connection_unavailable"
    elif type(error).__name__ == "OwnerSchemaRejected":
        # Original reason text belongs ONLY to our own fixed internal
        # exception literals. Unknown/dynamic messages never escape.
        reason = _SCHEMA_REASONS.get(str(error), "migration_state_unverified")
    elif phase == "ingress_attestation":
        reason = "ingress_unverified"
    elif phase == "settings":
        reason = "settings_rejected"
    elif phase in {
        "db_create",
        "connect",
        "migration_lock",
        "alembic_upgrade",
        "owner_schema_verify",
    }:
        reason = "database_error_unknown"
    else:
        reason = "startup_unknown"
    name = type(error).__name__
    return OwnerStartupDiagnostic(
        phase,
        reason,
        name if name in _EXCEPTION_TYPES else "UnknownError",
        sqlstate,
    )
