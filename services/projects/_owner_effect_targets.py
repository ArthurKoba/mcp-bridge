"""Concrete owner-local target CAS sources for signed owner effect receipts.

No cross-DB SQL, no native OS/Ghidra claim without independently verified
private attestation. Each reader is bound to ONE durable owner database by the
OwnerEffectReceiptAttestor that injects it. The source command/result are the
ORIGINAL signed command row+Fernet-authenticated outcome, not browser data.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from common.owner_contracts import OwnerAuthorityUnavailable, OwnerCommandDTO
from common.owner_effect_receipts import (
    EffectOwner,
    EffectState,
    OwnerEffectCommand,
    VerifiedOwnerTargetObservation,
)
from projects._file_quota_persistence import FileObjectRow, FileQuotaReservationRow
from projects._native_import_persistence import NativeImportRow, NativeProjectRow
from projects._resource_persistence import IntegrationRow, VariableRow
from projects._runtime_persistence import RuntimeJobRow, RuntimeSessionRow


@dataclass(frozen=True, slots=True)
class VerifiedNativeTarget:
    """Release-pinned private proof, validated OUTSIDE SQL by native supervisor."""

    owner: EffectOwner
    project_id: UUID
    operation_uuid: UUID
    recipient_service_id: UUID
    recipient_instance_uuid: UUID
    target_sha256: str
    observed_owner_revision: int
    observed_state: EffectState
    native_scope_digest: str
    observed_at: datetime
    expires_at: datetime


class TrustedLocalNativeEffectVerifier(Protocol):
    def verify_native_current(
        self,
        *,
        command: OwnerEffectCommand,
        source_command: OwnerCommandDTO,
        owner_revision: int,
        observed_state: EffectState,
    ) -> VerifiedNativeTarget:
        """Verify already acquired Ed25519/cgroup/inode proof with PINNED key.

        Must not call network/OS inside this owner SQL transaction and must not
        accept raw header/UUID/boolean as a physical result attestation.
        """
        ...


def _native(
    verified_by: TrustedLocalNativeEffectVerifier | None,
    *,
    command: OwnerEffectCommand,
    source_command: OwnerCommandDTO,
    revision: int,
    state: EffectState,
) -> bool:
    if verified_by is None:
        return False
    try:
        receipt = verified_by.verify_native_current(
            command=command,
            source_command=source_command,
            owner_revision=revision,
            observed_state=state,
        )
    except Exception:
        return False
    now = datetime.now(UTC)
    return (
        isinstance(receipt, VerifiedNativeTarget)
        and receipt.owner == command.owner
        and receipt.project_id == command.project_id
        and receipt.operation_uuid == command.operation_uuid
        and receipt.recipient_service_id == command.recipient_service_id
        and receipt.recipient_instance_uuid == command.recipient_instance_uuid
        and receipt.target_sha256 == command.target_sha256
        and receipt.observed_owner_revision == revision
        and receipt.observed_state == state
        and len(receipt.native_scope_digest) == 64
        and all(c in "0123456789abcdef" for c in receipt.native_scope_digest)
        and receipt.observed_at.tzinfo is not None
        and receipt.expires_at.tzinfo is not None
        and receipt.observed_at <= now < receipt.expires_at
        and now - receipt.observed_at <= timedelta(minutes=2)
        and receipt.expires_at - now <= timedelta(seconds=30)
    )


def _runtime_digest(session_uuid: UUID) -> str:
    return hashlib.sha256(b"execution-session-v1\x00" + session_uuid.bytes).hexdigest()


def _reverse_digest(item_uuid: UUID, *, file_object: bool) -> str:
    prefix = b"file-object-owner-v1\x00" if file_object else b"native-project-owner-v1\x00"
    return hashlib.sha256(prefix + item_uuid.bytes).hexdigest()


def _catalog_digest(project_id: UUID, kind: str, resource_id: UUID | None) -> str:
    return hashlib.sha256(
        b"catalog-resource-v1\x00"
        + project_id.bytes
        + b"\x00"
        + kind.encode()
        + b"\x00"
        + (resource_id.bytes if resource_id else b"collection")
    ).hexdigest()


def _scope(command: OwnerEffectCommand, source: OwnerCommandDTO) -> None:
    if (
        command.operation_uuid != source.operation_uuid
        or command.project_id != source.project_id
        or command.actor_id != source.caller_user_id
        or command.agent_session_uuid != source.session_uuid
        or command.idempotency_uuid != source.operation_uuid
    ):
        raise OwnerAuthorityUnavailable("owner original effect scope diverges")


class FilesTargetCAS:
    def __init__(self, native: TrustedLocalNativeEffectVerifier | None = None) -> None:
        self.native = native

    async def verify_current_target(
        self,
        tx: AsyncSession,
        *,
        command: OwnerEffectCommand,
        source_command: OwnerCommandDTO,
        stored_result: dict[str, object] | None,
    ) -> VerifiedOwnerTargetObservation:
        if stored_result is not None:
            original = stored_result.get("operation_uuid")
            if original is not None and original != str(command.operation_uuid):
                raise OwnerAuthorityUnavailable("owner encrypted result original UUID changed")
        _scope(command, source_command)
        if command.owner != "files" or source_command.target_owner != "files":
            raise OwnerAuthorityUnavailable("Files CAS is not foreign owner authority")
        row = await tx.scalar(
            select(FileQuotaReservationRow)
            .where(
                FileQuotaReservationRow.operation_uuid == command.operation_uuid,
                FileQuotaReservationRow.project_id == command.project_id,
                FileQuotaReservationRow.actor_user_id == command.actor_id,
                FileQuotaReservationRow.agent_session_uuid == command.agent_session_uuid,
                FileQuotaReservationRow.owner_service_id == command.recipient_service_id,
            )
            .with_for_update()
        )
        if row is None or row.path_digest != command.target_sha256:
            raise OwnerAuthorityUnavailable("Files original reservation/path CAS absent")
        state: EffectState
        if row.status == "reserved":
            state = "reserved"
        elif row.status == "dispatched":
            state = "dispatched"
        elif row.status == "committed":
            state = "committed"
        elif row.status == "released":
            state = "released"
        elif row.status == "unknown":
            state = "unknown"
        else:
            raise OwnerAuthorityUnavailable("Files original owner state unrecognized")
        if state == "released" and command.phase == "release" and row.dispatched_at is not None:
            raise OwnerAuthorityUnavailable(
                "dispatched Files cannot be released without native proof"
            )
        if state == "released" and command.phase == "reconcile" and row.dispatched_at is None:
            raise OwnerAuthorityUnavailable(
                "native Files reconciliation cannot claim undispatched write"
            )
        if state == "committed":
            obj = await tx.scalar(
                select(FileObjectRow)
                .where(
                    FileObjectRow.project_id == command.project_id,
                    FileObjectRow.path_digest == row.path_digest,
                    FileObjectRow.deleted.is_(False),
                )
                .with_for_update()
            )
            if (
                obj is None
                or obj.version != row.expected_file_version + 1
                or obj.size_bytes != row.planned_bytes
                or obj.content_sha256 != row.expected_content_sha256
                or obj.inode_digest != row.observed_inode_digest
            ):
                raise OwnerAuthorityUnavailable("Files finalized CAS no longer authoritative")
        proven = (
            _native(
                self.native,
                command=command,
                source_command=source_command,
                revision=row.version,
                state=state,
            )
            if state == "committed" or (state == "released" and command.phase == "reconcile")
            else False
        )
        return VerifiedOwnerTargetObservation(
            command.operation_uuid,
            command.target_sha256,
            row.version,
            state,
            proven,
        )


class RuntimeTargetCAS:
    def __init__(
        self,
        *,
        idempotency_hmac_key: bytes,
        native: TrustedLocalNativeEffectVerifier | None = None,
    ) -> None:
        if len(idempotency_hmac_key) < 32:
            raise ValueError("Runtime target source needs its own private HMAC key")
        self.key = idempotency_hmac_key
        self.native = native

    async def verify_current_target(
        self,
        tx: AsyncSession,
        *,
        command: OwnerEffectCommand,
        source_command: OwnerCommandDTO,
        stored_result: dict[str, object] | None,
    ) -> VerifiedOwnerTargetObservation:
        if stored_result is not None:
            original = stored_result.get("operation_uuid")
            if original is not None and original != str(command.operation_uuid):
                raise OwnerAuthorityUnavailable("owner encrypted result original UUID changed")
        _scope(command, source_command)
        if command.owner != "execution" or source_command.target_owner != "runtime":
            raise OwnerAuthorityUnavailable("Runtime target cannot read another owner")
        job = await tx.scalar(
            select(RuntimeJobRow)
            .where(
                RuntimeJobRow.job_uuid == command.operation_uuid,
                RuntimeJobRow.project_id == command.project_id,
                RuntimeJobRow.actor_user_id == command.actor_id,
                RuntimeJobRow.agent_session_uuid == command.agent_session_uuid,
                RuntimeJobRow.owner_service_id == command.recipient_service_id,
            )
            .with_for_update()
        )
        runtime_id: UUID | None = job.runtime_session_uuid if job is not None else None
        if runtime_id is None and stored_result is not None:
            raw = stored_result.get("runtime_session_uuid")
            try:
                runtime_id = UUID(raw) if isinstance(raw, str) else None
            except ValueError:
                runtime_id = None
        if runtime_id is None:
            # Original OPEN must reuse the owner's HMAC'd original key; a
            # heartbeat with a new key never guesses a previous session.
            digest = hmac.new(
                self.key, source_command.idempotency_key.encode(), hashlib.sha256
            ).hexdigest()
            candidate = await tx.scalar(
                select(RuntimeSessionRow)
                .where(
                    RuntimeSessionRow.project_id == command.project_id,
                    RuntimeSessionRow.actor_user_id == command.actor_id,
                    RuntimeSessionRow.agent_session_uuid == command.agent_session_uuid,
                    RuntimeSessionRow.owner_service_id == command.recipient_service_id,
                    RuntimeSessionRow.owner_instance == command.recipient_instance_uuid,
                    RuntimeSessionRow.open_idempotency_digest == digest,
                )
                .with_for_update()
            )
            runtime_id = candidate.runtime_session_uuid if candidate else None
        if runtime_id is None:
            raise OwnerAuthorityUnavailable("original RuntimeSession/Job CAS unavailable")
        session = await tx.scalar(
            select(RuntimeSessionRow)
            .where(
                RuntimeSessionRow.runtime_session_uuid == runtime_id,
            )
            .with_for_update()
        )
        if (
            session is None
            or session.project_id != command.project_id
            or session.actor_user_id != command.actor_id
            or session.agent_session_uuid != command.agent_session_uuid
            or session.owner_service_id != command.recipient_service_id
            or session.owner_instance != command.recipient_instance_uuid
            or command.target_sha256 != _runtime_digest(runtime_id)
        ):
            raise OwnerAuthorityUnavailable("Runtime signed target not current session/owner")
        if job is not None:
            if job.lease_nonce is None or job.lease_nonce != session.lease_nonce:
                raise OwnerAuthorityUnavailable("Runtime Job original nonce revoked or missing")
            states: dict[str, EffectState] = {
                "queued": "recorded",
                "running": "running",
                "succeeded": "finished",
                "failed": "failed",
                "unknown": "unknown",
                "cancelled": "cancelled",
            }
            state = states.get(job.status)
            if state is None:
                raise OwnerAuthorityUnavailable("unaccepted Runtime job state")
            revision = job.version
        else:
            states2: dict[str, EffectState] = {
                "active": "active",
                "revoked": "revoked",
                "closed": "closed",
            }
            state = states2.get(session.status)
            if state is None:
                raise OwnerAuthorityUnavailable("RuntimeSession OS state unverified")
            revision = session.version
        proven = (
            _native(
                self.native,
                command=command,
                source_command=source_command,
                revision=revision,
                state=state,
            )
            if state in {"finished", "failed", "closed"}
            else False
        )
        return VerifiedOwnerTargetObservation(
            command.operation_uuid,
            command.target_sha256,
            revision,
            state,
            proven,
        )


class ReverseTargetCAS:
    def __init__(self, native: TrustedLocalNativeEffectVerifier | None = None) -> None:
        self.native = native

    async def verify_current_target(
        self,
        tx: AsyncSession,
        *,
        command: OwnerEffectCommand,
        source_command: OwnerCommandDTO,
        stored_result: dict[str, object] | None,
    ) -> VerifiedOwnerTargetObservation:
        if stored_result is not None:
            original = stored_result.get("operation_uuid")
            if original is not None and original != str(command.operation_uuid):
                raise OwnerAuthorityUnavailable("owner encrypted result original UUID changed")
        _scope(command, source_command)
        if command.owner != "reverse" or source_command.target_owner != "reverse":
            raise OwnerAuthorityUnavailable("Reverse original source scope mismatch")
        row = await tx.scalar(
            select(NativeImportRow)
            .where(
                NativeImportRow.operation_uuid == command.operation_uuid,
                NativeImportRow.project_id == command.project_id,
                NativeImportRow.actor_user_id == command.actor_id,
                NativeImportRow.agent_session_uuid == command.agent_session_uuid,
                NativeImportRow.owner_service_id == command.recipient_service_id,
            )
            .with_for_update()
        )
        if row is None:
            raise OwnerAuthorityUnavailable("Reverse import original operation absent")
        native = await tx.scalar(
            select(NativeProjectRow)
            .where(
                NativeProjectRow.id == row.native_project_id,
            )
            .with_for_update()
        )
        if (
            native is None
            or native.project_id != command.project_id
            or native.owner_service_id != command.recipient_service_id
            or not native.enabled
        ):
            raise OwnerAuthorityUnavailable("Reverse native project currently revoked")
        expected = _reverse_digest(
            row.file_object_id if command.phase == "claim" else row.native_project_id,
            file_object=command.phase == "claim",
        )
        if command.target_sha256 != expected:
            raise OwnerAuthorityUnavailable("native signed target digest contradicts source UUID")
        states: dict[str, EffectState] = {
            "reserved": "reserved",
            "dispatched": "dispatched",
            "succeeded": "committed",
            "confirmed_absent": "absent",
            "unknown": "unknown",
            "cancelled": "cancelled",
        }
        state = states.get(row.status)
        if state is None:
            raise OwnerAuthorityUnavailable("Reverse source state unavailable")
        proven = (
            _native(
                self.native,
                command=command,
                source_command=source_command,
                revision=row.version,
                state=state,
            )
            if state in {"committed", "absent"}
            else False
        )
        return VerifiedOwnerTargetObservation(
            command.operation_uuid,
            command.target_sha256,
            row.version,
            state,
            proven,
        )


class CatalogTargetCAS:
    """Exact resource resolution only; inventory snapshots require owner revision.

    An empty list is not a durable source-version fence. Never pretend a
    metadata collection or one-use secret was physically verified from SQL.
    """

    async def verify_current_target(
        self,
        tx: AsyncSession,
        *,
        command: OwnerEffectCommand,
        source_command: OwnerCommandDTO,
        stored_result: dict[str, object] | None,
    ) -> VerifiedOwnerTargetObservation:
        if stored_result is not None:
            original = stored_result.get("operation_uuid")
            if original is not None and original != str(command.operation_uuid):
                raise OwnerAuthorityUnavailable("owner encrypted result original UUID changed")
        _scope(command, source_command)
        if (
            command.owner != "catalog"
            or source_command.target_owner != "resources"
            or stored_result is None
        ):
            raise OwnerAuthorityUnavailable("Catalog current read/target source unavailable")
        if source_command.operation.endswith(".list"):
            return await self._current_list(
                tx,
                command=command,
                source_command=source_command,
                original=stored_result,
            )
        if not source_command.operation.endswith(".resolve"):
            raise OwnerAuthorityUnavailable(
                "Catalog secret-use/transport effect is not a metadata CAS"
            )
        raw = stored_result.get("resource_id")
        version = stored_result.get("version")
        if not isinstance(raw, str) or type(version) is not int or version < 1:
            raise OwnerAuthorityUnavailable("Catalog resource identity/revision absent")
        try:
            resource_id = UUID(raw)
        except ValueError:
            raise OwnerAuthorityUnavailable("Catalog resource UUID invalid") from None
        if resource_id.version != 4:
            raise OwnerAuthorityUnavailable("Catalog resource UUID must be v4")
        kind = (
            "integration"
            if source_command.operation == "catalog.integrations.resolve"
            else ("variable" if source_command.operation == "catalog.variables.resolve" else None)
        )
        if kind is None or command.target_sha256 != _catalog_digest(
            command.project_id,
            kind,
            resource_id,
        ):
            raise OwnerAuthorityUnavailable("Catalog resource digest/operation mismatch")
        row_type = IntegrationRow if kind == "integration" else VariableRow
        resource = await tx.scalar(
            select(row_type).where(row_type.id == resource_id).with_for_update()
        )
        if resource is None or not isinstance(resource, (IntegrationRow, VariableRow)):
            raise OwnerAuthorityUnavailable("Catalog source resource unavailable")
        if (
            resource.deleted_at is not None
            or resource.version != version
            or (
                resource.owner_project_id != command.project_id
                and (
                    source_command.expected_team_id is None
                    or resource.owner_team_id != source_command.expected_team_id
                )
            )
        ):
            raise OwnerAuthorityUnavailable("Catalog resource/owner currently revoked")
        return VerifiedOwnerTargetObservation(
            command.operation_uuid,
            command.target_sha256,
            resource.version,
            "recorded",
            False,
        )

    @staticmethod
    async def _current_list(
        tx: AsyncSession,
        *,
        command: OwnerEffectCommand,
        source_command: OwnerCommandDTO,
        original: dict[str, object],
    ) -> VerifiedOwnerTargetObservation:
        """Compare EVERY bounded original Catalog record to current source SQL.

        A collection metadata snapshot never proves provider connectivity or
        custody/one-use authorization. No rows means a current empty *SQL*
        inventory only, never a monotonic cross-owner Project revision.
        """
        collection = original.get("kind")
        scope = original.get("scope")
        alias = original.get("alias_key")
        limit = original.get("limit")
        records = original.get("records")
        if (
            collection not in {"integrations", "variables"}
            or source_command.operation != f"catalog.{collection}.list"
            or scope not in {"all", "team", "project"}
            or (alias is not None and (not isinstance(alias, str) or len(alias) > 128))
            or type(limit) is not int
            or not 1 <= limit <= 100
            or not isinstance(records, list)
            or len(records) > limit
            or type(original.get("count")) is not int
            or original["count"] != len(records)
            or original.get("status") != "recorded"
            or original.get("project_id") != str(command.project_id)
            or original.get("source_secret_included") is not False
        ):
            raise OwnerAuthorityUnavailable(
                "Catalog original full bounded metadata receipt invalid"
            )
        kind = "integration" if collection == "integrations" else "variable"
        if command.target_sha256 != _catalog_digest(command.project_id, kind, None):
            raise OwnerAuthorityUnavailable("Catalog collection target digest changed")
        row_type = IntegrationRow if kind == "integration" else VariableRow
        filters = []
        if scope in {"all", "project"}:
            filters.append(row_type.owner_project_id == command.project_id)
        if scope in {"all", "team"} and source_command.expected_team_id is not None:
            filters.append(row_type.owner_team_id == source_command.expected_team_id)
        if not filters:
            raise OwnerAuthorityUnavailable("Catalog current Team owner not signed")
        stmt = select(row_type).where(or_(*filters), row_type.deleted_at.is_(None))
        if alias is not None:
            field = IntegrationRow.alias_key if kind == "integration" else VariableRow.name_key
            stmt = stmt.where(field == alias)
        rows = list(await tx.scalars(stmt.order_by(row_type.id).limit(limit + 1)))
        if len(rows) > limit or len(rows) != len(records):
            raise OwnerAuthorityUnavailable("Catalog source inventory changed after original read")
        expected = []
        for item in rows:
            if not isinstance(item, (IntegrationRow, VariableRow)):
                raise OwnerAuthorityUnavailable("Catalog metadata read returned foreign table")
            is_team = item.owner_team_id is not None
            owner_id = item.owner_team_id if is_team else item.owner_project_id
            if owner_id is None:
                raise OwnerAuthorityUnavailable("Catalog row violates owner XOR")
            expected.append(
                {
                    "resource_id": str(item.id),
                    "kind": collection,
                    "owner_scope": "team" if is_team else "project",
                    "owner_id": str(owner_id),
                    "name_key": item.alias_key
                    if isinstance(item, IntegrationRow)
                    else item.name_key,
                    "version": item.version,
                }
            )
        if records != expected:
            raise OwnerAuthorityUnavailable("Catalog metadata inventory/version changed")
        return VerifiedOwnerTargetObservation(
            command.operation_uuid,
            command.target_sha256,
            max(
                (item.version for item in rows if isinstance(item, (IntegrationRow, VariableRow))),
                default=1,
            ),
            "recorded",
            False,
        )
