"""Access-only Project AgentSession operations with signed current owner grants.

No shared SQL session with Identity/Team/Project and no unauthenticated UUID
as authority. Private source only until peer attestation C1-B2/C2 reviewed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authorization._idempotency import CommandOutcome, IdempotentCommandExecutor
from authorization._platform_persistence import OutboxRow, SecurityAuditRow
from authorization._session_persistence import ProjectAgentSessionRow, SessionApprovalRow
from common.owner_contracts import (
    CurrentOwnerAuthorityPort,
    OwnerCommandDTO,
    OwnerProofAuthority,
    SignedOwnerProofs,
    require_online_owner_decision,
    require_signed_payload,
)
from common.platform_db import PlatformDatabase
from common.platform_errors import AccessDenied, Conflict, InvalidInput

_NORMAL = timedelta(hours=24)
_ELEVATED = timedelta(minutes=5)
_ALLOWED = frozenset(
    {
        "files.read",
        "files.write",
        "project.metadata.read",
        "terminal.execute",
        "web.access",
        "analysis.import",
        "agents.manage",
        "integrations.use",
        "variables.use",
        "integrations.manage",
        "variables.manage",
    }
)
_BASIC = frozenset({"files.read", "project.metadata.read"})


class AccessSourceService:
    def __init__(
        self,
        db: PlatformDatabase,
        authority: OwnerProofAuthority,
        *,
        encryption_key: SecretStr,
        current_owners: CurrentOwnerAuthorityPort,
    ) -> None:
        if db.engine.url.database != "briareus_access":
            raise RuntimeError("Access cannot use another owner database")
        if current_owners is None:
            raise RuntimeError("online owner authority cannot be omitted")
        self.current_owners = current_owners
        self.db = db
        self.authority = authority
        self.commands = IdempotentCommandExecutor(db, encryption_key.get_secret_value())

    async def _verify(
        self,
        tx: AsyncSession,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        *,
        existing: bool = False,
    ) -> None:
        initial = self.authority.require_current(request, proofs)
        decision = await require_online_owner_decision(self.authority, self.current_owners, request)
        if (
            initial.identity_epoch != decision.identity_epoch
            or initial.control_epoch != decision.control_epoch
            or initial.access_epoch != decision.access_epoch
        ):
            raise AccessDenied("owner source epochs changed since original signature")
        if request.target_owner != "access" or decision.request != request:
            raise AccessDenied("signed Access command owner mismatch")
        if existing:
            row = await tx.scalar(
                select(ProjectAgentSessionRow)
                .where(
                    ProjectAgentSessionRow.session_uuid == request.session_uuid,
                    ProjectAgentSessionRow.project_id == request.project_id,
                )
                .with_for_update()
            )
            if (
                row is None
                or row.version != request.expected_access_revision
                or row.status != "active"
                or row.hard_expires_at <= datetime.now(UTC)
            ):
                raise AccessDenied("AgentSession no longer current")

    @staticmethod
    def _audit(tx: AsyncSession, request: OwnerCommandDTO, action: str, target: UUID) -> None:
        tx.add(
            SecurityAuditRow(
                actor_id=request.caller_user_id,
                project_id=request.project_id,
                action=action,
                object_id=str(target),
                details={"operation_uuid": str(request.operation_uuid)},
            )
        )
        tx.add(
            OutboxRow(
                event_name=action,
                event_payload={
                    "operation_uuid": str(request.operation_uuid),
                    "project_id": str(request.project_id),
                    "entity_id": str(target),
                },
            )
        )

    async def open_normal(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        *,
        elevation_policy: str = "requestable",
        label: str | None = None,
    ) -> CommandOutcome:
        if request.operation != "session.open" or elevation_policy not in {"fixed", "requestable"}:
            raise InvalidInput("unapproved normal AgentSession policy")
        require_signed_payload(request, {"elevation_policy": elevation_policy, "label": label})
        if label is not None and (not (1 <= len(label) <= 128) or any(ord(c) < 32 for c in label)):
            raise InvalidInput("AgentSession label is invalid")

        async def checked(tx: AsyncSession) -> None:
            await self._verify(tx, request, proofs)

        async def command(tx: AsyncSession) -> CommandOutcome:
            if await tx.get(ProjectAgentSessionRow, request.session_uuid) is not None:
                raise Conflict("AgentSession UUID already assigned")
            now = datetime.now(UTC)
            row = ProjectAgentSessionRow(
                session_uuid=request.session_uuid,
                project_id=request.project_id,
                created_by_principal_id=request.caller_user_id,
                grants={"operations": sorted(_BASIC)},
                is_elevated=False,
                elevation_policy=elevation_policy,
                label=label,
                status="active",
                version=1,
                created_at=now,
                hard_expires_at=now + _NORMAL,
            )
            tx.add(row)
            self._audit(tx, request, "session.opened", row.session_uuid)
            return CommandOutcome(
                201,
                {
                    "session_uuid": str(row.session_uuid),
                    "project_id": str(row.project_id),
                    "expires_at": row.hard_expires_at.isoformat(),
                    "revision": row.version,
                },
            )

        return await self.commands.execute(
            actor_scope=str(request.caller_user_id),
            project_scope=str(request.project_id),
            operation=request.operation,
            key=request.idempotency_key,
            payload={
                "uuid": str(request.session_uuid),
                "payload_sha256": request.payload_sha256,
                "policy": elevation_policy,
                "label": label,
            },
            command=command,
            reauthorize=checked,
        )

    async def revoke(self, request: OwnerCommandDTO, proofs: SignedOwnerProofs) -> CommandOutcome:
        if request.operation != "session.revoke":
            raise InvalidInput("unexpected Access operation")
        require_signed_payload(request, {})

        async def checked(tx: AsyncSession) -> None:
            await self._verify(tx, request, proofs, existing=True)

        async def command(tx: AsyncSession) -> CommandOutcome:
            row = await tx.scalar(
                select(ProjectAgentSessionRow)
                .where(ProjectAgentSessionRow.session_uuid == request.session_uuid)
                .with_for_update()
            )
            if row is None or row.project_id != request.project_id:
                raise AccessDenied("AgentSession not found in verified Project")
            row.status = "revoked"
            row.revoked_at = datetime.now(UTC)
            row.version += 1
            self._audit(tx, request, "session.revoked", row.session_uuid)
            return CommandOutcome(
                200,
                {
                    "session_uuid": str(row.session_uuid),
                    "version": row.version,
                    "status": row.status,
                },
            )

        return await self.commands.execute(
            actor_scope=str(request.caller_user_id),
            project_scope=str(request.project_id),
            operation=request.operation,
            key=request.idempotency_key,
            payload={"uuid": str(request.session_uuid), "payload_sha256": request.payload_sha256},
            command=command,
            reauthorize=checked,
        )

    async def request_elevation(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        *,
        grants: list[str],
        seconds: int,
    ) -> CommandOutcome:
        if (
            request.operation != "session.request_elevation"
            or not 1 <= seconds <= 300
            or not grants
            or not set(grants) <= _ALLOWED
        ):
            raise InvalidInput("invalid elevated operation or TTL/grant scope")
        require_signed_payload(request, {"grants": sorted(set(grants)), "seconds": seconds})

        async def checked(tx: AsyncSession) -> None:
            await self._verify(tx, request, proofs, existing=True)

        async def command(tx: AsyncSession) -> CommandOutcome:
            base = await tx.get(ProjectAgentSessionRow, request.session_uuid, with_for_update=True)
            if base is None or base.elevation_policy != "requestable" or base.is_elevated:
                raise AccessDenied("base session cannot request elevation")
            approval = SessionApprovalRow(
                id=request.operation_uuid,
                session_uuid=base.session_uuid,
                project_id=base.project_id,
                requested_by_user_id=request.caller_user_id,
                requested_grants={"operations": sorted(set(grants))},
                requested_expires_at=datetime.now(UTC) + timedelta(seconds=seconds),
                status="pending",
                version=1,
            )
            tx.add(approval)
            self._audit(tx, request, "session.elevation_requested", approval.id)
            return CommandOutcome(
                202, {"request_id": str(approval.id), "version": 1, "status": "pending"}
            )

        return await self.commands.execute(
            actor_scope=str(request.caller_user_id),
            project_scope=str(request.project_id),
            operation=request.operation,
            key=request.idempotency_key,
            payload={
                "uuid": str(request.session_uuid),
                "grants": sorted(set(grants)),
                "seconds": seconds,
                "payload_sha256": request.payload_sha256,
            },
            command=command,
            reauthorize=checked,
        )

    async def resolve_elevation(
        self,
        request: OwnerCommandDTO,
        proofs: SignedOwnerProofs,
        *,
        approval_id: UUID,
        approve: bool,
        allowed_grants: list[str] | None,
        explicit_expansion_confirmation: bool,
        expected_approval_version: int,
    ) -> CommandOutcome:
        if (
            request.operation != "session.resolve_elevation"
            or approval_id.version != 4
            or expected_approval_version < 1
            or (allowed_grants is not None and not set(allowed_grants) <= _ALLOWED)
        ):
            raise InvalidInput("invalid approval command or grant")
        require_signed_payload(
            request,
            {
                "approval_id": str(approval_id),
                "approve": approve,
                "allowed_grants": sorted(set(allowed_grants))
                if allowed_grants is not None
                else None,
                "explicit_expansion_confirmation": explicit_expansion_confirmation,
                "expected_approval_version": expected_approval_version,
            },
        )

        async def checked(tx: AsyncSession) -> None:
            await self._verify(tx, request, proofs, existing=True)

        async def command(tx: AsyncSession) -> CommandOutcome:
            approval = await tx.get(SessionApprovalRow, approval_id, with_for_update=True)
            if (
                approval is None
                or approval.project_id != request.project_id
                or approval.session_uuid != request.session_uuid
            ):
                raise AccessDenied("approval has no signed Project/session ownership")
            if approval.version != expected_approval_version or approval.status != "pending":
                raise Conflict("approval already resolved or revision changed")
            base = await tx.get(ProjectAgentSessionRow, request.session_uuid, with_for_update=True)
            now = datetime.now(UTC)
            if (
                base is None
                or base.project_id != request.project_id
                or base.status != "active"
                or base.hard_expires_at <= now
                or base.elevation_policy != "requestable"
                or base.is_elevated
            ):
                raise AccessDenied("base AgentSession not active or requestable")
            issued: UUID | None = None
            if approve:
                if approval.requested_expires_at <= now:
                    raise Conflict("request elevation lifetime expired")
                initial = approval.requested_grants.get("operations", [])
                if not isinstance(initial, list) or not set(initial) <= _ALLOWED:
                    raise AccessDenied("invalid stored approval grants")
                final = sorted(set(allowed_grants if allowed_grants is not None else initial))
                if not final or not set(final) <= _ALLOWED:
                    raise AccessDenied("unapproved elevated grant")
                if not set(final) <= set(initial) and not explicit_expansion_confirmation:
                    raise AccessDenied("expanded grants require explicit approval")
                from uuid import uuid4

                issued = uuid4()
                elevated = ProjectAgentSessionRow(
                    session_uuid=issued,
                    project_id=base.project_id,
                    created_by_principal_id=approval.requested_by_user_id,
                    is_elevated=True,
                    elevation_policy="fixed",
                    label=base.label,
                    grants={"operations": final},
                    status="active",
                    version=1,
                    created_at=now,
                    hard_expires_at=min(approval.requested_expires_at, now + _ELEVATED),
                )
                if elevated.hard_expires_at <= now:
                    raise Conflict("elevated hard TTL exhausted")
                tx.add(elevated)
                approval.issued_session_uuid = issued
            approval.status = "approved" if approve else "rejected"
            approval.version += 1
            approval.resolved_by_user_id = request.caller_user_id
            approval.resolved_at = now
            self._audit(tx, request, "session.elevation_resolved", approval.id)
            return CommandOutcome(
                200,
                {
                    "approval_id": str(approval.id),
                    "status": approval.status,
                    "version": approval.version,
                    "issued_session_uuid": str(issued) if issued else None,
                },
            )

        return await self.commands.execute(
            actor_scope=str(request.caller_user_id),
            project_scope=str(request.project_id),
            operation=request.operation,
            key=request.idempotency_key,
            payload={
                "uuid": str(request.session_uuid),
                "approval_id": str(approval_id),
                "approve": approve,
                "allowed_grants": allowed_grants,
                "expected_approval_version": expected_approval_version,
                "confirmed": explicit_expansion_confirmation,
            },
            command=command,
            reauthorize=checked,
        )

    async def verify_current_grant(
        self, request: OwnerCommandDTO, proofs: SignedOwnerProofs
    ) -> bool:
        """Read authoritative Access grant; no token/UUID alone is sufficient."""
        initial = self.authority.require_current(request, proofs)
        fresh = await require_online_owner_decision(self.authority, self.current_owners, request)
        if (
            initial.identity_epoch != fresh.identity_epoch
            or initial.control_epoch != fresh.control_epoch
            or initial.access_epoch != fresh.access_epoch
        ):
            raise AccessDenied("owner authorities no longer current")
        if request.target_owner != "access" or request.operation not in _ALLOWED:
            raise AccessDenied("sensitive operation must be an approved grant")
        async with self.db.transaction() as tx:
            row = await tx.get(ProjectAgentSessionRow, request.session_uuid)
            if (
                row is None
                or row.project_id != request.project_id
                or row.status != "active"
                or row.hard_expires_at <= datetime.now(UTC)
                or row.version != request.expected_access_revision
            ):
                raise AccessDenied("AgentSession grant expired or changed")
            operations = row.grants.get("operations", [])
            if not isinstance(operations, list) or request.operation not in operations:
                raise AccessDenied("AgentSession operation grant missing")
            return True
