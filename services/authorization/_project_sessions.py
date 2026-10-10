"""Project-owned AgentSession application operations (internal, not Gateway).

No legacy OAuth/session UID adapter, no remote authorization transport. Read
paths query authoritative DB until approved fenced Valkey cache is implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authorization._platform_application import PlatformApplication
from authorization._session_persistence import ProjectAgentSessionRow, SessionApprovalRow
from common.platform_errors import AccessDenied, Conflict, InvalidInput
from common.platform_ids import AgentSessionUuid, PlatformProjectId

from ._project_access import CallerPrincipal, ProjectPermission

NORMAL_TTL = timedelta(hours=24)
ELEVATED_HARD_TTL = timedelta(minutes=5)
SAFE_BASIC_GRANTS = frozenset({"files.read", "project.metadata.read"})
SUPPORTED_GRANTS = frozenset(
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


@dataclass(frozen=True, slots=True)
class AgentSessionView:
    session_uuid: AgentSessionUuid
    project_id: PlatformProjectId
    grants: tuple[str, ...]
    is_elevated: bool
    hard_expires_at: datetime
    status: str
    version: int
    label: str | None
    elevation_policy: str


def _session_view(row: ProjectAgentSessionRow) -> AgentSessionView:
    raw_grants = row.grants.get("operations", [])
    granted = tuple(str(v) for v in raw_grants) if isinstance(raw_grants, list) else ()
    return AgentSessionView(
        session_uuid=AgentSessionUuid(row.session_uuid),
        project_id=PlatformProjectId(row.project_id),
        grants=granted,
        is_elevated=row.is_elevated,
        hard_expires_at=row.hard_expires_at,
        status=row.status,
        version=row.version,
        label=row.label,
        elevation_policy=row.elevation_policy,
    )


def _check_grants(grants: list[str], *, allow_privileged: bool) -> list[str]:
    value = sorted(set(grants))
    if len(value) > 32 or not set(value).issubset(SUPPORTED_GRANTS):
        raise InvalidInput("unknown or excessive AgentSession grants")
    if not allow_privileged and not set(value).issubset(SAFE_BASIC_GRANTS):
        raise AccessDenied("basic session cannot grant privileged operations")
    return value


class ProjectSessionService:
    def __init__(self, application: PlatformApplication) -> None:
        self.application = application

    async def _row(
        self,
        session: AsyncSession,
        session_uuid: AgentSessionUuid,
        *,
        lock: bool = False,
    ) -> ProjectAgentSessionRow:
        if session_uuid.version != 4:
            raise AccessDenied("SESSION_UUID_INVALID")
        query = select(ProjectAgentSessionRow).where(
            ProjectAgentSessionRow.session_uuid == session_uuid
        )
        if lock:
            query = query.with_for_update().execution_options(populate_existing=True)
        row = await session.scalar(query)
        if row is None:
            raise AccessDenied("SESSION_UUID_INVALID")
        return row

    async def open_normal(
        self,
        session: AsyncSession,
        caller: CallerPrincipal,
        project_id: PlatformProjectId,
        *,
        elevation_policy: str = "requestable",
        label: str | None = None,
    ) -> AgentSessionView:
        await self.application.project_allowed(session, caller, project_id, for_write=True)
        if elevation_policy not in {"fixed", "requestable"}:
            raise InvalidInput("elevation_policy must be fixed or requestable")
        if label is not None:
            label = label.strip()
            if not 1 <= len(label) <= 128 or any(ord(c) < 32 for c in label):
                raise InvalidInput("AgentSession label must be 1-128 readable characters")
        now = datetime.now(UTC)
        row = ProjectAgentSessionRow(
            session_uuid=uuid4(),
            project_id=project_id,
            created_by_principal_id=caller.user_id,
            grants={"operations": sorted(SAFE_BASIC_GRANTS)},
            elevation_policy=elevation_policy,
            label=label,
            status="active",
            is_elevated=False,
            version=1,
            created_at=now,
            hard_expires_at=now + NORMAL_TTL,
        )
        session.add(row)
        await session.flush()
        self.application._audit(
            session,
            actor=caller.user_id,
            project=project_id,
            action="session.opened",
            target=row.session_uuid,
        )
        return _session_view(row)

    async def validate_operation(
        self,
        session: AsyncSession,
        caller: CallerPrincipal,
        project_id: PlatformProjectId,
        session_uuid: AgentSessionUuid,
        operation: str,
    ) -> AgentSessionView:
        # Both caller and target are checked independently on every use.
        await self.application.project_allowed(session, caller, project_id)
        row = await self._row(session, session_uuid)
        if row.project_id != project_id:
            raise AccessDenied("Project access denied")
        if row.status != "active" or row.hard_expires_at <= datetime.now(UTC):
            raise AccessDenied("SESSION_EXPIRED")
        view = _session_view(row)
        if operation not in view.grants:
            raise AccessDenied("AGENT_SESSION_GRANT_REQUIRED")
        return view

    async def request_elevation(
        self,
        session: AsyncSession,
        caller: CallerPrincipal,
        project_id: PlatformProjectId,
        session_uuid: AgentSessionUuid,
        grants: list[str],
        *,
        seconds: int,
    ) -> UUID:
        await self.application.project_allowed(session, caller, project_id, for_write=True)
        row = await self._row(session, session_uuid, lock=True)
        if row.project_id != project_id:
            raise AccessDenied("Project access denied")
        if row.status != "active" or row.hard_expires_at <= datetime.now(UTC):
            raise AccessDenied("SESSION_EXPIRED")
        if row.elevation_policy != "requestable" or row.is_elevated:
            raise AccessDenied("fixed or elevated session cannot request more grants")
        if not (1 <= seconds <= 300):
            raise InvalidInput("elevated hard TTL must be at most 300 seconds")
        approved = _check_grants(grants, allow_privileged=True)
        request = SessionApprovalRow(
            id=uuid4(),
            session_uuid=session_uuid,
            project_id=project_id,
            requested_by_user_id=caller.user_id,
            requested_grants={"operations": approved},
            requested_expires_at=datetime.now(UTC) + timedelta(seconds=seconds),
            status="pending",
        )
        session.add(request)
        await session.flush()
        self.application._audit(
            session,
            actor=caller.user_id,
            project=project_id,
            action="session.elevation_requested",
            target=request.id,
        )
        return request.id

    async def resolve_elevation(
        self,
        session: AsyncSession,
        caller: CallerPrincipal,
        project_id: PlatformProjectId,
        request_id: UUID,
        *,
        approve: bool,
        allowed_grants: list[str] | None = None,
        explicit_expansion_confirmation: bool = False,
        expected_version: int,
    ) -> AgentSessionView | None:
        await self.application.project_allowed(
            session, caller, project_id, ProjectPermission.APPROVE_AGENT_SESSION, for_write=True
        )
        request = await session.scalar(
            select(SessionApprovalRow)
            .where(SessionApprovalRow.id == request_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if request is None or request.project_id != project_id:
            raise AccessDenied("Project access denied")
        if request.status != "pending":
            raise Conflict("elevation request already resolved")
        if request.version != expected_version:
            raise Conflict("AgentSession approval revision mismatch")
        base = await self._row(session, AgentSessionUuid(request.session_uuid), lock=True)
        if base.project_id != project_id:
            raise AccessDenied("elevation request references another Project")
        now = datetime.now(UTC)
        if base.status != "active" or base.hard_expires_at <= now:
            raise Conflict("base AgentSession expired or revoked")
        result: AgentSessionView | None = None
        if approve:
            raw = request.requested_grants.get("operations", [])
            requested = _check_grants(
                [str(item) for item in raw] if isinstance(raw, list) else [],
                allow_privileged=True,
            )
            actual = _check_grants(
                allowed_grants if allowed_grants is not None else requested,
                allow_privileged=True,
            )
            if not set(actual).issubset(requested) and not explicit_expansion_confirmation:
                raise AccessDenied("expanded grants require explicit confirmation")
            expires_at = min(request.requested_expires_at, now + ELEVATED_HARD_TTL)
            if expires_at <= now:
                raise Conflict("elevation request TTL expired")
            elevated = ProjectAgentSessionRow(
                session_uuid=uuid4(),
                project_id=project_id,
                created_by_principal_id=request.requested_by_user_id,
                is_elevated=True,
                elevation_policy="fixed",
                label=base.label,
                grants={"operations": actual},
                status="active",
                version=1,
                created_at=now,
                hard_expires_at=expires_at,
            )
            session.add(elevated)
            await session.flush()
            request.issued_session_uuid = elevated.session_uuid
            result = _session_view(elevated)
        request.status = "approved" if approve else "rejected"
        request.version += 1
        request.resolved_by_user_id = caller.user_id
        request.resolved_at = now
        self.application._audit(
            session,
            actor=caller.user_id,
            project=project_id,
            action="session.elevation_resolved",
            target=request.id,
            event={"approved": approve},
        )
        return result

    async def revoke(
        self,
        session: AsyncSession,
        caller: CallerPrincipal,
        project_id: PlatformProjectId,
        session_uuid: AgentSessionUuid,
    ) -> AgentSessionView:
        await self.application.project_allowed(
            session, caller, project_id, ProjectPermission.APPROVE_AGENT_SESSION, for_write=True
        )
        row = await self._row(session, session_uuid, lock=True)
        if row.project_id != project_id:
            raise AccessDenied("Project access denied")
        if row.status == "active":
            row.status = "revoked"
            row.revoked_at = datetime.now(UTC)
            row.version += 1
            self.application._audit(
                session,
                actor=caller.user_id,
                project=project_id,
                action="session.revoked",
                target=session_uuid,
            )
        return _session_view(row)
