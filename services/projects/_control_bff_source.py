"""Private typed Control-domain Admin BFF source, NOT an authenticated HTTP app.

Control SQL verifies current personal/Team ownership and membership, while
fresh independently signed Identity/Access/Control source ports are mandatory
both BEFORE and AFTER every bounded page/original-command inspect.
No cross-owner SQL, public bearer from browser headers or optimistic ACK.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

from sqlalchemy import or_, select

from common.owner_bff_models import (
    OwnerCommandState,
    OwnerPage,
    OwnerProjectView,
    OwnerTeamCommandState,
    OwnerTeamView,
    VerifiedAdminCaller,
)
from common.owner_contracts import OwnerAuthorityUnavailable
from common.platform_db import PlatformDatabase
from projects._control_ledger import OwnerCommandRow
from projects._persistence import ProjectRow
from teams._persistence import TeamMembershipRow, TeamRow


@dataclass(frozen=True, slots=True)
class CurrentControlBffGrant:
    """Already independently signed from current 3-owner origin, not HTTP."""

    actor_user_id: UUID
    credential_version: int
    access_session_version: int
    identity_epoch: UUID
    access_epoch: UUID
    control_epoch: UUID
    expires_at: datetime
    can_read_projects: bool
    can_read_teams: bool


class TrustedControlBffGrantPort(Protocol):
    async def current(self, *, caller: VerifiedAdminCaller) -> CurrentControlBffGrant:
        """C2 verifies trusted caller/peer and three current signed owners."""
        ...


class ControlOwnerBffSource:
    def __init__(self, db: PlatformDatabase, grants: TrustedControlBffGrantPort) -> None:
        if db.engine.url.database != "briareus_platform" or grants is None:
            raise RuntimeError("Control BFF requires own database and current C2 owners")
        self.db = db
        self.grants = grants

    async def _grant(self, caller: VerifiedAdminCaller) -> CurrentControlBffGrant:
        try:
            async with asyncio.timeout(3):
                proof = await self.grants.current(caller=caller)
        except Exception:
            raise OwnerAuthorityUnavailable("BFF User/Control/Access proof unavailable") from None
        now = datetime.now(UTC)
        if (
            not isinstance(proof, CurrentControlBffGrant)
            or proof.actor_user_id != caller.user_id
            or proof.credential_version != caller.credential_version
            or proof.access_session_version < 1
            or any(
                item.version != 4
                for item in (
                    proof.identity_epoch,
                    proof.access_epoch,
                    proof.control_epoch,
                )
            )
            or proof.expires_at.tzinfo is None
            or proof.expires_at <= now
            or proof.expires_at > now + timedelta(seconds=15)
        ):
            raise OwnerAuthorityUnavailable("BFF signed scope version is stale/inconsistent")
        return proof

    async def _unchanged(
        self,
        caller: VerifiedAdminCaller,
        earlier: CurrentControlBffGrant,
    ) -> None:
        newer = await self._grant(caller)
        if (
            newer.identity_epoch != earlier.identity_epoch
            or newer.access_epoch != earlier.access_epoch
            or newer.control_epoch != earlier.control_epoch
            or newer.access_session_version != earlier.access_session_version
            or newer.can_read_projects != earlier.can_read_projects
            or newer.can_read_teams != earlier.can_read_teams
        ):
            raise OwnerAuthorityUnavailable("owner scope changed during BFF inspection")

    async def visible_projects(
        self,
        caller: VerifiedAdminCaller,
        *,
        after_id: UUID | None,
        limit: int,
    ) -> OwnerPage[OwnerProjectView]:
        if not 1 <= limit <= 100 or (after_id is not None and after_id.version != 4):
            raise ValueError("BFF bounded Project cursor invalid")
        first = await self._grant(caller)
        if not first.can_read_projects:
            raise OwnerAuthorityUnavailable("authenticated Project listing denied")
        async with self.db.transaction() as tx:
            member_teams = select(TeamMembershipRow.team_id).where(
                TeamMembershipRow.user_id == caller.user_id,
                TeamMembershipRow.active.is_(True),
            )
            query = select(ProjectRow).where(
                or_(
                    ProjectRow.owner_user_id == caller.user_id,
                    ProjectRow.owner_team_id.in_(member_teams),
                ),
                ProjectRow.lifecycle_status == "active",
            )
            if after_id is not None:
                query = query.where(ProjectRow.id > after_id)
            rows = list(await tx.scalars(query.order_by(ProjectRow.id).limit(limit + 1)))
            data: list[OwnerProjectView] = []
            for row in rows[:limit]:
                if (row.owner_user_id is None) == (row.owner_team_id is None):
                    raise OwnerAuthorityUnavailable("Control Project owner XOR invalid")
                data.append(
                    OwnerProjectView(
                        project_id=row.id,
                        name=row.name,
                        owner_user_id=row.owner_user_id,
                        owner_team_id=row.owner_team_id,
                        version=row.version,
                        lifecycle_status="active",
                        resource_revision=row.resource_revision,
                        current_identity_revision=first.credential_version,
                        current_access_revision=first.access_session_version,
                        # The UI must request independently approved per-action
                        # grants; BFF merely scopes these visible source rows.
                        effective_permissions=(),
                    )
                )
            has_more = len(rows) > limit
            next_id = rows[limit - 1].id if has_more else None
        await self._unchanged(caller, first)
        return OwnerPage(items=tuple(data), next_after_id=next_id, has_more=has_more)

    async def visible_teams(
        self,
        caller: VerifiedAdminCaller,
        *,
        after_id: UUID | None,
        limit: int,
    ) -> OwnerPage[OwnerTeamView]:
        if not 1 <= limit <= 100 or (after_id is not None and after_id.version != 4):
            raise ValueError("BFF bounded Team cursor invalid")
        first = await self._grant(caller)
        if not first.can_read_teams:
            raise OwnerAuthorityUnavailable("authenticated Team listing denied")
        async with self.db.transaction() as tx:
            active = select(TeamMembershipRow.team_id).where(
                TeamMembershipRow.user_id == caller.user_id,
                TeamMembershipRow.active.is_(True),
            )
            query = select(TeamRow).where(
                or_(
                    TeamRow.id.in_(active),
                    TeamRow.owner_user_id == caller.user_id,
                )
            )
            if after_id is not None:
                query = query.where(TeamRow.id > after_id)
            rows = list(await tx.scalars(query.order_by(TeamRow.id).limit(limit + 1)))
            result = tuple(
                OwnerTeamView(
                    team_id=row.id,
                    name=row.name,
                    owner_user_id=row.owner_user_id,
                    version=row.version,
                    current_membership_revision=row.version,
                )
                for row in rows[:limit]
            )
            more = len(rows) > limit
            next_id = rows[limit - 1].id if more else None
        await self._unchanged(caller, first)
        return OwnerPage(items=result, next_after_id=next_id, has_more=more)

    async def command_status(
        self,
        caller: VerifiedAdminCaller,
        *,
        owner: str,
        project_id: UUID,
        operation: str,
        key: str,
        operation_uuid: UUID,
    ) -> OwnerCommandState:
        if (
            owner != "platform"
            or project_id.version != 4
            or operation_uuid.version != 4
            or not 1 <= len(operation) <= 128
            or not 1 <= len(key) <= 128
            or not key.isascii()
            or not key.isprintable()
        ):
            raise OwnerAuthorityUnavailable("Control owner-command status selector invalid")
        first = await self._grant(caller)
        if not first.can_read_projects:
            raise OwnerAuthorityUnavailable("original Project scope denied")
        async with self.db.transaction() as tx:
            membership = select(TeamMembershipRow.team_id).where(
                TeamMembershipRow.user_id == caller.user_id,
                TeamMembershipRow.active.is_(True),
            )
            project = await tx.scalar(
                select(ProjectRow)
                .where(
                    ProjectRow.id == project_id,
                    or_(
                        ProjectRow.owner_user_id == caller.user_id,
                        ProjectRow.owner_team_id.in_(membership),
                    ),
                )
                .with_for_update()
            )
            if project is None or project.lifecycle_status != "active":
                raise OwnerAuthorityUnavailable("original Project ownership revoked")
            row = await tx.scalar(
                select(OwnerCommandRow)
                .where(
                    OwnerCommandRow.actor_scope == str(caller.user_id),
                    OwnerCommandRow.project_scope == str(project_id),
                    OwnerCommandRow.operation == operation,
                    OwnerCommandRow.key == key,
                    OwnerCommandRow.operation_uuid == operation_uuid,
                )
                .with_for_update()
            )
            if row is None:
                state: Literal["NOT_FOUND", "UNKNOWN", "COMMITTED", "DENIED"] = "NOT_FOUND"
            elif row.state in {"pending", "unknown"}:
                state = "UNKNOWN"
            elif row.state == "denied":
                state = "DENIED"
            elif row.state in {"completed", "reconciled"} and row.encrypted_outcome is not None:
                state = "COMMITTED"
            else:
                raise OwnerAuthorityUnavailable(
                    "original owner command state cannot be authenticated"
                )
        await self._unchanged(caller, first)
        return OwnerCommandState(
            owner="platform",
            operation_uuid=operation_uuid,
            project_id=project_id,
            operation=operation,
            state=state,
            reconciliation_required=True,
            operation_replay_safe=False,
        )

    async def team_command_status(
        self,
        caller: VerifiedAdminCaller,
        *,
        team_id: UUID,
        operation: Literal["team.member.add", "team.member.remove", "team.owner.transfer"],
        key: str,
        operation_uuid: UUID,
    ) -> OwnerTeamCommandState:
        if (
            team_id.version != 4
            or operation_uuid.version != 4
            or not 1 <= len(key) <= 128
            or not key.isascii()
            or not key.isprintable()
        ):
            raise OwnerAuthorityUnavailable("invalid original Team command selector")
        first = await self._grant(caller)
        if not first.can_read_teams:
            raise OwnerAuthorityUnavailable("current Team visibility denied")
        async with self.db.transaction() as tx:
            member = await tx.scalar(
                select(TeamMembershipRow.id).where(
                    TeamMembershipRow.team_id == team_id,
                    TeamMembershipRow.user_id == caller.user_id,
                    TeamMembershipRow.active.is_(True),
                )
            )
            team = await tx.scalar(select(TeamRow).where(TeamRow.id == team_id).with_for_update())
            if team is None or (team.owner_user_id != caller.user_id and member is None):
                raise OwnerAuthorityUnavailable("Team no longer authorized for caller")
            row = await tx.scalar(
                select(OwnerCommandRow)
                .where(
                    OwnerCommandRow.actor_scope == str(caller.user_id),
                    OwnerCommandRow.project_scope == f"team:{team_id}",
                    OwnerCommandRow.operation == operation,
                    OwnerCommandRow.key == key,
                    OwnerCommandRow.operation_uuid == operation_uuid,
                )
                .with_for_update()
            )
            if row is None:
                state: Literal["NOT_FOUND", "UNKNOWN", "COMMITTED", "DENIED"] = "NOT_FOUND"
            elif row.state in {"pending", "unknown"}:
                state = "UNKNOWN"
            elif row.state == "denied":
                state = "DENIED"
            elif row.state in {"completed", "reconciled"} and row.encrypted_outcome is not None:
                state = "COMMITTED"
            else:
                raise OwnerAuthorityUnavailable("original Team owner result unavailable")
        await self._unchanged(caller, first)
        return OwnerTeamCommandState(
            team_id=team_id,
            operation_uuid=operation_uuid,
            operation=operation,
            state=state,
            reconciliation_required=True,
            operation_replay_safe=False,
        )
