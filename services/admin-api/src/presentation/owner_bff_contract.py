# ruff: noqa: B008  # FastAPI typed boundary descriptors use Header/Query defaults
"""Source-only four-owner Admin BFF: never a SQLAlchemy global UnitOfWork.

All routes are UNMOUNTED until C1-B2/C2 independently accept caller/peer
verification. Frontend never receives DB DSNs, owner JWTs, session secrets,
provider credential ciphertext or Team collector bearer.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Literal, Protocol
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request

from common.owner_bff_models import (
    OwnerCommandState,
    OwnerPage,
    OwnerProjectView,
    OwnerRealtimeProjection,
    OwnerTeamCommandState,
    OwnerTeamView,
    VerifiedAdminCaller,
)
from common.platform_db import OwnerName


class AdminOwnerPrincipalResolver(Protocol):
    async def resolve(self, request: Request) -> VerifiedAdminCaller | None:
        """Fail closed when signed Identity credential/current revoke is unknown."""
        ...


class AuthenticatedOwnerBffPort(Protocol):
    """Separate typed authenticated owner HTTP/Unix clients, NEVER raw DB."""

    async def visible_projects(
        self, caller: VerifiedAdminCaller, *, after_id: UUID | None, limit: int
    ) -> OwnerPage[OwnerProjectView]: ...

    async def visible_teams(
        self, caller: VerifiedAdminCaller, *, after_id: UUID | None, limit: int
    ) -> OwnerPage[OwnerTeamView]: ...

    async def command_status(
        self,
        caller: VerifiedAdminCaller,
        *,
        owner: OwnerName,
        project_id: UUID,
        operation: str,
        key: str,
        operation_uuid: UUID,
    ) -> OwnerCommandState:
        """Fetch the original owner-local status under current reauthorization."""
        ...

    async def team_command_status(
        self,
        caller: VerifiedAdminCaller,
        *,
        team_id: UUID,
        operation: Literal["team.member.add", "team.member.remove", "team.owner.transfer"],
        key: str,
        operation_uuid: UUID,
    ) -> OwnerTeamCommandState:
        """Current Identity/Control/Access proof for Team-scoped owner ledger."""
        ...

    def scoped_events(
        self, caller: VerifiedAdminCaller, *, scope_kind: str, scope_id: UUID
    ) -> AsyncIterator[OwnerRealtimeProjection]:
        """Read projection only. No event carries or refreshes authority."""
        ...


def build_unmounted_owner_bff(
    caller_source: AdminOwnerPrincipalResolver | None,
    owner_ports: AuthenticatedOwnerBffPort | None,
) -> APIRouter:
    """Build only a private draft; the default Admin app does not mount this."""
    if caller_source is None or owner_ports is None:
        raise RuntimeError("C2 caller resolver and authenticated owner ports are required")
    router = APIRouter(prefix="/v1/platform", tags=["four-owner-bff-private-draft"])

    async def _caller(request: Request) -> VerifiedAdminCaller:
        # Explicit bearer only; neither browser cookie nor user IDs in proxy
        # headers can ever become a verified identity.
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer ") or len(header) > 8192:
            raise HTTPException(401, detail="verified Admin bearer required")
        try:
            resolved = await caller_source.resolve(request)
        except Exception:
            resolved = None
        if resolved is None or resolved.source != "verified-admin-bearer":
            raise HTTPException(401, detail="current Admin identity not verified")
        return resolved

    @router.get("/projects", response_model=OwnerPage[OwnerProjectView])
    async def visible_projects(
        request: Request,
        after_id: UUID | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=100),
    ) -> OwnerPage[OwnerProjectView]:
        if after_id is not None and after_id.version != 4:
            raise HTTPException(422, detail="invalid UUID cursor")
        caller = await _caller(request)
        try:
            return await owner_ports.visible_projects(caller, after_id=after_id, limit=limit)
        except Exception:
            raise HTTPException(503, detail="current owner project scope unavailable") from None

    @router.get("/teams", response_model=OwnerPage[OwnerTeamView])
    async def visible_teams(
        request: Request,
        after_id: UUID | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=100),
    ) -> OwnerPage[OwnerTeamView]:
        if after_id is not None and after_id.version != 4:
            raise HTTPException(422, detail="invalid UUID cursor")
        caller = await _caller(request)
        try:
            return await owner_ports.visible_teams(caller, after_id=after_id, limit=limit)
        except Exception:
            raise HTTPException(503, detail="current owner Team scope unavailable") from None

    @router.get(
        "/projects/{project_id}/commands/{operation}/status",
        response_model=OwnerCommandState,
    )
    async def owner_command_status(
        request: Request,
        project_id: UUID,
        operation: str,
        owner: OwnerName,
        operation_uuid: UUID = Header(alias="Operation-UUID"),
        key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> OwnerCommandState:
        if (
            project_id.version != 4
            or operation_uuid.version != 4
            or key != str(operation_uuid)
            or not key.isascii()
            or not key.isprintable()
            or not 1 <= len(operation) <= 128
        ):
            raise HTTPException(422, detail="invalid original operation selector")
        caller = await _caller(request)
        try:
            state = await owner_ports.command_status(
                caller,
                owner=owner,
                project_id=project_id,
                operation=operation,
                key=key,
                operation_uuid=operation_uuid,
            )
        except Exception:
            raise HTTPException(503, detail="owner command status unavailable") from None
        if (
            state.owner != owner
            or state.operation_uuid != operation_uuid
            or state.project_id != project_id
            or state.operation != operation
        ):
            raise HTTPException(503, detail="inconsistent owner operation provenance")
        # No response-body replay or foreign-owner SQL access at BFF edge.
        return state

    @router.get(
        "/teams/{team_id}/commands/{operation}/status",
        response_model=OwnerTeamCommandState,
    )
    async def team_command_status(
        request: Request,
        team_id: UUID,
        operation: Literal["team.member.add", "team.member.remove", "team.owner.transfer"],
        operation_uuid: UUID = Header(alias="Operation-UUID"),
        key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> OwnerTeamCommandState:
        if (
            team_id.version != 4
            or operation_uuid.version != 4
            or key != str(operation_uuid)
            or not key.isascii()
            or not key.isprintable()
        ):
            raise HTTPException(422, detail="invalid original Team operation selector")
        caller = await _caller(request)
        try:
            state = await owner_ports.team_command_status(
                caller,
                team_id=team_id,
                operation=operation,
                key=key,
                operation_uuid=operation_uuid,
            )
        except Exception:
            raise HTTPException(503, detail="Team command status unavailable") from None
        if (
            state.team_id != team_id
            or state.operation_uuid != operation_uuid
            or state.operation != operation
        ):
            raise HTTPException(503, detail="inconsistent Team operation provenance")
        return state

    return router
