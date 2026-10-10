"""Catalog-owned resource metadata and secret-safe selectors.

Separate Identity/Control/Access signed authority is mandatory. Resource
Catalog owns its own metadata/version and one-use secret custody. No global
Authorization SQL, provider key value or network/REST route exists here.
"""

from __future__ import annotations

import asyncio
import math
from typing import Literal, Protocol, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .authorization import (
    ProjectAccessDenied,
    ProjectInvocation,
    ProjectPermit,
    ProjectRuntimeAuthority,
    valid_project_revision,
)
from .integrations import IntegrationProvider, ProjectIntegrationError, ProjectIntegrationRef
from .resource_scope import EffectiveResourceScope
from .variables import ProjectVariableRef

ResourceKind = Literal["integration", "variable"]
OwnerKind = Literal["team", "project"]


class CatalogMetadataModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CatalogResourceView(CatalogMetadataModel):
    """A4 source resource projection. `value` is discarded, NEVER exposed."""

    resource_id: UUID
    kind: ResourceKind
    name: str = Field(min_length=1, max_length=128)
    version: int = Field(ge=1)
    project_access_revision: str | None = None
    team_access_revision: str | None = None
    owner_scope: OwnerKind
    owner_id: UUID
    origin: OwnerKind
    inherited: bool
    is_secret: bool
    masked: bool
    provider: str | None = None
    auth_type: str | None = None
    display_name: str = ""
    value: str | None = None

    @model_validator(mode="after")
    def forbid_any_secret_or_configuration_value(self) -> CatalogResourceView:
        if self.value is not None:
            raise ValueError("resource values do not belong in metadata")
        return self


class CatalogResourcePort(Protocol):
    """Project-permitted Backend A4 resource list/ID resolution.

    Implementations must reauthorize caller/service and Project/Team ownership
    in Backend DB in the same read transaction; a Runtime-issued ProjectPermit
    is an expected-state *fence*, not wire authentication.
    """

    async def list_project(
        self,
        invocation: ProjectInvocation,
        *,
        kind: ResourceKind,
        scope: Literal["all"],
        expected_access_revision: str,
    ) -> tuple[CatalogResourceView, ...]: ...

    async def resolve_project(
        self,
        invocation: ProjectInvocation,
        *,
        kind: ResourceKind,
        resource_id: UUID,
        expected_access_revision: str,
    ) -> CatalogResourceView: ...


class CatalogResourceAdapter:
    """Integration/variable selectors from one validated A4 resource source.

    Team + Project alias collisions survive on purpose. Raw secret values and
    password/token material never enter ProjectIntegrationRef/VariableRef.
    """

    def __init__(
        self,
        authority: ProjectRuntimeAuthority,
        source: CatalogResourcePort | None = None,
        *,
        timeout_seconds: float = 10.0,
        max_resources: int = 1000,
    ) -> None:
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
            raise ValueError("A4 resource timeout invalid")
        if not 1 <= max_resources <= 10000:
            raise ValueError("A4 resource collection limit invalid")
        self.authority = authority
        self._source = source
        self._timeout = timeout_seconds
        self._max_resources = max_resources

    @staticmethod
    def _scope(view: CatalogResourceView, permit: ProjectPermit) -> EffectiveResourceScope:
        if (
            not isinstance(view, CatalogResourceView)
            or not valid_project_revision(permit.project_access_revision)
            or permit.project_owner_scope not in {"team", "project"}
            or not isinstance(permit.project_owner_id, UUID)
            or view.project_access_revision != permit.project_access_revision
            or view.owner_scope != view.origin
            or view.inherited != (view.owner_scope == "team")
            or (view.is_secret and (not view.masked or view.value is not None))
        ):
            raise ProjectAccessDenied("A4_RESOURCE_SCOPE_INVALID")
        revision = permit.project_access_revision
        if not isinstance(revision, str):
            raise ProjectAccessDenied("A4_RESOURCE_REVISION_INVALID")
        team_id = permit.project_owner_id if permit.project_owner_scope == "team" else None
        scope = EffectiveResourceScope(
            effective_project_id=permit.project_id,
            owner_project_id=view.owner_id if view.owner_scope == "project" else None,
            owner_team_id=view.owner_id if view.owner_scope == "team" else None,
            project_owner_team_id=team_id,
            resource_revision=view.version,
            project_access_revision=revision,
        )
        scope.verify_for(permit.project_id)
        return scope

    async def _fresh(self, invocation: ProjectInvocation, permit: ProjectPermit) -> None:
        latest = await self.authority.require(invocation, permit.action)
        if (
            latest.actor_id != permit.actor_id
            or latest.session_uuid != permit.session_uuid
            or latest.project_access_revision != permit.project_access_revision
            or latest.project_owner_scope != permit.project_owner_scope
            or latest.project_owner_id != permit.project_owner_id
            or latest.owner_fence != permit.owner_fence
        ):
            raise ProjectAccessDenied("A4_PROJECT_SCOPE_STALE")

    async def _list(
        self,
        invocation: ProjectInvocation,
        kind: ResourceKind,
        permit: ProjectPermit,
    ) -> tuple[CatalogResourceView, ...]:
        revision = permit.project_access_revision
        if (
            self._source is None
            or not isinstance(revision, str)
            or not valid_project_revision(revision)
        ):
            raise ProjectAccessDenied("A4_RESOURCE_SOURCE_UNAVAILABLE")
        try:
            async with asyncio.timeout(self._timeout):
                views = await self._source.list_project(
                    invocation,
                    kind=kind,
                    scope="all",
                    expected_access_revision=revision,
                )
        except Exception as exc:
            raise ProjectAccessDenied("A4_RESOURCE_SOURCE_UNAVAILABLE") from exc
        if not isinstance(views, tuple) or len(views) > self._max_resources:
            raise ProjectAccessDenied("A4_RESOURCE_COLLECTION_INVALID")
        for view in views:
            if not isinstance(view, CatalogResourceView) or view.kind != kind:
                raise ProjectAccessDenied("A4_RESOURCE_METADATA_INVALID")
            self._scope(view, permit)
        await self._fresh(invocation, permit)
        return views

    async def _resolve(
        self,
        invocation: ProjectInvocation,
        kind: ResourceKind,
        resource_id: UUID,
        permit: ProjectPermit,
    ) -> CatalogResourceView:
        revision = permit.project_access_revision
        if (
            self._source is None
            or not isinstance(revision, str)
            or not valid_project_revision(revision)
        ):
            raise ProjectAccessDenied("A4_RESOURCE_SOURCE_UNAVAILABLE")
        try:
            async with asyncio.timeout(self._timeout):
                view = await self._source.resolve_project(
                    invocation,
                    kind=kind,
                    resource_id=resource_id,
                    expected_access_revision=revision,
                )
        except Exception as exc:
            raise ProjectAccessDenied("A4_RESOURCE_SOURCE_UNAVAILABLE") from exc
        if (
            not isinstance(view, CatalogResourceView)
            or view.kind != kind
            or view.resource_id != resource_id
        ):
            raise ProjectAccessDenied("A4_RESOURCE_METADATA_INVALID")
        self._scope(view, permit)
        await self._fresh(invocation, permit)
        return view

    @staticmethod
    def _integration(view: CatalogResourceView, permit: ProjectPermit) -> ProjectIntegrationRef:
        if view.provider not in {"github", "gitlab", "coolify", "signoz"} or not view.auth_type:
            raise ProjectIntegrationError("PROJECT_PROVIDER_INVALID")
        return ProjectIntegrationRef(
            scope=CatalogResourceAdapter._scope(view, permit),
            integration_id=view.resource_id,
            provider=cast(IntegrationProvider, view.provider),
            credential_type=view.auth_type,
            allowed_operations=frozenset({"read"}),
            name=view.name,
        )

    @staticmethod
    def _variable(view: CatalogResourceView, permit: ProjectPermit) -> ProjectVariableRef:
        return ProjectVariableRef(
            scope=CatalogResourceAdapter._scope(view, permit),
            variable_id=view.resource_id,
            kind="secret" if view.is_secret else "configuration",
            name=view.name,
        )

    async def list_effective(
        self,
        invocation: ProjectInvocation,
        *,
        provider: IntegrationProvider,
        permit: ProjectPermit,
    ) -> tuple[ProjectIntegrationRef, ...]:
        views = await self._list(invocation, "integration", permit)
        return tuple(self._integration(view, permit) for view in views if view.provider == provider)

    async def resolve(
        self,
        invocation: ProjectInvocation,
        *,
        integration_id: UUID,
        provider: IntegrationProvider,
        permit: ProjectPermit,
    ) -> ProjectIntegrationRef:
        view = await self._resolve(invocation, "integration", integration_id, permit)
        if view.provider != provider:
            raise ProjectIntegrationError("PROJECT_PROVIDER_MISMATCH")
        return self._integration(view, permit)

    async def list_effective_metadata(
        self,
        invocation: ProjectInvocation,
        *,
        permit: ProjectPermit,
    ) -> tuple[ProjectVariableRef, ...]:
        return tuple(
            self._variable(view, permit)
            for view in await self._list(invocation, "variable", permit)
        )

    async def resolve_metadata(
        self,
        invocation: ProjectInvocation,
        *,
        variable_id: UUID,
        permit: ProjectPermit,
    ) -> ProjectVariableRef:
        return self._variable(
            await self._resolve(invocation, "variable", variable_id, permit), permit
        )
