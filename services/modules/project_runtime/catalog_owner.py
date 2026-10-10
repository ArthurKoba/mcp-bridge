"""Separate Resource Catalog metadata and one-use provider read owner source.

The Catalog owns briareus_resources and its own credential leases/external
operation outbox, not Gateway or Access DB. Resource names may collide across
Team+Project; only exact resource UUID/provenance is authority. No secret,
OAuth token, SDK body or credential value is returned by this source module.
"""

from __future__ import annotations

import hashlib
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .a6_provider import ProviderReadCommand, ProviderReadReceipt
from .authorization import ProjectInvocation, ProjectRuntimeAuthority, valid_project_revision
from .catalog_metadata import (
    CatalogResourcePort,
    CatalogResourceView,
    ResourceKind,
)
from .owner_effects import OwnerEffectClient, OwnerEffectUnavailable


class CatalogListRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    project_id: UUID
    kind: ResourceKind
    scope: Literal["all"] = "all"
    expected_control_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    limit: int = Field(default=100, ge=1, le=100)


class CatalogListResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    views: tuple[CatalogResourceView, ...]
    project_id: UUID
    owner_database: Literal["briareus_resources"] = "briareus_resources"


class CatalogResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    project_id: UUID
    kind: ResourceKind
    resource_id: UUID
    expected_control_revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class CatalogResolveResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    view: CatalogResourceView | None
    owner_database: Literal["briareus_resources"] = "briareus_resources"


def catalog_target(project_id: UUID, kind: ResourceKind, resource_id: UUID | None) -> str:
    if not isinstance(project_id, UUID) or (
        resource_id is not None and not isinstance(resource_id, UUID)
    ):
        raise OwnerEffectUnavailable("CATALOG_TARGET_INVALID")
    return hashlib.sha256(
        b"catalog-resource-v1\x00"
        + project_id.bytes
        + b"\x00"
        + kind.encode()
        + b"\x00"
        + (resource_id.bytes if resource_id is not None else b"collection")
    ).hexdigest()


class CatalogOwnerSource(CatalogResourcePort):
    """Adapter to existing *metadata-only* selector, backed by signed Catalog.

    Existing A4 resource response is only a typed projection, not a trusted
    A4 global SQL repo. Its origin/version is checked again by the selector,
    after OwnerEffectClient verifies the Catalog-specific signed receipt.
    """

    def __init__(self, effects: OwnerEffectClient) -> None:
        self.effects = effects

    async def list_project(
        self,
        invocation: ProjectInvocation,
        *,
        kind: ResourceKind,
        scope: Literal["all"],
        expected_access_revision: str,
    ) -> tuple[CatalogResourceView, ...]:
        if scope != "all" or not valid_project_revision(expected_access_revision):
            raise OwnerEffectUnavailable("CATALOG_PROJECT_CONTROL_REVISION_REQUIRED")
        operation = invocation.operation_scope
        if operation is None or operation.action not in {
            "svc.read",
            "infrastructure.read",
            "resources.use",
        }:
            raise OwnerEffectUnavailable("CATALOG_RESOURCE_SCOPE_REQUIRED")
        result = await self.effects.execute(
            invocation,
            owner="catalog",
            phase="read",
            action=operation.action,
            target_sha256=catalog_target(invocation.project_id, kind, None),
            payload=CatalogListRequest(
                project_id=invocation.project_id,
                kind=kind,
                scope=scope,
                expected_control_revision=expected_access_revision,
            ),
            expected=CatalogListResult,
            original_operation_uuid=operation.request_uuid,
        )
        view = result.payload
        if (
            result.attestation.receipt.state != "committed"
            or view.project_id != invocation.project_id
            or len(view.views) > 1000
            or any(
                item.kind != kind
                or item.project_access_revision != expected_access_revision
                or item.value is not None
                for item in view.views
            )
        ):
            raise OwnerEffectUnavailable("CATALOG_RESOURCE_LIST_FENCE_INVALID")
        return view.views

    async def resolve_project(
        self,
        invocation: ProjectInvocation,
        *,
        kind: ResourceKind,
        resource_id: UUID,
        expected_access_revision: str,
    ) -> CatalogResourceView:
        if not valid_project_revision(expected_access_revision):
            raise OwnerEffectUnavailable("CATALOG_PROJECT_REVISION_INVALID")
        operation = invocation.operation_scope
        if operation is None or operation.action not in {
            "svc.read",
            "infrastructure.read",
            "resources.use",
        }:
            raise OwnerEffectUnavailable("CATALOG_RESOURCE_SCOPE_REQUIRED")
        result = await self.effects.execute(
            invocation,
            owner="catalog",
            phase="read",
            action=operation.action,
            target_sha256=catalog_target(invocation.project_id, kind, resource_id),
            payload=CatalogResolveRequest(
                project_id=invocation.project_id,
                kind=kind,
                resource_id=resource_id,
                expected_control_revision=expected_access_revision,
            ),
            expected=CatalogResolveResult,
            original_operation_uuid=operation.request_uuid,
        )
        view = result.payload.view
        if (
            result.attestation.receipt.state != "committed"
            or view is None
            or view.kind != kind
            or view.resource_id != resource_id
            or view.project_access_revision != expected_access_revision
            or view.value is not None
        ):
            raise OwnerEffectUnavailable("CATALOG_RESOURCE_PROVENANCE_INVALID")
        return view


class CatalogProviderReader:
    """Only one-use read-only Catalog-custodied provider access, no secrets."""

    def __init__(self, authority: ProjectRuntimeAuthority, effects: OwnerEffectClient) -> None:
        self.authority = authority
        self.effects = effects
        self.metadata = CatalogOwnerSource(effects)

    async def read_once(
        self,
        invocation: ProjectInvocation,
        *,
        provider: Literal["github", "gitlab", "coolify", "signoz"],
        resource_id: UUID,
        capability: str,
    ) -> ProviderReadReceipt:
        action = "infrastructure.read" if provider in {"coolify", "signoz"} else "svc.read"
        scope = invocation.operation_scope
        if scope is None or scope.action != action or scope.resource_id != resource_id:
            raise OwnerEffectUnavailable("CATALOG_PROVIDER_EXACT_RESOURCE_ID_REQUIRED")
        permit = await self.authority.require(invocation, action)
        if not valid_project_revision(permit.project_access_revision):
            raise OwnerEffectUnavailable("CATALOG_CURRENT_PROJECT_REQUIRED")
        # Catalog must resolve exact resource UUID, Team+Project provenance,
        # current Control grant and one-use credential within ONE signed
        # owner-local read operation. A prior projection is not a grant.
        # A metadata-read followed by a provider read with the SAME owner
        # operation UUID/phase but DIFFERENT body would violate idempotency.
        command = ProviderReadCommand(
            operation_uuid=scope.request_uuid,
            resource_id=resource_id,
            provider=provider,
            capability=capability,
            idempotency_key=str(scope.request_uuid),
        )
        result = await self.effects.execute(
            invocation,
            owner="catalog",
            phase="read",
            action=action,
            target_sha256=catalog_target(invocation.project_id, "integration", resource_id),
            payload=command,
            expected=ProviderReadReceipt,
            original_operation_uuid=scope.request_uuid,
        )
        receipt = result.payload
        if (
            result.attestation.receipt.state != "committed"
            or receipt.project_id != invocation.project_id
            or receipt.resource_id != resource_id
            or receipt.operation_uuid != scope.request_uuid
            or receipt.state != "recorded"
            or receipt.result_sha256 is None
        ):
            raise OwnerEffectUnavailable("CATALOG_PROVIDER_RESULT_UNVERIFIED", unknown=True)
        # Actual credential lease is a ONE-USE internal Catalog capability,
        # redeemed by its own provider worker; never returned here or passed
        # into Shell/Browser/agent-visible tool args/logs/traces.
        return receipt

    async def write_once(self, *_args: object, **_kwargs: object) -> None:
        raise OwnerEffectUnavailable("CATALOG_PROVIDER_WRITE_UNAPPROVED")
