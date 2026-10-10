"""Catalog-owned durable, encrypted-result metadata reads and lease abort.

Identity/Control/Access sign the exact immutable Project resource scope;
Catalog SQL selects only its own rows. Metadata never includes plaintext
credential, variable value, URLs, arbitrary provider JSON or secret hashes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from common.owner_contracts import (
    SignedOwnerProofs,
    VerifiedOwnerOperation,
    require_signed_payload,
)
from common.owner_transactions import OwnerCommandOutcome
from common.platform_errors import AccessDenied, Conflict, InvalidInput
from projects._catalog_source import CatalogSourceService
from projects._resource_persistence import CredentialLeaseRow, IntegrationRow, VariableRow

Kind = Literal["integrations", "variables"]
Scope = Literal["all", "project", "team"]


class CatalogOwnerLifecycle(CatalogSourceService):
    @staticmethod
    def _row(kind: Kind) -> type[IntegrationRow] | type[VariableRow]:
        return IntegrationRow if kind == "integrations" else VariableRow

    async def list_metadata_committed(
        self,
        decision: VerifiedOwnerOperation,
        proofs: SignedOwnerProofs,
        *,
        kind: Kind,
        scope: Scope = "all",
        alias_key: str | None = None,
        limit: int = 100,
    ) -> OwnerCommandOutcome:
        """Exactly scoped durable read acknowledgement (not a credential grant)."""
        request = decision.request
        if (
            request.target_owner != "resources"
            or request.operation != f"catalog.{kind}.list"
            or not 1 <= limit <= 100
            or (
                alias_key is not None
                and (
                    not 1 <= len(alias_key) <= 128
                    or not all(c.isascii() and (c.isalnum() or c in "_.-") for c in alias_key)
                )
            )
            or (scope == "team" and request.expected_team_id is None)
        ):
            raise InvalidInput("Catalog list requires one approved source selector")
        require_signed_payload(
            request,
            {
                "kind": kind,
                "scope": scope,
                "alias_key": alias_key,
                "limit": limit,
            },
        )
        row_type = self._row(kind)
        column = IntegrationRow.alias_key if kind == "integrations" else VariableRow.name_key
        filters = []
        if scope in {"all", "project"}:
            filters.append(row_type.owner_project_id == request.project_id)
        if scope in {"all", "team"} and request.expected_team_id is not None:
            filters.append(row_type.owner_team_id == request.expected_team_id)
        if not filters:
            raise AccessDenied("Catalog Team scope not proven by current Control owner")

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            stmt = select(row_type).where(or_(*filters), row_type.deleted_at.is_(None))
            if alias_key is not None:
                stmt = stmt.where(column == alias_key)
            selected = list(await tx.scalars(stmt.order_by(row_type.id).limit(limit + 1)))
            if len(selected) > limit:
                raise Conflict("Catalog bounded list requires smaller scope/page")
            values = []
            for row in selected:
                if not isinstance(row, (IntegrationRow, VariableRow)):
                    raise AccessDenied("Catalog SQL row type is not from its own owner")
                owner_scope = "team" if row.owner_team_id is not None else "project"
                owner_id = row.owner_team_id or row.owner_project_id
                if owner_id is None:
                    raise AccessDenied("Catalog XOR source owner absent")
                values.append(
                    {
                        "resource_id": str(row.id),
                        "kind": kind,
                        "owner_scope": owner_scope,
                        "owner_id": str(owner_id),
                        "name_key": row.alias_key
                        if isinstance(row, IntegrationRow)
                        else row.name_key,
                        "version": row.version,
                    }
                )
            if alias_key is not None and len(values) > 1:
                raise Conflict("equal Team/Project alias is ambiguous without exact owner")
            return {
                "status": "recorded",
                "kind": kind,
                "scope": scope,
                "alias_key": alias_key,
                "limit": limit,
                "project_id": str(request.project_id),
                "records": values,
                "count": len(values),
                "source_secret_included": False,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="catalog.metadata_listed",
            target=kind,
        )

    async def resolve_metadata_committed(
        self,
        decision: VerifiedOwnerOperation,
        proofs: SignedOwnerProofs,
        *,
        kind: Kind,
        resource_id: UUID,
        expected_resource_version: int,
        owner_scope: Literal["team", "project"],
        owner_id: UUID,
    ) -> OwnerCommandOutcome:
        """Read exact resource owner+version with no alias fallback/secret."""
        request = decision.request
        if (
            request.target_owner != "resources"
            or request.operation != f"catalog.{kind}.resolve"
            or resource_id.version != 4
            or owner_id.version != 4
            or expected_resource_version < 1
            or (owner_scope == "team" and owner_id != request.expected_team_id)
            or (owner_scope == "project" and owner_id != request.project_id)
        ):
            raise AccessDenied("Catalog original Project/Team resource owner mismatch")
        require_signed_payload(
            request,
            {
                "kind": kind,
                "resource_id": str(resource_id),
                "owner_scope": owner_scope,
                "owner_id": str(owner_id),
                "expected_resource_version": expected_resource_version,
            },
        )
        row_type = self._row(kind)

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            row = await tx.scalar(
                select(row_type).where(row_type.id == resource_id).with_for_update()
            )
            if row is not None and not isinstance(row, (IntegrationRow, VariableRow)):
                raise AccessDenied("Catalog source returned a foreign row")
            if (
                row is None
                or row.deleted_at is not None
                or row.version != expected_resource_version
                or (
                    owner_scope == "team"
                    and (row.owner_team_id != owner_id or row.owner_project_id is not None)
                )
                or (
                    owner_scope == "project"
                    and (row.owner_project_id != owner_id or row.owner_team_id is not None)
                )
            ):
                raise AccessDenied("Catalog resource gone, transferred or stale")
            return {
                "status": "recorded",
                "resource_id": str(row.id),
                "owner_scope": owner_scope,
                "owner_id": str(owner_id),
                "name_key": row.alias_key if isinstance(row, IntegrationRow) else row.name_key,
                "kind": kind,
                "version": row.version,
                "source_secret_included": False,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="catalog.metadata_resolved",
            target=str(resource_id),
        )

    async def revoke_unused_lease(
        self,
        decision: VerifiedOwnerOperation,
        proofs: SignedOwnerProofs,
        *,
        lease_id: UUID,
        service_id: UUID,
        instance_uuid: UUID,
    ) -> OwnerCommandOutcome:
        """Fence a one-use lease *before redemption*; never reveal credential."""
        request = decision.request
        if (
            request.target_owner != "resources"
            or request.operation != "catalog.lease.revoke"
            or any(x.version != 4 for x in (lease_id, service_id, instance_uuid))
        ):
            raise InvalidInput("Catalog lease revoke requires exact origin/recipient")
        require_signed_payload(
            request,
            {
                "lease_id": str(lease_id),
                "service_id": str(service_id),
                "instance_uuid": str(instance_uuid),
            },
        )

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            lease = await tx.scalar(
                select(CredentialLeaseRow)
                .where(
                    CredentialLeaseRow.id == lease_id,
                )
                .with_for_update()
            )
            if (
                lease is None
                or lease.project_id != request.project_id
                or lease.user_id != request.caller_user_id
                or lease.session_uuid != request.session_uuid
                or lease.service_id != service_id
                or lease.service_instance_uuid != instance_uuid
                or lease.redeemed_at is not None
                or lease.expires_at <= datetime.now(UTC)
            ):
                raise AccessDenied("Catalog lease already used, expired or foreign")
            lease.expires_at = datetime.now(UTC)
            return {
                "status": "revoked",
                "lease_id": str(lease.id),
                "resource_id": str(lease.resource_id),
                "secret_returned": False,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="catalog.lease_revoked",
            target=str(lease_id),
        )
