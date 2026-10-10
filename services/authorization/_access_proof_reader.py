"""Access-owned current AgentSession permission issuer; NO Control/Identity SQL.

Only exact allowlisted actions matching LIVE AgentSession grants can be signed.
Creating a new AgentSession, Team-global operations and Runtime-kind-dependent
leases require separately reviewed C1-B2/C2 bootstrap/typed proof contracts.
Their absence DENIES; no broad fallback grant from a User UUID or session ID.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import select

from authorization._session_persistence import ProjectAgentSessionRow
from common.owner_contracts import (
    OwnerAuthorityUnavailable,
    OwnerCommandDTO,
    TrustedOwnerServicePeerPort,
    VerifiedOwnerServicePeer,
)
from common.owner_proof_signing import OwnerVerifiedSourceSnapshot, SourceOwnerSigner
from common.platform_db import PlatformDatabase

# Source-canonical effect permissions. No mapping that lets a generic
# runtime.session.open claim execute arbitrary Terminal, Web or Reverse kinds.
_COMMAND_GRANTS: dict[str, str] = {
    "files.write.reserve": "files.write",
    "files.write.dispatch": "files.write",
    "files.write.reconcile": "files.write",
    "credential.reserve": "integrations.use",
    "credential.redeem": "integrations.use",
    "catalog.integration.create": "integrations.manage",
    "catalog.integration.rotate": "integrations.manage",
    "catalog.integration.revoke": "integrations.manage",
    "catalog.variable.create": "variables.manage",
    "catalog.variable.rotate": "variables.manage",
    "catalog.variable.revoke": "variables.manage",
    "catalog.variable.reserve": "variables.use",
    "catalog.variable.redeem": "variables.use",
    "reverse.import.reserve": "analysis.import",
    "reverse.import.dispatch": "analysis.import",
    "reverse.import.reconcile": "analysis.import",
    "agent.create": "agents.manage",
}


@dataclass(frozen=True, slots=True)
class VerifiedAccessActor:
    user_id: UUID
    identity_credential_version: int
    recipient_service_id: UUID
    expires_at: datetime


class TrustedAccessActorSource(Protocol):
    def verify_actor(
        self, evidence: object, *, peer: VerifiedOwnerServicePeer
    ) -> VerifiedAccessActor:
        """Must verify current human Identity delegation before Access SQL."""
        ...


class AccessOwnerProofReader:
    def __init__(
        self,
        database: PlatformDatabase,
        signer: SourceOwnerSigner,
        peers: TrustedOwnerServicePeerPort,
        actor_source: TrustedAccessActorSource,
    ) -> None:
        if (
            database.engine.url.database != "briareus_access"
            or peers is None
            or actor_source is None
        ):
            raise RuntimeError("Access source requires own database and trusted caller")
        self.db = database
        self.signer = signer
        self.peers = peers
        self.actors = actor_source

    async def issue_live_agent_session_grant(
        self,
        command: OwnerCommandDTO,
        *,
        peer_evidence: object,
        human_evidence: object,
    ) -> SecretStr:
        needed_grant = _COMMAND_GRANTS.get(command.operation)
        if needed_grant is None:
            raise OwnerAuthorityUnavailable("this operation lacks an accepted Access grant mapping")
        try:
            peer = self.peers.verify_peer(peer_evidence)
            actor = self.actors.verify_actor(human_evidence, peer=peer)
        except Exception:
            raise OwnerAuthorityUnavailable("Access trusted human/peer not verified") from None
        if (
            peer.audience != "briareus:access"
            or peer.expires_at <= datetime.now(UTC)
            or actor.user_id != command.caller_user_id
            or actor.identity_credential_version != command.expected_identity_revision
            or actor.recipient_service_id != peer.service_id
            or actor.expires_at.tzinfo is None
            or actor.expires_at <= datetime.now(UTC)
        ):
            raise OwnerAuthorityUnavailable("Access caller is not bound to verified Identity")
        async with self.db.transaction() as tx:
            row = await tx.scalar(
                select(ProjectAgentSessionRow)
                .where(ProjectAgentSessionRow.session_uuid == command.session_uuid)
                .with_for_update()
            )
            if (
                row is None
                or row.project_id != command.project_id
                or row.created_by_principal_id != actor.user_id
                or row.status != "active"
                or row.hard_expires_at <= datetime.now(UTC)
                or row.version != command.expected_access_revision
            ):
                raise OwnerAuthorityUnavailable("Access session revoked, expired or wrong Project")
            granted = row.grants.get("operations")
            if (
                not isinstance(granted, list)
                or len(granted) > 32
                or not all(isinstance(item, str) and len(item) <= 128 for item in granted)
                or needed_grant not in granted
            ):
                raise OwnerAuthorityUnavailable("required live AgentSession grant not active")
            snapshot = OwnerVerifiedSourceSnapshot(
                owner="access",
                caller_user_id=actor.user_id,
                project_id=row.project_id,
                agent_session_uuid=row.session_uuid,
                owner_revision=row.version,
                active=True,
                role=None,
                capabilities=(command.operation,),
                control_resource_revision=None,
                project_lifecycle=None,
                team_id=command.expected_team_id,
                team_revision=None,
                team_resource_revision=None,
                epoch_components=(
                    str(row.session_uuid),
                    str(row.version),
                    row.status,
                    row.hard_expires_at.isoformat(),
                    str(row.project_id),
                    str(actor.user_id),
                    needed_grant,
                ),
            )
            return self.signer.sign_project(command, snapshot)
