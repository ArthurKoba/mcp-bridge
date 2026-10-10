"""Access source-only R13 v1 AgentSession grant and hard-expiry attestation.

Access independently reads current AgentSession SQL; no Control/Identity join,
no generic User token/session UUID acting as a grant. Physical C2 is held.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from authorization._access_proof_reader import TrustedAccessActorSource
from authorization._session_persistence import ProjectAgentSessionRow
from common.owner_contracts import OwnerAuthorityUnavailable, TrustedOwnerServicePeerPort
from common.owner_effect_authorization import (
    OwnerEffectAuthoritySnapshot,
    OwnerEffectDecisionSigner,
    OwnerEffectIntent,
    ProjectAction,
    SignedOwnerDecision,
    derive_source_epoch,
)
from common.platform_db import PlatformDatabase

_ACTION_GRANTS: dict[ProjectAction, str] = {
    "files.read": "files.read",
    "files.write": "files.write",
    "terminal.attach": "terminal.execute",
    "web.internal": "web.access",
    "web.remote": "web.access",
    "reverse.import": "analysis.import",
    "reverse.read": "analysis.import",
    "resources.use": "integrations.use",
}


class AccessEffectIssuer:
    def __init__(
        self,
        database: PlatformDatabase,
        signer: OwnerEffectDecisionSigner,
        peers: TrustedOwnerServicePeerPort,
        actors: TrustedAccessActorSource,
    ) -> None:
        if (
            database.engine.url.database != "briareus_access"
            or signer.owner != "access"
            or peers is None
            or actors is None
        ):
            raise RuntimeError("Access signed effect requires isolated SQL and verified C2 peers")
        self.database = database
        self.signer = signer
        self.peers = peers
        self.actors = actors

    async def decide(
        self, intent: OwnerEffectIntent, *, peer_evidence: object, human_evidence: object
    ) -> SignedOwnerDecision:
        required = _ACTION_GRANTS.get(intent.action)
        if required is None:
            raise OwnerAuthorityUnavailable("Access effect action has no reviewed grant mapping")
        try:
            peer = self.peers.verify_peer(peer_evidence)
            actor = self.actors.verify_actor(human_evidence, peer=peer)
        except Exception:
            raise OwnerAuthorityUnavailable(
                "current Access human/service peer not verified"
            ) from None
        now = datetime.now(UTC)
        if (
            peer.audience != "briareus:access"
            or peer.service_id != intent.recipient_service_id
            or peer.instance_uuid != intent.recipient_instance_uuid
            or peer.expires_at <= now
            or actor.user_id != intent.actor_id
            or actor.identity_credential_version < 1
            or actor.recipient_service_id != peer.service_id
            or actor.expires_at.tzinfo is None
            or actor.expires_at <= now
        ):
            raise OwnerAuthorityUnavailable("Access service and current User identity disagree")
        async with self.database.transaction() as tx:
            session = await tx.scalar(
                select(ProjectAgentSessionRow)
                .where(ProjectAgentSessionRow.session_uuid == intent.session_uuid)
                .with_for_update()
            )
            if (
                session is None
                or session.project_id != intent.project_id
                or session.created_by_principal_id != intent.actor_id
                or session.version < 1
                or session.status != "active"
                or session.hard_expires_at.tzinfo is None
                or session.hard_expires_at <= datetime.now(UTC)
            ):
                raise OwnerAuthorityUnavailable("AgentSession revoked/expired or foreign Project")
            grants = session.grants.get("operations")
            if (
                not isinstance(grants, list)
                or len(grants) > 32
                or not all(isinstance(g, str) and len(g) <= 128 for g in grants)
                or required not in grants
            ):
                raise OwnerAuthorityUnavailable("current AgentSession has no approved effect grant")
            snapshot = OwnerEffectAuthoritySnapshot(
                owner="access",
                intent=intent,
                issued_from_owner_db="briareus_access",
                state_version=session.version,
                revoke_epoch=session.version - 1,
                authority_epoch=derive_source_epoch(
                    "access",
                    str(session.session_uuid),
                    session.version,
                    session.status,
                    session.hard_expires_at.isoformat(),
                    intent.project_id.hex,
                    intent.actor_id.hex,
                    required,
                ),
                active=True,
                granted_actions=(intent.action,),
                session_hard_expires_at=session.hard_expires_at,
                source_expires_at=min(actor.expires_at, session.hard_expires_at),
            )
            return self.signer.sign(snapshot, recipient=peer)
