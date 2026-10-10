"""Access Team-global issuer without fictional Project/AgentSession UUIDs.

Signs only an independently verified current human plus active, versioned
service key from Access SQL. Team ownership/grant remains Control's decision.
No C2 audience mapper or private signer custody => source refuses to activate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from pydantic import SecretStr
from sqlalchemy import select

from authorization._access_proof_reader import TrustedAccessActorSource
from authorization._service_identity import ALLOWED_AUDIENCES
from authorization._service_identity_persistence import ServiceKeyRow
from common.owner_contracts import (
    OwnerAuthorityUnavailable,
    TrustedOwnerServicePeerPort,
    VerifiedOwnerServicePeer,
)
from common.owner_proof_signing import OwnerVerifiedTeamSnapshot, SourceOwnerSigner
from common.owner_team_contracts import TeamOwnerCommandDTO
from common.platform_db import PlatformDatabase


class TrustedServiceAudiencePort(Protocol):
    def from_peer(self, peer: VerifiedOwnerServicePeer) -> str:
        """C2-custodied authorized gateway/BFF audience, not from headers."""
        ...


class AccessTeamIssuer:
    def __init__(
        self,
        db: PlatformDatabase,
        signer: SourceOwnerSigner,
        peers: TrustedOwnerServicePeerPort,
        actors: TrustedAccessActorSource,
        audiences: TrustedServiceAudiencePort,
    ) -> None:
        if (
            db.engine.url.database != "briareus_access"
            or peers is None
            or actors is None
            or audiences is None
        ):
            raise RuntimeError("Access Team issuer requires owner DB and trusted C2 audience")
        self.db = db
        self.signer = signer
        self.peers = peers
        self.actors = actors
        self.audiences = audiences

    async def issue_team_access_proof(
        self,
        command: TeamOwnerCommandDTO,
        *,
        peer_evidence: object,
        human_evidence: object,
    ) -> SecretStr:
        try:
            peer = self.peers.verify_peer(peer_evidence)
            actor = self.actors.verify_actor(human_evidence, peer=peer)
            audience = self.audiences.from_peer(peer)
        except Exception:
            raise OwnerAuthorityUnavailable(
                "Access private Team human/service proof absent"
            ) from None
        if (
            peer.audience != "briareus:access"
            or peer.expires_at <= datetime.now(UTC)
            or audience not in ALLOWED_AUDIENCES
            or actor.user_id != command.caller_user_id
            or actor.identity_credential_version != command.expected_identity_revision
            or actor.recipient_service_id != peer.service_id
            or actor.expires_at.tzinfo is None
            or actor.expires_at <= datetime.now(UTC)
        ):
            raise OwnerAuthorityUnavailable("Access Team owner service/actor identity changed")
        async with self.db.transaction() as tx:
            row = await tx.scalar(
                select(ServiceKeyRow)
                .where(
                    ServiceKeyRow.key_id == peer.signing_key_id,
                    ServiceKeyRow.service_id == peer.service_id,
                    ServiceKeyRow.audience == audience,
                )
                .with_for_update()
            )
            if (
                row is None
                or not row.enabled
                or row.revoked_at is not None
                or row.key_version != command.expected_access_revision
            ):
                raise OwnerAuthorityUnavailable("Access service key revoked or wrong Team revision")
            # This only proves current independent human+service transport;
            # Control separately decides whether the user owns this Team.
            snapshot = OwnerVerifiedTeamSnapshot(
                owner="access",
                caller_user_id=actor.user_id,
                team_id=command.team_id,
                owner_revision=row.key_version,
                active=True,
                role=None,
                capabilities=(command.operation,),
                epoch_components=(
                    str(row.key_id),
                    str(row.service_id),
                    str(row.key_version),
                    row.audience,
                    "active",
                    str(actor.user_id),
                    str(actor.identity_credential_version),
                ),
            )
            return self.signer.sign_team(command, snapshot)
