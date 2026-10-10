"""Access issuer for FIRST basic AgentSession without an existing session.

Identity+Control independently sign the real Project/current user; Access
checks its service key, origin peer and absence of the new UUID under its
OWN DB lock. Never calls SQL across owner DBs or creates elevated sessions.
No public route or trusted C2 transport implementation is included.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Protocol

from pydantic import SecretStr
from sqlalchemy import select

from authorization._access_proof_reader import TrustedAccessActorSource
from authorization._service_identity import ALLOWED_AUDIENCES
from authorization._service_identity_persistence import ServiceKeyRow
from authorization._session_persistence import ProjectAgentSessionRow
from authorization._team_access_issuer import TrustedServiceAudiencePort
from common.owner_contracts import (
    OwnerAuthorityUnavailable,
    OwnerCommandDTO,
    OwnerProofAuthority,
    TrustedOwnerServicePeerPort,
)
from common.owner_proof_signing import OwnerVerifiedSourceSnapshot, SourceOwnerSigner
from common.platform_db import PlatformDatabase


class CurrentBootstrapOwnerSources(Protocol):
    async def get_identity_and_control(
        self,
        request: OwnerCommandDTO,
    ) -> tuple[SecretStr, SecretStr]:
        """Two fresh source-signed grants, NEVER a cached Project projection."""
        ...


class AccessInitialSessionIssuer:
    def __init__(
        self,
        db: PlatformDatabase,
        signer: SourceOwnerSigner,
        verifier: OwnerProofAuthority,
        peers: TrustedOwnerServicePeerPort,
        actors: TrustedAccessActorSource,
        audiences: TrustedServiceAudiencePort,
        bootstrap_sources: CurrentBootstrapOwnerSources,
    ) -> None:
        if (
            db.engine.url.database != "briareus_access"
            or peers is None
            or actors is None
            or audiences is None
            or bootstrap_sources is None
            or verifier is None
        ):
            raise RuntimeError("Access initial Session issuer requires current owners/C2")
        self.db = db
        self.signer = signer
        self.verifier = verifier
        self.peers = peers
        self.actors = actors
        self.audiences = audiences
        self.sources = bootstrap_sources

    async def issue_normal_session_access_proof(
        self,
        request: OwnerCommandDTO,
        *,
        peer_evidence: object,
        human_evidence: object,
    ) -> SecretStr:
        if request.operation != "session.open" or request.target_owner != "access":
            raise OwnerAuthorityUnavailable("only first normal AgentSession may bootstrap")
        try:
            peer = self.peers.verify_peer(peer_evidence)
            actor = self.actors.verify_actor(human_evidence, peer=peer)
            scope = self.audiences.from_peer(peer)
        except Exception:
            raise OwnerAuthorityUnavailable(
                "Access bootstrap peer/human issuer unavailable"
            ) from None
        now = datetime.now(UTC)
        if (
            peer.audience != "briareus:access"
            or peer.expires_at <= now
            or scope not in ALLOWED_AUDIENCES
            or actor.user_id != request.caller_user_id
            or actor.identity_credential_version != request.expected_identity_revision
            or actor.recipient_service_id != peer.service_id
            or actor.expires_at.tzinfo is None
            or actor.expires_at <= now
        ):
            raise OwnerAuthorityUnavailable("new Session is not bound to a trusted live actor")
        try:
            async with asyncio.timeout(3):
                identity, control = await self.sources.get_identity_and_control(request)
            source_user, source_project = self.verifier.require_bootstrap_sources(
                request,
                identity=identity,
                platform=control,
            )
        except Exception:
            raise OwnerAuthorityUnavailable("current Identity/Control bootstrap denied") from None
        async with self.db.transaction() as tx:
            existing = await tx.scalar(
                select(ProjectAgentSessionRow.session_uuid)
                .where(ProjectAgentSessionRow.session_uuid == request.session_uuid)
                .with_for_update()
            )
            if existing is not None:
                raise OwnerAuthorityUnavailable("normal Session UUID already allocated")
            key = await tx.scalar(
                select(ServiceKeyRow)
                .where(
                    ServiceKeyRow.key_id == peer.signing_key_id,
                    ServiceKeyRow.service_id == peer.service_id,
                    ServiceKeyRow.audience == scope,
                )
                .with_for_update()
            )
            if (
                key is None
                or not key.enabled
                or key.revoked_at is not None
                or key.key_version != request.expected_access_revision
            ):
                raise OwnerAuthorityUnavailable("Access Session bootstrap service key revoked")
            # Fresh external issuers are rechecked after local Access lock;
            # no global DB transaction is pretended here.
            try:
                async with asyncio.timeout(3):
                    newer_identity, newer_control = await self.sources.get_identity_and_control(
                        request
                    )
                current_user, current_project = self.verifier.require_bootstrap_sources(
                    request,
                    identity=newer_identity,
                    platform=newer_control,
                )
            except Exception:
                raise OwnerAuthorityUnavailable("bootstrap Identity/Control changed") from None
            if (
                current_user.authority_epoch != source_user.authority_epoch
                or current_project.authority_epoch != source_project.authority_epoch
            ):
                raise OwnerAuthorityUnavailable("Session bootstrap revoked before Access signature")
            snapshot = OwnerVerifiedSourceSnapshot(
                owner="access",
                caller_user_id=actor.user_id,
                project_id=request.project_id,
                agent_session_uuid=request.session_uuid,
                owner_revision=key.key_version,
                active=True,
                role=None,
                capabilities=("session.open",),
                control_resource_revision=None,
                project_lifecycle=None,
                team_id=request.expected_team_id,
                team_revision=None,
                team_resource_revision=None,
                epoch_components=(
                    str(key.key_id),
                    str(key.service_id),
                    str(key.key_version),
                    str(actor.user_id),
                    str(actor.identity_credential_version),
                    str(request.session_uuid),
                    "normal-only",
                ),
            )
            return self.signer.sign_project(request, snapshot)
