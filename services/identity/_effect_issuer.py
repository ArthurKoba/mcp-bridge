"""Identity source-only signed R13 v1 effect decision from current User SQL.

C2 physical peer+human attestation is injected; no route or public bearer.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from sqlalchemy import select

from common.owner_contracts import (
    OwnerAuthorityUnavailable,
    TrustedOwnerServicePeerPort,
)
from common.owner_effect_authorization import (
    OwnerEffectAuthoritySnapshot,
    OwnerEffectDecisionSigner,
    OwnerEffectIntent,
    SignedOwnerDecision,
    derive_source_epoch,
)
from common.platform_db import PlatformDatabase
from identity._owner_proof_reader import TrustedHumanDelegationVerifier
from identity._persistence import AdminTokenRevocationRow, UserRow


class IdentityEffectIssuer:
    def __init__(
        self,
        database: PlatformDatabase,
        signer: OwnerEffectDecisionSigner,
        peers: TrustedOwnerServicePeerPort,
        human: TrustedHumanDelegationVerifier,
    ) -> None:
        if (
            database.engine.url.database != "briareus_identity"
            or signer.owner != "identity"
            or peers is None
            or human is None
        ):
            raise RuntimeError("Identity effect signer cannot use a foreign DB or absent C2")
        self.database = database
        self.signer = signer
        self.peers = peers
        self.human = human

    async def decide(
        self,
        intent: OwnerEffectIntent,
        *,
        peer_evidence: object,
        human_evidence: object,
    ) -> SignedOwnerDecision:
        try:
            peer = self.peers.verify_peer(peer_evidence)
            human = self.human.verify_human(human_evidence, recipient_peer=peer)
        except Exception:
            raise OwnerAuthorityUnavailable("trusted Identity effect caller not verified") from None
        now = datetime.now(UTC)
        if (
            peer.audience != "briareus:identity"
            or peer.service_id != intent.recipient_service_id
            or peer.instance_uuid != intent.recipient_instance_uuid
            or peer.expires_at <= now
            or human.user_id != intent.actor_id
            or human.recipient_service_id != peer.service_id
            or human.credential_version < 1
            or human.expires_at.tzinfo is None
            or human.expires_at <= now
            or not re.fullmatch(r"[a-f0-9]{64}", human.admin_jti_digest)
        ):
            raise OwnerAuthorityUnavailable("Identity source recipient/delegation changed")
        async with self.database.transaction() as tx:
            user = await tx.scalar(
                select(UserRow).where(UserRow.id == intent.actor_id).with_for_update()
            )
            if (
                user is None
                or user.enabled is not True
                or user.deleted_at is not None
                or user.credential_version != human.credential_version
                or user.role not in {"user", "superuser"}
            ):
                raise OwnerAuthorityUnavailable("current User suspended/deleted/changed")
            revoked = await tx.scalar(
                select(AdminTokenRevocationRow.jti_digest).where(
                    AdminTokenRevocationRow.jti_digest == human.admin_jti_digest
                )
            )
            if revoked is not None:
                raise OwnerAuthorityUnavailable("human delegation JTI was revoked")
            snapshot = OwnerEffectAuthoritySnapshot(
                owner="identity",
                intent=intent,
                issued_from_owner_db="briareus_identity",
                state_version=user.credential_version,
                revoke_epoch=user.credential_version - 1,
                authority_epoch=derive_source_epoch(
                    "identity",
                    str(user.id),
                    user.credential_version,
                    user.role,
                    "active",
                    human.admin_jti_digest,
                ),
                active=True,
                source_expires_at=human.expires_at,
            )
            return self.signer.sign(snapshot, recipient=peer)
