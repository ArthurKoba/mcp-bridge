"""Identity-owned current User JWT proof source; only Identity SQL is queried.

No HTTP endpoint is mounted here. The caller must already have separately
verified mTLS/Unix service peer and signed, revocable human delegation.
The issued JWT is only ONE of Identity+Control+Access live grants, never alone
sufficient for Files/Runtime/Catalog/Reverse effects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, cast
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import select

from common.owner_contracts import (
    OwnerAuthorityUnavailable,
    OwnerCommandDTO,
    TrustedOwnerServicePeerPort,
    VerifiedOwnerServicePeer,
)
from common.owner_proof_signing import (
    OwnerVerifiedSourceSnapshot,
    OwnerVerifiedTeamSnapshot,
    SourceOwnerSigner,
)
from common.owner_team_contracts import TeamOwnerCommandDTO
from common.platform_db import PlatformDatabase
from identity._persistence import AdminTokenRevocationRow, UserRow


@dataclass(frozen=True, slots=True)
class VerifiedHumanDelegation:
    """Trusted C2 issuer result, not an HTTP field or a reusable BFF cookie."""

    user_id: UUID
    credential_version: int
    admin_jti_digest: str
    recipient_service_id: UUID
    expires_at: datetime


class TrustedHumanDelegationVerifier(Protocol):
    def verify_human(
        self, evidence: object, *, recipient_peer: VerifiedOwnerServicePeer
    ) -> VerifiedHumanDelegation:
        """Must verify Ed25519/issuer, current peer and delegation chain."""
        ...


class IdentityOwnerProofReader:
    def __init__(
        self,
        database: PlatformDatabase,
        signer: SourceOwnerSigner,
        service_peers: TrustedOwnerServicePeerPort,
        human_delegation: TrustedHumanDelegationVerifier,
    ) -> None:
        if (
            database.engine.url.database != "briareus_identity"
            or service_peers is None
            or human_delegation is None
        ):
            raise RuntimeError("current User authority requires isolated Identity and C2 peers")
        self.db = database
        self.signer = signer
        self.peers = service_peers
        self.human = human_delegation

    async def issue_project_user_proof(
        self,
        command: OwnerCommandDTO,
        *,
        peer_evidence: object,
        human_evidence: object,
    ) -> SecretStr:
        if command.caller_user_id.version != 4:
            raise OwnerAuthorityUnavailable("current Identity subject must be UUIDv4")
        try:
            peer = self.peers.verify_peer(peer_evidence)
            delegation = self.human.verify_human(human_evidence, recipient_peer=peer)
        except Exception:
            raise OwnerAuthorityUnavailable(
                "trusted service/human delegation unavailable"
            ) from None
        if (
            peer.audience != "briareus:identity"
            or peer.expires_at <= datetime.now(UTC)
            or delegation.user_id != command.caller_user_id
            or delegation.recipient_service_id != peer.service_id
            or delegation.credential_version != command.expected_identity_revision
            or delegation.expires_at.tzinfo is None
            or delegation.expires_at <= datetime.now(UTC)
            or not re.fullmatch(r"[0-9a-f]{64}", delegation.admin_jti_digest)
        ):
            raise OwnerAuthorityUnavailable("Identity delegation not bound to current service")
        async with self.db.transaction() as tx:
            user = await tx.scalar(
                select(UserRow).where(UserRow.id == delegation.user_id).with_for_update()
            )
            if (
                user is None
                or not user.enabled
                or user.deleted_at is not None
                or user.credential_version != delegation.credential_version
                or user.role not in {"user", "superuser"}
            ):
                raise OwnerAuthorityUnavailable("Identity User is suspended or credentials revoked")
            revoked = await tx.scalar(
                select(AdminTokenRevocationRow.jti_digest).where(
                    AdminTokenRevocationRow.jti_digest == delegation.admin_jti_digest
                )
            )
            if revoked is not None:
                raise OwnerAuthorityUnavailable("Admin current credential was revoked")
            snapshot = OwnerVerifiedSourceSnapshot(
                owner="identity",
                caller_user_id=user.id,
                project_id=command.project_id,
                agent_session_uuid=command.session_uuid,
                owner_revision=user.credential_version,
                active=True,
                role=cast(Literal["user", "superuser"], user.role),
                capabilities=(),
                control_resource_revision=None,
                project_lifecycle=None,
                team_id=command.expected_team_id,
                team_revision=None,
                team_resource_revision=None,
                epoch_components=(
                    str(user.id),
                    str(user.credential_version),
                    user.role,
                    "active",
                    delegation.admin_jti_digest,
                ),
            )
            return self.signer.sign_project(command, snapshot)

    async def issue_team_user_proof(
        self,
        command: TeamOwnerCommandDTO,
        *,
        peer_evidence: object,
        human_evidence: object,
    ) -> SecretStr:
        """Source-owning Identity attestation, never a fabricated Project ID."""
        try:
            peer = self.peers.verify_peer(peer_evidence)
            delegated = self.human.verify_human(human_evidence, recipient_peer=peer)
        except Exception:
            raise OwnerAuthorityUnavailable(
                "Team Identity private delegation unavailable"
            ) from None
        if (
            peer.audience != "briareus:identity"
            or peer.expires_at <= datetime.now(UTC)
            or delegated.user_id != command.caller_user_id
            or delegated.recipient_service_id != peer.service_id
            or delegated.credential_version != command.expected_identity_revision
            or delegated.expires_at.tzinfo is None
            or delegated.expires_at <= datetime.now(UTC)
            or not re.fullmatch(r"[0-9a-f]{64}", delegated.admin_jti_digest)
        ):
            raise OwnerAuthorityUnavailable("Team current User credential mismatch")
        async with self.db.transaction() as tx:
            user = await tx.scalar(
                select(UserRow).where(UserRow.id == delegated.user_id).with_for_update()
            )
            if (
                user is None
                or not user.enabled
                or user.deleted_at is not None
                or user.credential_version != delegated.credential_version
                or user.role not in {"user", "superuser"}
            ):
                raise OwnerAuthorityUnavailable("Team User suspended or role changed")
            revoked = await tx.scalar(
                select(AdminTokenRevocationRow.jti_digest).where(
                    AdminTokenRevocationRow.jti_digest == delegated.admin_jti_digest
                )
            )
            if revoked is not None:
                raise OwnerAuthorityUnavailable("Team User Admin credential revoked")
            snapshot = OwnerVerifiedTeamSnapshot(
                owner="identity",
                caller_user_id=user.id,
                team_id=command.team_id,
                owner_revision=user.credential_version,
                active=True,
                role=cast(Literal["user", "superuser"], user.role),
                capabilities=(),
                epoch_components=(
                    str(user.id),
                    str(user.credential_version),
                    user.role,
                    "active",
                    delegated.admin_jti_digest,
                ),
            )
            return self.signer.sign_team(command, snapshot)
