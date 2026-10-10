"""Private source-owner Ed25519 producer; no public token minting API.

Only a trusted owner service may pass snapshots obtained from its own live
SQL authority. This is not a caller/admin-provided role or capability switch.
Issuer activation requires independent TLS/Unix peer and C1-B2/C2 review.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from common.owner_contracts import OwnerAuthorityUnavailable, OwnerCommandDTO
from common.owner_team_contracts import TeamOwnerCommandDTO
from common.platform_db import OWNER_DB_NAMES

Authority = Literal["identity", "platform", "access"]


@dataclass(frozen=True, slots=True)
class OwnerVerifiedSourceSnapshot:
    """Construct only AFTER owner-local DB and verified private caller read."""

    owner: Authority
    caller_user_id: UUID
    project_id: UUID
    agent_session_uuid: UUID
    owner_revision: int
    active: bool
    role: Literal["user", "superuser"] | None
    capabilities: tuple[str, ...]
    control_resource_revision: int | None
    project_lifecycle: Literal["active", "deleting", "deleted"] | None
    team_id: UUID | None
    team_revision: int | None
    team_resource_revision: int | None
    # Stable source row versions + active flags + membership epoch, NOT a
    # random UUID generated independently on each fresh proof request.
    epoch_components: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OwnerVerifiedTeamSnapshot:
    """Typed live Team-scope owner read; never map Team ID into Project ID."""

    owner: Authority
    caller_user_id: UUID
    team_id: UUID
    owner_revision: int
    active: bool
    role: Literal["user", "superuser"] | None
    capabilities: tuple[str, ...]
    epoch_components: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OwnerVerifiedTargetIdentitySnapshot:
    """Fresh authoritative Identity status of Team membership target."""

    team_id: UUID
    target_user_id: UUID
    enabled: bool
    credential_version: int
    operation_uuid: UUID


class SourceOwnerSigner:
    def __init__(
        self,
        *,
        owner: Authority,
        issuer: str,
        key_id: str,
        signing_key_pem: SecretStr,
    ) -> None:
        if not issuer.startswith("briareus:") or not key_id or len(key_id) > 128:
            raise ValueError("owner service issuer/key must come from approved release")
        try:
            key = serialization.load_pem_private_key(
                signing_key_pem.get_secret_value().encode(), password=None
            )
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("source owner signer must be Ed25519")
            material = key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        except (ValueError, TypeError):
            raise ValueError("owner signing key is invalid or not Ed25519") from None
        # Domain separation: a keyed epoch must not be usable as an EdDSA
        # signature or as a credential ciphertext/replay MAC.
        self._epoch_key = hashlib.sha256(
            b"briareus.owner-epoch.v1:" + owner.encode() + material
        ).digest()
        self._key = key
        self._owner = owner
        self._issuer = issuer
        self._key_id = key_id

    def _epoch(self, snapshot: OwnerVerifiedSourceSnapshot) -> UUID:
        if not snapshot.epoch_components or any(not part for part in snapshot.epoch_components):
            raise OwnerAuthorityUnavailable("source owner did not attest current row epochs")
        payload = json.dumps(
            (
                self._owner,
                str(snapshot.caller_user_id),
                str(snapshot.project_id),
                str(snapshot.agent_session_uuid),
                snapshot.owner_revision,
                snapshot.active,
                snapshot.epoch_components,
            ),
            separators=(",", ":"),
        ).encode()
        raw = bytearray(hmac.new(self._epoch_key, payload, hashlib.sha256).digest()[:16])
        # Deterministic version-4-shaped opaque fencing UUID: changes when
        # any current authoritative version changes. It is NOT an auth token.
        raw[6] = (raw[6] & 0x0F) | 0x40
        raw[8] = (raw[8] & 0x3F) | 0x80
        return UUID(bytes=bytes(raw))

    def _team_epoch(self, snapshot: OwnerVerifiedTeamSnapshot) -> UUID:
        if not snapshot.epoch_components or any(not part for part in snapshot.epoch_components):
            raise OwnerAuthorityUnavailable(
                "Team signer missing source-verified version components"
            )
        raw_payload = json.dumps(
            (
                "briareus.team-authority.v1",
                self._owner,
                str(snapshot.team_id),
                str(snapshot.caller_user_id),
                snapshot.owner_revision,
                snapshot.active,
                snapshot.epoch_components,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        raw = bytearray(hmac.new(self._epoch_key, raw_payload, hashlib.sha256).digest()[:16])
        raw[6] = (raw[6] & 0x0F) | 0x40
        raw[8] = (raw[8] & 0x3F) | 0x80
        return UUID(bytes=bytes(raw))

    def sign_team(
        self,
        command: TeamOwnerCommandDTO,
        snapshot: OwnerVerifiedTeamSnapshot,
    ) -> SecretStr:
        if (
            snapshot.owner != self._owner
            or snapshot.caller_user_id != command.caller_user_id
            or snapshot.team_id != command.team_id
            or not snapshot.active
            or snapshot.caller_user_id.version != 4
            or snapshot.team_id.version != 4
        ):
            raise OwnerAuthorityUnavailable(
                "Team issuer source scope does not match signed command"
            )
        expected = {
            "identity": command.expected_identity_revision,
            "platform": command.expected_team_revision,
            "access": command.expected_access_revision,
        }[self._owner]
        if snapshot.owner_revision != expected:
            raise OwnerAuthorityUnavailable("Team issuer current revision not attested")
        if self._owner == "identity" and snapshot.role not in {"user", "superuser"}:
            raise OwnerAuthorityUnavailable("Team actor Identity role unavailable")
        if self._owner != "identity" and command.operation not in snapshot.capabilities:
            raise OwnerAuthorityUnavailable("Team capability not granted by current owner")
        now = int(datetime.now(UTC).timestamp())
        claims = {
            "iss": self._issuer,
            "aud": "briareus:platform",
            "sub": str(command.caller_user_id),
            "owner": self._owner,
            "owner_database": OWNER_DB_NAMES[self._owner],
            "operation_uuid": str(command.operation_uuid),
            "team_id": str(command.team_id),
            "caller_user_id": str(command.caller_user_id),
            "operation": command.operation,
            "idempotency_key": command.idempotency_key,
            "payload_sha256": command.payload_sha256,
            "active": True,
            "role": snapshot.role,
            "capabilities": list(snapshot.capabilities),
            "owner_revision": snapshot.owner_revision,
            "authority_epoch": str(self._team_epoch(snapshot)),
            "iat": now,
            "nbf": now,
            "exp": now + 20,
        }
        return SecretStr(
            jwt.encode(claims, self._key, algorithm="EdDSA", headers={"kid": self._key_id})
        )

    def sign_target_team_identity(
        self,
        command: TeamOwnerCommandDTO,
        snapshot: OwnerVerifiedTargetIdentitySnapshot,
    ) -> SecretStr:
        if self._owner != "identity":
            raise OwnerAuthorityUnavailable("only current Identity may sign a Team target User")
        if (
            snapshot.operation_uuid != command.operation_uuid
            or snapshot.team_id != command.team_id
            or snapshot.target_user_id.version != 4
            or not snapshot.enabled
            or snapshot.credential_version < 1
        ):
            raise OwnerAuthorityUnavailable("Team target User status was not current/active")
        now = int(datetime.now(UTC).timestamp())
        claims = {
            "iss": self._issuer,
            "aud": "briareus:platform",
            "sub": str(snapshot.target_user_id),
            "owner": "identity",
            "owner_database": "briareus_identity",
            "operation_uuid": str(command.operation_uuid),
            "team_id": str(command.team_id),
            "target_user_id": str(snapshot.target_user_id),
            "enabled": True,
            "credential_version": snapshot.credential_version,
            "iat": now,
            "nbf": now,
            "exp": now + 15,
        }
        return SecretStr(
            jwt.encode(claims, self._key, algorithm="EdDSA", headers={"kid": self._key_id})
        )

    def sign_project(
        self,
        command: OwnerCommandDTO,
        snapshot: OwnerVerifiedSourceSnapshot,
    ) -> SecretStr:
        if (
            snapshot.owner != self._owner
            or not snapshot.active
            or snapshot.caller_user_id != command.caller_user_id
            or snapshot.project_id != command.project_id
            or snapshot.agent_session_uuid != command.session_uuid
        ):
            raise OwnerAuthorityUnavailable("owner signer source snapshot provenance mismatch")
        expected = {
            "identity": command.expected_identity_revision,
            "platform": command.expected_control_revision,
            "access": command.expected_access_revision,
        }[self._owner]
        if snapshot.owner_revision != expected:
            raise OwnerAuthorityUnavailable("owner signer source revision does not match intent")
        if self._owner == "identity" and snapshot.role not in {"user", "superuser"}:
            raise OwnerAuthorityUnavailable("identity signer requires current User role")
        if self._owner == "platform" and (
            snapshot.control_resource_revision != command.expected_control_resource_revision
            or snapshot.team_revision != command.expected_team_revision
            or snapshot.team_resource_revision != command.expected_team_resource_revision
            or snapshot.project_lifecycle
            != ("deleting" if command.operation == "project.delete.confirm" else "active")
        ):
            raise OwnerAuthorityUnavailable("Control source Project lifecycle/version mismatch")
        if self._owner != "identity" and command.operation not in snapshot.capabilities:
            raise OwnerAuthorityUnavailable("signed owner capability absent in current source")
        now = int(datetime.now(UTC).timestamp())
        claims = {
            "iss": self._issuer,
            "aud": f"briareus:{command.target_owner}",
            "sub": str(command.caller_user_id),
            "owner": self._owner,
            "owner_database": OWNER_DB_NAMES[self._owner],
            "operation_uuid": str(command.operation_uuid),
            "caller_user_id": str(command.caller_user_id),
            "project_id": str(command.project_id),
            "session_uuid": str(command.session_uuid),
            "operation": command.operation,
            "idempotency_key": command.idempotency_key,
            "payload_sha256": command.payload_sha256,
            "active": True,
            "role": snapshot.role,
            "capabilities": list(snapshot.capabilities),
            "owner_revision": snapshot.owner_revision,
            "control_resource_revision": snapshot.control_resource_revision,
            "project_lifecycle": snapshot.project_lifecycle,
            "team_id": str(snapshot.team_id) if snapshot.team_id else None,
            "team_revision": snapshot.team_revision,
            "team_resource_revision": snapshot.team_resource_revision,
            "authority_epoch": str(self._epoch(snapshot)),
            "iat": now,
            "nbf": now,
            "exp": now + int(timedelta(seconds=20).total_seconds()),
        }
        return SecretStr(
            jwt.encode(claims, self._key, algorithm="EdDSA", headers={"kid": self._key_id})
        )
