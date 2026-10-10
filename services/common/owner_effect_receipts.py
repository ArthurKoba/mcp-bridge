"""Canonical R13 owner-effect response JWS from committed OWN source SQL.

No WS/projection/non-durable ACK may sign COMMITTED. Each attestation requires
one original owner-local command row, freshly checked three owner authorities,
verified recipient, source SQL target CAS and exact result payload hash.
No public transport: C1-B2/C2 physical signer custody remains unaccepted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import import_module
from typing import Literal, Protocol
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from common.owner_contracts import (
    CurrentOwnerAuthorityPort,
    OwnerAuthorityUnavailable,
    OwnerCommandDTO,
    OwnerProofAuthority,
    SignedOwnerProofs,
    VerifiedOwnerServicePeer,
    require_online_owner_decision,
    require_signed_payload,
)
from common.owner_effect_authorization import (
    CurrentEffectDecisionPort,
    OwnerEffectIntent,
    PinnedEffectOwnerPublicKeys,
    ProjectAction,
    _hash,
    verify_owner_effect_decision,
)
from common.owner_effect_phase_map import require_exact_owner_operation
from common.platform_db import OWNER_DB_NAMES, OwnerName, PlatformDatabase

EffectOwner = Literal["catalog", "files", "execution", "reverse"]
EffectPhase = Literal[
    "read",
    "list",
    "metadata",
    "file_dispatch",
    "file_reconcile",
    "reserve",
    "dispatch",
    "finalize",
    "inspect",
    "reconcile",
    "release",
    "claim",
    "cancel",
    "revoke",
    "open",
    "heartbeat",
    "queue_job",
    "start_job",
    "finish_job",
    "fail_job",
    "mark_unknown",
    "confirm_cleanup",
]
EffectState = Literal[
    "reserved",
    "dispatched",
    "unknown",
    "committed",
    "released",
    "active",
    "revoked",
    "closed",
    "running",
    "finished",
    "failed",
    "cancelled",
    "recorded",
    "absent",
]
_TARGET: dict[EffectOwner, OwnerName] = {
    "catalog": "resources",
    "files": "files",
    "execution": "runtime",
    "reverse": "reverse",
}
_ALLOWED_PHASES: dict[EffectOwner, frozenset[str]] = {
    "catalog": frozenset({"read", "inspect", "reserve", "revoke", "mark_unknown", "reconcile"}),
    "files": frozenset(
        {
            "read",
            "list",
            "metadata",
            "file_dispatch",
            "file_reconcile",
            "reserve",
            "dispatch",
            "finalize",
            "inspect",
            "reconcile",
            "release",
            "mark_unknown",
        }
    ),
    "execution": frozenset(
        {
            "open",
            "heartbeat",
            "queue_job",
            "start_job",
            "finish_job",
            "fail_job",
            "inspect",
            "revoke",
            "mark_unknown",
            "confirm_cleanup",
        }
    ),
    "reverse": frozenset({"claim", "dispatch", "inspect", "reconcile", "cancel", "mark_unknown"}),
}
# Original Runtime R13 receipt.phase->state contract. A phase not here is
# intentionally unimplemented until R14 freezes its actual target adapter.
_ALLOWED_ACK_STATES: dict[EffectOwner, dict[str, frozenset[EffectState]]] = {
    "catalog": {
        "read": frozenset({"recorded"}),
        "inspect": frozenset({"recorded"}),
        "reserve": frozenset({"reserved"}),
        "revoke": frozenset({"revoked"}),
    },
    "files": {
        "read": frozenset({"recorded"}),
        "list": frozenset({"recorded"}),
        "metadata": frozenset({"recorded"}),
        "reserve": frozenset({"reserved"}),
        "dispatch": frozenset({"dispatched"}),
        "finalize": frozenset({"committed"}),
        "reconcile": frozenset({"committed", "released", "unknown"}),
        "inspect": frozenset({"recorded", "unknown"}),
        "release": frozenset({"released"}),
        "mark_unknown": frozenset({"unknown"}),
    },
    "execution": {
        "open": frozenset({"active"}),
        "heartbeat": frozenset({"active"}),
        "queue_job": frozenset({"recorded"}),
        "start_job": frozenset({"running"}),
        "finish_job": frozenset({"finished"}),
        "fail_job": frozenset({"failed"}),
        "revoke": frozenset({"revoked"}),
        "confirm_cleanup": frozenset({"closed"}),
    },
    "reverse": {
        "claim": frozenset({"reserved"}),
        "dispatch": frozenset({"dispatched"}),
        "reconcile": frozenset({"committed", "absent", "unknown"}),
        "cancel": frozenset({"cancelled"}),
    },
}


# Only these owner SQL statuses normalize to Runtime v1 receipt states.
# SQL `queued` is a recorded reservation, NEVER evidence of native execution.
_SOURCE_RECEIPT_STATES: dict[tuple[EffectOwner, str, str], EffectState] = {
    ("execution", "queue_job", "queued"): "recorded",
    ("execution", "finish_job", "succeeded"): "finished",
    ("reverse", "reconcile", "succeeded"): "committed",
    ("reverse", "reconcile", "confirmed_absent"): "absent",
}


_LEDGER_MODULE: dict[EffectOwner, str] = {
    "catalog": "projects._catalog_ledger",
    "files": "projects._files_ledger",
    "execution": "projects._execution_ledger",
    "reverse": "projects._reverse_ledger",
}


def _v4(value: UUID) -> bool:
    return isinstance(value, UUID) and value.version == 4


class OwnerEffectFence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    identity_version: int = Field(ge=1)
    identity_revocation_epoch: int = Field(ge=0)
    identity_authority_epoch: UUID
    control_state_version: int = Field(ge=1)
    control_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    control_scope_epoch: int = Field(ge=0)
    control_authority_epoch: UUID
    access_session_version: int = Field(ge=1)
    access_revocation_epoch: int = Field(ge=0)
    access_authority_epoch: UUID


class OwnerEffectCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    protocol: Literal["owner-effect-command-v1"] = "owner-effect-command-v1"
    owner: EffectOwner
    owner_database: Literal[
        "briareus_resources", "briareus_files", "briareus_runtime", "briareus_reverse"
    ]
    phase: EffectPhase
    action: ProjectAction
    operation_uuid: UUID
    idempotency_uuid: UUID
    project_id: UUID
    agent_session_uuid: UUID
    actor_id: UUID
    recipient_service_id: UUID
    recipient_instance_uuid: UUID
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload_type: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,95}$")
    expected_version: int = Field(ge=0)
    fence: OwnerEffectFence

    @model_validator(mode="after")
    def validate_owner(self) -> OwnerEffectCommand:
        if (
            self.owner_database != OWNER_DB_NAMES[_TARGET[self.owner]]
            or self.phase not in _ALLOWED_PHASES[self.owner]
            or not all(
                _v4(x)
                for x in (
                    self.operation_uuid,
                    self.idempotency_uuid,
                    self.agent_session_uuid,
                    self.recipient_service_id,
                    self.recipient_instance_uuid,
                )
            )
            or self.operation_uuid != self.idempotency_uuid
        ):
            raise ValueError("effect command phase/owner/original UUID invalid")
        return self


class OwnerEffectReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    protocol: Literal["owner-effect-receipt-v1"] = "owner-effect-receipt-v1"
    owner: EffectOwner
    owner_database: Literal[
        "briareus_resources", "briareus_files", "briareus_runtime", "briareus_reverse"
    ]
    recipient_service_id: UUID
    recipient_instance_uuid: UUID
    project_id: UUID
    actor_id: UUID
    agent_session_uuid: UUID
    operation_uuid: UUID
    idempotency_uuid: UUID
    action: ProjectAction
    phase: EffectPhase
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    result_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_revision: int = Field(ge=1)
    state: EffectState
    fence: OwnerEffectFence
    expires_at: datetime
    acknowledged_at: datetime

    @model_validator(mode="after")
    def verify_scope(self) -> OwnerEffectReceipt:
        if (
            self.owner_database != OWNER_DB_NAMES[_TARGET[self.owner]]
            or self.phase not in _ALLOWED_PHASES[self.owner]
            or not all(
                _v4(x)
                for x in (
                    self.recipient_service_id,
                    self.recipient_instance_uuid,
                    self.agent_session_uuid,
                    self.operation_uuid,
                    self.idempotency_uuid,
                )
            )
            or self.operation_uuid != self.idempotency_uuid
            or self.expires_at.tzinfo is None
            or self.acknowledged_at.tzinfo is None
            or self.acknowledged_at > datetime.now(UTC)
        ):
            raise ValueError("owner receipt scope/provenance invalid")
        return self


class SignedOwnerEffectReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    receipt: OwnerEffectReceipt
    attestation_jws: str = Field(min_length=100, max_length=8192)


async def require_fresh_effect_fence(
    *,
    command: OwnerEffectCommand,
    recipient: VerifiedOwnerServicePeer,
    decisions: CurrentEffectDecisionPort,
    keys: PinnedEffectOwnerPublicKeys,
) -> None:
    """Three *new-v1* signed SOURCE decisions; never compare A11 epoch space."""
    intent = OwnerEffectIntent(
        project_id=command.project_id,
        actor_id=command.actor_id,
        session_uuid=command.agent_session_uuid,
        operation_uuid=command.operation_uuid,
        request_sha256=command.request_sha256,
        action=command.action,
        recipient_service_id=recipient.service_id,
        recipient_instance_uuid=recipient.instance_uuid,
    )
    states = {}
    for source_owner in ("identity", "platform", "access"):
        try:
            attested = await decisions.fresh(source_owner, intent=intent, recipient=recipient)
            states[source_owner] = verify_owner_effect_decision(
                attested,
                owner=source_owner,
                pinned_key=keys.owner_key(source_owner),
                intent=intent,
                recipient=recipient,
            )
        except Exception:
            raise OwnerAuthorityUnavailable("fresh owner state not signed or trusted") from None
    identity = states["identity"]
    control = states["platform"]
    access = states["access"]
    f = command.fence
    if (
        command.action not in control.granted_actions
        or command.action not in access.granted_actions
        or control.project_revision != f.control_revision
        or access.session_hard_expires_at is None
        or access.session_hard_expires_at <= datetime.now(UTC)
        or f.identity_version != identity.state_version
        or f.identity_revocation_epoch != identity.revoke_epoch
        or f.identity_authority_epoch != identity.authority_epoch
        or f.control_state_version != control.state_version
        or f.control_scope_epoch != control.revoke_epoch
        or f.control_authority_epoch != control.authority_epoch
        or f.access_session_version != access.state_version
        or f.access_revocation_epoch != access.revoke_epoch
        or f.access_authority_epoch != access.authority_epoch
    ):
        raise OwnerAuthorityUnavailable("owner EFFECT fence stale/permission revoked")


@dataclass(frozen=True, slots=True)
class VerifiedOwnerTargetObservation:
    """From SAME owner-local transaction with independently checked target.

    Durable SQL state is not by itself native OS/Ghidra/Files observation.
    An adapter must explicitly attest a native effect before asserting the
    resulting physical `committed`/`finished`/`closed` status.
    """

    operation_uuid: UUID
    target_sha256: str
    owner_revision: int
    state: EffectState
    native_effect_verified: bool = False


_NATIVE_EFFECT_STATES = frozenset({"committed", "finished", "failed", "closed", "absent"})


class OwnerTargetCASPort(Protocol):
    async def verify_current_target(
        self,
        tx: AsyncSession,
        *,
        command: OwnerEffectCommand,
        source_command: OwnerCommandDTO,
        stored_result: dict[str, object] | None,
    ) -> VerifiedOwnerTargetObservation:
        """Read authoritative target row/nonce/version in SAME owner DB tx.

        Deny mismatched target SHA, tombstone, retention or revision. No
        mTLS/HTTP/network lookup may occur inside owner SQL session.
        """
        ...


class OwnerEffectReceiptAttestor:
    """Private owner signer bound to durable command SQL and target CAS."""

    def __init__(
        self,
        *,
        owner: EffectOwner,
        database: PlatformDatabase,
        key_pem: SecretStr,
        current_authority: CurrentOwnerAuthorityPort,
        proof_verifier: OwnerProofAuthority,
        effect_decisions: CurrentEffectDecisionPort,
        pinned_effect_keys: PinnedEffectOwnerPublicKeys,
        target_cas: OwnerTargetCASPort,
        cipher_key: SecretStr,
    ) -> None:
        from cryptography.fernet import Fernet

        if (
            database.engine.url.database != OWNER_DB_NAMES[_TARGET[owner]]
            or current_authority is None
            or proof_verifier is None
            or effect_decisions is None
            or pinned_effect_keys is None
            or target_cas is None
        ):
            raise RuntimeError("owner effect signing requires OWN SQL, current C2 and target CAS")
        try:
            key = serialization.load_pem_private_key(
                key_pem.get_secret_value().encode(), password=None
            )
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("Ed25519 owner signing key required")
            cipher = Fernet(cipher_key.get_secret_value().encode())
        except (ValueError, TypeError):
            raise ValueError("owner effect signer/response encryption keys invalid") from None
        self.owner = owner
        self.database = database
        self._key = key
        self._cipher = cipher
        self._kid = _hash(
            key.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )
        # JOSE kid MUST be sha256(raw public key), NOT a JSON hex digest.
        import hashlib

        self._kid = hashlib.sha256(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).hexdigest()
        self._current = current_authority
        self._proofs = proof_verifier
        self._cas = target_cas
        self._effect_decisions = effect_decisions
        self._effect_keys = pinned_effect_keys
        self._row = import_module(_LEDGER_MODULE[owner]).OwnerCommandRow

    async def attest_committed(
        self,
        *,
        command: OwnerEffectCommand,
        source_command: OwnerCommandDTO,
        source_proofs: SignedOwnerProofs,
        recipient: VerifiedOwnerServicePeer,
        request_payload: BaseModel,
        business_payload: dict[str, object],
        result_payload: BaseModel,
    ) -> SignedOwnerEffectReceipt:
        """Never signs a caller assertion; checks committed encrypted owner row."""
        now = datetime.now(UTC)
        original = self._proofs.require_current(source_command, source_proofs)
        current = await require_online_owner_decision(self._proofs, self._current, source_command)
        if (
            original.identity_epoch != current.identity_epoch
            or original.control_epoch != current.control_epoch
            or original.access_epoch != current.access_epoch
            or original.actor_role != current.actor_role
        ):
            raise OwnerAuthorityUnavailable("revoke fences changed since signed owner command")
        if (
            command.owner != self.owner
            or source_command.target_owner != _TARGET[self.owner]
            or source_command.operation_uuid != command.operation_uuid
            or source_command.idempotency_key != str(command.operation_uuid)
            or source_command.caller_user_id != command.actor_id
            or source_command.project_id != command.project_id
            or source_command.session_uuid != command.agent_session_uuid
            or recipient.service_id != command.recipient_service_id
            or recipient.instance_uuid != command.recipient_instance_uuid
            or recipient.expires_at <= now
            or not isinstance(request_payload, BaseModel)
            or type(request_payload).__name__ != command.payload_type
            or source_command.payload_sha256 != _hash(business_payload)
            or command.payload_sha256
            != _hash(
                {
                    "owner": self.owner,
                    "phase": command.phase,
                    "command": type(request_payload).__name__,
                    "body": request_payload.model_dump(mode="json"),
                }
            )
            or not isinstance(result_payload, BaseModel)
        ):
            raise OwnerAuthorityUnavailable("original owner effect/request/source scope mismatch")
        require_exact_owner_operation(
            owner=self.owner,
            phase=command.phase,
            payload_type=command.payload_type,
            operation=source_command.operation,
        )
        # The source-owned business JSON is NOT the Runtime envelope body.
        # Its canonical SHA is the fingerprint persisted by the owner.
        require_signed_payload(source_command, business_payload)
        # New R13 canonical JWS epochs are distinct from A11 internal
        # owner-local command JWT epochs. Both must be freshly checked; they
        # are NOT interchangeable. A cached R13 permit never mints a receipt.
        effect_intent = OwnerEffectIntent(
            project_id=command.project_id,
            actor_id=command.actor_id,
            session_uuid=command.agent_session_uuid,
            operation_uuid=command.operation_uuid,
            request_sha256=command.request_sha256,
            action=command.action,
            recipient_service_id=recipient.service_id,
            recipient_instance_uuid=recipient.instance_uuid,
        )
        effect_states = {}
        for source_owner in ("identity", "platform", "access"):
            try:
                signed_decision = await self._effect_decisions.fresh(
                    source_owner, intent=effect_intent, recipient=recipient
                )
                owner_key = self._effect_keys.owner_key(source_owner)
                effect_states[source_owner] = verify_owner_effect_decision(
                    signed_decision,
                    owner=source_owner,
                    pinned_key=owner_key,
                    intent=effect_intent,
                    recipient=recipient,
                )
            except Exception:
                raise OwnerAuthorityUnavailable(
                    "current pinned Identity/Control/Access effect receipt fence unavailable"
                ) from None
        identity = effect_states["identity"]
        control = effect_states["platform"]
        access = effect_states["access"]
        if (
            command.action not in control.granted_actions
            or command.action not in access.granted_actions
            or control.project_revision != command.fence.control_revision
            or access.session_hard_expires_at is None
            or access.session_hard_expires_at <= datetime.now(UTC)
        ):
            raise OwnerAuthorityUnavailable("current source owner Project or Access action denied")
        fence = command.fence
        if (
            fence.identity_version != identity.state_version
            or fence.identity_revocation_epoch != identity.revoke_epoch
            or fence.identity_authority_epoch != identity.authority_epoch
            or fence.control_state_version != control.state_version
            or fence.control_scope_epoch != control.revoke_epoch
            or fence.control_authority_epoch != control.authority_epoch
            or fence.access_session_version != access.state_version
            or fence.access_revocation_epoch != access.revoke_epoch
            or fence.access_authority_epoch != access.authority_epoch
        ):
            raise OwnerAuthorityUnavailable("effect CAS fence not signed by all current owners")
        if (
            fence.identity_version != source_command.expected_identity_revision
            or fence.control_state_version != source_command.expected_control_revision
            or fence.access_session_version != source_command.expected_access_revision
        ):
            raise OwnerAuthorityUnavailable("effect fence diverges from current owner source")
        async with self.database.transaction() as tx:
            row = await tx.scalar(
                select(self._row)
                .where(
                    self._row.operation_uuid == command.operation_uuid,
                    self._row.actor_scope == str(command.actor_id),
                    self._row.project_scope == str(command.project_id),
                    self._row.operation == source_command.operation,
                    self._row.key == source_command.idempotency_key,
                )
                .with_for_update()
            )
            if (
                row is None
                or row.state != "completed"
                or row.encrypted_outcome is None
                or row.fingerprint != source_command.payload_sha256
            ):
                raise OwnerAuthorityUnavailable("owner transaction not durably committed")
            try:
                stored = json.loads(self._cipher.decrypt(row.encrypted_outcome.encode()))
            except Exception:
                raise OwnerAuthorityUnavailable("owner response encryption proof invalid") from None
            if not isinstance(stored, dict) or stored != result_payload.model_dump(mode="json"):
                raise OwnerAuthorityUnavailable("owner COMMITTED response differs from durable SQL")
            observed = await self._cas.verify_current_target(
                tx,
                command=command,
                source_command=source_command,
                stored_result=stored,
            )
            if (
                not isinstance(observed, VerifiedOwnerTargetObservation)
                or observed.operation_uuid != command.operation_uuid
                or observed.target_sha256 != command.target_sha256
                or type(observed.owner_revision) is not int
                or observed.owner_revision < max(1, command.expected_version)
                or observed.state not in _ALLOWED_ACK_STATES[self.owner].get(command.phase, ())
                or (
                    (
                        observed.state in _NATIVE_EFFECT_STATES
                        or (
                            self.owner == "files"
                            and command.phase == "reconcile"
                            and observed.state == "released"
                        )
                    )
                    and self.owner in {"files", "execution", "reverse"}
                    and not observed.native_effect_verified
                )
            ):
                raise OwnerAuthorityUnavailable("owner native/CAS/state receipt not proven")
            claimed_status = stored.get("status")
            if isinstance(claimed_status, str):
                signed_state = _SOURCE_RECEIPT_STATES.get(
                    (self.owner, command.phase, claimed_status), claimed_status
                )
                if signed_state != observed.state:
                    raise OwnerAuthorityUnavailable(
                        "owner SQL status contradicts verified owner receipt state"
                    )
            committed_at = datetime.now(UTC)
        last = await require_online_owner_decision(self._proofs, self._current, source_command)
        if (
            last.identity_epoch != current.identity_epoch
            or last.control_epoch != current.control_epoch
            or last.access_epoch != current.access_epoch
        ):
            raise OwnerAuthorityUnavailable("owner source revoked before attesting SQL receipt")
        candidate = min(committed_at + timedelta(seconds=30), recipient.expires_at)
        expires = datetime.fromtimestamp(int(candidate.timestamp()), UTC)
        if expires <= datetime.now(UTC):
            raise OwnerAuthorityUnavailable("owner signed result cannot outlive recipient")
        receipt = OwnerEffectReceipt(
            owner=self.owner,
            owner_database=command.owner_database,
            recipient_service_id=recipient.service_id,
            recipient_instance_uuid=recipient.instance_uuid,
            project_id=command.project_id,
            actor_id=command.actor_id,
            agent_session_uuid=command.agent_session_uuid,
            operation_uuid=command.operation_uuid,
            idempotency_uuid=command.idempotency_uuid,
            action=command.action,
            phase=command.phase,
            request_sha256=command.request_sha256,
            target_sha256=command.target_sha256,
            payload_sha256=command.payload_sha256,
            result_sha256=_hash(result_payload.model_dump(mode="json")),
            owner_revision=observed.owner_revision,
            state=observed.state,
            fence=fence,
            expires_at=expires,
            acknowledged_at=committed_at,
        )
        claims = {
            "iss": f"briareus-{_TARGET[self.owner]}",
            "aud": f"owner-effect:{recipient.service_id}",
            "iat": int(committed_at.timestamp()),
            "nbf": int(committed_at.timestamp()),
            "exp": int(expires.timestamp()),
            "purpose": "owner-effect-receipt-v1",
            "jti": str(uuid4()),
            "receipt": receipt.model_dump(mode="json"),
        }
        token = jwt.encode(
            claims,
            self._key,
            algorithm="EdDSA",
            headers={"typ": "briareus-owner-effect+jwt", "kid": self._kid},
        )
        return SignedOwnerEffectReceipt(receipt=receipt, attestation_jws=token)


def verify_signed_owner_effect_receipt(
    signed: SignedOwnerEffectReceipt,
    *,
    pinned_key: Ed25519PublicKey,
    command: OwnerEffectCommand,
    recipient: VerifiedOwnerServicePeer,
    result_payload: BaseModel,
) -> OwnerEffectReceipt:
    """Runtime-v1 compatible pure receipt verifier; never a current grant."""
    import hashlib

    try:
        header = jwt.get_unverified_header(signed.attestation_jws)
        kid = hashlib.sha256(
            pinned_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).hexdigest()
        if (
            header.get("alg") != "EdDSA"
            or header.get("typ") != "briareus-owner-effect+jwt"
            or header.get("kid") != kid
            or header.get("crit")
        ):
            raise OwnerAuthorityUnavailable("effect signer not pinned")
        claims = jwt.decode(
            signed.attestation_jws,
            pinned_key,
            algorithms=["EdDSA"],
            issuer=f"briareus-{_TARGET[command.owner]}",
            audience=f"owner-effect:{recipient.service_id}",
            leeway=0,
            options={"require": ["iss", "aud", "iat", "nbf", "exp", "jti", "purpose", "receipt"]},
        )
        signed_value = OwnerEffectReceipt.model_validate_json(
            json.dumps(claims["receipt"], sort_keys=True, separators=(",", ":"), allow_nan=False)
        )
        r = signed.receipt
        if (
            UUID(claims["jti"]).version != 4
            or claims["purpose"] != "owner-effect-receipt-v1"
            or not 0 < claims["exp"] - claims["iat"] <= 30
            or r != signed_value
            or r.owner != command.owner
            or r.owner_database != command.owner_database
            or r.recipient_service_id != recipient.service_id
            or r.recipient_instance_uuid != recipient.instance_uuid
            or r.project_id != command.project_id
            or r.actor_id != command.actor_id
            or r.agent_session_uuid != command.agent_session_uuid
            or r.operation_uuid != command.operation_uuid
            or r.idempotency_uuid != command.idempotency_uuid
            or r.action != command.action
            or r.phase != command.phase
            or r.request_sha256 != command.request_sha256
            or r.target_sha256 != command.target_sha256
            or r.payload_sha256 != command.payload_sha256
            or r.fence != command.fence
            or r.result_sha256 != _hash(result_payload.model_dump(mode="json"))
            or r.owner_revision < command.expected_version
            or r.expires_at <= datetime.now(UTC)
            or r.expires_at > recipient.expires_at
            or r.expires_at > datetime.fromtimestamp(claims["exp"], UTC)
        ):
            raise OwnerAuthorityUnavailable("owner effect receipt scope/CAS mismatch")
        return r
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, ValidationError):
        raise OwnerAuthorityUnavailable("owner effect signed receipt invalid") from None
