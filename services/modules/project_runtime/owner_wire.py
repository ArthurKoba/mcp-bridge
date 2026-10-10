"""Accepted A11 owner source-command ABI, NOT a public RPC transport.

Only commands whose owner name, operation and business-body SHA preimage are
independently confirmed from the accepted Backend A11 owner source are mapped.
Missing owner-local APIs, signed native OS evidence, credential custody and
signed result JWS MUST DENY, not silently send a guessed generic operation.

The A11 command JSON is the canonical Pydantic `OwnerCommandDTO` metadata,
while `business_payload` is exactly the `require_signed_payload` dictionary
inside the accepted owner method. Those are DIFFERENT signed preimages from
the historical A6 `FilesSignedIntent` and the Runtime private effect envelope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

from .owner_authorization import VerifiedOwnerRecipient

A11EffectOwner = Literal["catalog", "files", "execution", "reverse"]

# The accepted A11 Backend SOURCE offers only these small subsets. A full
# external-effect lifecycle also needs a signed OS/native observation,
# UNKNOWN-inspect/reconcile, durable cleanup and per-owner signed result ACK.
# Do not make a Files socket/write or an Execution ACTIVE SQL lease merely
# because the RESERVE/OPEN method exists while the rest remains unaccepted.
_ACCEPTED_OWNER_PHASES: dict[A11EffectOwner, frozenset[str]] = {
    "catalog": frozenset(),
    "files": frozenset({"reserve", "dispatch"}),
    "execution": frozenset({"open", "heartbeat", "revoke"}),
    "reverse": frozenset(),
}
_REQUIRED_EFFECT_PHASES: dict[A11EffectOwner, frozenset[str]] = {
    "catalog": frozenset({"read", "reserve", "revoke", "reconcile"}),
    "files": frozenset({"reserve", "dispatch", "finalize", "inspect", "reconcile", "mark_unknown"}),
    "execution": frozenset(
        {"open", "heartbeat", "revoke", "queue_job", "start_job", "finish_job", "confirm_cleanup"}
    ),
    "reverse": frozenset({"claim", "dispatch", "inspect", "reconcile", "mark_unknown"}),
}


def require_accepted_owner_lifecycle(owner: A11EffectOwner) -> None:
    """Prevent irreversible action before complete accepted source lifecycle.

    This is a STATIC source-contract gate in addition to real signed C2 trust;
    no env boolean, caller-provided feature flag or fake SQL status can pass.
    An A12 source acceptance must update the implemented mapper AND accepted
    phase sets before any real owner effect can be enabled.
    """
    if (
        owner not in _ACCEPTED_OWNER_PHASES
        or not _REQUIRED_EFFECT_PHASES[owner] <= _ACCEPTED_OWNER_PHASES[owner]
    ):
        raise A11OwnerWireNotAccepted("A12_OWNER_COMPLETE_SIGNED_EFFECT_LIFECYCLE_REQUIRED")


class A11OwnerWireNotAccepted(ValueError):
    """No trusted accepted Backend source operation matches this command."""

    def __init__(self, code: str = "A11_OWNER_OPERATION_NOT_ACCEPTED") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class A11OwnerWire:
    operation: str
    business_payload: dict[str, object]
    # The backend signs/verifies each owner-local effect again; this structure
    # does NOT authenticate an arbitrary native OS observation or SQL row.


def _peer(peer: VerifiedOwnerRecipient) -> dict[str, str]:
    if (
        not isinstance(peer, VerifiedOwnerRecipient)
        or not isinstance(peer.service_id, UUID)
        or peer.service_id.version != 4
        or not isinstance(peer.instance_uuid, UUID)
        or peer.instance_uuid.version != 4
    ):
        raise A11OwnerWireNotAccepted("A11_OWNER_VERIFIED_PEER_REQUIRED")
    return {"service_id": str(peer.service_id), "instance_uuid": str(peer.instance_uuid)}


def accepted_a11_owner_wire(
    owner: A11EffectOwner,
    phase: str,
    payload: BaseModel,
    *,
    peer: VerifiedOwnerRecipient,
) -> A11OwnerWire:
    """Exact approved SOURCE subsets; all absent operations DENY BEFORE IO.

    Backend A11 currently has NO accepted recipient-bound signed owner result
    and no owner read/inspect bridge. Thus even recognized operations remain
    private/unmounted until A12 accepts final signed ACK/status and C2 peers.
    """
    if not isinstance(payload, BaseModel):
        raise A11OwnerWireNotAccepted("A11_OWNER_TYPED_PAYLOAD_REQUIRED")
    p = _peer(peer)
    # Lazy imports prevent a cyclic import: Files signed flow depends on the
    # private OwnerEffectClient, while this mapper is used by that client.
    if owner == "files":
        from modules.files.a6_signed import FilesReserve, FilesTransition, path_fingerprint

        if phase == "reserve" and isinstance(payload, FilesReserve):
            if payload.expected_file_version != 0 or payload.maximum_bytes > 262144:
                raise A11OwnerWireNotAccepted("A11_FILES_UNAPPROVED_OVERWRITE_OR_SIZE")
            return A11OwnerWire(
                "files.write.reserve",
                {
                    **p,
                    "path_digest": path_fingerprint(payload.destination),
                    "content_sha256": payload.expected_sha256,
                    "planned_bytes": payload.maximum_bytes,
                    "expected_file_version": payload.expected_file_version,
                    "ttl_seconds": 600,
                },
            )
        if phase == "dispatch" and isinstance(payload, FilesTransition):
            if payload.phase != "dispatch":
                raise A11OwnerWireNotAccepted("A11_FILES_DISPATCH_PHASE_MISMATCH")
            return A11OwnerWire(
                "files.write.dispatch",
                {
                    "reservation_id": str(payload.reservation_id),
                    "reservation_operation_uuid": str(payload.operation_uuid),
                    "expected_reservation_version": payload.expected_version,
                    **p,
                },
            )
        # A13 candidate SOURCE preimages, still denied by the accepted
        # full-lifecycle and Backend phase-contract gates until review.
        if phase in {"release", "mark_unknown"} and isinstance(payload, FilesTransition):
            required = "release" if phase == "release" else "unknown"
            if payload.phase != required:
                raise A11OwnerWireNotAccepted("A13_FILES_TRANSITION_PHASE_MISMATCH")
            return A11OwnerWire(
                f"files.write.{phase}",
                {
                    "reservation_id": str(payload.reservation_id),
                    "original_operation_uuid": str(payload.operation_uuid),
                    "expected_version": payload.expected_version,
                    **p,
                },
            )
        # Files reconcile requires native_evidence independently verified by
        # FilesOwnerSource, NOT just the client FilesCommittedObservation DTO.
        # No A11 Files read/list/info/inspect/abort API has been accepted.
        raise A11OwnerWireNotAccepted("A11_FILES_OWNER_PHASE_UNACCEPTED")

    if owner == "execution":
        from .a6_runtime import RuntimeLeaseCommand, RuntimeOpenCommand

        if phase == "open" and isinstance(payload, RuntimeOpenCommand):
            if payload.instance_uuid != peer.instance_uuid:
                raise A11OwnerWireNotAccepted("A11_RUNTIME_OWNER_INSTANCE_MISMATCH")
            return A11OwnerWire(
                "runtime.session.open",
                {
                    "runtime_session_uuid": str(payload.runtime_session_uuid),
                    **p,
                    "kind": payload.kind,
                    "idle_ttl_seconds": payload.idle_seconds,
                    "hard_ttl_seconds": payload.hard_seconds,
                },
            )
        if phase == "heartbeat" and isinstance(payload, RuntimeLeaseCommand):
            if payload.phase != "heartbeat":
                raise A11OwnerWireNotAccepted("A11_RUNTIME_HEARTBEAT_PHASE_INVALID")
            return A11OwnerWire(
                "runtime.session.renew",
                {
                    "runtime_session_uuid": str(payload.runtime_session_uuid),
                    "expected_version": payload.expected_version,
                    "expected_lease_nonce": str(payload.lease_nonce),
                    **p,
                },
            )
        if phase == "revoke" and isinstance(payload, RuntimeLeaseCommand):
            if payload.phase != "revoke":
                raise A11OwnerWireNotAccepted("A11_RUNTIME_REVOKE_PHASE_INVALID")
            # The Backend local SQL revoke checks service+instance+CAS only;
            # the Runtime consumer additionally requires a VERIFIED prior
            # owner nonce/short-lived lease before constructing this command.
            return A11OwnerWire(
                "runtime.session.revoke",
                {
                    "runtime_session_uuid": str(payload.runtime_session_uuid),
                    "expected_version": payload.expected_version,
                    **p,
                },
            )
        # Job queue/dispatch carries an OS effect and a separately accepted
        # SQL reservation/cgroup-proof protocol, not inferred from statuses.
        raise A11OwnerWireNotAccepted("A11_EXECUTION_JOB_PHASE_UNACCEPTED")

    if owner == "reverse":
        from modules.analysis.a6_native import NativeImportTransition

        if phase == "dispatch" and isinstance(payload, NativeImportTransition):
            if payload.phase != "dispatch":
                raise A11OwnerWireNotAccepted("A11_NATIVE_DISPATCH_PHASE_INVALID")
            return A11OwnerWire(
                "reverse.import.dispatch",
                {
                    "import_uuid": str(payload.import_uuid),
                    "original_operation_uuid": str(payload.operation_uuid),
                    "expected_import_version": payload.expected_version,
                    **p,
                },
            )
        # A13 candidate only: SQL cancellation is valid before dispatch;
        # UNKNOWN freezes a dispatched native effect under ORIGINAL UUID.
        if phase in {"cancel", "mark_unknown"} and isinstance(payload, NativeImportTransition):
            required = "cancel" if phase == "cancel" else "unknown"
            if payload.phase != required:
                raise A11OwnerWireNotAccepted("A13_NATIVE_TRANSITION_PHASE_MISMATCH")
            return A11OwnerWire(
                f"reverse.import.{phase}",
                {
                    "import_uuid": str(payload.import_uuid),
                    "original_operation_uuid": str(payload.operation_uuid),
                    "expected_version": payload.expected_version,
                    **p,
                },
            )
        # Native claim needs independently authenticated current Files source
        # revision; reconciliation needs independently signed Ghidra inventory.
        raise A11OwnerWireNotAccepted("A11_REVERSE_NATIVE_PROOF_UNACCEPTED")

    if owner == "catalog":
        from .catalog_owner import CatalogListRequest

        if phase == "read" and isinstance(payload, CatalogListRequest):
            if payload.limit > 100 or payload.scope != "all":
                raise A11OwnerWireNotAccepted("A11_CATALOG_READ_QUERY_UNSUPPORTED")
            name = "integrations" if payload.kind == "integration" else "variables"
            return A11OwnerWire(
                f"catalog.{name}.list",
                {"kind": name, "scope": payload.scope, "alias_key": None, "limit": payload.limit},
            )
        # Generic provider.read is NOT Catalog credential.reserve/redeem and
        # must not substitute for a one-use scoped secret custodian.
        raise A11OwnerWireNotAccepted("A11_CATALOG_ONE_USE_OPERATION_UNACCEPTED")

    raise A11OwnerWireNotAccepted
