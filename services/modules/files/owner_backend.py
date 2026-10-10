"""Briareus Files-owner durable adapter (one briareus_files local UoW).

This PRIVATE client translates existing FilesQuota-v2 DTOs into signed Files
owner commands. No Authorization-global file ledger or shared SQL session.
The owner verifies current three-source Identity/Control/Access fences again
inside EACH Files transaction before mutating its own quota/command/outbox.
"""

from __future__ import annotations

import hashlib
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict

from modules.project_runtime import ProjectInvocation
from modules.project_runtime.owner_effects import (
    OwnerEffectClient,
    OwnerEffectReply,
    OwnerEffectUnavailable,
)

from .a6_signed import (
    FilesCommittedObservation,
    FilesInspect,
    FilesQuotaReceipt,
    FilesRead,
    FilesReadPermit,
    FilesReserve,
    FilesSignedIntent,
    FilesTransition,
    VerifiedFilesPeer,
    files_payload_fingerprint,
    path_fingerprint,
)


class FilesOwnerInspection(BaseModel):
    """An absent ledger row does NOT certify an absent OS write."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    found: bool
    quota: FilesQuotaReceipt | None = None
    retry_allowed: Literal[False] = False


class FilesOwnerBackend:
    """Owner-only implementation of the existing signed FilesBackend port.

    OwnerEffectClient returns a *signed* envelope with the full FileQuota v2
    payload hash. Its owner_database must be briareus_files; its signer and
    service recipient are pinned and the original UUID/target path are bound.
    The A6 SignedFilesFlow checks the returned reserve/transition exact
    state+version. Both layers are required; neither receipt authorizes OS.
    """

    def __init__(self, effects: OwnerEffectClient) -> None:
        if not isinstance(effects, OwnerEffectClient):
            raise ValueError("Files owner requires trusted effects client")
        self.effects = effects

    @staticmethod
    def _scope(
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        payload: FilesReserve
        | FilesTransition
        | FilesCommittedObservation
        | FilesInspect
        | FilesRead,
        peer: VerifiedFilesPeer,
    ) -> None:
        if (
            intent.project_id != invocation.project_id
            or intent.session_uuid != invocation.session_uuid
            or intent.operation_uuid != payload.operation_uuid
            or intent.target_audience != "files"
            or intent.instance_uuid != peer.instance_uuid
            or intent.payload_sha256 != files_payload_fingerprint(payload)
            or intent.resource_id is not None
            or intent.operation
            != ("files.read" if isinstance(payload, FilesRead) else "files.write")
        ):
            raise OwnerEffectUnavailable("FILES_OWNER_A6_REQUEST_FINGERPRINT_MISMATCH")

    async def _execute[T: BaseModel](
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesReserve
        | FilesTransition
        | FilesCommittedObservation
        | FilesInspect
        | FilesRead,
        peer: VerifiedFilesPeer,
        phase: Literal[
            "read",
            "list",
            "metadata",
            "reserve",
            "dispatch",
            "finalize",
            "inspect",
            "reconcile",
            "release",
            "mark_unknown",
        ],
        expected: type[T],
        target: str,
        expected_version: int,
    ) -> OwnerEffectReply[T]:
        self._scope(invocation, intent=intent, payload=command, peer=peer)
        return await self.effects.execute(
            invocation,
            owner="files",
            phase=phase,
            action="files.read" if isinstance(command, FilesRead) else "files.write",
            target_sha256=(
                path_fingerprint(target)
                if target
                else hashlib.sha256(b"files-project-relative-v1\x00").hexdigest()
            ),
            payload=command,
            expected=expected,
            expected_version=expected_version,
            original_operation_uuid=command.operation_uuid,
            expected_service_id=peer.service_id,
            expected_instance_uuid=peer.instance_uuid,
        )

    async def reserve(
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesReserve,
        peer: VerifiedFilesPeer,
    ) -> FilesQuotaReceipt:
        result = await self._execute(
            invocation,
            intent=intent,
            command=command,
            peer=peer,
            phase="reserve",
            expected=FilesQuotaReceipt,
            target=command.destination,
            expected_version=0,
        )
        if result.attestation.receipt.state != "committed" or result.payload.status != "reserved":
            raise OwnerEffectUnavailable("FILES_OWNER_RESERVATION_NOT_COMMITTED", unknown=True)
        return result.payload

    async def transition(
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesTransition,
        peer: VerifiedFilesPeer,
    ) -> FilesQuotaReceipt:
        phases = {"dispatch": "dispatch", "release": "release", "unknown": "mark_unknown"}
        selected = cast(Literal["dispatch", "release", "mark_unknown"], phases[command.phase])
        result = await self._execute(
            invocation,
            intent=intent,
            command=command,
            peer=peer,
            phase=selected,
            expected=FilesQuotaReceipt,
            target=command.destination,
            expected_version=command.expected_version,
        )
        expected_state = {"dispatch": "dispatched", "release": "released", "unknown": "unknown"}[
            command.phase
        ]
        if (
            result.attestation.receipt.state != "committed"
            or result.payload.status != expected_state
        ):
            raise OwnerEffectUnavailable("FILES_OWNER_TRANSITION_STATE_MISMATCH", unknown=True)
        return result.payload

    async def complete(
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesCommittedObservation,
        peer: VerifiedFilesPeer,
    ) -> FilesQuotaReceipt:
        phase: Literal["finalize", "reconcile"] = command.phase
        result = await self._execute(
            invocation,
            intent=intent,
            command=command,
            peer=peer,
            phase=phase,
            expected=FilesQuotaReceipt,
            target=command.destination,
            expected_version=command.expected_version,
        )
        state = "released" if command.confirmed_absent else "committed"
        if result.attestation.receipt.state != "committed" or result.payload.status != state:
            raise OwnerEffectUnavailable("FILES_OWNER_FINALIZE_STATE_UNVERIFIED", unknown=True)
        return result.payload

    async def inspect(
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesInspect,
        peer: VerifiedFilesPeer,
    ) -> FilesQuotaReceipt | None:
        result = await self._execute(
            invocation,
            intent=intent,
            command=command,
            peer=peer,
            phase="inspect",
            expected=FilesOwnerInspection,
            target=command.destination,
            expected_version=0,
        )
        info = result.payload
        if not info.found:
            if info.quota is not None or result.attestation.receipt.state != "committed":
                raise OwnerEffectUnavailable("FILES_OWNER_INSPECT_ABSENCE_UNVERIFIED", unknown=True)
            return None
        if info.quota is None or info.quota.operation_uuid != command.operation_uuid:
            raise OwnerEffectUnavailable("FILES_OWNER_INSPECT_RECEIPT_INVALID", unknown=True)
        if result.attestation.receipt.state != "committed":
            raise OwnerEffectUnavailable("FILES_OWNER_INSPECT_LEDGER_STATE_MISMATCH", unknown=True)
        return info.quota

    async def issue_read_permit(
        self,
        invocation: ProjectInvocation,
        *,
        intent: FilesSignedIntent,
        command: FilesRead,
        peer: VerifiedFilesPeer,
    ) -> FilesReadPermit:
        result = await self._execute(
            invocation,
            intent=intent,
            command=command,
            peer=peer,
            phase=command.phase,
            expected=FilesReadPermit,
            target=command.path,
            expected_version=0,
        )
        if result.attestation.receipt.state != "committed":
            raise OwnerEffectUnavailable("FILES_OWNER_READ_SCOPE_NOT_VERIFIED")
        return result.payload
