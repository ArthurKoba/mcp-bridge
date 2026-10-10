"""Canonical A13 owner-local phase/payload/SQL ABI for the R15 private consumer.

This strict registry only identifies *source-owned* methods. It does not
authorize physical effects, guess SQL operation names or mint keys/proofs.
The original UUID and Idempotency-Key remain unchanged across phases; every
method independently validates its source-owned canonical business digest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from common.owner_contracts import OwnerAuthorityUnavailable

EffectOwner = Literal["catalog", "files", "execution", "reverse"]


@dataclass(frozen=True, slots=True)
class OwnerPhaseBinding:
    owner: EffectOwner
    phase: str
    payload_type: str
    operations: frozenset[str]
    source_method: str
    native_required: bool = False
    metadata_only: bool = False


_BINDINGS: tuple[OwnerPhaseBinding, ...] = (
    OwnerPhaseBinding(
        "files",
        "reserve",
        "FilesReserve",
        frozenset({"files.write.reserve"}),
        "FilesOwnerSource.reserve_write",
    ),
    OwnerPhaseBinding(
        "files",
        "dispatch",
        "FilesTransition",
        frozenset({"files.write.dispatch"}),
        "FilesOwnerSource.mark_dispatched",
    ),
    OwnerPhaseBinding(
        "files",
        "finalize",
        "FilesCommittedObservation",
        frozenset({"files.write.finalize"}),
        "FilesOwnerSource.reconcile_write",
        True,
    ),
    OwnerPhaseBinding(
        "files",
        "reconcile",
        "FilesCommittedObservation",
        frozenset({"files.write.reconcile"}),
        "FilesOwnerSource.reconcile_write",
        True,
    ),
    OwnerPhaseBinding(
        "files",
        "release",
        "FilesTransition",
        frozenset({"files.write.release"}),
        "FilesOwnerLifecycle.release_undispatched",
    ),
    OwnerPhaseBinding(
        "files",
        "mark_unknown",
        "FilesTransition",
        frozenset({"files.write.mark_unknown"}),
        "FilesOwnerLifecycle.mark_unknown",
    ),
    OwnerPhaseBinding(
        "files",
        "inspect",
        "FilesInspect",
        frozenset({"files.write.inspect"}),
        "FilesOwnerLifecycle.inspect_reservation",
        metadata_only=True,
    ),
    OwnerPhaseBinding(
        "files",
        "list",
        "FilesRead",
        frozenset({"files.list"}),
        "FilesOwnerLifecycle.list_file_index",
        metadata_only=True,
    ),
    OwnerPhaseBinding(
        "files",
        "metadata",
        "FilesRead",
        frozenset({"files.metadata"}),
        "FilesOwnerLifecycle.inspect_file_metadata",
        metadata_only=True,
    ),
    OwnerPhaseBinding(
        "execution",
        "open",
        "RuntimeOpenCommand",
        frozenset({"runtime.session.open"}),
        "RuntimeOwnerSource.open_runtime",
    ),
    OwnerPhaseBinding(
        "execution",
        "heartbeat",
        "RuntimeLeaseCommand",
        frozenset({"runtime.session.renew"}),
        "RuntimeOwnerSource.renew_runtime",
    ),
    OwnerPhaseBinding(
        "execution",
        "revoke",
        "RuntimeLeaseCommand",
        frozenset({"runtime.session.revoke"}),
        "RuntimeOwnerSource.revoke_runtime",
    ),
    OwnerPhaseBinding(
        "execution",
        "queue_job",
        "RuntimeJobCommand",
        frozenset(
            {"runtime.terminal.job.queue", "runtime.web.job.queue", "runtime.reverse.job.queue"}
        ),
        "RuntimeOwnerSource.queue_job",
    ),
    OwnerPhaseBinding(
        "execution",
        "start_job",
        "RuntimeJobTransition",
        frozenset(
            {
                "runtime.terminal.job.dispatch",
                "runtime.web.job.dispatch",
                "runtime.reverse.job.dispatch",
            }
        ),
        "RuntimeOwnerSource.dispatch_job",
    ),
    OwnerPhaseBinding(
        "execution",
        "finish_job",
        "RuntimeJobTransition",
        frozenset({"runtime.job.reconcile"}),
        "RuntimeOwnerLifecycle.reconcile_native_job",
        True,
    ),
    OwnerPhaseBinding(
        "execution",
        "fail_job",
        "RuntimeJobTransition",
        frozenset({"runtime.job.reconcile"}),
        "RuntimeOwnerLifecycle.reconcile_native_job",
        True,
    ),
    OwnerPhaseBinding(
        "execution",
        "mark_unknown",
        "RuntimeJobTransition",
        frozenset({"runtime.job.mark_unknown"}),
        "RuntimeOwnerLifecycle.mark_job_unknown",
    ),
    OwnerPhaseBinding(
        "execution",
        "cancel",
        "RuntimeJobTransition",
        frozenset({"runtime.job.cancel"}),
        "RuntimeOwnerLifecycle.cancel_undispatched_job",
    ),
    OwnerPhaseBinding(
        "execution",
        "inspect",
        "RuntimeJobTransition",
        frozenset({"runtime.job.inspect"}),
        "RuntimeOwnerLifecycle.inspect_job",
        metadata_only=True,
    ),
    OwnerPhaseBinding(
        "execution",
        "confirm_cleanup",
        "RuntimeLeaseCommand",
        frozenset({"runtime.cleanup.confirm"}),
        "RuntimeOwnerSource.confirm_cleanup",
        True,
    ),
    OwnerPhaseBinding(
        "reverse",
        "claim",
        "NativeImportClaimCommand",
        frozenset({"reverse.import.claim"}),
        "ReverseOwnerSource.reserve_import",
        True,
    ),
    OwnerPhaseBinding(
        "reverse",
        "dispatch",
        "NativeImportTransition",
        frozenset({"reverse.import.dispatch"}),
        "ReverseOwnerSource.mark_dispatched",
    ),
    OwnerPhaseBinding(
        "reverse",
        "reconcile",
        "NativeImportResult",
        frozenset({"reverse.import.reconcile"}),
        "ReverseOwnerSource.reconcile_import",
        True,
    ),
    OwnerPhaseBinding(
        "reverse",
        "mark_unknown",
        "NativeImportTransition",
        frozenset({"reverse.import.mark_unknown"}),
        "ReverseOwnerLifecycle.mark_unknown",
    ),
    OwnerPhaseBinding(
        "reverse",
        "cancel",
        "NativeImportTransition",
        frozenset({"reverse.import.cancel"}),
        "ReverseOwnerLifecycle.cancel_before_dispatch",
    ),
    OwnerPhaseBinding(
        "reverse",
        "inspect",
        "NativeImportInspect",
        frozenset({"reverse.import.inspect"}),
        "ReverseOwnerLifecycle.inspect_import",
        metadata_only=True,
    ),
    OwnerPhaseBinding(
        "catalog",
        "read",
        "CatalogListRequest",
        frozenset({"catalog.integrations.list", "catalog.variables.list"}),
        "CatalogOwnerLifecycle.list_metadata_committed",
        metadata_only=True,
    ),
    OwnerPhaseBinding(
        "catalog",
        "read",
        "CatalogResolveRequest",
        frozenset({"catalog.integrations.resolve", "catalog.variables.resolve"}),
        "CatalogOwnerLifecycle.resolve_metadata_committed",
        metadata_only=True,
    ),
)
_INDEX: dict[tuple[EffectOwner, str, str], OwnerPhaseBinding] = {
    (entry.owner, entry.phase, entry.payload_type): entry for entry in _BINDINGS
}
if len(_INDEX) != len(_BINDINGS):
    raise RuntimeError("duplicate owner source phase binding")


def canonical_owner_phase_binding(
    *,
    owner: EffectOwner,
    phase: str,
    payload_type: str,
) -> OwnerPhaseBinding:
    entry = _INDEX.get((owner, phase, payload_type))
    if entry is None:
        raise OwnerAuthorityUnavailable("owner SQL/native payload phase not source-accepted")
    return entry


def require_exact_owner_operation(
    *,
    owner: EffectOwner,
    phase: str,
    payload_type: str,
    operation: str,
) -> None:
    entry = canonical_owner_phase_binding(owner=owner, phase=phase, payload_type=payload_type)
    if operation not in entry.operations:
        raise OwnerAuthorityUnavailable("source operation does not match original payload phase")
    # A native_required entry still DENIES without independently verified
    # Files/OS/Ghidra observation at the concrete owner method. Metadata-only
    # methods do not attest native bytes or permit an irreversible effect.


def source_phase_contracts() -> tuple[OwnerPhaseBinding, ...]:
    """A single immutable source handoff inventory for R15 and D4."""
    return _BINDINGS
