"""Unmounted Briareus split-owner Project composition, not a global DB.

Identity, Control and Access own separate signed current-state decisions;
Catalog, Files, Execution and Reverse own independent command/SQL/outbox
ports. Gateway/Web are stateless and MUST NOT own an application database.
A missing peer/owner contract denies. No legacy Authorization global SQL
permit, alternate Session UoW, unsafe local reaper or invented service URL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .a11_owner_wire import VerifiedA11RevisionPort
from .authorization import ProjectRuntimeAuthority
from .catalog_metadata import CatalogResourceAdapter
from .catalog_owner import CatalogOwnerSource, CatalogProviderReader
from .integrations import ProjectIntegrationSelector
from .owner_authorization import (
    OwnerAuthorizationPort,
    OwnerPublicKeyPort,
    OwnerRecipientPort,
    SplitOwnerSourceAuthorization,
)
from .owner_effects import OwnerEffectBackendPort, OwnerEffectClient, OwnerEffectTrustPort
from .runtime_owner_lease import RuntimeOwnerLeaseKeyPort
from .variables import ProjectVariableSelector
from .workspace_roots import ProjectRootRegistry

if TYPE_CHECKING:
    from bridge.project_dispatch import (
        ProjectGatewayDispatch,
        ProjectOwnerReadinessPort,
        ProjectOwnerReleaseManifestPort,
    )
    from modules.analysis.reverse_owner import NativeOSInventoryPort, ReverseOwnerClient
    from modules.files.a6_signed import TrustedFilesStoragePort, VerifiedFilesPeerPort
    from modules.files.project_explorer import ProjectFileExplorer
    from modules.files.project_files import ProjectFilesService
    from modules.terminal.execution_owner import (
        ExecutionOwnerRuntime,
        TrustedExecutionSupervisorPort,
    )
    from modules.terminal.project_isolation import ProjectIsolationInspector
    from modules.terminal.project_terminal import ProjectTerminalRuntime
    from modules.web.project_runtime import ProjectWebRuntime


@dataclass(slots=True)
class PrivateProjectRuntime:
    """Trusted owner SOURCE adapters only. Does not create any DB or server.

    The physical OS services and C2 transport are initially all unconfigured.
    Owner source setters can only receive implementations independently
    accepted by A11/C2; no untrusted JSON or environment variable is trusted.
    """

    roots: ProjectRootRegistry
    recipient_source: OwnerRecipientPort | None = None
    identity_control_access_source: OwnerAuthorizationPort | None = None
    owner_public_keys: OwnerPublicKeyPort | None = None
    effect_backend: OwnerEffectBackendPort | None = None
    effect_trust: OwnerEffectTrustPort | None = None
    a11_revisions: VerifiedA11RevisionPort | None = None
    files_peer: VerifiedFilesPeerPort | None = None
    files_observer: TrustedFilesStoragePort | None = None
    runtime_owner_lease_keys: RuntimeOwnerLeaseKeyPort | None = None
    execution_supervisor: TrustedExecutionSupervisorPort | None = None
    native_inventory: NativeOSInventoryPort | None = None
    authority: ProjectRuntimeAuthority = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.roots, ProjectRootRegistry):
            raise ValueError("Project owner root registry must be explicit")
        self.authority = ProjectRuntimeAuthority(
            SplitOwnerSourceAuthorization(
                recipients=self.recipient_source,
                sources=self.identity_control_access_source,
                trusted_keys=self.owner_public_keys,
            )
        )

    @classmethod
    def from_split_owner_sources(
        cls,
        *,
        roots: ProjectRootRegistry,
        recipient_source: OwnerRecipientPort | None = None,
        identity_control_access_source: OwnerAuthorizationPort | None = None,
        owner_public_keys: OwnerPublicKeyPort | None = None,
        effect_backend: OwnerEffectBackendPort | None = None,
        effect_trust: OwnerEffectTrustPort | None = None,
        a11_revisions: VerifiedA11RevisionPort | None = None,
        files_peer: VerifiedFilesPeerPort | None = None,
        files_observer: TrustedFilesStoragePort | None = None,
        runtime_owner_lease_keys: RuntimeOwnerLeaseKeyPort | None = None,
        execution_supervisor: TrustedExecutionSupervisorPort | None = None,
        native_inventory: NativeOSInventoryPort | None = None,
    ) -> PrivateProjectRuntime:
        """No global Authorization SQL UoW, no guessing A11 API URL/DTO."""
        return cls(
            roots=roots,
            recipient_source=recipient_source,
            identity_control_access_source=identity_control_access_source,
            owner_public_keys=owner_public_keys,
            effect_backend=effect_backend,
            effect_trust=effect_trust,
            a11_revisions=a11_revisions,
            files_peer=files_peer,
            files_observer=files_observer,
            runtime_owner_lease_keys=runtime_owner_lease_keys,
            execution_supervisor=execution_supervisor,
            native_inventory=native_inventory,
        )

    def owner_effects(self) -> OwnerEffectClient:
        """Effect responses must come from the matching signed owner store."""
        return OwnerEffectClient(
            self.authority,
            backend=self.effect_backend,
            trust=self.effect_trust,
            a11_revisions=self.a11_revisions,
        )

    def _resources(self) -> CatalogResourceAdapter:
        """Metadata is Catalog-owned, never a global A4 database fetch."""
        return CatalogResourceAdapter(
            self.authority,
            CatalogOwnerSource(self.owner_effects()),
        )

    def files(self, *, max_file_bytes: int) -> ProjectFilesService:
        from modules.files.a6_signed import A6SignedFilesFlow
        from modules.files.owner_backend import FilesOwnerBackend
        from modules.files.project_files import ProjectFilesService

        return ProjectFilesService(
            self.authority,
            self.roots,
            max_file_bytes=max_file_bytes,
            a6_quota=A6SignedFilesFlow(
                self.authority,
                peer_port=self.files_peer,
                backend=FilesOwnerBackend(self.owner_effects()),
                observer=self.files_observer,
            ),
        )

    @staticmethod
    def explorer(*, files: ProjectFilesService) -> ProjectFileExplorer:
        from modules.files.project_explorer import ProjectFileExplorer

        return ProjectFileExplorer(files)

    def terminal(
        self, *, isolation: ProjectIsolationInspector | None = None
    ) -> ProjectTerminalRuntime:
        """Fail-closed Terminal facade; actual exec requires C2 OS custody."""
        from modules.terminal.project_terminal import ProjectTerminalRuntime

        return ProjectTerminalRuntime(
            authority=self.authority,
            roots=self.roots,
            isolation=isolation,
        )

    def execution(self) -> ExecutionOwnerRuntime:
        from modules.terminal.execution_owner import ExecutionOwnerRuntime

        return ExecutionOwnerRuntime(
            self.authority,
            self.owner_effects(),
            owner_lease_keys=self.runtime_owner_lease_keys,
            supervisor=self.execution_supervisor,
        )

    def reverse(self) -> ReverseOwnerClient:
        from modules.analysis.reverse_owner import ReverseOwnerClient

        return ReverseOwnerClient(
            self.authority,
            files=self.owner_effects(),
            reverse=self.owner_effects(),
            inventory=self.native_inventory,
        )

    def web(self, *, files: ProjectFilesService) -> ProjectWebRuntime:
        from modules.web.project_runtime import ProjectWebRuntime

        return ProjectWebRuntime(authority=self.authority, files=files)

    def gateway(
        self,
        *,
        files: ProjectFilesService | None = None,
        readiness: ProjectOwnerReadinessPort | None = None,
        release_manifest: ProjectOwnerReleaseManifestPort | None = None,
    ) -> ProjectGatewayDispatch:
        """Stateless private ingress; A11 signed owner readiness is required."""
        from bridge.project_dispatch import ProjectGatewayDispatch
        from bridge.project_services import (
            PrivateProjectModuleForwarder,
            PrivateProjectToolClassifier,
        )

        return ProjectGatewayDispatch(
            self.authority,
            classifier=PrivateProjectToolClassifier(),
            readiness=readiness,
            release_manifest=release_manifest,
            forwarder=PrivateProjectModuleForwarder(
                self.authority,
                files=files,
                integrations=self.integrations(),
                variables=self.variables(),
            ),
        )

    def integrations(self) -> ProjectIntegrationSelector:
        return ProjectIntegrationSelector(self.authority, self._resources())

    def variables(self) -> ProjectVariableSelector:
        return ProjectVariableSelector(self.authority, self._resources())

    def provider(self) -> CatalogProviderReader:
        """Catalog read-only one-use lease; no secrets returned to Gateway."""
        return CatalogProviderReader(self.authority, self.owner_effects())
