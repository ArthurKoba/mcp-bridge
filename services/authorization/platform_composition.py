"""Composition for a fresh, dedicated greenfield PostgreSQL-backed core.

Factory only. Existing Authorization/Admin runtimes are NOT switched over.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from sqlalchemy import MetaData

from common.platform_db import PlatformDatabase, PlatformDatabaseSettings
from identity._operator_channel import UnixFirstAdminOperatorGate
from identity._service import IdentityService
from projects._file_quota import FileQuotaLedger
from projects._native_import_ledger import NativeImportLedger
from projects._resource_service import ResourceService
from projects._runtime_ledger import RuntimeLedger

from ._external_operations import ExternalOperationLedger
from ._files_vertical import SignedFilesAuthority
from ._idempotency import IdempotentCommandExecutor
from ._mtls_peer import PinnedMTLSPeerVerifier, PinnedServiceCertificate
from ._native_vertical import SignedNativeImportAuthority
from ._outbox import OutboxDispatcher
from ._platform_application import PlatformApplication
from ._platform_auth import PlatformAdminBearerAuth
from ._project_sessions import ProjectSessionService
from ._provider_vertical import SignedProviderReadAuthority
from ._resource_leases import ResourceCredentialUse
from ._runtime_vertical import SignedRuntimeAuthority
from ._scoped_events import ScopedEventFeed
from ._service_identity import ServiceIdentityAuthority, ServiceIdentitySettings
from ._service_transport import PrivateServiceAuthorizationController


def platform_metadata() -> MetaData:
    """Retired: cross-owner metadata is never a valid SQL or migration target."""
    raise RuntimeError("Authorization-global platform metadata is retired; use owner_metadata")

@dataclass(frozen=True)
class PlatformServices:
    database: PlatformDatabase
    identity: IdentityService
    application: PlatformApplication
    sessions: ProjectSessionService
    commands: IdempotentCommandExecutor
    resources: ResourceService
    credential_use: ResourceCredentialUse
    admin_auth: PlatformAdminBearerAuth
    external_operations: ExternalOperationLedger
    service_identity: ServiceIdentityAuthority | None
    service_transport: PrivateServiceAuthorizationController
    signed_files: SignedFilesAuthority
    signed_runtime: SignedRuntimeAuthority
    signed_native_imports: SignedNativeImportAuthority
    signed_provider_reads: SignedProviderReadAuthority
    runtimes: RuntimeLedger
    file_quotas: FileQuotaLedger
    native_imports: NativeImportLedger
    scoped_events: ScopedEventFeed
    scoped_outbox: OutboxDispatcher


def compose_platform(
    settings: PlatformDatabaseSettings,
    *,
    signed_authorization: ServiceIdentitySettings | None = None,
    first_admin_operator_gate: UnixFirstAdminOperatorGate | None = None,
) -> PlatformServices:
    raise RuntimeError(
        "single-DB PlatformServices composition is forbidden; use verified owner ports"
    )

def compose_signed_authorization(settings: PlatformDatabaseSettings) -> PlatformServices:
    """Opt-in via secure service *entrypoint*, never an operator toggle.

    DELEGATION_SIGNING_PRIVATE_KEY is required and validated only for the
    authorization process that actually signs cross-service operations.
    """
    return compose_platform(settings, signed_authorization=ServiceIdentitySettings())


def bind_explicit_dev_mtls(
    services: PlatformServices,
    *,
    pins: tuple[PinnedServiceCertificate, ...],
) -> PlatformServices:
    """Opt-in service transport composition after independent D1 trust review.

    The pins MUST be supplied by an authenticated infrastructure supervisor
    from its trusted release configuration. No operator/browser/controller
    request body, proxy headers or unauthenticated environment value may
    create a trusted service binding. This neither binds an HTTP listener nor
    mounts private/project routes; external activation remains C1-B2/C2.
    """
    if services.service_identity is None:
        raise ValueError("DEV service identity is not enabled with trusted signing material")
    verifier = PinnedMTLSPeerVerifier(pins)
    controller = PrivateServiceAuthorizationController(
        services.service_identity, peer_authenticator=verifier
    )
    return replace(
        services,
        service_transport=controller,
        signed_files=SignedFilesAuthority(controller, services.file_quotas),
        signed_runtime=SignedRuntimeAuthority(controller, services.runtimes),
        signed_native_imports=SignedNativeImportAuthority(controller, services.native_imports),
        signed_provider_reads=SignedProviderReadAuthority(
            controller, services.resources, services.credential_use, services.external_operations
        ),
    )
