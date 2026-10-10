from __future__ import annotations

import asyncio
import platform
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.middleware import Middleware
from fastmcp.server.providers.proxy import FastMCPProxy
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.routing import BaseRoute

from common.admin_api_client import AdminApiClient, AdminApiClientError
from common.mcp_surfaces import (
    MCP_SURFACE_PATHS,
    resource_url,
    surface_base_url,
)
from common.models import JsonObject
from common.runtime_annotations import (
    DESTRUCTIVE_EXTERNAL,
    READ_EXTERNAL,
    READ_ONLY_LOCAL,
)
from common.runtime_policy_contracts import McpRuntimePolicy
from common.settings import (
    AdminApiClientSettings,
    AuthorizationAccessClientSettings,
    BridgeSettings,
    GatewayAuthorizationSettings,
)
from modules.project_runtime.runtime_telemetry import RuntimeTelemetry, SafeRuntimeToolTelemetry

from . import __version__
from .access_middleware import AccessSessionMiddleware
from .access_tools import register_access_session_tools
from .authorization_access_client import AuthorizationAccessClient
from .authorization_client import LocalAuthorizationTokenVerifier
from .backend_catalog import existing_backend_descriptors
from .backend_router import BackendRouter
from .backend_sessions import ProxyClientPool
from .models import BridgeBuildInfo, BridgeCapabilities, BridgePing

_STARTED_AT = datetime.now(UTC).isoformat()
_runtime_telemetry = RuntimeTelemetry.construct("gateway")
_PROXY_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


async def _backend_timeout_seconds() -> float:
    try:
        policy = await asyncio.wait_for(
            asyncio.to_thread(_admin_api.mcp_runtime_policy),
            timeout=1.0,
        )
    except (TimeoutError, AdminApiClientError, ValueError):
        policy = McpRuntimePolicy()
    return float(policy.call_timeout_seconds)


def _proxy_target(name: str, target: str | FastMCP[Any]) -> FastMCP:
    pool = ProxyClientPool(
        target,
        name=name,
        timeout_provider=_backend_timeout_seconds,
        size=2,
    )
    return FastMCPProxy(
        client_factory=pool.acquire,
        name=f"{name}-backend",
        lifespan=pool.lifespan,
    )


def _proxy(name: str, url: str) -> FastMCP:
    return _proxy_target(name, url)


def _build_surface_authorization(
    settings: GatewayAuthorizationSettings,
) -> dict[str, RemoteAuthProvider]:
    if not settings.enabled:
        return {}

    settings.validate_bootstrap()
    authorization_server = AnyHttpUrl(settings.public_base_url)
    result: dict[str, RemoteAuthProvider] = {}
    for surface in MCP_SURFACE_PATHS:
        resource = resource_url(settings.mcp_public_base_url, surface)
        verifier = LocalAuthorizationTokenVerifier(settings, resource)
        result[surface] = RemoteAuthProvider(
            token_verifier=verifier,
            authorization_servers=[authorization_server],
            base_url=surface_base_url(settings.mcp_public_base_url, surface),
            scopes_supported=["read:user"],
            resource_name=f"Koba {surface.title()}",
        )
    return result


def _public_facade(
    name: str,
    backend_name: str,
    backend_url: str,
    authorization_by_surface: dict[str, RemoteAuthProvider],
) -> FastMCP:
    middleware: list[Middleware] = [
        SafeRuntimeToolTelemetry(
            "gateway", _runtime_telemetry.sink, buffer=_runtime_telemetry.event_buffer
        )
    ]
    if _authorization_access_settings.enabled:
        middleware.append(AccessSessionMiddleware(surface=name, client=_authorization_access))
    surface = FastMCP(
        name,
        version=__version__,
        auth=authorization_by_surface.get(name),
        middleware=middleware,
    )
    if _authorization_access_settings.enabled:
        register_access_session_tools(surface, surface=name, client=_authorization_access)
    surface.mount(server=_proxy(backend_name, backend_url))
    return surface


_settings = BridgeSettings()
_authorization_settings = GatewayAuthorizationSettings()
_authorization_access_settings = AuthorizationAccessClientSettings()
_authorization_access_settings.validate_bootstrap()
_admin_api_settings = AdminApiClientSettings()
_BACKENDS = _settings.backends
_admin_api = AdminApiClient(_admin_api_settings)
_authorization_access = AuthorizationAccessClient(_authorization_access_settings)
_authorization_by_surface = _build_surface_authorization(_authorization_settings)

_backend_router = BackendRouter(
    existing_backend_descriptors(_BACKENDS),
    timeout_provider=_backend_timeout_seconds,
)

mcp = FastMCP(
    "mcp-bridge",
    version=__version__,
    middleware=[
        SafeRuntimeToolTelemetry(
            "gateway", _runtime_telemetry.sink, buffer=_runtime_telemetry.event_buffer
        ),
        *(
            [AccessSessionMiddleware(surface="root", client=_authorization_access)]
            if _authorization_access_settings.enabled
            else []
        ),
    ],
    instructions=(
        "Universal MCP map and bridge. Dedicated backends are not automatically "
        "published on this root surface. Use bridge_backends to inspect availability, "
        "bridge_tools to fetch one backend tool catalog/signatures, and bridge_call "
        "to forward a call to a selected backend."
    ),
    auth=_authorization_by_surface.get("root"),
)

github_surface = _public_facade(
    "github",
    "github",
    _BACKENDS["github"],
    _authorization_by_surface,
)
gitlab_surface = _public_facade(
    "gitlab",
    "gitlab",
    _BACKENDS["gitlab"],
    _authorization_by_surface,
)
files_surface = _public_facade(
    "files",
    "files",
    _BACKENDS["files"],
    _authorization_by_surface,
)
web_surface = _public_facade(
    "web",
    "web",
    _BACKENDS["web"],
    _authorization_by_surface,
)
analysis_surface = _public_facade(
    "analysis",
    "analysis",
    _BACKENDS["analysis"],
    _authorization_by_surface,
)
terminal_surface = _public_facade(
    "terminal",
    "terminal",
    _BACKENDS["terminal"],
    _authorization_by_surface,
)
observability_surface = _public_facade(
    "observability",
    "observability",
    _BACKENDS["observability"],
    _authorization_by_surface,
)


if _authorization_access_settings.enabled:
    register_access_session_tools(mcp, surface="root", client=_authorization_access)


@mcp.tool(title="Bridge ping", annotations=READ_ONLY_LOCAL)
def bridge_ping() -> JsonObject:
    return BridgePing(version=__version__, time=datetime.now(UTC).isoformat()).to_json()


@mcp.tool(title="Bridge build info", annotations=READ_ONLY_LOCAL)
def bridge_build_info() -> JsonObject:
    return BridgeBuildInfo(
        version=__version__,
        commit=_settings.build_sha,
        built_at=_settings.build_time,
        started_at=_STARTED_AT,
        python=platform.python_version(),
    ).to_json()


@mcp.tool(title="Bridge backends", annotations=READ_EXTERNAL)
async def bridge_backends() -> JsonObject:
    """List public/private bridge backends with live availability and tool counts."""
    return await _backend_router.describe()


@mcp.tool(title="Bridge backend tools", annotations=READ_EXTERNAL)
async def bridge_tools(backend: str, refresh: bool = False) -> JsonObject:
    """Fetch one backend tool catalog and signatures without publishing it at root."""
    return await _backend_router.tools(backend, refresh=refresh)


@mcp.tool(title="Bridge forward call", annotations=DESTRUCTIVE_EXTERNAL)
async def bridge_call(
    backend: str,
    tool_name: str,
    arguments: JsonObject | None = None,
) -> JsonObject:
    """Forward one tool call to a selected backend without adding bridge metadata."""
    return await _backend_router.call(backend, tool_name, arguments)


@mcp.tool(title="Bridge capabilities", annotations=READ_ONLY_LOCAL)
def bridge_capabilities() -> JsonObject:
    return BridgeCapabilities(
        backends=sorted(_BACKENDS),
        public_surfaces=list(MCP_SURFACE_PATHS.values()),
        features=[
            "mcp",
            "streamable-http",
            "gateway",
            "central-oauth",
            "backend-map",
            "backend-signatures",
            "generic-forwarding",
            "account-admin",
            "multi-account-github",
            "multi-account-gitlab",
            "files",
            "web",
            "curl",
            "browser",
            "playwright",
            "analysis",
            "terminal",
            "jobs",
            "observability",
            "multi-account-signoz",
            "multi-account-coolify",
        ],
    ).to_json()


_allowed_hosts = list(_settings.http.allowed_hosts)
_allowed_origins = list(_settings.http.allowed_origins)


def _http_app(surface: FastMCP) -> Starlette:
    return surface.http_app(
        path="/mcp",
        allowed_hosts=_allowed_hosts,
        allowed_origins=_allowed_origins,
    )


def _resource_discovery_routes() -> list[BaseRoute]:
    routes: list[BaseRoute] = []
    seen_paths: set[str] = set()
    for authorization_provider in _authorization_by_surface.values():
        for route in authorization_provider.get_well_known_routes(mcp_path="/mcp"):
            path = getattr(route, "path", "")
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            routes.append(route)
    return routes


_root_http_app = _http_app(mcp)
_github_http_app = _http_app(github_surface)
_gitlab_http_app = _http_app(gitlab_surface)
_files_http_app = _http_app(files_surface)
_web_http_app = _http_app(web_surface)
_analysis_http_app = _http_app(analysis_surface)
_terminal_http_app = _http_app(terminal_surface)
_observability_http_app = _http_app(observability_surface)

_MCP_HTTP_APPS = (
    _root_http_app,
    _github_http_app,
    _gitlab_http_app,
    _files_http_app,
    _web_http_app,
    _analysis_http_app,
    _terminal_http_app,
    _observability_http_app,
)
_MCP_LIFESPANS = tuple(mcp_app.router.lifespan_context for mcp_app in _MCP_HTTP_APPS)


@asynccontextmanager
async def _gateway_lifespan(app: Starlette) -> AsyncIterator[None]:
    async with AsyncExitStack() as stack:
        for lifespan in _MCP_LIFESPANS:
            await stack.enter_async_context(lifespan(app))
        try:
            yield
        finally:
            await _backend_router.close()
            await _authorization_access.close()


app = _runtime_telemetry.attach(Starlette(lifespan=_gateway_lifespan))

for _route in _resource_discovery_routes():
    app.router.routes.append(_route)


app.mount("/github", _github_http_app)
app.mount("/gitlab", _gitlab_http_app)
app.mount("/files", _files_http_app)
app.mount("/web", _web_http_app)
app.mount("/analysis", _analysis_http_app)
app.mount("/terminal", _terminal_http_app)
app.mount("/observability", _observability_http_app)
app.mount("/", _root_http_app)
