"""Minimal private owner startup: ONLY its own DB schema and verified ingress.

One source entrypoint per persistence owner; none mounts public business APIs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter
from typing import Protocol
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from starlette.responses import Response

from common.owner_migrations import migrate_owner, verify_owner
from common.platform_db import OwnerDatabaseSettings, OwnerName, PlatformDatabase
from common.platform_telemetry import BriareusHttpTelemetry

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class VerifiedOwnerIngress:
    owner: OwnerName
    authenticated_transport: str
    signer_present: bool
    expires_at: datetime


class OwnerIngressVerifier(Protocol):
    async def verify_running_ingress(self) -> VerifiedOwnerIngress: ...


class OwnerReadiness(BaseModel):
    owner: str
    state: str = "not_started"
    revision: str | None = None
    table_count: int = 0
    security_ready: bool = False


def create_owner_app(
    owner: OwnerName,
    *,
    settings: OwnerDatabaseSettings | None = None,
    trusted_ingress: OwnerIngressVerifier | None = None,
) -> FastAPI:
    current = OwnerReadiness(owner=owner)
    database: PlatformDatabase | None = None
    telemetry: BriareusHttpTelemetry | None = None

    async def _attest_ingress() -> bool:
        if trusted_ingress is None:
            return False
        try:
            async with asyncio.timeout(3):
                verified = await trusted_ingress.verify_running_ingress()
            return (
                isinstance(verified, VerifiedOwnerIngress)
                and verified.owner == owner
                and verified.authenticated_transport in {"mtls", "unix-peer"}
                and verified.signer_present
                and verified.expires_at.tzinfo is not None
                and verified.expires_at > datetime.now(UTC)
            )
        except Exception:
            return False

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        nonlocal current, database, telemetry
        current = OwnerReadiness(owner=owner, state="database_wait")
        try:
            local = settings or OwnerDatabaseSettings(owner=owner)
            if local.owner != owner:
                raise RuntimeError("owner runtime got foreign DB settings")
            database = PlatformDatabase(local)
            telemetry = BriareusHttpTelemetry("authorization" if owner == "access" else owner)
            telemetry.started()
            current = current.model_copy(update={"state": "migrating"})
            # One owner-scoped PostgreSQL role applies only this owner's
            # reviewed Alembic revisions during the normal trusted startup.
            # PostgreSQL provisioning must first create its logical DB/role.
            result = await migrate_owner(database, local)
            await verify_owner(database, local)
            current = current.model_copy(
                update={
                    "state": "security_pending",
                    "revision": result.revision,
                    "table_count": result.tables,
                }
            )
            if trusted_ingress is not None:
                if not await _attest_ingress():
                    raise RuntimeError("owner ingress trust attestation denied")
                current = current.model_copy(update={"state": "ready", "security_ready": True})
            logger.info("owner schema verified owner=%s head=%s", owner, result.revision)
            yield
        except Exception:
            current = OwnerReadiness(owner=owner, state="failed")
            logger.error("owner startup failed closed owner=%s", owner)
            raise RuntimeError("owner schema or service trust unavailable") from None
        finally:
            if telemetry is not None:
                telemetry.shutdown()
            if database is not None:
                await database.close()
            current = OwnerReadiness(owner=owner, state="stopped")

    app = FastAPI(
        title=f"Briareus {owner} private owner",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def bounded_telemetry(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Framework middleware is intentionally telemetry-only. It cannot
        # mount or authorize private service routes or trust caller headers.
        dispatch = call_next
        started = perf_counter()
        method = request.method
        active = telemetry
        status = 500
        try:
            if active is None:
                response = await dispatch(request)
            else:
                with active.trace_request(method=method, correlation_id=str(uuid4())):
                    response = await dispatch(request)
            status = response.status_code
            return response
        finally:
            if active is not None:
                active.observe_http(
                    method=method,
                    status_code=status,
                    duration_ms=(perf_counter() - started) * 1000,
                )

    @app.get("/health/live", include_in_schema=False)
    async def live() -> dict[str, str]:
        return {"owner": owner, "state": "live"}

    @app.get("/health/ready", include_in_schema=False)
    async def ready() -> OwnerReadiness:
        if not current.security_ready or current.state != "ready" or database is None:
            raise HTTPException(503, detail="authoritative owner not ready")
        try:
            if not await _attest_ingress():
                raise RuntimeError("trusted ingress expired or revoked")
            local = settings or OwnerDatabaseSettings(owner=owner)
            await verify_owner(database, local)
        except Exception:
            raise HTTPException(
                503, detail="authoritative owner schema or ingress unavailable"
            ) from None
        return current

    @app.get("/internal/schema-status", include_in_schema=False)
    async def schema_status(request: Request) -> OwnerReadiness:
        bound = request.scope.get("server")
        origin = request.client.host if request.client is not None else ""
        forwarded = {
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-real-ip",
        }
        try:
            loopback = ipaddress.ip_address(origin).is_loopback
            server_loopback = (
                isinstance(bound, (tuple, list))
                and bool(bound)
                and isinstance(bound[0], str)
                and ipaddress.ip_address(bound[0]).is_loopback
            )
        except ValueError:
            loopback = server_loopback = False
        if not loopback or not server_loopback or any(k in request.headers for k in forwarded):
            raise HTTPException(404, detail="not found")
        return current

    return app
