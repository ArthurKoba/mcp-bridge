"""Unmounted owner-authenticated Admin BFF scoped feed and diagnostic relay.

No guessed URL, cookie, CORS allowlist, WS endpoint, JS credential, or
public router is installed here. Physical same-origin HTTPS and C2 bearer,
verified scope, service peer, and original source revisions are REQUIRED.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from telemetry_ingest import FrontendTelemetryProxy

from authorization._browser_ingest_owner import BrowserIngestOwner
from common.owner_bff_models import VerifiedAdminCaller
from projects._scoped_owner_source import (
    OwnerScopeEvent,
    ScopedOwnerProjection,
    ScopeKind,
)


class TrustedBrowserBffIngress(Protocol):
    async def verify(self, *, evidence: object, actor: VerifiedAdminCaller) -> None:
        """C2 verifies SAME-origin HTTPS Host/Origin/proxy/CSRF/admin bearer."""
        ...


class VerifiedRealtimeBffSubscriber(Protocol):
    async def require_current(
        self,
        *,
        actor: VerifiedAdminCaller,
        scope_kind: ScopeKind,
        scope_id: UUID,
        source_evidence: object,
    ) -> None:
        """Independently recheck current User and Team/Project before delivery."""
        ...


class SafeBrowserTelemetryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    kind: Literal["navigation", "http_failure", "render_error", "performance", "interaction"]
    component: Literal[
        "auth",
        "navigation",
        "project",
        "team",
        "users",
        "agents",
        "sessions",
        "resources",
        "settings",
    ]
    outcome: Literal["ok", "denied", "failed", "cancelled", "pending"]
    route_key: Literal[
        "login",
        "projects",
        "teams",
        "users",
        "agents",
        "sessions",
        "resources",
        "settings",
        "unknown",
    ]
    occurred_at: datetime
    duration_ms: int = Field(default=0, ge=0, le=300_000)


class BrowserTelemetryEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    project_id: UUID | None = None
    events: tuple[SafeBrowserTelemetryEvent, ...] = Field(min_length=1, max_length=32)


class ScopedAdminBffFlow:
    def __init__(
        self,
        *,
        scope_projection: ScopedOwnerProjection,
        ingress: TrustedBrowserBffIngress,
        reader: VerifiedRealtimeBffSubscriber,
    ) -> None:
        if not scope_projection or not ingress or not reader:
            raise RuntimeError("BFF scoped feed requires current source and C2 origin")
        self.projection = scope_projection
        self.ingress = ingress
        self.reader = reader

    async def poll(
        self,
        *,
        actor: VerifiedAdminCaller,
        source_evidence: object,
        scope_kind: ScopeKind,
        scope_id: UUID,
        offset_epoch: UUID | None,
        after_sequence: int,
        limit: int = 64,
    ) -> tuple[OwnerScopeEvent, ...]:
        if scope_kind not in {"user", "team", "project"} or not 1 <= limit <= 128:
            raise ValueError("unsupported scoped read cursor")
        async with asyncio.timeout(3):
            await self.ingress.verify(evidence=source_evidence, actor=actor)
            await self.reader.require_current(
                actor=actor,
                scope_kind=scope_kind,
                scope_id=scope_id,
                source_evidence=source_evidence,
            )
            # Per poll, require the same current User/scope owner. Old
            # snapshot, previous page and WS cursor are never grants.
            return await self.projection.read(
                actor_user_id=actor.user_id,
                scope_kind=scope_kind,
                scope_id=scope_id,
                epoch=offset_epoch,
                after_sequence=after_sequence,
                limit=limit,
            )


class PrivateBrowserTelemetryRelay:
    def __init__(
        self,
        *,
        ingress: TrustedBrowserBffIngress,
        ingest: BrowserIngestOwner,
        exporter: FrontendTelemetryProxy,
    ) -> None:
        if ingress is None or ingest is None or exporter is None:
            raise RuntimeError("Browser relay requires verified C2+Ingest+server OTLP")
        self.ingress = ingress
        self.ingest = ingest
        self.exporter = exporter

    async def relay(
        self,
        *,
        actor: VerifiedAdminCaller,
        source_evidence: object,
        envelope: BrowserTelemetryEnvelope,
    ) -> int:
        if (envelope.project_id is not None and envelope.project_id.version != 4) or len(
            envelope.events
        ) > 32:
            raise ValueError("browser diagnostic scope/payload rejected")
        async with asyncio.timeout(3):
            await self.ingress.verify(evidence=source_evidence, actor=actor)
        # No raw URLs, IDs, exception stacks, network endpoints, arbitrary
        # attributes or credential tokens are accepted by these exact types.
        now = datetime.now(UTC)
        sanitized: list[object] = []
        for event in envelope.events:
            if event.occurred_at.tzinfo is None or not now - timedelta(
                minutes=5
            ) <= event.occurred_at <= now + timedelta(minutes=1):
                raise ValueError("browser diagnostics time outside allowed window")
            sanitized.append(
                {
                    "id": "privacy-safe",
                    "name": event.kind,
                    "occurredAt": event.occurred_at.isoformat(),
                    "route": event.route_key,
                    "durationMs": event.duration_ms,
                    "attributes": {"component": event.component, "outcome": event.outcome},
                }
            )
        encoded = json.dumps(
            sanitized, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
        if len(encoded) > 16_384:
            raise ValueError("browser telemetry exceeds bounded admission")
        await self.ingest.admit(
            user_id=actor.user_id,
            project_id=envelope.project_id,
            source_evidence=source_evidence,
            event_count=len(sanitized),
            payload_bytes=len(encoded),
        )
        if not self.exporter.enabled:
            raise RuntimeError("server-only OTLP unavailable; diagnostic outcome unknown")
        queued = self.exporter.enqueue(sanitized)
        accepted = queued.get("accepted")
        if type(accepted) is not int or accepted != len(sanitized):
            raise RuntimeError("browser diagnostic collector enqueue unconfirmed")
        return accepted
