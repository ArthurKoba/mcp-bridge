"""Source-only browser telemetry admission with separate ingest quota ownership.

Consent authority remains current Identity. Project eligibility comes from
current Control/Access. Neither Identity nor Control tables are queried from
the ingest SQL transaction; no raw events or URLs are persisted here.
C1-B2/C2 browser same-origin and collector receipt are separately unaccepted.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from authorization._browser_telemetry_persistence import BrowserTelemetryBudgetRow
from common.platform_db import PlatformDatabase
from common.platform_errors import AccessDenied, AuthenticationRateLimited, InvalidInput

_USER_EVENTS = 180
_USER_BYTES = 262144
_PROJECT_EVENTS = 90
_PROJECT_BYTES = 131072


@dataclass(frozen=True, slots=True)
class VerifiedCurrentBrowserConsent:
    user_id: UUID
    project_id: UUID | None
    current_identity_revision: int
    identity_epoch: UUID
    control_epoch: UUID | None
    access_epoch: UUID
    explicit_opt_in: bool
    project_permission_active: bool
    same_origin_verified: bool
    attested_at: datetime


class TrustedBrowserOwnerAttestor(Protocol):
    async def require_current(
        self, *, user_id: UUID, project_id: UUID | None, source_evidence: object
    ) -> VerifiedCurrentBrowserConsent:
        """Must verify browser origin, current User consent and Project rights."""
        ...


@dataclass(frozen=True, slots=True)
class BrowserAdmissionResult:
    accepted: int
    accepted_bytes: int
    consent_revision: int
    collector_receipt_required: bool = True


class BrowserIngestOwner:
    def __init__(self, database: PlatformDatabase, source: TrustedBrowserOwnerAttestor) -> None:
        if database.engine.url.database != "briareus_ingest" or source is None:
            raise RuntimeError("browser counters require isolated ingest owner and current consent")
        self.db = database
        self.source = source

    async def admit(
        self,
        *,
        user_id: UUID,
        project_id: UUID | None,
        source_evidence: object,
        event_count: int,
        payload_bytes: int,
    ) -> BrowserAdmissionResult:
        if (
            user_id.version != 4
            or (project_id is not None and project_id.version != 4)
            or not 1 <= event_count <= 32
            or not 1 <= payload_bytes <= 16384
        ):
            raise InvalidInput("browser ingest quota and scope bounds invalid")
        try:
            async with asyncio.timeout(3):
                current = await self.source.require_current(
                    user_id=user_id, project_id=project_id, source_evidence=source_evidence
                )
        except Exception:
            raise AccessDenied("authoritative Identity/browser consent unavailable") from None
        now = datetime.now(UTC)
        if (
            not isinstance(current, VerifiedCurrentBrowserConsent)
            or current.user_id != user_id
            or current.project_id != project_id
            or current.current_identity_revision < 1
            or current.identity_epoch.version != 4
            or current.access_epoch.version != 4
            or not current.explicit_opt_in
            or not current.same_origin_verified
            or (
                project_id is not None
                and (
                    not current.project_permission_active
                    or current.control_epoch is None
                    or current.control_epoch.version != 4
                )
            )
            or current.attested_at.tzinfo is None
            or current.attested_at > now
            or now - current.attested_at > timedelta(seconds=3)
        ):
            raise AccessDenied("current browser consent/scope proof rejected")
        async with self.db.transaction() as tx:
            minute = await tx.scalar(select(func.date_trunc("minute", func.now())))
            if not isinstance(minute, datetime) or minute.tzinfo is None:
                raise AccessDenied("ingest owner database time unavailable")
            budget_scopes = [("user", user_id, _USER_EVENTS, _USER_BYTES)]
            if project_id is not None:
                budget_scopes.append(("project", project_id, _PROJECT_EVENTS, _PROJECT_BYTES))
            for kind, scope_id, max_count, max_bytes in budget_scopes:
                stmt = insert(BrowserTelemetryBudgetRow).values(
                    user_id=user_id,
                    scope_kind=kind,
                    scope_id=scope_id,
                    minute_start=minute,
                    event_count=event_count,
                    byte_count=payload_bytes,
                )
                updated = await tx.scalar(
                    stmt.on_conflict_do_update(
                        index_elements=[
                            BrowserTelemetryBudgetRow.user_id,
                            BrowserTelemetryBudgetRow.scope_kind,
                            BrowserTelemetryBudgetRow.scope_id,
                            BrowserTelemetryBudgetRow.minute_start,
                        ],
                        set_={
                            "event_count": BrowserTelemetryBudgetRow.event_count + event_count,
                            "byte_count": BrowserTelemetryBudgetRow.byte_count + payload_bytes,
                        },
                        where=(
                            (BrowserTelemetryBudgetRow.event_count + event_count <= max_count)
                            & (BrowserTelemetryBudgetRow.byte_count + payload_bytes <= max_bytes)
                        ),
                    ).returning(BrowserTelemetryBudgetRow.user_id)
                )
                if updated is None:
                    raise AuthenticationRateLimited("browser owner telemetry quota exceeded")
            # OTLP delivery is a separate privacy-filtered stage. Successful
            # quota reservation alone never means the collector received data.
            return BrowserAdmissionResult(
                event_count, payload_bytes, current.current_identity_revision
            )
