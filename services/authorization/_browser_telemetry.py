"""Durable explicit-opt-in, project-authorized browser telemetry admission.

Browser events and URLs are never stored here. A PostgreSQL atomic UPSERT
charges BOTH the User-global and selected Project budgets. Denial of either
budget rolls back the entire SQL unit of work; no cross-project permission
or browser-supplied User identity may bypass the authenticated caller.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from common.platform_errors import AccessDenied, AuthenticationRateLimited, InvalidInput
from common.platform_ids import PlatformProjectId
from identity._persistence import UserRow

from ._browser_telemetry_persistence import BrowserTelemetryBudgetRow
from ._platform_application import PlatformApplication
from ._project_access import CallerPrincipal

_USER_EVENTS_PER_MINUTE = 180
_USER_BYTES_PER_MINUTE = 262_144
_PROJECT_EVENTS_PER_MINUTE = 90
_PROJECT_BYTES_PER_MINUTE = 131_072


class BrowserTelemetryAdmission:
    def __init__(self, app: PlatformApplication) -> None:
        # Source hold: these original APIs join Identity, Project and quota
        # counters through the rejected Authorization-global SQL Session.
        # They must never become an alternative public telemetry route.
        raise RuntimeError("global browser admission retired; use isolated owner ingest")
        self.app = app

    async def _current_opt_in(self, tx: AsyncSession, caller: CallerPrincipal) -> UserRow:
        await self.app.current_user(tx, caller, lock=True)
        user = await tx.scalar(
            select(UserRow)
            .where(UserRow.id == caller.user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if user is None or not user.enabled:
            raise AccessDenied("active verified User required for browser telemetry")
        if not user.browser_telemetry_opt_in:
            raise AccessDenied("explicit current browser telemetry consent required")
        return user

    async def consent(self, tx: AsyncSession, caller: CallerPrincipal) -> bool:
        await self.app.current_user(tx, caller, lock=True)
        user = await tx.scalar(
            select(UserRow)
            .where(UserRow.id == caller.user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if user is None or not user.enabled:
            raise AccessDenied("User session unavailable")
        return bool(user.browser_telemetry_opt_in)

    async def change_consent(
        self,
        tx: AsyncSession,
        caller: CallerPrincipal,
        *,
        enabled: bool,
    ) -> bool:
        await self.app.current_user(tx, caller, lock=True)
        user = await tx.scalar(
            select(UserRow)
            .where(UserRow.id == caller.user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if user is None or not user.enabled:
            raise AccessDenied("active User required")
        if type(enabled) is not bool:
            raise InvalidInput("explicit boolean browser consent required")
        if user.browser_telemetry_opt_in != enabled:
            user.browser_telemetry_opt_in = enabled
            user.updated_at = datetime.now(UTC)
            self.app._audit(
                tx,
                actor=caller.user_id,
                project=None,
                action="identity.browser_telemetry_consent_changed",
                target=caller.user_id,
                event={"enabled": enabled},
            )
        return enabled

    async def _reserve_bucket(
        self,
        tx: AsyncSession,
        *,
        caller: CallerPrincipal,
        scope_kind: str,
        scope_id: UUID,
        minute_start: datetime,
        events: int,
        bytes_count: int,
        max_events: int,
        max_bytes: int,
    ) -> None:
        stmt = insert(BrowserTelemetryBudgetRow).values(
            user_id=caller.user_id,
            scope_kind=scope_kind,
            scope_id=scope_id,
            minute_start=minute_start,
            event_count=events,
            byte_count=bytes_count,
        )
        upsert = stmt.on_conflict_do_update(
            index_elements=[
                BrowserTelemetryBudgetRow.user_id,
                BrowserTelemetryBudgetRow.scope_kind,
                BrowserTelemetryBudgetRow.scope_id,
                BrowserTelemetryBudgetRow.minute_start,
            ],
            set_={
                "event_count": BrowserTelemetryBudgetRow.event_count + events,
                "byte_count": BrowserTelemetryBudgetRow.byte_count + bytes_count,
            },
            where=(
                (BrowserTelemetryBudgetRow.event_count + events <= max_events)
                & (BrowserTelemetryBudgetRow.byte_count + bytes_count <= max_bytes)
            ),
        ).returning(BrowserTelemetryBudgetRow.user_id)
        updated = await tx.scalar(upsert)
        if updated is None:
            raise AuthenticationRateLimited("per-User/Project browser telemetry budget exceeded")

    async def reserve(
        self,
        tx: AsyncSession,
        caller: CallerPrincipal,
        *,
        project_id: PlatformProjectId | None,
        event_count: int,
        payload_bytes: int,
    ) -> None:
        if not 1 <= event_count <= 32 or not 1 <= payload_bytes <= 16_384:
            raise InvalidInput("browser event count/payload size outside bounded quota")
        await self._current_opt_in(tx, caller)
        if project_id is not None:
            await self.app.project_allowed(tx, caller, project_id)

        # Postgres DB clock is authoritative across processes with
        # differently configured Team operator display timezones.
        minute_start = await tx.scalar(select(func.date_trunc("minute", func.now())))
        if not isinstance(minute_start, datetime) or minute_start.tzinfo is None:
            raise AccessDenied("authoritative database time unavailable")

        await self._reserve_bucket(
            tx,
            caller=caller,
            scope_kind="user",
            scope_id=caller.user_id,
            minute_start=minute_start,
            events=event_count,
            bytes_count=payload_bytes,
            max_events=_USER_EVENTS_PER_MINUTE,
            max_bytes=_USER_BYTES_PER_MINUTE,
        )
        if project_id is not None:
            await self._reserve_bucket(
                tx,
                caller=caller,
                scope_kind="project",
                scope_id=project_id,
                minute_start=minute_start,
                events=event_count,
                bytes_count=payload_bytes,
                max_events=_PROJECT_EVENTS_PER_MINUTE,
                max_bytes=_PROJECT_BYTES_PER_MINUTE,
            )
