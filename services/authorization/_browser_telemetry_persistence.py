"""Minimal durable per-User/per-scope browser telemetry quota.

No raw telemetry payloads, bearer tokens, full URLs, request bodies,
Project secrets or setup codes are persisted. Budget rows are only counters.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import IngestBase


class BrowserTelemetryBudgetRow(IngestBase):
    __tablename__ = "browser_telemetry_budgets"
    __table_args__ = (
        CheckConstraint("scope_kind IN ('user','project')", name="ck_browser_telemetry_scope"),
        CheckConstraint(
            "event_count >= 0 AND event_count <= 180 AND byte_count >= 0 AND byte_count <= 262144",
            name="ck_browser_telemetry_budget",
        ),
        {"schema": "ingest"},
    )

    user_id: Mapped[UUID] = mapped_column(primary_key=True)
    scope_kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(primary_key=True)
    minute_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False)
