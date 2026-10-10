"""Briareus server-owned OpenTelemetry lifecycle and privacy-safe HTTP context.

The server's actual package/release, environment and process identity are
supplied by ObservabilitySettings. Browser/user payload, Authorization bearer,
registration/setup code, Project/Team secret, raw URL/path and filesystem
path are never accepted as metric labels or trace attributes.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from math import isfinite
from typing import Literal

from opentelemetry import metrics
from opentelemetry.trace import Span

from .observability import CompositeObservabilitySink, build_observability
from .settings import ObservabilitySettings

ServiceName = Literal[
    "authorization",
    "admin-api",
    "identity",
    "platform",
    "resources",
    "files",
    "runtime",
    "reverse",
    "ingest",
]


class BriareusHttpTelemetry:
    def __init__(
        self,
        service_name: ServiceName,
        *,
        settings: ObservabilitySettings | None = None,
    ) -> None:
        self.service_name = service_name
        self.settings = settings or ObservabilitySettings()
        if self.settings.enabled and self.settings.service_name != service_name:
            raise ValueError("active OTel_SERVICE_NAME mismatches actual entrypoint")
        self.sink: CompositeObservabilitySink = build_observability(
            service_name, settings=self.settings
        )
        meter = metrics.get_meter(f"briareus.{service_name}")
        self.http_requests = meter.create_counter(
            "briareus.http.requests",
            unit="{request}",
            description="Sanitized Briareus HTTP requests",
        )
        self.http_duration = meter.create_histogram(
            "briareus.http.duration",
            unit="ms",
            description="Briareus HTTP request latency (no URL/user labels)",
        )
        self._closed = False

    @contextmanager
    def trace_request(
        self,
        *,
        method: str,
        correlation_id: str,
    ) -> Iterator[Span | None]:
        # Never use raw URL, path, query, header or User/Team/Project
        # identity as an OTLP tag, even when supplied by trusted middleware.
        method = (
            method
            if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
            else "OTHER"
        )
        with self.sink.trace_span(
            f"{self.service_name}.http",
            {
                "http.request.method": method,
                "briareus.correlation_id": correlation_id,
            },
        ) as span:
            yield span

    def observe_http(
        self,
        *,
        method: str,
        status_code: int,
        duration_ms: float,
    ) -> None:
        method = (
            method
            if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
            else "OTHER"
        )
        code = status_code if 100 <= status_code <= 599 else 500
        milliseconds = min(max(0.0, duration_ms), 300_000.0) if isfinite(duration_ms) else 0.0
        attributes = {
            "http.request.method": method,
            "http.response.status_code": code,
        }
        self.http_requests.add(1, attributes)
        self.http_duration.record(milliseconds, attributes)

    def started(self) -> None:
        if self.settings.enabled:
            self.sink.record_runtime_started(self.service_name)

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        for sink in self.sink.sinks:
            shutdown = getattr(sink, "shutdown", None)
            if callable(shutdown):
                shutdown()
