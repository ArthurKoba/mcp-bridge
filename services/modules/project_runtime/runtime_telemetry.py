"""One owned OTel lifecycle for the Briareus Python Runtime ASGI services.

Actual exporter/settings implementations are Backend-owned `common` source.
Runtime alone owns how a service starts, heartbeats and flushes its sink.
Never expose collector bearer, service JWTs, UUIDs, request bodies, provider
credentials or high-cardinality resource identifiers in logs or attributes.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from typing import Any

import mcp.types as mt
from fastmcp import FastMCP
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from starlette.applications import Starlette

from common.account_contracts import InvocationEvent
from common.observability import (
    CompositeObservabilitySink,
    OpenTelemetrySink,
    build_observability,
)
from common.settings import ObservabilitySettings

_LOG = logging.getLogger("briareus.runtime.telemetry")
_ALLOWED = frozenset({"gateway", "files", "terminal", "web", "svc", "infrastructure", "reverse"})
_HEARTBEAT_SECONDS = 60.0
_EVENT_QUEUE_LIMIT = 512
_EVENT_BATCH_LIMIT = 64
# Explicitly closed metric dimensions. Unknown tool names never become tags.
_TOOL_FAMILIES = frozenset(
    {
        "access",
        "analysis",
        "bridge",
        "browser",
        "coolify",
        "devtools",
        "external",
        "file",
        "files",
        "ghidra",
        "git",
        "github",
        "gitlab",
        "job",
        "observability",
        "project",
        "resource",
        "runtime",
        "session",
        "terminal",
        "variable",
        "web",
    }
)


class _OnlySanitizedRuntimeLogs(logging.Filter):
    """Protect collector logs from generic old tool inputs and SDK errors.

    Backend's shared exporter currently installs a root LoggingHandler. A
    provider/HTTP exception or arbitrary Terminal argument can otherwise end
    up in the OTLP log body, even if MCP metrics are correctly redacted. Until
    A10 accepts a general safe log routing policy, forward only own bounded
    runtime lifecycle records. This filter does not change console handlers.
    """

    _LIFECYCLE_TEMPLATES = frozenset(
        {
            "OpenTelemetry runtime started scope=%s service=%s",
            "OpenTelemetry startup signals flushed scope=%s",
            "OpenTelemetry startup flush timed out scope=%s",
            "Runtime telemetry metrics discarded service=%s count=%d",
            "Runtime telemetry drain timeout service=%s",
            "Runtime telemetry shutdown failed service=%s",
        }
    )

    def filter(self, record: logging.LogRecord) -> bool:
        # Only our static, non-exception lifecycle templates can reach the
        # remote collector. A generic briareus.observability logger.exception
        # includes arbitrary SDK/provider error messages and stack frames.
        # Accepting a logger NAME alone would still export those secrets.
        if (
            record.name not in {"briareus.observability", "briareus.runtime.telemetry"}
            or record.exc_info is not None
            or record.stack_info is not None
            or not isinstance(record.msg, str)
            or record.msg not in self._LIFECYCLE_TEMPLATES
        ):
            return False
        args = record.args
        if not isinstance(args, tuple) or not 1 <= len(args) <= 2:
            return False
        for arg in args:
            if isinstance(arg, str):
                if arg not in _ALLOWED:
                    return False
            elif type(arg) is not int or arg < 0:
                return False
        return True


@dataclass(slots=True)
class BoundedRuntimeToolEvents:
    """Bounded in-process meter buffer, not an Access DB event store.

    An untrusted caller can produce arbitrarily many MCP tool invocations.
    Do not allocate unbounded tasks, queues or labels or block a tool call on
    OTLP network I/O. A full queue drops a SANITIZED metric event; it NEVER
    drops the authoritative owner-local SQL command/outbox/audit operation.
    The SDK's own BatchLog/SpanProcessors separately own bounded exporters.
    """

    scope: str
    sink: CompositeObservabilitySink
    max_events: int = _EVENT_QUEUE_LIMIT
    _queue: asyncio.Queue[InvocationEvent] = field(init=False, repr=False)
    _accepting: bool = False
    _dropped: int = 0

    def __post_init__(self) -> None:
        if type(self.max_events) is not int or not 1 <= self.max_events <= _EVENT_QUEUE_LIMIT:
            raise ValueError("bounded Runtime telemetry queue capacity invalid")
        self._queue = asyncio.Queue(maxsize=self.max_events)

    def publish(self, event: InvocationEvent) -> None:
        if not self._accepting:
            self._dropped += 1
            return
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._dropped += 1

    async def run(self, stop: asyncio.Event) -> None:
        self._accepting = True
        try:
            while not stop.is_set() or not self._queue.empty():
                try:
                    first = await asyncio.wait_for(self._queue.get(), timeout=0.25)
                except TimeoutError:
                    continue
                batch = [first]
                while len(batch) < _EVENT_BATCH_LIMIT:
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                # Counter/histogram updates are synchronous in-memory SDK
                # methods. No HTTP/secret/SQL request on this worker path.
                try:
                    for record in batch:
                        self.sink.record_invocation(record, audit=False)
                finally:
                    for _ in batch:
                        self._queue.task_done()
                await asyncio.sleep(0)
        finally:
            self._accepting = False
            if self._dropped:
                _LOG.warning(
                    "Runtime telemetry metrics discarded service=%s count=%d",
                    self.scope,
                    self._dropped,
                )
                self._dropped = 0

    def stop_accepting(self) -> None:
        self._accepting = False


class SafeRuntimeToolTelemetry(Middleware):
    """OTel metrics/spans with bounded static labels and NO payload capture.

    The historical generic MCP audit middleware may serialize tool arguments,
    result bodies and unaudited provider values. It must not receive Project
    bearer/delegation/collector secrets. Trace IDs are carried in the OTel
    context, never duplicated as high-cardinality metric dimensions.
    """

    def __init__(
        self,
        service: str,
        sink: CompositeObservabilitySink,
        *,
        buffer: BoundedRuntimeToolEvents | None = None,
    ) -> None:
        self.service = service
        self.sink = sink
        self.buffer = buffer

    def _publish(self, event: InvocationEvent) -> None:
        if self.buffer is not None:
            self.buffer.publish(event)
        else:
            # Source-only fallback, used by non-ASGI private facades. The
            # officially constructed Gateway/modules always supply a buffer.
            self.sink.record_invocation(event, audit=False)

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        raw = context.message.name
        family = raw.partition("_")[0].partition(".")[0].casefold()
        tool = family if family in _TOOL_FAMILIES else "other"
        attributes: dict[str, object] = {"mcp.scope": self.service, "mcp.tool": tool}
        started = time.monotonic()
        failure: BaseException | None = None
        result: ToolResult | None = None
        # Common OTel trace_span(record_exception=True) would put the original
        # exception.message (potentially credential-bearing) into exporter
        # events if a provider exception escaped the span context. Catch the
        # exception *inside*, record only bounded error TYPE, then propagate
        # it to FastMCP only AFTER the trace span has closed successfully.
        with self.sink.trace_span("briareus.runtime.tool", attributes):
            try:
                result = await call_next(context)
            except asyncio.CancelledError as exc:
                failure = exc
                self._publish(
                    InvocationEvent(
                        module=self.service,
                        tool=tool,
                        status="error",
                        duration_ms=(time.monotonic() - started) * 1000,
                        error_type="cancelled",
                    )
                )
            except Exception as exc:
                failure = exc
                # Bounded, CLOSED error categories only. A dynamically named
                # provider exception must not create high-cardinality labels.
                raw = type(exc).__name__.casefold()
                if "timeout" in raw:
                    error = "timeout"
                elif "permission" in raw or "denied" in raw or "forbidden" in raw:
                    error = "denied"
                elif "invalid" in raw or "validation" in raw or "valueerror" in raw:
                    error = "invalid"
                elif "unavailable" in raw or "connection" in raw:
                    error = "unavailable"
                else:
                    error = "other"
                self._publish(
                    InvocationEvent(
                        module=self.service,
                        tool=tool,
                        status="error",
                        duration_ms=(time.monotonic() - started) * 1000,
                        error_type=error,
                    )
                )
            else:
                self._publish(
                    InvocationEvent(
                        module=self.service,
                        tool=tool,
                        status="success",
                        duration_ms=(time.monotonic() - started) * 1000,
                    )
                )
        if failure is not None:
            raise failure
        assert result is not None
        return result


@dataclass(slots=True)
class RuntimeTelemetry:
    """Own a single exporter, not a second global tracer/meter provider."""

    service: str
    sink: CompositeObservabilitySink
    event_buffer: BoundedRuntimeToolEvents = field(init=False)
    _started: bool = False

    def __post_init__(self) -> None:
        self.event_buffer = BoundedRuntimeToolEvents(self.service, self.sink)

    @classmethod
    def construct(
        cls,
        service: str,
    ) -> RuntimeTelemetry:
        if service not in _ALLOWED:
            raise ValueError("unknown Briareus OTel service.name")
        settings = ObservabilitySettings()
        # Per-App literal identity is not another user-editable Team override.
        # Reject bad D4 composition rather than exporting service data under
        # a different product's resource name or a shared fake identity.
        if settings.service_name and settings.service_name != service:
            raise ValueError("OTEL_SERVICE_NAME conflicts with the Runtime service")
        # Do not create historical AdminApiAuditSink: that queue transports
        # rendered tool arguments/results and is NOT a protected MCP audit UoW.
        sink = build_observability(service, settings=settings)
        for channel in sink.sinks:
            if isinstance(channel, OpenTelemetrySink):
                channel.logging_handler.addFilter(_OnlySanitizedRuntimeLogs())
        return cls(service=service, sink=sink)

    async def _heartbeats(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=_HEARTBEAT_SECONDS)
            except TimeoutError:
                await asyncio.to_thread(self.sink.record_runtime_heartbeat, self.service)

    async def _shutdown(self) -> None:
        def close_all() -> None:
            # Existing shared CompositeObservabilitySink intentionally has no
            # close() method. Its Backend-owned concrete sinks do; never
            # install an additional exporter merely to flush these.
            for sink in reversed(self.sink.sinks):
                try:
                    if hasattr(sink, "shutdown"):
                        sink.shutdown()
                    elif hasattr(sink, "close"):
                        sink.close()
                except Exception:
                    _LOG.warning("Runtime telemetry shutdown failed service=%s", self.service)

        await asyncio.to_thread(close_all)

    def attach(self, app: Starlette) -> Starlette:
        """Wrap the EXISTING FastMCP lifespan, preserving provider cleanup."""
        original = app.router.lifespan_context

        @asynccontextmanager
        async def lifecycle(active: Starlette) -> AsyncIterator[Any]:
            # FastMCP may yield ASGI lifespan state (including its session
            # manager). Preserve it; dropping this mapping breaks tool calls
            # even though OTel startup metrics appeared to work.
            async with original(active) as original_state:
                if self._started:
                    raise RuntimeError("Runtime telemetry lifespan entered twice")
                self._started = True
                stop = asyncio.Event()
                task: asyncio.Task[None] | None = None
                meter_worker: asyncio.Task[None] | None = None
                try:
                    # `record_runtime_started` creates a counter, gauge,
                    # trace and redacted log and force-flushes all three.
                    # Startup reporting must not block the ASGI event loop.
                    await asyncio.to_thread(self.sink.record_runtime_started, self.service)
                    meter_worker = asyncio.create_task(self.event_buffer.run(stop))
                    task = asyncio.create_task(self._heartbeats(stop))
                    yield original_state
                finally:
                    self.event_buffer.stop_accepting()
                    stop.set()
                    if task is not None:
                        task.cancel()
                        with suppress(asyncio.CancelledError):
                            await task
                    if meter_worker is not None:
                        try:
                            # No indefinitely draining exporter backlog. The
                            # queue has at most 512 nonsecret metric events.
                            await asyncio.wait_for(meter_worker, timeout=5.0)
                        except (TimeoutError, asyncio.CancelledError):
                            meter_worker.cancel()
                            with suppress(asyncio.CancelledError):
                                await meter_worker
                            _LOG.warning("Runtime telemetry drain timeout service=%s", self.service)
                    await self._shutdown()
                    self._started = False

        app.router.lifespan_context = lifecycle
        return app


def build_runtime_mcp(
    service: str,
    *,
    name: str | None = None,
) -> tuple[FastMCP, RuntimeTelemetry]:
    """One sink/provider per actual process, shared with MCP tool middleware."""
    owner = RuntimeTelemetry.construct(service)
    mcp = FastMCP(
        name or service,
        middleware=[SafeRuntimeToolTelemetry(service, owner.sink, buffer=owner.event_buffer)],
    )
    return mcp, owner
