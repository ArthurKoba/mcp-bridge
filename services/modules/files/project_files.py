"""Unmounted Briareus Project Files: A6 signed quota and storage authority.

Never bind methods to FastMCP/HTTP before C1-B2/C2; no A4/A5/R6 quota,
unsafe global workspace, unauthenticated local write or overwrite fallback.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from modules.project_runtime import (
    ProjectAccessDenied,
    ProjectInvocation,
    ProjectPermit,
    ProjectRootRegistry,
    ProjectRuntimeAuthority,
)

from .a6_signed import A6FilesUnavailable, A6SignedFilesFlow, canonical_files_path
from .project_workspace import (
    ProjectFileEntry,
    ProjectFilePage,
    ProjectFileSnapshot,
    ProjectFileWriteStage,
    ProjectWorkspaceFiles,
)


async def _drain_cancellable_file_io[**P, T](
    func: Callable[P, T], *args: P.args, **kwargs: P.kwargs
) -> T:
    """Never close a staging fd while a non-cancellable OS thread uses it."""
    pending = asyncio.create_task(asyncio.to_thread(func, *args, **kwargs))
    try:
        return await asyncio.shield(pending)
    except asyncio.CancelledError:
        # A second cancellation must not make stage.close race a worker fd.
        while not pending.done():
            try:
                await asyncio.shield(pending)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        with suppress(BaseException):
            pending.result()
        raise


class ProjectFilesService:
    def __init__(
        self,
        authority: ProjectRuntimeAuthority,
        roots: ProjectRootRegistry,
        *,
        max_file_bytes: int,
        a6_quota: A6SignedFilesFlow,
    ) -> None:
        if not isinstance(a6_quota, A6SignedFilesFlow):
            raise A6FilesUnavailable("A6_FILES_SIGNED_QUOTA_REQUIRED")
        self.a6_quota = a6_quota
        self.authority = authority
        self.roots = roots
        self._store = ProjectWorkspaceFiles(roots, max_file_bytes=max_file_bytes)
        self.max_file_bytes = max_file_bytes

    async def _confirm_read(
        self, invocation: ProjectInvocation, previous: ProjectPermit
    ) -> ProjectPermit:
        """Fence a long Files read against revoked/changed Project ownership."""
        current = await self.authority.require(invocation, "files.read")
        if (
            current.project_id != previous.project_id
            or current.actor_id != previous.actor_id
            or current.session_uuid != previous.session_uuid
            or current.project_access_revision != previous.project_access_revision
            or current.decision_version != previous.decision_version
            or current.project_owner_scope != previous.project_owner_scope
            or current.project_owner_id != previous.project_owner_id
            or current.owner_fence != previous.owner_fence
        ):
            raise ProjectAccessDenied("FILE_PROJECT_ACCESS_STALE")
        return current

    async def _a6_read_permit(
        self,
        invocation: ProjectInvocation,
        permit: ProjectPermit,
        *,
        path: str,
        phase: Literal["read", "list", "metadata"],
        max_bytes: int,
    ) -> None:
        flow = self.a6_quota
        scope = invocation.operation_scope
        if scope is None or scope.action != "files.read":
            raise A6FilesUnavailable("A6_FILES_READ_SCOPE_REQUIRED")
        await flow.read_permit(
            invocation,
            initial=permit,
            path=path,
            phase=phase,
            max_bytes=max_bytes,
            operation_uuid=scope.request_uuid,
        )

    async def provision(self, invocation: ProjectInvocation) -> None:
        # Storage roots can only be provisioned by a trusted Project OS owner
        # after a signed Backend management operation; FilesQuota-v2 does not
        # grant directory creation or an arbitrary Unix mount lifecycle.
        await self.authority.require(invocation, "files.write")
        raise A6FilesUnavailable("A6_FILES_PROVISIONING_OS_OWNER_REQUIRED")

    async def list(
        self,
        invocation: ProjectInvocation,
        path: str = "",
        *,
        offset: int = 0,
        limit: int = 200,
    ) -> ProjectFilePage:
        permit = await self.authority.require(invocation, "files.read")
        await self._a6_read_permit(invocation, permit, path=path, phase="list", max_bytes=0)
        result = await asyncio.to_thread(self._store.list, permit, path, offset=offset, limit=limit)
        await self._confirm_read(invocation, permit)
        return result

    async def info(self, invocation: ProjectInvocation, path: str) -> ProjectFileEntry:
        permit = await self.authority.require(invocation, "files.read")
        await self._a6_read_permit(invocation, permit, path=path, phase="metadata", max_bytes=0)
        result = await asyncio.to_thread(self._store.info, permit, path)
        await self._confirm_read(invocation, permit)
        return result

    @asynccontextmanager
    async def open_snapshot(
        self,
        invocation: ProjectInvocation,
        path: str,
        *,
        chunk_bytes: int = 1024 * 1024,
    ) -> AsyncIterator[ProjectFileSnapshot]:
        permit = await self.authority.require(invocation, "files.read")
        # The signed read budget must also cap the physical snapshot copy.
        metadata = await self.info(invocation, path)
        if metadata.kind != "file" or metadata.size_bytes > 1048576:
            raise A6FilesUnavailable("A6_FILES_SNAPSHOT_TOO_LARGE")
        await self._a6_read_permit(
            invocation,
            permit,
            path=path,
            phase="read",
            max_bytes=metadata.size_bytes,
        )
        task = asyncio.create_task(
            asyncio.to_thread(
                self._store.snapshot,
                permit,
                path,
                chunk_bytes=chunk_bytes,
                max_snapshot_bytes=metadata.size_bytes,
            )
        )
        try:
            snapshot = await asyncio.shield(task)
        except asyncio.CancelledError:
            # A thread cannot be canceled mid-copy; reclaim the anonymous fd
            # even when its caller has already disconnected/canceled.
            def discard_late_result(done: asyncio.Task[ProjectFileSnapshot]) -> None:
                if not done.cancelled() and done.exception() is None:
                    done.result().close()

            task.add_done_callback(discard_late_result)
            raise
        try:
            if snapshot.size_bytes != metadata.size_bytes:
                raise A6FilesUnavailable("A6_FILES_SNAPSHOT_REVISION_CHANGED")
            scope = invocation.operation_scope
            if scope is None or scope.action != "files.read":
                raise A6FilesUnavailable("A6_FILES_SNAPSHOT_SIGNED_SCOPE_REQUIRED")
            # ONE signed owner READ covers bounded private FD content. Every
            # subsequent chunk still checks the current three-owner grant,
            # without conflicting A11 (UUID, phase) idempotency payloads.
            snapshot.signed_operation_uuid = scope.request_uuid
            snapshot.signed_owner_fence = permit.owner_fence
            await self._confirm_read(invocation, permit)
            yield snapshot
        finally:
            snapshot.close()

    async def read_snapshot_chunk(
        self,
        invocation: ProjectInvocation,
        snapshot: ProjectFileSnapshot,
        *,
        offset: int,
        length: int,
    ) -> bytes:
        """Refresh Files read grants during long-lived Reverse upload sessions."""
        if (
            type(offset) is not int
            or type(length) is not int
            or offset < 0
            or not 0 < length <= 1048576
            or offset > snapshot.size_bytes
        ):
            raise A6FilesUnavailable("A6_FILES_SIGNED_CHUNK_RANGE_INVALID")
        permit = await self.authority.require(invocation, "files.read")
        scope = invocation.operation_scope
        if (
            scope is None
            or scope.action != "files.read"
            or snapshot.signed_operation_uuid != scope.request_uuid
            or snapshot.signed_owner_fence != permit.owner_fence
        ):
            raise ProjectAccessDenied("FILE_SNAPSHOT_SIGNED_OWNER_CHANGED")
        if (
            snapshot.project_id != permit.project_id
            or snapshot.actor_id != permit.actor_id
            or snapshot.agent_session_uuid != permit.session_uuid
            or snapshot.project_access_revision != permit.project_access_revision
            or snapshot.agent_session_version != permit.decision_version
        ):
            raise ProjectAccessDenied("FILE_SNAPSHOT_SCOPE_DENIED")
        content = await _drain_cancellable_file_io(snapshot.read_chunk, offset, length)
        await self._confirm_read(invocation, permit)
        return content

    async def sha256(self, invocation: ProjectInvocation, path: str) -> str:
        permit = await self.authority.require(invocation, "files.read")
        metadata = await self.info(invocation, path)
        if metadata.kind != "file" or metadata.size_bytes > 1048576:
            raise A6FilesUnavailable("A6_FILES_HASH_TOO_LARGE")
        await self._a6_read_permit(
            invocation,
            permit,
            path=path,
            phase="read",
            max_bytes=metadata.size_bytes,
        )
        # Enforce the actual signed read budget. The low-level store detects
        # concurrent inode modification before returning any digest bytes.
        payload = await asyncio.to_thread(
            self._store.read, permit, path, max_bytes=metadata.size_bytes
        )
        if len(payload) != metadata.size_bytes:
            raise A6FilesUnavailable("A6_FILES_HASH_CONTENT_CHANGED")
        digest = hashlib.sha256(payload).hexdigest()
        await self._confirm_read(invocation, permit)
        return digest

    async def read(
        self, invocation: ProjectInvocation, path: str, *, max_bytes: int | None = None
    ) -> bytes:
        permit = await self.authority.require(invocation, "files.read")
        limit = self.max_file_bytes if max_bytes is None else max_bytes
        if type(limit) is not int or not 0 < limit <= 1048576:
            raise A6FilesUnavailable("A6_FILES_READ_LIMIT_EXCEEDED")
        await self._a6_read_permit(
            invocation,
            permit,
            path=path,
            phase="read",
            max_bytes=limit,
        )
        result = await asyncio.to_thread(self._store.read, permit, path, max_bytes=limit)
        await self._confirm_read(invocation, permit)
        return result

    async def write_stream(
        self,
        invocation: ProjectInvocation,
        destination: str,
        chunks: AsyncIterator[bytes],
        *,
        create_parents: bool = False,
        expected_sha256: str = "",
        expected_size: int | None = None,
        operation_uuid: UUID | None = None,
    ) -> ProjectFileEntry:
        if create_parents:
            raise A6FilesUnavailable("A6_DIRECTORY_INODE_LEDGER_UNAVAILABLE")
        if (
            type(expected_size) is not int
            or not 0 <= expected_size <= min(self.max_file_bytes, 262144)
            or not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_sha256)
            or not isinstance(operation_uuid, UUID)
            or operation_uuid.version != 4
        ):
            raise A6FilesUnavailable("A6_FILES_EXACT_UPLOAD_PARAMETERS_REQUIRED")
        destination = canonical_files_path(destination)
        initial = await self.authority.require(invocation, "files.write")
        return await self._write_stream_a6(
            invocation,
            initial=initial,
            destination=destination,
            chunks=chunks,
            expected_sha256=expected_sha256,
            expected_size=expected_size,
            operation_uuid=operation_uuid,
        )

    async def _write_stream_a6(
        self,
        invocation: ProjectInvocation,
        *,
        initial: ProjectPermit,
        destination: str,
        chunks: AsyncIterator[bytes],
        expected_sha256: str,
        expected_size: int,
        operation_uuid: UUID,
    ) -> ProjectFileEntry:
        """One independent signed A6 authorization per SQL/OS phase.

        The verified peer and an independently trusted UID/mount/inode Files
        supervisor are REQUIRED before even reserving quota. A6 v2 never
        falls back to a local or unsigned SQL quota adapter.
        """
        flow = self.a6_quota
        flow.require_write_ready()
        reserved = await flow.reserve(
            invocation,
            initial=initial,
            destination=destination,
            operation_uuid=operation_uuid,
            size_bytes=expected_size,
            sha256=expected_sha256,
        )
        dispatched = await flow.transition(
            invocation,
            initial=initial,
            before=reserved,
            phase="dispatch",
        )
        # The SQL DISPATCHED ACK precedes all filesystem mutation. An unknown
        # dispatch outcome is never resumed/replayed from a new UUID.
        task = asyncio.create_task(
            asyncio.to_thread(
                self._store.open_write_stage,
                initial,
                destination,
                create_parents=False,
                expected_sha256=expected_sha256,
            )
        )
        try:
            stage = await asyncio.shield(task)
        except BaseException:

            def dispose_late_stage(done: asyncio.Task[ProjectFileWriteStage]) -> None:
                if not done.cancelled() and done.exception() is None:
                    done.result().close()

            task.add_done_callback(dispose_late_stage)
            with suppress(Exception):
                await asyncio.shield(
                    flow.mark_unknown(
                        invocation,
                        initial=initial,
                        dispatched=dispatched,
                    )
                )
            raise
        try:
            offset = 0
            async for chunk in chunks:
                if not isinstance(chunk, bytes):
                    raise A6FilesUnavailable("A6_FILES_CHUNK_NOT_BYTES")
                if len(chunk) > 262144 or offset + len(chunk) > expected_size:
                    raise A6FilesUnavailable("A6_FILES_CHUNK_EXCEEDS_SIGNED_RESERVATION")
                offset = await _drain_cancellable_file_io(stage.write_chunk, offset, chunk)
                if offset > expected_size:
                    raise A6FilesUnavailable("A6_FILES_STREAM_OVERRAN_RESERVATION")
            if offset != expected_size:
                raise A6FilesUnavailable("A6_FILES_STREAM_SHORT")
            current = await self.authority.require(invocation, "files.write")
            if (
                current.actor_id != initial.actor_id
                or current.session_uuid != initial.session_uuid
                or current.decision_version != initial.decision_version
                or current.project_access_revision != initial.project_access_revision
                or current.project_owner_scope != initial.project_owner_scope
                or current.project_owner_id != initial.project_owner_id
                or current.owner_fence != initial.owner_fence
                or current.expires_at <= datetime.now(UTC)
                or dispatched.expires_at <= datetime.now(UTC)
            ):
                raise A6FilesUnavailable("A6_FILES_OWNER_OR_SESSION_STALE")
            committed = await _drain_cancellable_file_io(stage.commit, current)
            inode_digest = await _drain_cancellable_file_io(lambda: stage.observed_inode_digest)
            # This only validates a pinned descriptor and current destination.
            # A separate Files storage supervisor MUST attest current mount,
            # UID, volume digest and inode provenance before SQL finalize.
            observation = await flow.committed_observation(
                invocation,
                initial=initial,
                dispatched=dispatched,
                inode_digest=inode_digest,
                content_sha256=expected_sha256,
                size_bytes=committed.size_bytes,
            )
            await flow.complete(
                invocation,
                initial=initial,
                dispatched=dispatched,
                command=observation,
            )
            return committed
        except BaseException:
            # The irreversible rename or SQL commit may already have happened.
            # An OS/SQL observer must reconcile the ORIGINAL operation UUID.
            with suppress(Exception):
                await asyncio.shield(
                    flow.mark_unknown(
                        invocation,
                        initial=initial,
                        dispatched=dispatched,
                    )
                )
            raise
        finally:
            stage.close()

    async def write(
        self,
        invocation: ProjectInvocation,
        path: str,
        contents: bytes,
        *,
        overwrite: bool = False,
        create_parents: bool = False,
        operation_uuid: UUID | None = None,
    ) -> ProjectFileEntry:
        if overwrite:
            raise A6FilesUnavailable("A6_FILES_OVERWRITE_UNAVAILABLE")
        if not isinstance(contents, bytes):
            raise A6FilesUnavailable("A6_FILES_CONTENT_INVALID")

        async def one_chunk() -> AsyncIterator[bytes]:
            yield contents

        return await self.write_stream(
            invocation,
            path,
            one_chunk(),
            create_parents=create_parents,
            expected_size=len(contents),
            expected_sha256=hashlib.sha256(contents).hexdigest(),
            operation_uuid=operation_uuid,
        )

    async def mkdir(
        self, invocation: ProjectInvocation, path: str, *, parents: bool = False
    ) -> None:
        _ = (invocation, path, parents)
        raise A6FilesUnavailable("A6_DIRECTORY_INODE_LEDGER_UNAVAILABLE")

    async def move(
        self,
        invocation: ProjectInvocation,
        source: str,
        destination: str,
        *,
        overwrite: bool = False,
    ) -> None:
        _ = (invocation, source, destination, overwrite)
        raise A6FilesUnavailable("A6_FILES_MOVE_METADATA_CAS_UNAVAILABLE")

    async def copy(
        self,
        invocation: ProjectInvocation,
        source: str,
        destination: str,
        *,
        overwrite: bool = False,
        operation_uuid: UUID | None = None,
    ) -> ProjectFileEntry:
        _ = (invocation, source, destination, overwrite, operation_uuid)
        raise A6FilesUnavailable("A6_FILES_COPY_SOURCE_CAS_UNAVAILABLE")

    async def cleanup_orphan_uploads(
        self,
        invocation: ProjectInvocation,
        path: str = "",
        *,
        older_than_seconds: float = 3600.0,
        limit: int = 128,
    ) -> int:
        _ = (invocation, path, older_than_seconds, limit)
        raise A6FilesUnavailable("A6_FILES_ORPHAN_CLEANUP_LEDGER_REQUIRED")

    async def delete(self, invocation: ProjectInvocation, path: str) -> None:
        _ = (invocation, path)
        raise A6FilesUnavailable("A6_FILES_DELETE_METADATA_CAS_UNAVAILABLE")
