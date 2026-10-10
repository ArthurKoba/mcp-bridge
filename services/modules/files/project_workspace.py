"""Descriptor-confined Project filesystem, not registered as MCP tools.

The caller must have obtained a fresh ProjectPermit through the private
ProjectRuntimeAuthority. The Unix process running this store must itself be
isolated from untrusted shell processes before project routes are mounted.
"""

from __future__ import annotations

import ctypes

# Nested descriptor scopes make the containment boundary visible at each step.
# ruff: noqa: SIM117
import errno
import fcntl
import hashlib
import os
import re
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from modules.project_runtime import ProjectAction, ProjectPermit
from modules.project_runtime.authorization import ProjectOwnerFence
from modules.project_runtime.workspace_roots import (
    _DIR_FLAGS,
    ProjectFileError,
    ProjectRootRegistry,
    _open_beneath,
    _safe_directory,
)

_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_RENAME_NOREPLACE = 1
_TEMP_NAME = re.compile(r"^\.upload-[0-9a-f]{32}\.tmp$")


@dataclass(frozen=True, slots=True)
class ProjectFileEntry:
    path: str
    kind: str
    size_bytes: int
    modified_at_ns: int


@dataclass(frozen=True, slots=True)
class ProjectFilePage:
    entries: tuple[ProjectFileEntry, ...]
    total: int
    offset: int
    limit: int


def _components(value: str, *, root_allowed: bool = False) -> tuple[str, ...]:
    if not isinstance(value, str) or "\\" in value or "\x00" in value or value.startswith("/"):
        raise ProjectFileError("FILE_PATH_INVALID")
    if root_allowed and value == "":
        return ()
    parts = value.split("/")
    try:
        byte_length = len(value.encode("utf-8", errors="strict"))
        invalid_parts = any(
            p in {"", ".", ".."}
            or len(p.encode("utf-8", errors="strict")) > 255
            or any(ord(c) < 32 or ord(c) == 127 for c in p)
            for p in parts
        )
    except UnicodeError as exc:
        raise ProjectFileError("FILE_PATH_INVALID") from exc
    if byte_length > 4096 or len(parts) > 64 or invalid_parts:
        raise ProjectFileError("FILE_PATH_INVALID")
    if any(_TEMP_NAME.fullmatch(part) for part in parts):
        raise ProjectFileError("FILE_PATH_RESERVED")
    return tuple(parts)


def _leaf_stat(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _checked_file(fd: int, *, device: int) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise ProjectFileError("FILE_REGULAR_REQUIRED")
    if info.st_dev != device or info.st_nlink != 1:
        raise ProjectFileError("FILE_UNSAFE_LINK")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        # A Project worker must not read a file created for a different UID
        # or accidentally exposed to other Unix users/groups. A mode-0600
        # source is a necessary (not sufficient) OS isolation invariant.
        raise ProjectFileError("FILE_OWNER_MODE_UNSAFE")
    return info


def _checked_entry(info: os.stat_result, *, device: int) -> None:
    if info.st_dev != device:
        raise ProjectFileError("FILE_MOUNT_CROSSING_DENIED")
    if stat.S_ISLNK(info.st_mode):
        raise ProjectFileError("FILE_SYMLINK_DENIED")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise ProjectFileError("FILE_UNSAFE_LINK")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ProjectFileError("FILE_OWNER_MODE_UNSAFE")
    if not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
        raise ProjectFileError("FILE_TYPE_DENIED")


def _rename_no_replace(
    source_fd: int, source_name: str, destination_fd: int, destination_name: str
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise ProjectFileError("FILE_ATOMIC_MOVE_UNAVAILABLE")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result: int = rename(
        source_fd,
        os.fsencode(source_name),
        destination_fd,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    number = ctypes.get_errno()
    if number == errno.EEXIST:
        raise ProjectFileError("FILE_EXISTS")
    if number in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
        raise ProjectFileError("FILE_ATOMIC_MOVE_UNAVAILABLE")
    raise OSError(number, os.strerror(number))


@dataclass(slots=True)
class ProjectFileSnapshot:
    """Owned anonymous snapshot descriptor. Close after use; never expose fd in MCP."""

    project_id: UUID
    actor_id: UUID
    agent_session_uuid: UUID
    project_access_revision: str | None
    agent_session_version: int
    path: str
    size_bytes: int
    sha256: str
    _fd: int
    signed_operation_uuid: UUID | None = None
    signed_owner_fence: ProjectOwnerFence | None = None

    def read_chunk(self, offset: int, length: int) -> bytes:
        if self._fd < 0:
            raise ProjectFileError("FILE_SNAPSHOT_CLOSED")
        if offset < 0 or not 0 < length <= 16 * 1024 * 1024:
            raise ProjectFileError("FILE_SNAPSHOT_RANGE_INVALID")
        return os.pread(self._fd, min(length, max(0, self.size_bytes - offset)), offset)

    def close(self) -> None:
        if self._fd >= 0:
            fd = self._fd
            self._fd = -1
            os.close(fd)


class ProjectFileWriteStage:
    """An explicitly closed private staging capability, never an MCP tool.

    No partial target file is visible. Overwrite is deliberately unavailable
    until the cross-process expected-version/idempotency policy is accepted.
    """

    def __init__(
        self,
        *,
        project_id: UUID,
        actor_id: UUID,
        session_uuid: UUID,
        project_access_revision: str | None,
        agent_session_version: int,
        owner_fence: ProjectOwnerFence,
        destination: str,
        name: str,
        temporary: str,
        fd: int,
        parent_fd: int,
        max_bytes: int,
        expected_sha256: str = "",
    ) -> None:
        self.project_id = project_id
        self.actor_id = actor_id
        self.session_uuid = session_uuid
        self.project_access_revision = project_access_revision
        self.agent_session_version = agent_session_version
        if not isinstance(owner_fence, ProjectOwnerFence) or not owner_fence.valid():
            raise ProjectFileError("FILE_STAGE_SIGNED_OWNER_FENCE_REQUIRED")
        self.owner_fence = owner_fence
        self.destination = destination
        self._name = name
        self._temporary = temporary
        self._fd = fd
        self._parent_fd = parent_fd
        self.max_bytes = max_bytes
        self.expected_sha256 = expected_sha256
        self._size = 0
        self._digest = hashlib.sha256()
        self._committed = False
        self._closed = False
        self._inode = os.fstat(fd).st_ino
        # Cross-process advisory lock: orphan cleanup must skip live stages.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    @property
    def committed(self) -> bool:
        return self._committed

    @property
    def observed_inode_digest(self) -> str:
        """Digest of pinned file identity after atomic rename, never OS path."""
        if not self._committed or self._closed:
            raise ProjectFileError("FILE_STAGE_NOT_COMMITTED")
        info = os.fstat(self._fd)
        # An open descriptor can survive a rename *away* from the Project
        # destination. Verify the current target leaf before reporting inode
        # proof to A5 FileQuotaLedger, not just the historic pinned FD.
        destination = _leaf_stat(self._parent_fd, self._name)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_ino != self._inode
            or info.st_nlink != 1
            or info.st_size != self._size
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or destination is None
            or not stat.S_ISREG(destination.st_mode)
            or destination.st_dev != info.st_dev
            or destination.st_ino != info.st_ino
            or destination.st_nlink != 1
            or destination.st_size != info.st_size
            or destination.st_ctime_ns != info.st_ctime_ns
            or destination.st_mtime_ns != info.st_mtime_ns
            or destination.st_uid != info.st_uid
            or destination.st_mode & 0o077
        ):
            raise ProjectFileError("FILE_STAGE_CHANGED_AFTER_COMMIT")
        return hashlib.sha256(
            f"{info.st_dev}:{info.st_ino}:{info.st_ctime_ns}".encode("ascii")
        ).hexdigest()

    def write_chunk(self, offset: int, data: bytes) -> int:
        if self._closed or self._committed:
            raise ProjectFileError("FILE_STAGE_CLOSED")
        if not isinstance(data, bytes) or offset != self._size or offset < 0:
            raise ProjectFileError("FILE_STAGE_OFFSET_INVALID")
        if self._size + len(data) > self.max_bytes:
            raise ProjectFileError("FILE_TOO_LARGE")
        view = memoryview(data)
        while view:
            written = os.write(self._fd, view)
            if written <= 0:
                raise ProjectFileError("FILE_STAGE_WRITE_FAILED")
            view = view[written:]
        self._digest.update(data)
        self._size += len(data)
        return self._size

    def commit(self, permit: ProjectPermit) -> ProjectFileEntry:
        if self._closed or self._committed:
            raise ProjectFileError("FILE_STAGE_CLOSED")
        if (
            permit.action != "files.write"
            or permit.project_id != self.project_id
            or permit.actor_id != self.actor_id
            or permit.session_uuid != self.session_uuid
            or permit.project_access_revision != self.project_access_revision
            or permit.decision_version != self.agent_session_version
            or permit.owner_fence != self.owner_fence
        ):
            raise ProjectFileError("FILE_STAGE_PERMISSION_DENIED")
        if (
            not isinstance(permit.expires_at, datetime)
            or permit.expires_at.tzinfo is None
            or permit.expires_at <= datetime.now(UTC)
        ):
            raise ProjectFileError("FILE_STAGE_PERMIT_EXPIRED")
        if self.expected_sha256 and self._digest.hexdigest() != self.expected_sha256:
            raise ProjectFileError("FILE_STAGE_CHECKSUM_MISMATCH")
        os.fsync(self._fd)
        info = os.fstat(self._fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_ino != self._inode
            or info.st_nlink != 1
            or info.st_size != self._size
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise ProjectFileError("FILE_STAGE_CHANGED")
        _rename_no_replace(self._parent_fd, self._temporary, self._parent_fd, self._name)
        self._committed = True
        try:
            os.fsync(self._parent_fd)
        except OSError as exc:
            # Destination already appeared: never ask a caller to retry a
            # potentially non-idempotent upload on a lost fsync response.
            raise ProjectFileError("FILE_STAGE_COMMIT_UNCERTAIN") from exc
        return ProjectFileEntry(
            self.destination, "file", self._size, os.fstat(self._fd).st_mtime_ns
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if not self._committed:
                current = _leaf_stat(self._parent_fd, self._temporary)
                if current is not None and current.st_ino == self._inode:
                    os.unlink(self._temporary, dir_fd=self._parent_fd)
        finally:
            try:
                os.close(self._fd)
            finally:
                os.close(self._parent_fd)


class ProjectWorkspaceFiles:
    """Owner-scoped filesystem operations; permission is refreshed by caller.

    Operations remain limited to regular single-link files and directories on
    the same device. All ancestors are opened with O_NOFOLLOW. Per-file size
    is capped; cross-process aggregate quota/transactions are C1-B decisions.
    """

    def __init__(
        self,
        roots: ProjectRootRegistry,
        *,
        max_file_bytes: int,
        max_directory_entries: int = 10000,
    ) -> None:
        if max_file_bytes <= 0 or max_directory_entries <= 0:
            raise ValueError("filesystem limits must be positive")
        self.roots = roots
        self.max_file_bytes = max_file_bytes
        self.max_directory_entries = max_directory_entries

    @staticmethod
    def _require_action(permit: ProjectPermit, action: ProjectAction) -> None:
        if (
            not isinstance(permit, ProjectPermit)
            or permit.action != action
            or not isinstance(permit.owner_fence, ProjectOwnerFence)
            or not permit.owner_fence.valid()
            or permit.expires_at.tzinfo is None
            or permit.expires_at <= datetime.now(UTC)
        ):
            raise ProjectFileError("FILE_PERMISSION_OR_OWNER_FENCE_DENIED")

    @staticmethod
    @contextmanager
    def _parent(root_fd: int, parts: tuple[str, ...], *, create: bool = False) -> Iterator[int]:
        device = os.fstat(root_fd).st_dev
        fd = os.dup(root_fd)
        try:
            for part in parts:
                if create:
                    with suppress(FileExistsError):
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                next_fd = _open_beneath(fd, part, _DIR_FLAGS)
                os.close(fd)
                fd = next_fd
                _safe_directory(fd, expected_device=device)
            yield fd
        except FileNotFoundError as exc:
            raise ProjectFileError("FILE_DIRECTORY_NOT_FOUND") from exc
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ProjectFileError("FILE_PATH_UNSAFE") from exc
            raise
        finally:
            os.close(fd)

    def list(
        self,
        permit: ProjectPermit,
        path: str = "",
        *,
        offset: int = 0,
        limit: int = 200,
    ) -> ProjectFilePage:
        self._require_action(permit, "files.read")
        if offset < 0 or not 1 <= limit <= 1000:
            raise ProjectFileError("FILE_PAGINATION_INVALID")
        parts = _components(path, root_allowed=True)
        with self.roots.open(permit) as root_fd:
            with self._parent(root_fd, parts) as directory_fd:
                device = os.fstat(root_fd).st_dev
                entries: list[ProjectFileEntry] = []
                with os.scandir(directory_fd) as items:
                    scanned = 0
                    for item in items:
                        scanned += 1
                        if scanned > self.max_directory_entries:
                            raise ProjectFileError("FILE_DIRECTORY_TOO_LARGE")
                        if _TEMP_NAME.fullmatch(item.name):
                            continue
                        info = item.stat(follow_symlinks=False)
                        try:
                            _checked_entry(info, device=device)
                        except ProjectFileError:
                            continue
                        entries.append(
                            ProjectFileEntry(
                                path="/".join((*parts, item.name)),
                                kind="directory" if stat.S_ISDIR(info.st_mode) else "file",
                                size_bytes=0 if stat.S_ISDIR(info.st_mode) else info.st_size,
                                modified_at_ns=info.st_mtime_ns,
                            )
                        )
                entries.sort(key=lambda entry: (entry.kind != "directory", entry.path.casefold()))
                self.roots._project_name(permit)
                return ProjectFilePage(
                    entries=tuple(entries[offset : offset + limit]),
                    total=len(entries),
                    offset=offset,
                    limit=limit,
                )

    def info(self, permit: ProjectPermit, path: str) -> ProjectFileEntry:
        self._require_action(permit, "files.read")
        parts = _components(path)
        with self.roots.open(permit) as root_fd:
            with self._parent(root_fd, parts[:-1]) as parent_fd:
                info = _leaf_stat(parent_fd, parts[-1])
                if info is None:
                    raise ProjectFileError("FILE_NOT_FOUND")
                _checked_entry(info, device=os.fstat(root_fd).st_dev)
                kind = "directory" if stat.S_ISDIR(info.st_mode) else "file"
                return ProjectFileEntry(
                    path=path,
                    kind=kind,
                    size_bytes=0 if kind == "directory" else info.st_size,
                    modified_at_ns=info.st_mtime_ns,
                )

    def read(self, permit: ProjectPermit, path: str, *, max_bytes: int | None = None) -> bytes:
        self._require_action(permit, "files.read")
        parts = _components(path)
        limit = self.max_file_bytes if max_bytes is None else min(self.max_file_bytes, max_bytes)
        if type(limit) is not int or limit < 0:
            raise ProjectFileError("FILE_SIZE_INVALID")
        with self.roots.open(permit) as root_fd:
            with self._parent(root_fd, parts[:-1]) as parent_fd:
                try:
                    fd = _open_beneath(parent_fd, parts[-1], _FILE_FLAGS)
                except FileNotFoundError as exc:
                    raise ProjectFileError("FILE_NOT_FOUND") from exc
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise ProjectFileError("FILE_SYMLINK_DENIED") from exc
                    raise
                try:
                    info = _checked_file(fd, device=os.fstat(root_fd).st_dev)
                    if info.st_size > limit:
                        raise ProjectFileError("FILE_TOO_LARGE")
                    with os.fdopen(fd, "rb", closefd=False) as stream:
                        contents = stream.read(limit + 1)
                    if len(contents) > limit:
                        raise ProjectFileError("FILE_TOO_LARGE")
                    after = _checked_file(fd, device=os.fstat(root_fd).st_dev)
                    destination = _leaf_stat(parent_fd, parts[-1])
                    if (
                        after.st_ino != info.st_ino
                        or after.st_size != info.st_size
                        or after.st_mtime_ns != info.st_mtime_ns
                        or after.st_ctime_ns != info.st_ctime_ns
                        or len(contents) != info.st_size
                        or destination is None
                        or not stat.S_ISREG(destination.st_mode)
                        or destination.st_dev != info.st_dev
                        or destination.st_ino != info.st_ino
                        or destination.st_size != info.st_size
                        or destination.st_mtime_ns != info.st_mtime_ns
                        or destination.st_ctime_ns != info.st_ctime_ns
                        or destination.st_nlink != 1
                    ):
                        # Check the current path as well as the pinned FD:
                        # a rename-away or in-place mutation invalidates
                        # the signed read result even if its length is same.
                        raise ProjectFileError("FILE_CHANGED_DURING_READ")
                    self.roots._project_name(permit)
                    return contents
                finally:
                    os.close(fd)

    def open_write_stage(
        self,
        permit: ProjectPermit,
        path: str,
        *,
        create_parents: bool = False,
        expected_sha256: str = "",
    ) -> ProjectFileWriteStage:
        """Create a private append-only stream; no destination appears until commit."""
        self._require_action(permit, "files.write")
        owner_fence = permit.owner_fence
        if not isinstance(owner_fence, ProjectOwnerFence) or not owner_fence.valid():
            raise ProjectFileError("FILE_STAGE_SIGNED_OWNER_FENCE_REQUIRED")
        if expected_sha256 and (
            len(expected_sha256) != 64
            or any(char not in "0123456789abcdef" for char in expected_sha256)
        ):
            raise ProjectFileError("FILE_STAGE_CHECKSUM_INVALID")
        parts = _components(path)
        with self.roots.open(permit) as root_fd:
            with self._parent(root_fd, parts[:-1], create=create_parents) as parent_fd:
                if _leaf_stat(parent_fd, parts[-1]) is not None:
                    raise ProjectFileError("FILE_EXISTS")
                tmp_name = f".upload-{uuid4().hex}.tmp"
                descriptor = os.open(
                    tmp_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent_fd,
                )
                parent_copy: int | None = None
                try:
                    parent_copy = os.dup(parent_fd)
                    return ProjectFileWriteStage(
                        project_id=permit.project_id,
                        actor_id=permit.actor_id,
                        session_uuid=permit.session_uuid,
                        project_access_revision=permit.project_access_revision,
                        agent_session_version=permit.decision_version,
                        owner_fence=owner_fence,
                        destination=path,
                        name=parts[-1],
                        temporary=tmp_name,
                        fd=descriptor,
                        parent_fd=parent_copy,
                        max_bytes=self.max_file_bytes,
                        expected_sha256=expected_sha256,
                    )
                except BaseException:
                    # A raised flock/constructor must not leak the duplicate
                    # parent directory FD across subsequent Project requests.
                    if parent_copy is not None:
                        os.close(parent_copy)
                    os.close(descriptor)
                    with suppress(FileNotFoundError):
                        os.unlink(tmp_name, dir_fd=parent_fd)
                    raise

    def snapshot(
        self,
        permit: ProjectPermit,
        path: str,
        *,
        chunk_bytes: int = 1024 * 1024,
        max_snapshot_bytes: int | None = None,
    ) -> ProjectFileSnapshot:
        """Copy a bounded regular file into an unlinked, owner-private inode.

        A single pinned source descriptor survives atomic destination renames.
        In-place source mutations during the copy cause a fail-closed error.
        No duplicate plain file path, unsafe global tempdir, or whole-file
        buffer is created. O_TMPFILE support is mandatory (no unsafe fallback).
        """
        self._require_action(permit, "files.read")
        if not 0 < chunk_bytes <= 16 * 1024 * 1024:
            raise ProjectFileError("FILE_SNAPSHOT_CHUNK_INVALID")
        upper_bound = self.max_file_bytes
        if max_snapshot_bytes is not None:
            if type(max_snapshot_bytes) is not int or not 0 <= max_snapshot_bytes <= upper_bound:
                raise ProjectFileError("FILE_SNAPSHOT_LIMIT_INVALID")
            upper_bound = max_snapshot_bytes
        if not hasattr(os, "O_TMPFILE"):
            raise ProjectFileError("FILE_SNAPSHOT_UNAVAILABLE")
        parts = _components(path)
        with self.roots.open(permit) as root_fd:
            with self._parent(root_fd, parts[:-1]) as parent_fd:
                source_fd = _open_beneath(parent_fd, parts[-1], _FILE_FLAGS)
                try:
                    before = _checked_file(source_fd, device=os.fstat(root_fd).st_dev)
                    if before.st_size > upper_bound:
                        raise ProjectFileError("FILE_TOO_LARGE")
                    try:
                        snapshot_fd = os.open(
                            ".",
                            os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC,
                            0o600,
                            dir_fd=root_fd,
                        )
                    except OSError as exc:
                        if exc.errno in {errno.EOPNOTSUPP, errno.EINVAL, errno.EISDIR}:
                            raise ProjectFileError("FILE_SNAPSHOT_UNAVAILABLE") from exc
                        raise
                    try:
                        digest = hashlib.sha256()
                        total = 0
                        while True:
                            data = os.read(source_fd, chunk_bytes)
                            if not data:
                                break
                            total += len(data)
                            if total > upper_bound:
                                raise ProjectFileError("FILE_TOO_LARGE")
                            digest.update(data)
                            view = memoryview(data)
                            while view:
                                written = os.write(snapshot_fd, view)
                                if written <= 0:
                                    raise ProjectFileError("FILE_SNAPSHOT_WRITE_FAILED")
                                view = view[written:]
                        after = _checked_file(source_fd, device=os.fstat(root_fd).st_dev)
                        if (
                            before.st_ino != after.st_ino
                            or before.st_size != after.st_size
                            or before.st_mtime_ns != after.st_mtime_ns
                            or before.st_ctime_ns != after.st_ctime_ns
                            or total != before.st_size
                        ):
                            raise ProjectFileError("FILE_CHANGED_DURING_SNAPSHOT")
                        destination = _leaf_stat(parent_fd, parts[-1])
                        if (
                            destination is None
                            or not stat.S_ISREG(destination.st_mode)
                            or destination.st_dev != after.st_dev
                            or destination.st_ino != after.st_ino
                            or destination.st_size != after.st_size
                            or destination.st_mtime_ns != after.st_mtime_ns
                            or destination.st_ctime_ns != after.st_ctime_ns
                            or destination.st_nlink != 1
                        ):
                            raise ProjectFileError("FILE_CHANGED_DURING_SNAPSHOT")
                        # A long disk read cannot extend a backend decision's
                        # expiry. Do not return an obsolete Project capability.
                        self.roots._project_name(permit)
                        os.fsync(snapshot_fd)
                        return ProjectFileSnapshot(
                            project_id=permit.project_id,
                            actor_id=permit.actor_id,
                            agent_session_uuid=permit.session_uuid,
                            project_access_revision=permit.project_access_revision,
                            agent_session_version=permit.decision_version,
                            path=path,
                            size_bytes=total,
                            sha256=digest.hexdigest(),
                            _fd=snapshot_fd,
                        )
                    except BaseException:
                        os.close(snapshot_fd)
                        raise
                finally:
                    os.close(source_fd)

    def sha256(self, permit: ProjectPermit, path: str) -> str:
        self._require_action(permit, "files.read")
        return hashlib.sha256(self.read(permit, path)).hexdigest()

    def mkdir(self, permit: ProjectPermit, path: str, *, parents: bool = False) -> None:
        self._require_action(permit, "files.write")
        parts = _components(path)
        with self.roots.open(permit) as root_fd:
            with self._parent(root_fd, parts[:-1], create=parents) as parent_fd:
                try:
                    os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
                except FileExistsError:
                    fd = _open_beneath(parent_fd, parts[-1], _DIR_FLAGS)
                    try:
                        _safe_directory(fd, expected_device=os.fstat(root_fd).st_dev)
                    finally:
                        os.close(fd)
                os.fsync(parent_fd)

    def move(
        self,
        permit: ProjectPermit,
        source: str,
        destination: str,
        *,
        overwrite: bool = False,
    ) -> None:
        self._require_action(permit, "files.write")
        if overwrite:
            raise ProjectFileError("FILE_QUOTA_OVERWRITE_UNAVAILABLE")
        src, dst = _components(source), _components(destination)
        if src == dst or (len(dst) > len(src) and dst[: len(src)] == src):
            raise ProjectFileError("FILE_MOVE_INVALID")
        with self.roots.open(permit) as root_fd:
            with self._parent(root_fd, src[:-1]) as source_fd:
                with self._parent(root_fd, dst[:-1]) as destination_fd:
                    info = _leaf_stat(source_fd, src[-1])
                    if info is None:
                        raise ProjectFileError("FILE_NOT_FOUND")
                    _checked_entry(info, device=os.fstat(root_fd).st_dev)
                    self.roots._project_name(permit)
                    _rename_no_replace(source_fd, src[-1], destination_fd, dst[-1])
                    os.fsync(source_fd)
                    if destination_fd != source_fd:
                        os.fsync(destination_fd)

    def cleanup_orphan_uploads(
        self,
        permit: ProjectPermit,
        path: str = "",
        *,
        older_than_seconds: float = 3600.0,
        limit: int = 128,
    ) -> int:
        """Bounded cleanup of abandoned private staging files only.

        Caller enforces a management grant; no recursive Project deletion.
        Advisory fcntl locks coordinate our stages across local processes.
        A hostile same-UID writer can still race rename/unlink; OS isolation
        and durable Project deletion/maintenance fencing remain C1-B/C2 gates.
        """
        self._require_action(permit, "files.manage")
        if not 60 <= older_than_seconds <= 30 * 86400 or not 1 <= limit <= 1000:
            raise ProjectFileError("FILE_CLEANUP_LIMIT_INVALID")
        parts = _components(path, root_allowed=True)
        cutoff_ns = time.time_ns() - int(older_than_seconds * 1_000_000_000)
        removed = 0
        with self.roots.open(permit) as root_fd:
            with self._parent(root_fd, parts) as directory_fd:
                device = os.fstat(root_fd).st_dev
                with os.scandir(directory_fd) as items:
                    for item in items:
                        if removed >= limit:
                            break
                        if not _TEMP_NAME.fullmatch(item.name):
                            continue
                        # Validate a pinned no-follow descriptor and try to
                        # take the same file lock as active ProjectFileWriteStage.
                        # A staged write older than the TTL remains protected.
                        try:
                            fd = _open_beneath(directory_fd, item.name, _FILE_FLAGS)
                        except (OSError, ProjectFileError):
                            continue
                        try:
                            try:
                                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            except BlockingIOError:
                                continue
                            info = _checked_file(fd, device=device)
                            current = _leaf_stat(directory_fd, item.name)
                            if (
                                current is not None
                                and stat.S_ISREG(current.st_mode)
                                and current.st_ino == info.st_ino
                                and current.st_dev == info.st_dev
                                and info.st_mtime_ns < cutoff_ns
                            ):
                                os.unlink(item.name, dir_fd=directory_fd)
                                removed += 1
                        except ProjectFileError:
                            continue
                        finally:
                            os.close(fd)
                if removed:
                    os.fsync(directory_fd)
        return removed

    def delete(self, permit: ProjectPermit, path: str) -> None:
        self._require_action(permit, "files.manage")
        parts = _components(path)
        with self.roots.open(permit) as root_fd:
            with self._parent(root_fd, parts[:-1]) as parent_fd:
                info = _leaf_stat(parent_fd, parts[-1])
                if info is None:
                    raise ProjectFileError("FILE_NOT_FOUND")
                _checked_entry(info, device=os.fstat(root_fd).st_dev)
                if stat.S_ISDIR(info.st_mode):
                    os.rmdir(parts[-1], dir_fd=parent_fd)
                else:
                    os.unlink(parts[-1], dir_fd=parent_fd)
                os.fsync(parent_fd)
