"""Per-execution advisory writer ownership on trusted local Linux storage."""

from __future__ import annotations

import errno
import fcntl
import os
import stat
import threading
import uuid
from pathlib import Path
from types import TracebackType
from typing import Self

from aerlog.storage.exceptions import ExecutionBusyError, InvalidExecutionIdError, StorageError


def validate_execution_id(execution_id: str) -> str:
    """Validate canonical UUID syntax and reject any path-traversal characters."""
    if not isinstance(execution_id, str) or not execution_id.strip():
        raise InvalidExecutionIdError("execution_id must be a non-empty string")
    if "/" in execution_id or "\\" in execution_id or ".." in execution_id:
        raise InvalidExecutionIdError(f"Unsafe execution_id path characters: {execution_id!r}")
    try:
        parsed = uuid.UUID(execution_id)
    except ValueError as exc:
        raise InvalidExecutionIdError(f"Invalid UUID execution_id: {execution_id!r}") from exc
    canonical = str(parsed)
    if canonical != execution_id:
        raise InvalidExecutionIdError(
            f"execution_id must be canonical lowercase UUID string, got {execution_id!r}"
        )
    return canonical


class ExecutionOwnership:
    """An open flock description, optionally shared with a nested writer or worker.

    Each handle closes its own descriptor. Linux releases the flock when the last
    descriptor closes, including on process death. Never unlink the stable sidecar.
    """

    def __init__(self, root: Path, execution_id: str, fd: int) -> None:
        self._root = root
        self._execution_id = execution_id
        self._fd: int | None = fd
        self._guard = threading.Lock()

    @classmethod
    def acquire(cls, data_dir: Path, execution_id: str) -> Self:
        """Take a fresh nonblocking exclusive lock, before inspecting destination state."""
        eid = validate_execution_id(execution_id)
        root = data_dir.resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        locks = root / ".locks"
        locks.mkdir(mode=0o700, exist_ok=True)
        dir_fd = os.open(locks, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            directory = os.fstat(dir_fd)
            if directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) != 0o700:
                raise StorageError(
                    f"Execution lock directory must be private and user-owned: {locks}"
                )
            flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            fd = os.open(f"{eid}.lock", flags, 0o600, dir_fd=dir_fd)
        finally:
            os.close(dir_fd)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise StorageError(f"Unsafe execution lock file for {eid}")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    raise ExecutionBusyError(
                        f"Execution {eid} is busy; retry after it closes"
                    ) from exc
                raise
            return cls(root, eid, fd)
        except BaseException:
            os.close(fd)
            raise

    def share(self, data_dir: Path, execution_id: str) -> Self:
        """Carry this lock into a nested operation with an independent lifetime."""
        if data_dir.resolve() != self._root or execution_id != self._execution_id:
            raise ValueError("Execution ownership belongs to a different destination")
        with self._guard:
            if self._fd is None:
                raise ValueError("Execution ownership is closed")
            return type(self)(self._root, self._execution_id, os.dup(self._fd))

    def check_new_capture(self, spool_path: Path) -> None:
        """Refuse reuse of an execution directory or an orphaned recovery spool."""
        from aerlog.storage.event_log import resolve_execution_dir

        if resolve_execution_dir(self._root, self._execution_id).exists():
            raise ValueError(
                f"Execution ID {self._execution_id!r} already exists in {self._root}; "
                "omit '--execution-id' or provide a new UUID."
            )
        if spool_path.exists():
            raise ValueError(
                f"A recovery spool already exists for execution ID {self._execution_id!r}; "
                "omit '--execution-id' or provide a new UUID."
            )

    def close(self) -> None:
        """Drop this handle's reference to the flock."""
        with self._guard:
            if self._fd is not None:
                fd, self._fd = self._fd, None
                os.close(fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
