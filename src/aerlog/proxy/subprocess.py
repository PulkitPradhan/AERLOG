"""Subprocess launch, pipe-safe exit detection, and POSIX process-group cleanup."""

from __future__ import annotations

import asyncio
import os
import signal
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from aerlog.proxy.diagnostics import DiagnosticSink

EXIT_SPAWN_PERMISSION = 126
EXIT_SPAWN_NOT_FOUND = 127

_EXIT_POLL_INTERVAL = 0.01
_KILL_REAP_TIMEOUT = 2.0
_POST_EXIT_GROUP_GRACE = 0.1


class SpawnError(Exception):
    """Raised when the target MCP server subprocess cannot be started."""

    def __init__(self, message: str, *, exit_code: int) -> None:
        self.exit_code = exit_code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ManagedProcess:
    """Running MCP server subprocess paired with its POSIX process-group ID."""

    process: asyncio.subprocess.Process
    pgid: int


def normalize_returncode(returncode: int | None) -> int:
    """Convert an OS return code (negative for signal) to a POSIX shell exit code."""
    if returncode is None:
        return 1
    return 128 + (-returncode) if returncode < 0 else returncode


def group_alive(pgid: int) -> bool:
    """Return True if any process in POSIX process group ``pgid`` still exists."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # On macOS, EPERM can occur for zombies or foreign-EUID children; treat as alive.
        return True
    return True


async def spawn_mcp_server(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    chunk_size: int = 65536,
) -> ManagedProcess:
    """Spawn the configured MCP server subprocess in its own POSIX session.

    Inherits ``os.environ`` merged with optional ``env`` overrides so host-provided
    configuration reaches the server transparently. Environment keys and values are
    never logged.
    """
    cmd_list = list(command)
    if not cmd_list:
        raise SpawnError("Target MCP server command must not be empty", exit_code=1)
    if any("\x00" in part for part in cmd_list):
        raise SpawnError("Command arguments must not contain NUL bytes", exit_code=1)

    merged_env: dict[str, str] | None = None
    if env is not None:
        merged_env = dict(os.environ)
        merged_env.update(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_list,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=chunk_size,
            cwd=cwd,
            env=merged_env,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        raise SpawnError(
            f"Executable not found: {cmd_list[0]} ({exc})",
            exit_code=EXIT_SPAWN_NOT_FOUND,
        ) from exc
    except PermissionError as exc:
        raise SpawnError(
            f"Permission denied executing {cmd_list[0]} ({exc})", exit_code=EXIT_SPAWN_PERMISSION
        ) from exc
    except (OSError, ValueError) as exc:
        raise SpawnError(f"Failed to launch {cmd_list[0]}: {exc}", exit_code=1) from exc

    # Record pgid immediately at spawn; getpgid() fails once the leader exits.
    return ManagedProcess(process=proc, pgid=proc.pid)


async def wait_for_process_exit(
    proc: asyncio.subprocess.Process,
    *,
    poll_interval: float = _EXIT_POLL_INTERVAL,
) -> int:
    """Poll ``proc.returncode`` instead of ``proc.wait()`` to avoid pipe-EOF hangs.

    On Python 3.11+, ``asyncio.subprocess.Process.wait()`` also waits for pipe EOF;
    a descendant that inherited stdout/stderr makes an exited server appear hung.
    """
    while proc.returncode is None:
        await asyncio.sleep(poll_interval)
    return proc.returncode


async def _wait_group_settled(
    proc: asyncio.subprocess.Process,
    pgid: int,
    timeout: float,
) -> bool:
    """Poll until both the leader exited and its POSIX process group is gone."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, timeout)
    while True:
        if proc.returncode is not None and not group_alive(pgid):
            return True
        if loop.time() >= deadline:
            return False
        await asyncio.sleep(_EXIT_POLL_INTERVAL)


def _close_subprocess_transport(proc: asyncio.subprocess.Process) -> None:
    """Close underlying asyncio subprocess transport to prevent GC resource warnings."""
    transport = getattr(proc, "_transport", None)
    close = getattr(transport, "close", None)
    if callable(close):
        with suppress(OSError, RuntimeError):
            close()


async def terminate_process_group(
    managed: ManagedProcess,
    sink: DiagnosticSink,
    *,
    grace_before_term: float = 2.0,
    grace_before_kill: float = 2.0,
) -> int:
    """Close server ``stdin`` and escalate ``SIGTERM`` -> ``SIGKILL`` on ``pgid``."""
    proc = managed.process
    pgid = managed.pgid

    if proc.stdin is not None:
        with suppress(OSError, BrokenPipeError, ConnectionResetError, RuntimeError):
            proc.stdin.close()
            await proc.stdin.wait_closed()

    grace = _POST_EXIT_GROUP_GRACE if proc.returncode is not None else grace_before_term
    if not await _wait_group_settled(proc, pgid, grace):
        await sink.emit("child_shutdown_escalate", signal="SIGTERM", pgid=pgid)
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            await sink.emit(
                "child_signal_permission_error",
                signal="SIGTERM",
                pgid=pgid,
                error=repr(exc),
            )

        if not await _wait_group_settled(proc, pgid, grace_before_kill):
            await sink.emit("child_shutdown_escalate", signal="SIGKILL", pgid=pgid)
            with suppress(ProcessLookupError, PermissionError):
                os.killpg(pgid, signal.SIGKILL)
            loop = asyncio.get_running_loop()
            reap_deadline = loop.time() + _KILL_REAP_TIMEOUT
            while proc.returncode is None and loop.time() < reap_deadline:
                await asyncio.sleep(_EXIT_POLL_INTERVAL)

    _close_subprocess_transport(proc)
    return normalize_returncode(proc.returncode)
