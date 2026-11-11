"""Production Phase 3 transparent MCP stdio proxy orchestrator."""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from aerlog.protocol.framing import DEFAULT_MAX_FRAME_BYTES, FrameTooLargeError
from aerlog.protocol.jsonrpc import redact_text
from aerlog.proxy.diagnostics import (
    BackpressurePolicy,
    DiagnosticConfig,
    DiagnosticFatalWriteError,
    DiagnosticSink,
    DiagnosticWritePolicy,
)
from aerlog.proxy.forwarding import (
    ProxyObserver,
    StreamForwardResult,
    forward_protocol_stream,
    forward_stderr_stream,
)
from aerlog.proxy.subprocess import (
    EXIT_SPAWN_NOT_FOUND,
    EXIT_SPAWN_PERMISSION,
    ManagedProcess,
    SpawnError,
    normalize_returncode,
    spawn_mcp_server,
    terminate_process_group,
    wait_for_process_exit,
)

EXIT_OK = 0
EXIT_FRAME_TOO_LARGE = 65  # EX_DATAERR
EXIT_DIAGNOSTIC_WRITE_FAILED = 74  # EX_IOERR

_FAST_SIGNAL_GRACE_TERM = 0.2
_FAST_SIGNAL_GRACE_KILL = 0.8


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    """Runtime configuration for :class:`StdioProxy`."""

    command: tuple[str, ...]
    cwd: Path | None = None
    env: Mapping[str, str] | None = None
    log_file: Path | None = None
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES
    chunk_size: int = 65536
    grace_before_term: float = 2.0
    grace_before_kill: float = 2.0
    drain_timeout: float = 1.0
    diagnostic_queue_size: int = 1024
    diagnostic_write_policy: DiagnosticWritePolicy = "degrade"
    backpressure_policy: BackpressurePolicy = "drop_with_gap"
    include_previews: bool = True
    preview_max_chars: int = 120
    preview_max_hex_bytes: int = 32

    def __post_init__(self) -> None:
        if not self.command:
            raise ValueError("ProxyConfig.command must not be empty")
        if self.max_frame_bytes <= 0:
            raise ValueError("ProxyConfig.max_frame_bytes must be positive")
        if self.chunk_size <= 0:
            raise ValueError("ProxyConfig.chunk_size must be positive")


@dataclass(frozen=True, slots=True)
class ProxyResult:
    """Outcome summary returned after a proxy execution finishes."""

    exit_code: int
    client_frames: int
    server_frames: int
    diagnostic_write_errors: int
    dropped_diagnostics: int
    diagnostics_complete: bool
    oversized_error: FrameTooLargeError | None
    termination_reason: str


async def open_stdio_pipes(
    loop: asyncio.AbstractEventLoop,
    chunk_size: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Attach asyncio streams to process ``stdin`` and ``stdout`` OS pipes."""
    stdin_reader = asyncio.StreamReader(limit=max(chunk_size, 65536))
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(stdin_reader),
        sys.stdin.buffer,
    )

    # StreamReaderProtocol provides _get_close_waiter for StreamWriter.wait_closed().
    write_transport, write_protocol = await loop.connect_write_pipe(
        lambda: asyncio.StreamReaderProtocol(asyncio.StreamReader(limit=64), loop=loop),
        sys.stdout.buffer,
    )
    stdout_writer = asyncio.StreamWriter(write_transport, write_protocol, None, loop)
    return stdin_reader, stdout_writer


class StdioProxy:
    """Transparent bidirectional MCP stdio proxy."""

    def __init__(self, config: ProxyConfig) -> None:
        self._config = config

    async def run(
        self,
        *,
        stdin_reader: asyncio.StreamReader | None = None,
        stdout_writer: asyncio.StreamWriter | None = None,
        diag_stream: TextIO | None = None,
        fallback_stderr: TextIO | None = None,
        observer: ProxyObserver | None = None,
    ) -> ProxyResult:
        """Launch the MCP server subprocess and proxy stdio until completion."""
        cfg = self._config
        sink = DiagnosticSink(
            DiagnosticConfig(
                log_file=cfg.log_file,
                queue_size=cfg.diagnostic_queue_size,
                write_policy=cfg.diagnostic_write_policy,
                backpressure_policy=cfg.backpressure_policy,
                include_previews=cfg.include_previews,
                preview_max_chars=cfg.preview_max_chars,
                preview_max_hex_bytes=cfg.preview_max_hex_bytes,
            ),
            stream=diag_stream,
            fallback_stderr=fallback_stderr,
        )

        try:
            await sink.start()
        except DiagnosticFatalWriteError:
            return ProxyResult(
                exit_code=EXIT_DIAGNOSTIC_WRITE_FAILED,
                client_frames=0,
                server_frames=0,
                diagnostic_write_errors=sink.write_errors,
                dropped_diagnostics=sink.dropped_count,
                diagnostics_complete=False,
                oversized_error=None,
                termination_reason="diagnostic_write_failed",
            )

        redacted_cmd = [redact_text(part) for part in cfg.command]
        loop = asyncio.get_running_loop()
        owns_stdout = stdout_writer is None
        if stdin_reader is None or stdout_writer is None:
            pipe_reader, pipe_writer = await open_stdio_pipes(loop, cfg.chunk_size)
            if stdin_reader is None:
                stdin_reader = pipe_reader
            if stdout_writer is None:
                stdout_writer = pipe_writer

        managed: ManagedProcess | None = None
        if observer is not None:
            await observer.on_execution_started(
                command=cfg.command,
                cwd=cfg.cwd,
                env_overrides=cfg.env,
                monotonic_time_ns=time.monotonic_ns(),
            )
        try:
            managed = await spawn_mcp_server(
                cfg.command,
                cwd=cfg.cwd,
                env=cfg.env,
                chunk_size=cfg.chunk_size,
            )
        except SpawnError as exc:
            await sink.emit("server_spawn_failed", command=redacted_cmd, error=str(exc))
            if observer is not None:
                await observer.on_transport_error(
                    None, "spawn_failed", str(exc), time.monotonic_ns()
                )
                await observer.on_execution_finished(
                    termination_reason="spawn_failed",
                    exit_code=exc.exit_code,
                    returncode=None,
                )
            await sink.close()
            if owns_stdout:
                with suppress(OSError, BrokenPipeError, ConnectionResetError):
                    stdout_writer.close()
                    await stdout_writer.wait_closed()
            return ProxyResult(
                exit_code=exc.exit_code,
                client_frames=0,
                server_frames=0,
                diagnostic_write_errors=sink.write_errors,
                dropped_diagnostics=sink.dropped_count,
                diagnostics_complete=sink.is_complete,
                oversized_error=None,
                termination_reason="spawn_failed",
            )

        proc = managed.process
        assert proc.stdin is not None
        assert proc.stdout is not None
        assert proc.stderr is not None

        await sink.emit("server_started", pid=proc.pid, pgid=managed.pgid, command=redacted_cmd)

        signal_event = asyncio.Event()
        received_signal: int | None = None

        def _on_signal(sig: signal.Signals) -> None:
            nonlocal received_signal
            if received_signal is None:
                received_signal = sig.value
                sink.emit_nowait("proxy_signal_received", signal=sig.name)
                signal_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            with suppress(NotImplementedError):
                loop.add_signal_handler(sig, _on_signal, sig)

        c2s_task = asyncio.create_task(
            forward_protocol_stream(
                "client_to_server",
                stdin_reader,
                proc.stdin,
                sink,
                max_frame_bytes=cfg.max_frame_bytes,
                chunk_size=cfg.chunk_size,
                close_writer_on_eof=True,
                observer=observer,
            )
        )
        s2c_task = asyncio.create_task(
            forward_protocol_stream(
                "server_to_client",
                proc.stdout,
                stdout_writer,
                sink,
                max_frame_bytes=cfg.max_frame_bytes,
                chunk_size=cfg.chunk_size,
                close_writer_on_eof=False,
                observer=observer,
            )
        )
        err_task = asyncio.create_task(
            forward_stderr_stream(
                proc.stderr,
                sink,
                chunk_size=cfg.chunk_size,
                observer=observer,
            )
        )
        exit_task = asyncio.create_task(wait_for_process_exit(proc))
        sig_task = asyncio.create_task(signal_event.wait())
        fatal_diag_task = asyncio.create_task(sink.fatal_event.wait())

        exit_code = EXIT_OK
        termination_reason = "completed"
        oversized_error: FrameTooLargeError | None = None
        c2s_result: StreamForwardResult | None = None
        s2c_result: StreamForwardResult | None = None
        was_cancelled = False
        already_terminated = False

        pending: set[asyncio.Task[object]] = {
            c2s_task,
            s2c_task,
            exit_task,
            sig_task,
            fatal_diag_task,
        }

        try:
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

                if sig_task in done:
                    sig_num = signal.SIGTERM.value if received_signal is None else received_signal
                    sig_name = signal.Signals(sig_num).name
                    exit_code = 128 + sig_num
                    termination_reason = "signal"
                    if observer is not None:
                        await observer.on_proxy_signal(sig_name, time.monotonic_ns())
                    break

                if fatal_diag_task in done:
                    exit_code = EXIT_DIAGNOSTIC_WRITE_FAILED
                    termination_reason = "diagnostic_write_failed"
                    break

                if c2s_task in done:
                    c2s_exc = c2s_task.exception()
                    if isinstance(c2s_exc, FrameTooLargeError):
                        oversized_error = c2s_exc
                        exit_code = EXIT_FRAME_TOO_LARGE
                        termination_reason = "frame_too_large"
                        break
                    if c2s_exc is not None:
                        raise c2s_exc
                    c2s_result = c2s_task.result()
                    if not pending:
                        break

                if s2c_task in done:
                    s2c_done_exc = s2c_task.exception()
                    if isinstance(s2c_done_exc, FrameTooLargeError):
                        oversized_error = s2c_done_exc
                        exit_code = EXIT_FRAME_TOO_LARGE
                        termination_reason = "frame_too_large"
                        break
                    if s2c_done_exc is not None:
                        raise s2c_done_exc
                    s2c_result = s2c_task.result()
                    with suppress(TimeoutError):
                        await asyncio.wait_for(
                            asyncio.gather(err_task, return_exceptions=True),
                            timeout=cfg.drain_timeout,
                        )
                    exit_code = await terminate_process_group(
                        managed,
                        sink,
                        grace_before_term=cfg.grace_before_term,
                        grace_before_kill=cfg.grace_before_kill,
                        observer=observer,
                    )
                    already_terminated = True
                    termination_reason = "server_stdout_eof"
                    await sink.emit(
                        "server_stdout_eof", returncode=proc.returncode, exit_code=exit_code
                    )
                    if observer is not None:
                        await observer.on_process_exited(proc.returncode, time.monotonic_ns())
                    break

                if exit_task in done:
                    server_rc = exit_task.result()
                    with suppress(TimeoutError):
                        await asyncio.wait_for(
                            asyncio.gather(s2c_task, err_task, return_exceptions=True),
                            timeout=cfg.drain_timeout,
                        )
                    if s2c_task.done() and not s2c_task.cancelled():
                        s2c_exc = s2c_task.exception()
                        if isinstance(s2c_exc, FrameTooLargeError):
                            oversized_error = s2c_exc
                            exit_code = EXIT_FRAME_TOO_LARGE
                            termination_reason = "frame_too_large"
                            break
                        if s2c_exc is None:
                            s2c_result = s2c_task.result()
                    exit_code = normalize_returncode(server_rc)
                    termination_reason = "server_exited"
                    await sink.emit("server_exited", returncode=server_rc, exit_code=exit_code)
                    if observer is not None:
                        await observer.on_process_exited(server_rc, time.monotonic_ns())
                    break
        except asyncio.CancelledError:
            was_cancelled = True
            termination_reason = "cancelled"
            sink.emit_nowait("proxy_cancelled")
            raise
        finally:
            fast_teardown = was_cancelled or termination_reason in {
                "signal",
                "frame_too_large",
                "diagnostic_write_failed",
            }
            for task in (c2s_task, s2c_task, err_task, exit_task, sig_task, fatal_diag_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(
                c2s_task,
                s2c_task,
                err_task,
                exit_task,
                sig_task,
                fatal_diag_task,
                return_exceptions=True,
            )

            if (
                c2s_result is None
                and c2s_task.done()
                and not c2s_task.cancelled()
                and c2s_task.exception() is None
            ):
                c2s_result = c2s_task.result()
            if (
                s2c_result is None
                and s2c_task.done()
                and not s2c_task.cancelled()
                and s2c_task.exception() is None
            ):
                s2c_result = s2c_task.result()

            if not already_terminated:
                reaped_code = await terminate_process_group(
                    managed,
                    sink,
                    grace_before_term=(
                        _FAST_SIGNAL_GRACE_TERM if fast_teardown else cfg.grace_before_term
                    ),
                    grace_before_kill=(
                        _FAST_SIGNAL_GRACE_KILL if fast_teardown else cfg.grace_before_kill
                    ),
                    observer=observer,
                )
                if termination_reason == "completed":
                    exit_code = reaped_code

            if observer is not None:
                if was_cancelled:
                    await observer.on_proxy_signal("CANCELLED", time.monotonic_ns())
                await observer.on_execution_finished(
                    termination_reason=termination_reason,
                    exit_code=exit_code,
                    returncode=proc.returncode,
                )

            if owns_stdout:
                with suppress(OSError, BrokenPipeError, ConnectionResetError):
                    stdout_writer.close()
                    await stdout_writer.wait_closed()

            for sig in (signal.SIGINT, signal.SIGTERM):
                with suppress(NotImplementedError):
                    loop.remove_signal_handler(sig)

            await sink.close()

        return ProxyResult(
            exit_code=exit_code,
            client_frames=c2s_result.frames_forwarded if c2s_result else 0,
            server_frames=s2c_result.frames_forwarded if s2c_result else 0,
            diagnostic_write_errors=sink.write_errors,
            dropped_diagnostics=sink.dropped_count,
            diagnostics_complete=sink.is_complete,
            oversized_error=oversized_error,
            termination_reason=termination_reason,
        )


async def run_stdio_proxy(
    config: ProxyConfig,
    *,
    observer: ProxyObserver | None = None,
) -> ProxyResult:
    """Convenience coroutine to execute :class:`StdioProxy` with ``config``."""
    return await StdioProxy(config).run(observer=observer)


def _parse_args(argv: Sequence[str] | None = None) -> ProxyConfig:
    parser = argparse.ArgumentParser(
        prog="python -m aerlog.proxy.stdio_proxy",
        description="AERLOG transparent MCP stdio proxy",
    )
    parser.add_argument("--log-file", type=Path, default=None)
    parser.add_argument("--max-frame-bytes", type=int, default=DEFAULT_MAX_FRAME_BYTES)
    parser.add_argument(
        "--write-policy",
        choices=("degrade", "strict"),
        default="degrade",
    )
    parser.add_argument(
        "--backpressure-policy",
        choices=("drop_with_gap", "block"),
        default="drop_with_gap",
    )
    parser.add_argument(
        "--no-previews",
        action="store_true",
        help="Disable diagnostic payload and stderr previews.",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Target MCP server command after --",
    )
    args = parser.parse_args(argv)
    cmd = list(args.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("Target MCP server command is required (pass after --)")
    if args.max_frame_bytes <= 0:
        parser.error("--max-frame-bytes must be a positive integer")
    return ProxyConfig(
        command=tuple(cmd),
        log_file=args.log_file,
        max_frame_bytes=args.max_frame_bytes,
        diagnostic_write_policy=args.write_policy,
        backpressure_policy=args.backpressure_policy,
        include_previews=not args.no_previews,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for invoking the stdio proxy directly."""
    config = _parse_args(argv)
    try:
        result = asyncio.run(run_stdio_proxy(config))
    except KeyboardInterrupt:
        return 130
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())

__all__ = [
    "EXIT_DIAGNOSTIC_WRITE_FAILED",
    "EXIT_FRAME_TOO_LARGE",
    "EXIT_OK",
    "EXIT_SPAWN_NOT_FOUND",
    "EXIT_SPAWN_PERMISSION",
    "ProxyConfig",
    "ProxyResult",
    "StdioProxy",
    "main",
    "open_stdio_pipes",
    "run_stdio_proxy",
]
