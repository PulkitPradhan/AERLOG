"""Transparent bidirectional MCP stdio proxy orchestrator."""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import errno
import logging
import os
import signal
import stat
import sys
import threading
import time
import weakref
from collections import deque
from collections.abc import Coroutine, Mapping, Sequence, Sized
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Protocol, TextIO, TypeVar

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

    class _SeparatorBuffer(ReadableBuffer, Sized, Protocol): ...


from aerlog.capture.redaction import EventRedactor, RedactionConfig
from aerlog.protocol.framing import DEFAULT_MAX_FRAME_BYTES, FrameTooLargeError
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
    WritableByteStream,
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
_FALLBACK_IN_FLIGHT_JOIN_TIMEOUT = 0.5
_LOGGER = logging.getLogger(__name__)
_T = TypeVar("_T")


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
        if self.grace_before_term < 0 or self.grace_before_kill < 0 or self.drain_timeout < 0:
            raise ValueError("Timeout settings must be non-negative")


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


def _can_use_pipe_transport(fd: int) -> bool:
    """Return True only for FDs supported safely by asyncio epoll/kqueue pipe transports.

    Regular files raise ``ValueError`` in ``connect_read_pipe``/``connect_write_pipe``.
    Non-TTY character devices such as ``/dev/null`` report ``S_ISCHR`` yet fail
    ``epoll.register()`` with ``PermissionError`` on Linux, so ``S_ISCHR`` is
    accepted only when ``os.isatty(fd)`` is True (PTYs).
    """
    mode = os.fstat(fd).st_mode
    return stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or (stat.S_ISCHR(mode) and os.isatty(fd))


def _is_expected_pipe_close_error(exc: BaseException) -> bool:
    """Return True for benign peer-disconnect errors when closing stdout."""
    if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
        return True
    return isinstance(exc, OSError) and exc.errno in (errno.EPIPE, errno.ECONNRESET)


def _bridge_cf_future(
    loop: asyncio.AbstractEventLoop,
    cf_future: concurrent.futures.Future[_T],
) -> asyncio.Future[_T]:
    """Bridge ``concurrent.futures.Future`` without cancelling the worker on waiter cancel."""
    waiter: asyncio.Future[_T] = loop.create_future()

    def _on_done(done_future: concurrent.futures.Future[_T]) -> None:
        exc = done_future.exception()
        res: _T | None = None if exc is not None else done_future.result()

        def _resolve() -> None:
            if waiter.done():
                return
            if exc is not None:
                waiter.set_exception(exc)
            else:
                # res is guaranteed _T when exc is None.
                waiter.set_result(res)  # type: ignore[arg-type]

        with suppress(RuntimeError):
            loop.call_soon_threadsafe(_resolve)

    cf_future.add_done_callback(_on_done)
    return waiter


class _OwnedStreamReader(asyncio.StreamReader):
    """``StreamReader`` holding ownership handle so callers can call ``aclose()``."""

    def __init__(self, limit: int) -> None:
        super().__init__(limit=limit)
        self._stdin_owner: _OwnedStdinStream | None = None

    async def aclose(self) -> None:
        """Close the owned stdin transport/FD and stop background feeder tasks."""
        if self._stdin_owner is not None:
            await self._stdin_owner.aclose()


class _AsyncFileStreamReader(_OwnedStreamReader):
    """``StreamReader`` subclass tracking consumed bytes for bounded fallback read-ahead."""

    def __init__(self, limit: int) -> None:
        super().__init__(limit=limit)
        self.consumed_bytes = 0
        self.demand_bytes = 0
        self.space_event: asyncio.Event | None = None

    def _mark_consumed(self, count: int) -> None:
        if count > 0:
            self.consumed_bytes += count
            if self.space_event is not None:
                self.space_event.set()

    async def read(self, n: int = -1) -> bytes:
        data = await super().read(n)
        # StreamReader.read(n < 0) delegates internally to self.read(self._limit);
        # counting only n > 0 prevents double-counting consumed bytes on read(-1).
        if n > 0:
            self._mark_consumed(len(data))
        return data

    async def readuntil(self, separator: _SeparatorBuffer = b"\n") -> bytes:
        # Both readuntil() and readline() / async iteration consume through here.
        try:
            data = await super().readuntil(separator)
        except asyncio.IncompleteReadError as exc:
            self._mark_consumed(len(exc.partial))
            raise
        self._mark_consumed(len(data))
        return data

    async def readexactly(self, n: int) -> bytes:
        if n > self.demand_bytes:
            self.demand_bytes = n
            if self.space_event is not None:
                self.space_event.set()
        try:
            data = await super().readexactly(n)
        except asyncio.IncompleteReadError as exc:
            self._mark_consumed(len(exc.partial))
            raise
        finally:
            self.demand_bytes = 0
        self._mark_consumed(len(data))
        return data


class _OwnedStdinStream:
    """Explicit owner for an opened ``stdin`` reader, its worker futures, and duped FD.

    Note on non-TTY character devices:
        Regular files and ``/dev/null`` complete ``os.read()`` promptly without blocking.
        An arbitrary non-TTY character device whose kernel ``read()`` blocks cannot be
        forcibly interrupted by POSIX ``close()`` or asyncio cancellation; in that case
        ``aclose()`` refuses to close the owned FD while the worker is active and defers
        ``os.close()`` to the worker's ``finally:`` block upon return.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        *,
        transport: asyncio.ReadTransport | None = None,
        owned_fd: int | None = None,
        chunk_size: int = 65536,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self._strong_reader: asyncio.StreamReader | None = reader
        self._reader_ref: weakref.ref[asyncio.StreamReader] = weakref.ref(reader)
        if isinstance(reader, _OwnedStreamReader):
            reader._stdin_owner = self
        self._transport = transport
        self._owned_fd = owned_fd
        self._chunk_size = chunk_size
        self._loop = loop
        self._fd_lock = threading.Lock()
        self._worker_running = False
        self._close_requested = False
        self._in_flight_worker: concurrent.futures.Future[bytes] | None = None
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._feeder_task: asyncio.Task[None] | None = None
        self._close_task: asyncio.Task[None] | None = None
        self._reader_finalizer: weakref.finalize[[], asyncio.StreamReader] | None = None
        self._space_event: asyncio.Event | None = None
        self._fed_bytes = 0
        self._high_water = max(chunk_size * 2, 131_072)

        if owned_fd is not None:
            assert loop is not None
            space_event = asyncio.Event()
            space_event.set()
            self._space_event = space_event
            if isinstance(reader, _AsyncFileStreamReader):
                reader.space_event = space_event
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=1,
                thread_name_prefix="aerlog-stdin-fb",
            )
            self._feeder_task = loop.create_task(self._feeder_loop())

    @property
    def reader(self) -> asyncio.StreamReader:
        """Return underlying ``StreamReader`` instance."""
        reader_obj = self._strong_reader if self._strong_reader is not None else self._reader_ref()
        if reader_obj is None:
            raise RuntimeError("Stdin reader has already been released")
        return reader_obj

    def detach_reader(self) -> asyncio.StreamReader:
        """Transfer strong ownership to the returned reader with a GC cleanup finalizer."""
        reader_obj = self.reader
        self._strong_reader = None
        if self._reader_finalizer is None:
            self._reader_finalizer = weakref.finalize(reader_obj, self._finalize_on_reader_gc)
        return reader_obj

    def _finalize_on_reader_gc(self) -> None:
        self._release_fd_if_idle()
        if self._executor is not None:
            self._executor.shutdown(wait=False)
        if self._loop is not None and not self._loop.is_closed():

            def _schedule_aclose() -> None:
                if self._close_task is None:
                    self._close_task = asyncio.create_task(self._close_once())

            with suppress(RuntimeError):
                self._loop.call_soon_threadsafe(_schedule_aclose)
        elif self._transport is not None:
            with suppress(OSError, RuntimeError):
                self._transport.close()
            self._transport = None

    def _read_chunk_sync(self) -> bytes:
        with self._fd_lock:
            if self._close_requested or self._owned_fd is None:
                return b""
            fd = self._owned_fd
            self._worker_running = True
        try:
            return os.read(fd, self._chunk_size)
        finally:
            fd_to_close: int | None = None
            with self._fd_lock:
                self._worker_running = False
                if self._close_requested and self._owned_fd is not None:
                    fd_to_close = self._owned_fd
                    self._owned_fd = None
            if fd_to_close is not None:
                with suppress(OSError):
                    os.close(fd_to_close)

    def _release_fd_if_idle(self) -> None:
        fd_to_close: int | None = None
        with self._fd_lock:
            self._close_requested = True
            if not self._worker_running and self._owned_fd is not None:
                fd_to_close = self._owned_fd
                self._owned_fd = None
        if fd_to_close is not None:
            with suppress(OSError):
                os.close(fd_to_close)

    async def _feeder_loop(self) -> None:
        assert self._loop is not None
        assert self._executor is not None
        assert self._space_event is not None
        try:
            while not self._close_requested:
                while not self._close_requested:
                    reader_obj = self._reader_ref()
                    if reader_obj is None:
                        return
                    if isinstance(reader_obj, _AsyncFileStreamReader):
                        consumed = reader_obj.consumed_bytes
                        effective_limit = max(self._high_water, reader_obj.demand_bytes)
                    else:
                        consumed = 0
                        effective_limit = self._high_water
                    del reader_obj
                    if (self._fed_bytes - consumed) < effective_limit:
                        break
                    self._space_event.clear()
                    reader_obj = self._reader_ref()
                    if reader_obj is None:
                        return
                    if isinstance(reader_obj, _AsyncFileStreamReader):
                        consumed = reader_obj.consumed_bytes
                        effective_limit = max(self._high_water, reader_obj.demand_bytes)
                    else:
                        consumed = 0
                        effective_limit = self._high_water
                    del reader_obj
                    if (
                        not self._close_requested
                        and (self._fed_bytes - consumed) >= effective_limit
                    ):
                        await self._space_event.wait()
                if self._close_requested:
                    break

                try:
                    cf_future = self._executor.submit(self._read_chunk_sync)
                except RuntimeError:
                    break
                self._in_flight_worker = cf_future
                try:
                    chunk = await _bridge_cf_future(self._loop, cf_future)
                finally:
                    if cf_future.done():
                        self._in_flight_worker = None

                reader_obj = self._reader_ref()
                if reader_obj is None:
                    break
                if not chunk:
                    reader_obj.feed_eof()
                    del reader_obj
                    break
                reader_obj.feed_data(chunk)
                del reader_obj
                self._fed_bytes += len(chunk)
        except OSError as exc:
            reader_obj = self._reader_ref()
            if reader_obj is not None:
                reader_obj.set_exception(exc)
                reader_obj.feed_eof()
                del reader_obj
        except asyncio.CancelledError:
            reader_obj = self._reader_ref()
            if reader_obj is not None:
                reader_obj.feed_eof()
                del reader_obj
            raise
        finally:
            self._release_fd_if_idle()
            if self._executor is not None:
                self._executor.shutdown(wait=False)

    async def _close_once(self) -> None:
        if self._reader_finalizer is not None:
            self._reader_finalizer.detach()
        if self._transport is not None:
            with suppress(OSError, RuntimeError):
                self._transport.close()
            self._transport = None
            return

        with self._fd_lock:
            self._close_requested = True
        if self._space_event is not None:
            self._space_event.set()

        if self._feeder_task is not None and not self._feeder_task.done():
            self._feeder_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await self._feeder_task

        in_flight = self._in_flight_worker
        if in_flight is not None and not in_flight.done() and self._loop is not None:
            waiter = _bridge_cf_future(self._loop, in_flight)
            with suppress(TimeoutError, asyncio.CancelledError, Exception):
                await asyncio.wait_for(
                    asyncio.shield(waiter),
                    timeout=_FALLBACK_IN_FLIGHT_JOIN_TIMEOUT,
                )
            if in_flight.done():
                self._in_flight_worker = None
            else:
                _LOGGER.warning(
                    "Fallback stdin worker still blocked in OS read; "
                    "deferring FD close to worker exit"
                )

        self._release_fd_if_idle()
        if self._executor is not None:
            self._executor.shutdown(wait=False)

    async def aclose(self) -> None:
        """Idempotently stop feeder tasks and release owned transports/FDs cleanly."""
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close_once())
        await asyncio.shield(self._close_task)


class _FallbackStdoutWriter:
    """Serialized, backpressure-bounded async writer over a ``dup``ed OS FD."""

    def __init__(
        self,
        *,
        owned_fd: int,
        chunk_size: int,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self._owned_fd: int | None = owned_fd
        self._loop = loop
        self._fd_lock = threading.Lock()
        self._worker_running = False
        self._close_requested = False
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="aerlog-stdout-fb",
        )
        self._in_flight_worker: concurrent.futures.Future[None] | None = None
        self._pending: deque[bytes] = deque()
        self._buffered_bytes = 0
        self._high_water = max(chunk_size * 4, 262_144)
        self._low_water = self._high_water // 2
        self._wake = asyncio.Event()
        self._space_available = asyncio.Event()
        self._space_available.set()
        self._closing = False
        self._closed = False
        self._write_error: BaseException | None = None
        self._writer_task: asyncio.Task[None] = loop.create_task(self._drain_loop())

    def write(self, data: bytes | bytearray | memoryview) -> None:
        """Queue bytes in strict FIFO order for serialized OS writes."""
        if self._write_error is not None:
            raise self._write_error
        if self._closing or self._closed:
            raise BrokenPipeError("Fallback stdout writer is closed")
        raw = bytes(data)
        if not raw:
            return
        self._pending.append(raw)
        self._buffered_bytes += len(raw)
        if self._buffered_bytes >= self._high_water:
            self._space_available.clear()
        self._wake.set()

    async def drain(self) -> None:
        """Pause caller when buffered writes exceed the high-water threshold."""
        if self._write_error is not None:
            raise self._write_error
        while (
            self._buffered_bytes >= self._high_water
            and self._write_error is None
            and not self._writer_task.done()
        ):
            self._space_available.clear()
            if (
                self._buffered_bytes >= self._high_water
                and self._write_error is None
                and not self._writer_task.done()
            ):
                await self._space_available.wait()
        if self._write_error is not None:
            raise self._write_error

    def _write_batch_sync(self, payload: bytes) -> None:
        with self._fd_lock:
            if self._owned_fd is None:
                raise BrokenPipeError("Fallback stdout FD already closed")
            fd = self._owned_fd
            self._worker_running = True
        try:
            view = memoryview(payload)
            sent = 0
            while sent < len(payload):
                n = os.write(fd, view[sent:])
                if n <= 0:
                    raise BrokenPipeError("Zero-byte os.write to stdout fallback")
                sent += n
        finally:
            fd_to_close: int | None = None
            with self._fd_lock:
                self._worker_running = False
                if self._close_requested and self._owned_fd is not None:
                    fd_to_close = self._owned_fd
                    self._owned_fd = None
            if fd_to_close is not None:
                with suppress(OSError):
                    os.close(fd_to_close)

    def _release_fd_if_idle(self) -> None:
        fd_to_close: int | None = None
        with self._fd_lock:
            self._close_requested = True
            if not self._worker_running and self._owned_fd is not None:
                fd_to_close = self._owned_fd
                self._owned_fd = None
        if fd_to_close is not None:
            with suppress(OSError):
                os.close(fd_to_close)

    async def _drain_loop(self) -> None:
        try:
            while True:
                while not self._pending and not self._closing:
                    self._wake.clear()
                    if not self._pending and not self._closing:
                        await self._wake.wait()
                if not self._pending and self._closing:
                    break

                chunks: list[bytes] = []
                while self._pending:
                    chunks.append(self._pending.popleft())
                payload = b"".join(chunks)
                batch_len = len(payload)

                cf_future = self._executor.submit(self._write_batch_sync, payload)
                self._in_flight_worker = cf_future
                try:
                    await _bridge_cf_future(self._loop, cf_future)
                except BaseException as exc:
                    if cf_future.done():
                        self._in_flight_worker = None
                    self._write_error = exc
                    self._pending.clear()
                    self._buffered_bytes = 0
                    self._space_available.set()
                    break
                finally:
                    if cf_future.done():
                        self._in_flight_worker = None

                self._buffered_bytes = max(0, self._buffered_bytes - batch_len)
                if self._buffered_bytes <= self._low_water:
                    self._space_available.set()
        finally:
            self._closing = True
            self._closed = True
            self._space_available.set()
            self._release_fd_if_idle()
            self._executor.shutdown(wait=False)

    def close(self) -> None:
        """Initiate orderly flush and FD closure once pending bytes drain."""
        self._closing = True
        self._wake.set()

    async def wait_closed(self) -> None:
        """Flush buffered stdout writes, release owned FD, and propagate any write error."""
        self.close()
        if not self._writer_task.done():
            await asyncio.shield(self._writer_task)
        if self._write_error is not None:
            raise self._write_error


async def open_stdin_stream(
    loop: asyncio.AbstractEventLoop,
    chunk_size: int,
    *,
    stream: BinaryIO | None = None,
) -> _OwnedStdinStream:
    """Attach an async reader to ``stdin`` (pipe transport when supported, fallback otherwise)."""
    source = sys.stdin.buffer if stream is None else stream
    raw_fd = source.fileno()
    if _can_use_pipe_transport(raw_fd):
        dup_fd = os.dup(raw_fd)
        try:
            dup_file = os.fdopen(dup_fd, "rb", buffering=0, closefd=True)
        except BaseException:
            with suppress(OSError):
                os.close(dup_fd)
            raise
        stdin_reader: asyncio.StreamReader = _OwnedStreamReader(limit=max(chunk_size, 65536))
        try:
            read_transport, _ = await loop.connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(stdin_reader),
                dup_file,
            )
        except BaseException:
            with suppress(OSError):
                dup_file.close()
            raise
        return _OwnedStdinStream(
            stdin_reader,
            transport=read_transport,
            chunk_size=chunk_size,
            loop=loop,
        )

    dup_fd = os.dup(raw_fd)
    stdin_reader = _AsyncFileStreamReader(limit=max(chunk_size, 65536))
    return _OwnedStdinStream(
        stdin_reader,
        owned_fd=dup_fd,
        chunk_size=chunk_size,
        loop=loop,
    )


async def open_stdout_stream(
    loop: asyncio.AbstractEventLoop,
    chunk_size: int,
    *,
    stream: BinaryIO | None = None,
) -> WritableByteStream:
    """Attach an async writer to ``stdout`` (pipe transport when supported, fallback otherwise)."""
    target = sys.stdout.buffer if stream is None else stream
    target.flush()
    raw_fd = target.fileno()
    if _can_use_pipe_transport(raw_fd):
        dup_fd = os.dup(raw_fd)
        try:
            dup_file = os.fdopen(dup_fd, "wb", buffering=0, closefd=True)
        except BaseException:
            with suppress(OSError):
                os.close(dup_fd)
            raise
        # StreamReaderProtocol provides _get_close_waiter for StreamWriter.wait_closed().
        try:
            write_transport, write_protocol = await loop.connect_write_pipe(
                lambda: asyncio.StreamReaderProtocol(asyncio.StreamReader(limit=64), loop=loop),
                dup_file,
            )
        except BaseException:
            with suppress(OSError):
                dup_file.close()
            raise
        return asyncio.StreamWriter(write_transport, write_protocol, None, loop)

    dup_fd = os.dup(raw_fd)
    return _FallbackStdoutWriter(owned_fd=dup_fd, chunk_size=chunk_size, loop=loop)


async def open_stdio_pipes(
    loop: asyncio.AbstractEventLoop,
    chunk_size: int,
) -> tuple[asyncio.StreamReader, WritableByteStream]:
    """Attach asyncio streams to process ``stdin`` and ``stdout`` OS descriptors.

    The returned ``stdin`` reader owns its underlying transport/FD handle and
    exposes ``aclose()`` for explicit early shutdown; dropping the reader also
    triggers cleanup via a weakref finalizer.
    """
    stdin_handle = await open_stdin_stream(loop, chunk_size)
    try:
        stdout_writer = await open_stdout_stream(loop, chunk_size)
    except BaseException:
        await stdin_handle.aclose()
        raise
    return stdin_handle.detach_reader(), stdout_writer


class StdioProxy:
    """Transparent bidirectional MCP stdio proxy."""

    def __init__(self, config: ProxyConfig) -> None:
        self._config = config

    async def run(
        self,
        *,
        stdin_reader: asyncio.StreamReader | None = None,
        stdout_writer: WritableByteStream | None = None,
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

        safe_cmd, _ = EventRedactor(RedactionConfig(mode="standard")).redact_command(cfg.command)
        redacted_cmd = list(safe_cmd)
        loop = asyncio.get_running_loop()

        stdin_handle: _OwnedStdinStream | None = None
        owns_stdout = stdout_writer is None
        active_stdout_writer: WritableByteStream | None = stdout_writer
        managed: ManagedProcess | None = None

        c2s_task: asyncio.Task[StreamForwardResult] | None = None
        s2c_task: asyncio.Task[StreamForwardResult] | None = None
        err_task: asyncio.Task[None] | None = None
        exit_task: asyncio.Task[int] | None = None
        sig_task: asyncio.Task[bool] | None = None
        fatal_diag_task: asyncio.Task[bool] | None = None

        c2s_result: StreamForwardResult | None = None
        s2c_result: StreamForwardResult | None = None
        oversized_error: FrameTooLargeError | None = None
        exit_code = EXIT_OK
        termination_reason = "completed"
        was_cancelled = False
        already_terminated = False
        registered_signals: list[signal.Signals] = []
        primary_exc: BaseException | None = None
        primary_cancel: asyncio.CancelledError | None = None
        teardown_task: asyncio.Task[list[tuple[str, BaseException]]] | None = None

        async def _perform_cleanup() -> list[tuple[str, BaseException]]:
            nonlocal c2s_result, s2c_result, exit_code
            errors: list[tuple[str, BaseException]] = []

            async def _step(
                name: str,
                coro: Coroutine[Any, Any, Any],
                *,
                allow_pipe_errors: bool = False,
            ) -> Any:
                try:
                    return await coro
                except asyncio.CancelledError as exc:
                    errors.append((name, exc))
                    return None
                except Exception as exc:
                    if allow_pipe_errors and _is_expected_pipe_close_error(exc):
                        _LOGGER.debug("StdioProxy cleanup %s saw peer disconnect: %r", name, exc)
                        return None
                    errors.append((name, exc))
                    return None

            proxy_tasks: tuple[asyncio.Task[Any], ...] = tuple(
                t
                for t in (c2s_task, s2c_task, err_task, exit_task, sig_task, fatal_diag_task)
                if t is not None
            )
            if proxy_tasks:
                for task in proxy_tasks:
                    if not task.done():
                        task.cancel()
                results = await asyncio.gather(*proxy_tasks, return_exceptions=True)
                for idx, res in enumerate(results):
                    if isinstance(res, asyncio.CancelledError):
                        continue
                    if (
                        isinstance(res, BaseException)
                        and res is not primary_exc
                        and not isinstance(res, FrameTooLargeError)
                    ):
                        errors.append((f"proxy_task[{idx}]", res))

                if (
                    c2s_task is not None
                    and c2s_result is None
                    and c2s_task.done()
                    and not c2s_task.cancelled()
                    and c2s_task.exception() is None
                ):
                    c2s_result = c2s_task.result()
                if (
                    s2c_task is not None
                    and s2c_result is None
                    and s2c_task.done()
                    and not s2c_task.cancelled()
                    and s2c_task.exception() is None
                ):
                    s2c_result = s2c_task.result()

            if managed is not None:
                if not already_terminated:
                    fast_teardown = was_cancelled or termination_reason in {
                        "signal",
                        "frame_too_large",
                        "diagnostic_write_failed",
                    }
                    reaped_code = await _step(
                        "terminate_process_group",
                        terminate_process_group(
                            managed,
                            sink,
                            grace_before_term=(
                                _FAST_SIGNAL_GRACE_TERM if fast_teardown else cfg.grace_before_term
                            ),
                            grace_before_kill=(
                                _FAST_SIGNAL_GRACE_KILL if fast_teardown else cfg.grace_before_kill
                            ),
                            observer=observer,
                        ),
                    )
                    if isinstance(reaped_code, int) and termination_reason == "completed":
                        exit_code = reaped_code

                if observer is not None:
                    if was_cancelled:
                        await _step(
                            "observer.on_proxy_signal",
                            observer.on_proxy_signal("CANCELLED", time.monotonic_ns()),
                        )
                    await _step(
                        "observer.on_execution_finished",
                        observer.on_execution_finished(
                            termination_reason=termination_reason,
                            exit_code=exit_code,
                            returncode=managed.process.returncode,
                        ),
                    )

            for sig in registered_signals:
                try:
                    loop.remove_signal_handler(sig)
                except NotImplementedError:
                    pass
                except Exception as exc:
                    errors.append((f"remove_signal_handler({sig.name})", exc))

            if stdin_handle is not None:
                await _step("stdin_handle.aclose", stdin_handle.aclose())

            if owns_stdout and active_stdout_writer is not None:
                try:
                    active_stdout_writer.close()
                except Exception as exc:
                    if _is_expected_pipe_close_error(exc):
                        _LOGGER.debug("StdioProxy cleanup stdout.close disconnect: %r", exc)
                    else:
                        errors.append(("stdout_writer.close", exc))
                else:
                    await _step(
                        "stdout_writer.wait_closed",
                        active_stdout_writer.wait_closed(),
                        allow_pipe_errors=True,
                    )

            if errors:
                for step_name, err in list(errors):
                    with suppress(Exception):
                        _LOGGER.error("StdioProxy cleanup step %s failed: %r", step_name, err)
                    try:
                        sink.emit_nowait("proxy_cleanup_error", step=step_name, error=repr(err))
                    except (Exception, asyncio.CancelledError) as report_exc:
                        with suppress(Exception):
                            _LOGGER.error(
                                "StdioProxy cleanup error reporting failed for %s: %r",
                                step_name,
                                report_exc,
                            )
                        errors.append(("proxy_cleanup_error_report", report_exc))

            await _step("sink.close", sink.close())
            return errors

        async def _run_teardown_once() -> None:
            nonlocal teardown_task, was_cancelled
            if teardown_task is None:
                teardown_task = asyncio.create_task(_perform_cleanup())
            teardown_cancel: asyncio.CancelledError | None = None
            while not teardown_task.done():
                try:
                    await asyncio.shield(teardown_task)
                except asyncio.CancelledError as exc:
                    was_cancelled = True
                    if teardown_cancel is None:
                        teardown_cancel = exc

            errors = teardown_task.result()
            if primary_cancel is not None:
                for step_name, err in errors:
                    primary_cancel.add_note(f"Cleanup step {step_name} failed: {err!r}")
                return
            if primary_exc is not None:
                for step_name, err in errors:
                    primary_exc.add_note(f"Cleanup step {step_name} failed: {err!r}")
                return
            if teardown_cancel is not None:
                for step_name, err in errors:
                    teardown_cancel.add_note(f"Cleanup step {step_name} failed: {err!r}")
                raise teardown_cancel
            if errors:
                if len(errors) == 1:
                    raise errors[0][1]
                raise BaseExceptionGroup(
                    "StdioProxy cleanup failed across multiple steps",
                    [err for _, err in errors],
                )

        try:
            if stdin_reader is None:
                stdin_handle = await open_stdin_stream(loop, cfg.chunk_size)
                stdin_reader = stdin_handle.reader
            if active_stdout_writer is None:
                active_stdout_writer = await open_stdout_stream(loop, cfg.chunk_size)

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
        except asyncio.CancelledError as exc:
            primary_cancel = exc
            was_cancelled = True
            termination_reason = "cancelled"
            raise
        except BaseException as exc:
            primary_exc = exc
            raise
        finally:
            if managed is None:
                await _run_teardown_once()

        assert stdin_reader is not None
        assert active_stdout_writer is not None

        proc = managed.process
        assert proc.stdin is not None
        assert proc.stdout is not None
        assert proc.stderr is not None

        try:
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
                try:
                    loop.add_signal_handler(sig, _on_signal, sig)
                    registered_signals.append(sig)
                except NotImplementedError:
                    pass

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
                    active_stdout_writer,
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

            pending: set[asyncio.Task[Any]] = {
                c2s_task,
                s2c_task,
                exit_task,
                sig_task,
                fatal_diag_task,
            }

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
                        termination_reason = "transport_error"
                        exit_code = 1
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
                        termination_reason = "transport_error"
                        exit_code = 1
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
        except asyncio.CancelledError as exc:
            primary_cancel = exc
            was_cancelled = True
            termination_reason = "cancelled"
            sink.emit_nowait("proxy_cancelled")
            raise
        except BaseException as exc:
            primary_exc = exc
            raise
        finally:
            await _run_teardown_once()

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
    "open_stdin_stream",
    "open_stdio_pipes",
    "open_stdout_stream",
    "run_stdio_proxy",
]
