"""Unit and integration tests for Gate 1A (F-01) stdio fallback and teardown."""

from __future__ import annotations

import asyncio
import errno
import gc
import json
import os
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aerlog.proxy import stdio_proxy as sp
from aerlog.proxy.diagnostics import DiagnosticSink
from aerlog.proxy.forwarding import ProxyObserver, WritableByteStream
from aerlog.proxy.stdio_proxy import (
    ProxyConfig,
    StdioProxy,
    _AsyncFileStreamReader,
    _can_use_pipe_transport,
    _FallbackStdoutWriter,
    _OwnedStreamReader,
    open_stdin_stream,
    open_stdio_pipes,
    open_stdout_stream,
)

PYTHON = sys.executable


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _fd_is_closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError as exc:
        return exc.errno == errno.EBADF
    return False


class _RecordingObserver:
    """Minimal ProxyObserver recording lifecycle calls and optional fault injection."""

    def __init__(
        self,
        *,
        finish_delay: float = 0.0,
        finish_exc: BaseException | None = None,
    ) -> None:
        self.finish_delay = finish_delay
        self.finish_exc = finish_exc
        self.finish_calls = 0
        self.signals: list[str] = []

    async def on_execution_started(
        self,
        *,
        command: Sequence[str],
        cwd: Path | None,
        env_overrides: Mapping[str, str] | None,
        monotonic_time_ns: int,
    ) -> None:
        _ = (command, cwd, env_overrides, monotonic_time_ns)

    async def on_wire_frame(self, direction: Any, raw_frame: bytes, monotonic_time_ns: int) -> None:
        _ = (direction, raw_frame, monotonic_time_ns)

    async def on_incomplete_frame(
        self, direction: Any, trailing_bytes: bytes, monotonic_time_ns: int
    ) -> None:
        _ = (direction, trailing_bytes, monotonic_time_ns)

    async def on_frame_too_large(
        self, direction: Any, observed_bytes: int, max_frame_bytes: int, monotonic_time_ns: int
    ) -> None:
        _ = (direction, observed_bytes, max_frame_bytes, monotonic_time_ns)

    async def on_stderr_line(self, raw_line: bytes, monotonic_time_ns: int) -> None:
        _ = (raw_line, monotonic_time_ns)

    async def on_transport_error(
        self,
        stream_direction: Any,
        reason: str,
        error: str,
        monotonic_time_ns: int,
    ) -> None:
        _ = (stream_direction, reason, error, monotonic_time_ns)

    async def on_proxy_signal(self, signal_name: str, monotonic_time_ns: int) -> None:
        _ = monotonic_time_ns
        self.signals.append(signal_name)

    async def on_child_shutdown_escalate(
        self, signal_name: str, pgid: int, error: str | None, monotonic_time_ns: int
    ) -> None:
        _ = (signal_name, pgid, error, monotonic_time_ns)

    async def on_process_exited(self, returncode: int | None, monotonic_time_ns: int) -> None:
        _ = (returncode, monotonic_time_ns)

    async def on_execution_finished(
        self,
        *,
        termination_reason: str,
        exit_code: int,
        returncode: int | None,
    ) -> None:
        _ = (termination_reason, exit_code, returncode)
        self.finish_calls += 1
        if self.finish_delay > 0:
            await asyncio.sleep(self.finish_delay)
        if self.finish_exc is not None:
            raise self.finish_exc


def test_can_use_pipe_transport_classification(tmp_path: Path) -> None:
    """Only FIFO, socket, and TTY character devices use native pipe transports."""
    r_fd, w_fd = os.pipe()
    try:
        assert _can_use_pipe_transport(r_fd) is True
        assert _can_use_pipe_transport(w_fd) is True
    finally:
        os.close(r_fd)
        os.close(w_fd)

    reg = tmp_path / "regular.jsonl"
    reg.write_text("hello\n", encoding="utf-8")
    with reg.open("rb") as f_reg:
        assert _can_use_pipe_transport(f_reg.fileno()) is False

    with Path(os.devnull).open("rb") as f_null:
        assert stat.S_ISCHR(os.fstat(f_null.fileno()).st_mode)
        assert _can_use_pipe_transport(f_null.fileno()) is False


def test_stdio_proxy_subprocess_redirected_regular_files_and_devnull(tmp_path: Path) -> None:
    """CLI proxy works end-to-end with regular-file redirects and /dev/null stdio."""
    echo_server = (
        "import sys\n"
        "for line in sys.stdin.buffer:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n"
    )
    payload = (
        b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
    )
    in_file = tmp_path / "in.jsonl"
    out_file = tmp_path / "out.jsonl"
    diag_file = tmp_path / "diag.jsonl"
    in_file.write_bytes(payload)

    with in_file.open("rb") as f_in, out_file.open("wb") as f_out:
        proc = subprocess.run(
            [
                PYTHON,
                "-m",
                "aerlog.proxy.stdio_proxy",
                "--log-file",
                str(diag_file),
                "--",
                PYTHON,
                "-u",
                "-c",
                echo_server,
            ],
            stdin=f_in,
            stdout=f_out,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    assert proc.returncode == 0
    assert out_file.read_bytes() == payload

    greeting_server = (
        'import sys; sys.stdout.buffer.write(b\'{"jsonrpc":"2.0","method":"ready"}\\n\')\n'
    )
    with Path(os.devnull).open("wb") as f_null:
        proc_null = subprocess.run(
            [
                PYTHON,
                "-m",
                "aerlog.proxy.stdio_proxy",
                "--",
                PYTHON,
                "-u",
                "-c",
                greeting_server,
            ],
            stdin=subprocess.DEVNULL,
            stdout=f_null,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    assert proc_null.returncode == 0


async def test_owned_stdin_stream_delays_fd_close_until_in_flight_worker_exits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancelling or closing fallback stdin never closes the duped FD mid-worker os.read()."""
    in_path = tmp_path / "data.jsonl"
    in_path.write_bytes(b'{"a":1}\n')

    entered_read = threading.Event()
    allow_read_finish = threading.Event()
    closed_fds: list[int] = []

    orig_os_read = os.read
    orig_os_close = os.close

    def blocked_read(fd: int, n: int) -> bytes:
        entered_read.set()
        allow_read_finish.wait(timeout=5.0)
        return orig_os_read(fd, n)

    def tracked_close(fd: int) -> None:
        closed_fds.append(fd)
        orig_os_close(fd)

    with in_path.open("rb") as stream:
        monkeypatch.setattr(sp, "_FALLBACK_IN_FLIGHT_JOIN_TIMEOUT", 0.05)
        monkeypatch.setattr(os, "read", blocked_read)
        monkeypatch.setattr(os, "close", tracked_close)

        handle = await open_stdin_stream(asyncio.get_running_loop(), 1024, stream=stream)
        owned_fd = handle._owned_fd
        assert owned_fd is not None
        assert await asyncio.to_thread(entered_read.wait, 2.0)

        # Trigger close while worker thread is still blocked in os.read().
        await handle.aclose()
        await handle.aclose()  # idempotent double close

        assert owned_fd not in closed_fds
        assert not _fd_is_closed(owned_fd)

        allow_read_finish.set()
        if handle._in_flight_worker is not None:
            await asyncio.to_thread(handle._in_flight_worker.result, 2.0)
        # Give worker finally: a brief moment to complete os.close().
        deadline = time.monotonic() + 2.0
        while owned_fd not in closed_fds and time.monotonic() < deadline:
            await asyncio.sleep(0.01)

        assert closed_fds.count(owned_fd) == 1
        assert _fd_is_closed(owned_fd)
        # Original caller stream FD remains untouched and valid.
        assert not _fd_is_closed(stream.fileno())


async def test_owned_stdin_stream_bounded_readahead(tmp_path: Path) -> None:
    """Fallback stdin pauses reading ahead when reader hasn't consumed buffered chunks."""
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * (600 * 1024))
    with big.open("rb") as stream:
        handle = await open_stdin_stream(asyncio.get_running_loop(), 16384, stream=stream)
        try:
            await asyncio.sleep(0.05)
            # High water is 131_072; only bounded chunks are buffered before any read().
            assert handle._fed_bytes <= 131_072 + 16_384

            total = 0
            while True:
                chunk = await handle.reader.read(32768)
                if not chunk:
                    break
                total += len(chunk)
            assert total == 600 * 1024
        finally:
            await handle.aclose()


async def test_fallback_stdout_writer_partial_writes_fifo_ordering_backpressure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fallback stdout handles short os.write(), preserves FIFO order, and enforces backpressure."""
    out_path = tmp_path / "out.jsonl"
    orig_write = os.write
    orig_close = os.close
    write_gate = threading.Event()
    write_gate.set()
    write_calls = 0
    closed_fds: list[int] = []

    def partial_write(fd: int, data: Any) -> int:
        nonlocal write_calls
        write_gate.wait(timeout=5.0)
        write_calls += 1
        # Simulate short writes of at most 3 bytes at a time.
        return orig_write(fd, memoryview(data)[:3])

    def tracked_close(fd: int) -> None:
        closed_fds.append(fd)
        orig_close(fd)

    monkeypatch.setattr(os, "write", partial_write)
    monkeypatch.setattr(os, "close", tracked_close)

    with out_path.open("wb") as stream:
        writer = await open_stdout_stream(asyncio.get_running_loop(), 1024, stream=stream)
        assert isinstance(writer, _FallbackStdoutWriter)
        owned_fd = writer._owned_fd
        assert owned_fd is not None

        # Concurrent/sequential FIFO write ordering across partial os.write() loops.
        parts = [f'{{"seq":{i}}}\n'.encode() for i in range(40)]
        enqueued_order: list[int] = []

        async def _write_slice(chunk: list[bytes]) -> None:
            for item in chunk:
                enqueued_order.append(int(json.loads(item)["seq"]))
                writer.write(item)
                await asyncio.sleep(0)

        await asyncio.gather(_write_slice(parts[:20]), _write_slice(parts[20:]))
        await writer.drain()

        # Verify backpressure pauses drain() when buffered exceeds high_water while worker blocks.
        write_gate.clear()
        writer.write(b"A" * 300_000)
        drain_task = asyncio.create_task(writer.drain())
        await asyncio.sleep(0.03)
        assert not drain_task.done()
        write_gate.set()
        await asyncio.wait_for(drain_task, timeout=5.0)

        writer.close()
        writer.close()  # idempotent
        await writer.wait_closed()
        await writer.wait_closed()  # idempotent

        assert write_calls > 100
        assert closed_fds.count(owned_fd) == 1
        assert _fd_is_closed(owned_fd)
        assert not _fd_is_closed(stream.fileno())

    # Complete output order must match enqueue order under concurrent producers + short writes.
    raw_lines = out_path.read_bytes().splitlines()
    observed_seqs = [int(json.loads(ln)["seq"]) for ln in raw_lines[:40]]
    assert observed_seqs == enqueued_order
    # Each half preserved its own exact relative ordering without tearing or interleaving mid-line.
    first_half = [ln for ln in raw_lines[:40] if int(json.loads(ln)["seq"]) < 20]
    second_half = [ln for ln in raw_lines[:40] if int(json.loads(ln)["seq"]) >= 20]
    assert [json.loads(ln)["seq"] for ln in first_half] == list(range(20))
    assert [json.loads(ln)["seq"] for ln in second_half] == list(range(20, 40))
    assert out_path.read_bytes().endswith(b"A" * 300_000)


async def test_fallback_stdout_writer_propagates_write_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Write OSError from worker propagates via wait_closed(), drain(), and subsequent write()."""
    out_path = tmp_path / "err_out.jsonl"
    in_write = threading.Event()
    release_write = threading.Event()
    orig_close = os.close
    closed_fds: list[int] = []

    def failing_write(fd: int, data: Any) -> int:
        _ = (fd, data)
        in_write.set()
        release_write.wait(timeout=5.0)
        raise OSError(errno.ENOSPC, "No space left on device")

    def tracked_close(fd: int) -> None:
        closed_fds.append(fd)
        orig_close(fd)

    monkeypatch.setattr(os, "write", failing_write)
    monkeypatch.setattr(os, "close", tracked_close)

    with out_path.open("wb") as stream:
        writer = await open_stdout_stream(asyncio.get_running_loop(), 1024, stream=stream)
        assert isinstance(writer, _FallbackStdoutWriter)
        owned_fd = writer._owned_fd
        assert owned_fd is not None

        writer.write(b'{"id":1}\n')
        assert await asyncio.to_thread(in_write.wait, 2.0)

        # Cancel an outer wait_closed() while worker is still inside os.write().
        wc_task = asyncio.create_task(writer.wait_closed())
        await asyncio.sleep(0.02)
        wc_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await wc_task
        # FD must not be closed before worker finishes failing_write.
        assert owned_fd not in closed_fds

        release_write.set()
        with pytest.raises(OSError, match="No space left on device"):
            await writer.wait_closed()
        with pytest.raises(OSError, match="No space left on device"):
            writer.write(b'{"id":2}\n')
        assert closed_fds.count(owned_fd) == 1
        assert _fd_is_closed(owned_fd)


async def test_stdio_proxy_selective_opening_and_repeated_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Selective stream opening + repeated CancelledError teardown completes once & reaps tree."""
    pids_file = tmp_path / "pids.json"
    server_code = (
        "import json, os, pathlib, subprocess, sys, time\n"
        "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"pathlib.Path({str(pids_file)!r}).write_text("
        "json.dumps({'child': os.getpid(), 'grandchild': gc.pid}))\n"
        "time.sleep(60)\n"
    )
    in_path = tmp_path / "redirect_in.jsonl"
    in_path.write_bytes(b"")

    open_in_calls = 0
    open_out_calls = 0
    closed_stdin_handles: list[bool] = []

    orig_open_in = sp.open_stdin_stream

    async def spy_open_stdin(loop: Any, chunk_size: int) -> Any:
        nonlocal open_in_calls
        open_in_calls += 1
        with in_path.open("rb") as caller_in:
            handle = await orig_open_in(loop, chunk_size, stream=caller_in)
        orig_aclose = handle.aclose

        async def tracked_aclose() -> None:
            closed_stdin_handles.append(True)
            await orig_aclose()

        monkeypatch.setattr(handle, "aclose", tracked_aclose)
        return handle

    async def forbidden_open_stdout(loop: Any, chunk_size: int) -> WritableByteStream:
        nonlocal open_out_calls
        _ = (loop, chunk_size)
        open_out_calls += 1
        raise AssertionError("open_stdout_stream must not run when stdout_writer is injected")

    monkeypatch.setattr(sp, "open_stdin_stream", spy_open_stdin)
    monkeypatch.setattr(sp, "open_stdout_stream", forbidden_open_stdout)

    class _NullWriter:
        def __init__(self) -> None:
            self.closed = False

        def write(self, data: bytes | bytearray | memoryview) -> None:
            _ = data

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    injected_writer = _NullWriter()
    observer = _RecordingObserver(finish_delay=0.15)
    proxy = StdioProxy(
        ProxyConfig(
            command=(PYTHON, "-u", "-c", server_code),
            grace_before_term=0.1,
            grace_before_kill=0.1,
        )
    )
    task = asyncio.create_task(
        proxy.run(
            stdin_reader=None,
            stdout_writer=injected_writer,
            observer=observer,
        )
    )

    deadline = time.monotonic() + 5.0
    while not pids_file.exists() and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    assert pids_file.exists()
    pids = json.loads(pids_file.read_text(encoding="utf-8"))

    # Hammer with repeated cancellations while observer.on_execution_finished sleeps.
    task.cancel("first-cancel")
    await asyncio.sleep(0.02)
    task.cancel("second-cancel")
    await asyncio.sleep(0.02)
    task.cancel("third-cancel")

    with pytest.raises(asyncio.CancelledError):
        await task

    assert open_in_calls == 1
    assert open_out_calls == 0
    assert len(closed_stdin_handles) == 1
    assert observer.finish_calls == 1
    assert observer.signals == ["CANCELLED"]
    # Injected writer was NOT owned by proxy, so proxy must not close it.
    assert injected_writer.closed is False
    for pid in pids.values():
        assert not _pid_alive(int(pid))


async def test_stdio_proxy_teardown_continues_across_failures_and_preserves_precedence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failing/cancelled cleanup steps neither skip subsequent cleanup nor drop errors."""
    out_file = tmp_path / "out.jsonl"
    in_file = tmp_path / "in.jsonl"
    in_file.write_bytes(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
    server_code = (
        "import sys\n"
        "for line in sys.stdin.buffer:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n"
    )

    with in_file.open("rb") as f_in, out_file.open("wb") as f_out:
        orig_open_in = sp.open_stdin_stream
        orig_open_out = sp.open_stdout_stream
        stdin_closed = 0
        stdout_closed = 0
        sink_closed = 0

        async def wrapped_open_in(loop: Any, chunk_size: int) -> Any:
            handle = await orig_open_in(loop, chunk_size, stream=f_in)
            orig_aclose = handle.aclose

            async def track_close() -> None:
                nonlocal stdin_closed
                stdin_closed += 1
                await orig_aclose()

            monkeypatch.setattr(handle, "aclose", track_close)
            return handle

        async def wrapped_open_out(loop: Any, chunk_size: int) -> WritableByteStream:
            writer = await orig_open_out(loop, chunk_size, stream=f_out)
            orig_wc = writer.wait_closed

            async def track_wc() -> None:
                nonlocal stdout_closed
                stdout_closed += 1
                await orig_wc()

            monkeypatch.setattr(writer, "wait_closed", track_wc)
            return writer

        orig_sink_close = DiagnosticSink.close

        async def failing_sink_close(self: DiagnosticSink) -> None:
            nonlocal sink_closed
            sink_closed += 1
            await orig_sink_close(self)
            raise OSError("disk close error")

        monkeypatch.setattr(sp, "open_stdin_stream", wrapped_open_in)
        monkeypatch.setattr(sp, "open_stdout_stream", wrapped_open_out)
        monkeypatch.setattr(DiagnosticSink, "close", failing_sink_close)

        # Step failure (observer raises CancelledError inside cleanup step) + sink.close failure:
        # Both steps still run, streams still close, and BaseExceptionGroup surfaces both errors.
        observer: ProxyObserver = _RecordingObserver(
            finish_exc=asyncio.CancelledError("step-cancelled")
        )
        proxy = StdioProxy(ProxyConfig(command=(PYTHON, "-u", "-c", server_code)))
        with pytest.raises(BaseExceptionGroup) as exc_info:
            await proxy.run(observer=observer)

        assert stdin_closed == 1
        assert stdout_closed == 1
        assert sink_closed == 1
        excs = exc_info.value.exceptions
        assert any(isinstance(e, asyncio.CancelledError) for e in excs)
        assert any(isinstance(e, OSError) and "disk close error" in str(e) for e in excs)


async def test_stdio_proxy_primary_cancellation_preserves_precedence_with_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When cancelled externally and a cleanup step fails, CancelledError still wins."""
    in_path = tmp_path / "empty_in.jsonl"
    out_path = tmp_path / "out.jsonl"
    in_path.write_bytes(b"")
    ready_file = tmp_path / "ready"
    server_code = (
        f"import pathlib, time; pathlib.Path({str(ready_file)!r}).write_text('1'); time.sleep(60)\n"
    )

    with in_path.open("rb") as f_in, out_path.open("wb") as f_out:
        orig_open_in = sp.open_stdin_stream
        orig_open_out = sp.open_stdout_stream
        monkeypatch.setattr(
            sp,
            "open_stdin_stream",
            lambda loop, cs: orig_open_in(loop, cs, stream=f_in),
        )
        monkeypatch.setattr(
            sp,
            "open_stdout_stream",
            lambda loop, cs: orig_open_out(loop, cs, stream=f_out),
        )

        observer: ProxyObserver = _RecordingObserver(finish_exc=RuntimeError("observer failed"))
        proxy = StdioProxy(
            ProxyConfig(
                command=(PYTHON, "-u", "-c", server_code),
                grace_before_term=0.1,
                grace_before_kill=0.1,
            )
        )
        task = asyncio.create_task(proxy.run(observer=observer))
        deadline = time.monotonic() + 5.0
        while not ready_file.exists() and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        assert ready_file.exists()

        task.cancel("external-shutdown")
        with pytest.raises(asyncio.CancelledError) as exc_info:
            await task
        notes = getattr(exc_info.value, "__notes__", [])
        assert any("observer.on_execution_finished" in note for note in notes)


async def test_open_stdio_pipes_regular_file_stdin_cleanup_explicit_and_gc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """open_stdio_pipes() cleans up fallback stdin resources both on aclose() and GC drop."""
    in_path = tmp_path / "large_in.bin"
    out_path = tmp_path / "out.bin"
    in_path.write_bytes(b"Z" * (400 * 1024))

    # 1. Explicit cleanup via reader.aclose() before reading EOF.
    with in_path.open("rb") as f_in, out_path.open("wb") as f_out:
        monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=f_in))
        monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=f_out))
        reader, writer = await open_stdio_pipes(asyncio.get_running_loop(), 16384)
        assert isinstance(reader, _OwnedStreamReader)
        owner = reader._stdin_owner
        assert owner is not None
        owned_fd = owner._owned_fd
        assert owned_fd is not None
        feeder_task = owner._feeder_task
        assert feeder_task is not None

        head = await reader.read(64)
        assert len(head) == 64
        await reader.aclose()
        writer.close()
        await writer.wait_closed()

        assert feeder_task.done()
        assert _fd_is_closed(owned_fd)
        assert not _fd_is_closed(f_in.fileno())

    # 2. Implicit cleanup on early reader drop (GC finalizer breaks paused feeder task cleanly).
    with in_path.open("rb") as f_in2, out_path.open("wb") as f_out2:
        monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=f_in2))
        monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=f_out2))
        reader2, writer2 = await open_stdio_pipes(asyncio.get_running_loop(), 16384)
        assert isinstance(reader2, _OwnedStreamReader)
        owner2 = reader2._stdin_owner
        assert owner2 is not None
        owned_fd2 = owner2._owned_fd
        assert owned_fd2 is not None
        feeder_task2 = owner2._feeder_task
        assert feeder_task2 is not None

        await asyncio.sleep(0.05)  # allow feeder to fill up to high_water and pause
        assert not feeder_task2.done()

        del owner2
        del reader2
        gc.collect()
        deadline = time.monotonic() + 2.0
        while not feeder_task2.done() and time.monotonic() < deadline:
            await asyncio.sleep(0.01)

        writer2.close()
        await writer2.wait_closed()
        assert feeder_task2.done()
        assert _fd_is_closed(owned_fd2)
        assert not _fd_is_closed(f_in2.fileno())


async def test_owned_stdin_stream_read_all_no_double_counting_and_bounded_readahead(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_AsyncFileStreamReader.read(-1) counts consumed bytes once and bounds read-ahead."""
    payload = os.urandom(512 * 1024)
    in_path = tmp_path / "read_all.bin"
    in_path.write_bytes(payload)

    chunk_size = 16384
    observed_in_flight_ahead: list[int] = []
    orig_read = os.read
    handle_ref: list[sp._OwnedStdinStream] = []

    def tracking_read(fd: int, n: int) -> bytes:
        if handle_ref:
            h = handle_ref[0]
            r = h.reader
            if isinstance(r, _AsyncFileStreamReader):
                observed_in_flight_ahead.append(h._fed_bytes - r.consumed_bytes)
        return orig_read(fd, n)

    monkeypatch.setattr(os, "read", tracking_read)

    with in_path.open("rb") as stream:
        handle = await open_stdin_stream(asyncio.get_running_loop(), chunk_size, stream=stream)
        handle_ref.append(handle)
        try:
            reader = handle.reader
            assert isinstance(reader, _AsyncFileStreamReader)
            await asyncio.sleep(0.05)

            data = await reader.read(-1)
            assert data == payload
            assert reader.consumed_bytes == len(payload)
            assert observed_in_flight_ahead
            assert max(observed_in_flight_ahead) < handle._high_water + chunk_size
        finally:
            await handle.aclose()


async def test_stdio_proxy_teardown_error_reporting_failure_does_not_skip_sink_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If reporting cleanup failures raises, sink.close() still runs and errors are preserved."""
    out_file = tmp_path / "out.jsonl"
    in_file = tmp_path / "in.jsonl"
    in_file.write_bytes(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
    server_code = (
        "import sys\n"
        "for line in sys.stdin.buffer:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n"
    )

    with in_file.open("rb") as f_in, out_file.open("wb") as f_out:
        orig_open_in = sp.open_stdin_stream
        orig_open_out = sp.open_stdout_stream
        monkeypatch.setattr(
            sp,
            "open_stdin_stream",
            lambda loop, cs: orig_open_in(loop, cs, stream=f_in),
        )
        monkeypatch.setattr(
            sp,
            "open_stdout_stream",
            lambda loop, cs: orig_open_out(loop, cs, stream=f_out),
        )

        orig_emit_nowait = DiagnosticSink.emit_nowait
        orig_sink_close = DiagnosticSink.close
        sink_closed = 0

        def failing_emit_nowait(self: DiagnosticSink, event: str, **fields: Any) -> None:
            if event == "proxy_cleanup_error":
                raise RuntimeError("emit_nowait failed during cleanup report")
            orig_emit_nowait(self, event, **fields)

        async def tracked_sink_close(self: DiagnosticSink) -> None:
            nonlocal sink_closed
            sink_closed += 1
            await orig_sink_close(self)

        monkeypatch.setattr(DiagnosticSink, "emit_nowait", failing_emit_nowait)
        monkeypatch.setattr(DiagnosticSink, "close", tracked_sink_close)

        observer: ProxyObserver = _RecordingObserver(finish_exc=RuntimeError("observer failed"))
        proxy = StdioProxy(ProxyConfig(command=(PYTHON, "-u", "-c", server_code)))
        with pytest.raises(BaseExceptionGroup) as exc_info:
            await proxy.run(observer=observer)

        assert sink_closed == 1
        msgs = [str(e) for e in exc_info.value.exceptions]
        assert any("observer failed" in m for m in msgs)
        assert any("emit_nowait failed during cleanup report" in m for m in msgs)


def test_open_stdio_pipes_gc_while_worker_running_and_loop_closed_shuts_down_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dropping reader while worker is running (even after loop closes) shuts down executor."""
    in_path = tmp_path / "in_gc_loop_closed.jsonl"
    out_path = tmp_path / "out_gc_loop_closed.jsonl"
    in_path.write_bytes(b'{"a":1}\n')

    entered_read = threading.Event()
    allow_read = threading.Event()
    closed_fds: list[int] = []
    orig_read = os.read
    orig_close = os.close

    def blocked_read(fd: int, n: int) -> bytes:
        entered_read.set()
        allow_read.wait(timeout=5.0)
        return orig_read(fd, n)

    def tracked_close(fd: int) -> None:
        closed_fds.append(fd)
        orig_close(fd)

    monkeypatch.setattr(os, "read", blocked_read)
    monkeypatch.setattr(os, "close", tracked_close)

    loop = asyncio.new_event_loop()
    with in_path.open("rb") as f_in, out_path.open("wb") as f_out:
        monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=f_in))
        monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=f_out))
        reader, writer = loop.run_until_complete(open_stdio_pipes(loop, 1024))
        assert isinstance(reader, _OwnedStreamReader)
        owner = reader._stdin_owner
        assert owner is not None
        owned_fd = owner._owned_fd
        executor = owner._executor
        assert owned_fd is not None
        assert executor is not None

        assert entered_read.wait(timeout=2.0)

        # Close writer & close loop cleanly BEFORE dropping reader while worker is still active.
        loop.run_until_complete(writer.wait_closed())
        for pending_task in asyncio.all_tasks(loop):
            pending_task.cancel()
        loop.run_until_complete(asyncio.gather(*asyncio.all_tasks(loop), return_exceptions=True))
        loop.close()

        # Drop reader after loop close while os.read worker is still running.
        del owner
        del reader
        gc.collect()

        assert executor._shutdown is True
        assert owned_fd not in closed_fds
        assert not _fd_is_closed(owned_fd)

        allow_read.set()
        executor.shutdown(wait=True)

        assert closed_fds.count(owned_fd) == 1
        assert _fd_is_closed(owned_fd)
        assert not _fd_is_closed(f_in.fileno())


async def test_fallback_stdout_writer_cancellation_mid_write_preserves_fd_and_write_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancelling wait_closed() mid-write keeps FD open and preserves cancellation."""
    out_path = tmp_path / "cancel_mid_write.jsonl"
    entered_write = threading.Event()
    release_write = threading.Event()
    orig_write = os.write
    orig_close = os.close
    closed_fds: list[int] = []

    def slow_write(fd: int, data: Any) -> int:
        entered_write.set()
        release_write.wait(timeout=5.0)
        return orig_write(fd, data)

    def tracked_close(fd: int) -> None:
        closed_fds.append(fd)
        orig_close(fd)

    monkeypatch.setattr(os, "write", slow_write)
    monkeypatch.setattr(os, "close", tracked_close)

    with out_path.open("wb") as stream:
        writer = await open_stdout_stream(asyncio.get_running_loop(), 1024, stream=stream)
        assert isinstance(writer, _FallbackStdoutWriter)
        owned_fd = writer._owned_fd
        assert owned_fd is not None

        payload = b'{"chunk":1}\n'
        writer.write(payload)
        assert await asyncio.to_thread(entered_write.wait, 2.0)

        wc_task = asyncio.create_task(writer.wait_closed())
        await asyncio.sleep(0.02)
        wc_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await wc_task

        # FD must NOT be closed/reusable while _write_batch_sync() is still running,
        # and writes after close() initiated must fail rather than enqueueing.
        assert owned_fd not in closed_fds
        assert not _fd_is_closed(owned_fd)
        assert not writer._writer_task.done()
        with pytest.raises(BrokenPipeError):
            writer.write(b'{"chunk":2}\n')

        release_write.set()
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        assert closed_fds.count(owned_fd) == 1
        assert _fd_is_closed(owned_fd)
        assert not _fd_is_closed(stream.fileno())

    assert out_path.read_bytes() == payload


async def test_stdio_proxy_repeated_cancellation_during_stdin_and_stdout_cleanup_no_unhandled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated cancellation during stdin/stdout cleanup leaves zero unhandled tasks."""
    in_path = tmp_path / "in_cancel.jsonl"
    out_path = tmp_path / "out_cancel.jsonl"
    in_path.write_bytes(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
    server_code = (
        "import sys\n"
        "for line in sys.stdin.buffer:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n"
    )

    loop = asyncio.get_running_loop()
    loop_exceptions: list[dict[str, Any]] = []
    orig_handler = loop.get_exception_handler()

    def _capture_exc(target_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        loop_exceptions.append(context)
        if orig_handler is not None:
            orig_handler(target_loop, context)

    loop.set_exception_handler(_capture_exc)

    stdin_cleanup_entered = asyncio.Event()
    stdout_cleanup_entered = asyncio.Event()
    cleanup_steps: list[str] = []

    try:
        with in_path.open("rb") as f_in, out_path.open("wb") as f_out:
            orig_open_in = sp.open_stdin_stream
            orig_open_out = sp.open_stdout_stream

            async def wrapped_in(target_loop: Any, cs: int) -> Any:
                handle = await orig_open_in(target_loop, cs, stream=f_in)
                orig_aclose = handle.aclose

                async def slow_aclose() -> None:
                    cleanup_steps.append("stdin_start")
                    stdin_cleanup_entered.set()
                    await asyncio.sleep(0.08)
                    await orig_aclose()
                    cleanup_steps.append("stdin_done")

                monkeypatch.setattr(handle, "aclose", slow_aclose)
                return handle

            async def wrapped_out(target_loop: Any, cs: int) -> WritableByteStream:
                writer = await orig_open_out(target_loop, cs, stream=f_out)
                orig_wc = writer.wait_closed

                async def slow_wc() -> None:
                    cleanup_steps.append("stdout_start")
                    stdout_cleanup_entered.set()
                    await asyncio.sleep(0.08)
                    await orig_wc()
                    cleanup_steps.append("stdout_done")

                monkeypatch.setattr(writer, "wait_closed", slow_wc)
                return writer

            orig_sink_close = DiagnosticSink.close

            async def tracked_sink_close(self: DiagnosticSink) -> None:
                await orig_sink_close(self)
                cleanup_steps.append("sink_done")

            monkeypatch.setattr(sp, "open_stdin_stream", wrapped_in)
            monkeypatch.setattr(sp, "open_stdout_stream", wrapped_out)
            monkeypatch.setattr(DiagnosticSink, "close", tracked_sink_close)

            # Force teardown directly when stdin/stdout close runs by terminating right after echo:
            # Delay observer slightly so cleanup happens cleanly inside teardown_task.
            proxy = StdioProxy(ProxyConfig(command=(PYTHON, "-u", "-c", server_code)))
            proxy_task = asyncio.create_task(proxy.run())

            await asyncio.wait_for(stdin_cleanup_entered.wait(), timeout=5.0)
            proxy_task.cancel("cancel-during-stdin-1")
            await asyncio.sleep(0.01)
            proxy_task.cancel("cancel-during-stdin-2")

            await asyncio.wait_for(stdout_cleanup_entered.wait(), timeout=5.0)
            proxy_task.cancel("cancel-during-stdout-1")
            await asyncio.sleep(0.01)
            proxy_task.cancel("cancel-during-stdout-2")

            with pytest.raises(asyncio.CancelledError):
                await proxy_task

            assert cleanup_steps == [
                "stdin_start",
                "stdin_done",
                "stdout_start",
                "stdout_done",
                "sink_done",
            ]
            current = asyncio.current_task()
            remaining = [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()]
            assert remaining == []
            gc.collect()
            await asyncio.sleep(0.02)
            assert loop_exceptions == []
    finally:
        loop.set_exception_handler(orig_handler)


async def test_owned_stdin_stream_readline_does_not_stall_and_bounds_readahead(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """readline() and async iteration advance consumed_bytes cleanly without stalling."""
    # ~320 KiB of lines (> 131_072 high_water), ending with an unterminated partial line.
    lines_data = [f'{{"line":{i},"pad":"{"x" * 64}"}}\n'.encode() for i in range(3800)]
    lines_data.append(b'{"trailing":"no_newline"}')
    payload = b"".join(lines_data)
    in_path = tmp_path / "lines_large.jsonl"
    in_path.write_bytes(payload)

    chunk_size = 16384
    observed_buffered: list[int] = []
    orig_read = os.read
    handle_ref: list[sp._OwnedStdinStream] = []

    def tracking_read(fd: int, n: int) -> bytes:
        if handle_ref:
            h = handle_ref[0]
            r = h.reader
            if isinstance(r, _AsyncFileStreamReader):
                observed_buffered.append(h._fed_bytes - r.consumed_bytes)
        return orig_read(fd, n)

    monkeypatch.setattr(os, "read", tracking_read)

    with in_path.open("rb") as stream:
        handle = await open_stdin_stream(asyncio.get_running_loop(), chunk_size, stream=stream)
        handle_ref.append(handle)
        try:
            reader = handle.reader
            assert isinstance(reader, _AsyncFileStreamReader)
            read_lines: list[bytes] = []
            async for line in reader:
                read_lines.append(line)

            assert read_lines == lines_data
            assert reader.consumed_bytes == len(payload)
            assert observed_buffered
            assert max(observed_buffered) < handle._high_water + chunk_size
        finally:
            await handle.aclose()


async def test_owned_stdin_stream_readexactly_below_and_above_high_water(
    tmp_path: Path,
) -> None:
    """readexactly() never stalls either in small steps or when n > high_water."""
    payload = os.urandom(400 * 1024)
    in_path = tmp_path / "exact_large.bin"
    in_path.write_bytes(payload)

    with in_path.open("rb") as stream:
        handle = await open_stdin_stream(asyncio.get_running_loop(), 16384, stream=stream)
        try:
            reader = handle.reader
            assert isinstance(reader, _AsyncFileStreamReader)
            # First advance by small reads (< high_water), then demand > high_water.
            head = await asyncio.wait_for(reader.readexactly(32_768), timeout=3.0)
            mid = await asyncio.wait_for(reader.readexactly(262_144), timeout=3.0)
            rem = len(payload) - len(head) - len(mid)
            with pytest.raises(asyncio.IncompleteReadError) as exc_info:
                await asyncio.wait_for(reader.readexactly(rem + 128), timeout=3.0)

            assert head + mid + exc_info.value.partial == payload
            assert reader.consumed_bytes == len(payload)
        finally:
            await handle.aclose()


@pytest.mark.parametrize("worker_raises", [False, True])
async def test_fallback_stdout_writer_direct_writer_task_cancellation_mid_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    worker_raises: bool,
) -> None:
    """Cancelling _writer_task directly mid-write preserves FD safety and raises on wait_closed."""
    out_path = tmp_path / f"direct_cancel_{worker_raises}.jsonl"
    entered_write = threading.Event()
    release_write = threading.Event()
    orig_write = os.write
    orig_close = os.close
    closed_fds: list[int] = []

    def blocked_write(fd: int, data: Any) -> int:
        entered_write.set()
        release_write.wait(timeout=5.0)
        if worker_raises:
            raise OSError(errno.EIO, "delayed io error")
        return orig_write(fd, data)

    def tracked_close(fd: int) -> None:
        closed_fds.append(fd)
        orig_close(fd)

    monkeypatch.setattr(os, "write", blocked_write)
    monkeypatch.setattr(os, "close", tracked_close)

    loop = asyncio.get_running_loop()
    loop_exceptions: list[dict[str, Any]] = []
    orig_handler = loop.get_exception_handler()

    def _capture_exc(target_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        loop_exceptions.append(context)
        if orig_handler is not None:
            orig_handler(target_loop, context)

    loop.set_exception_handler(_capture_exc)

    try:
        with out_path.open("wb") as stream:
            writer = await open_stdout_stream(loop, 1024, stream=stream)
            assert isinstance(writer, _FallbackStdoutWriter)
            owned_fd = writer._owned_fd
            executor = writer._executor
            assert owned_fd is not None

            payload = b'{"direct_cancel":true}\n'
            writer.write(payload)
            assert await asyncio.to_thread(entered_write.wait, 2.0)

            # Cancel _writer_task directly while _write_batch_sync() is blocked inside os.write().
            writer._writer_task.cancel("direct-task-cancel")
            await asyncio.sleep(0.02)
            assert writer._writer_task.done()
            assert writer._writer_task.exception() is None

            # FD must remain valid & unclosed while worker holds it, and wait_closed() must fail.
            assert owned_fd not in closed_fds
            assert not _fd_is_closed(owned_fd)
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)

            release_write.set()
            await asyncio.to_thread(executor.shutdown, wait=True)

            assert closed_fds.count(owned_fd) == 1
            assert _fd_is_closed(owned_fd)
            assert not _fd_is_closed(stream.fileno())
            if not worker_raises:
                assert out_path.read_bytes() == payload

        gc.collect()
        await asyncio.sleep(0.02)
        assert loop_exceptions == []
    finally:
        loop.set_exception_handler(orig_handler)
