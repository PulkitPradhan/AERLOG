"""Unit and subprocess tests for Gate 1B (F-04) non-blocking replay stdio & signal shutdown."""

from __future__ import annotations

import asyncio
import gc
import json
import os
import signal
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aerlog.capture.normalizer import EventNormalizer, RawWireFrameInput
from aerlog.events.ids import new_execution_id
from aerlog.events.models import ExecutionEvent
from aerlog.proxy import stdio_proxy as sp
from aerlog.replay import (
    Cassette,
    ReplayInterruptedError,
    build_cassette_from_read_result,
    save_cassette,
    serve_cassette_stdio,
)
from aerlog.storage.event_log import IndexedLogEvent, JsonlReadResult

PYTHON = sys.executable


def _make_ping_cassette() -> Cassette:
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("mock-server",),
    )
    events: list[ExecutionEvent] = list(norm.start_execution())
    events.extend(
        norm.normalize(
            RawWireFrameInput(
                timestamp=t0,
                monotonic_time_ns=2_000,
                direction="client_to_server",
                raw_frame=b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
            )
        )
    )
    events.extend(
        norm.normalize(
            RawWireFrameInput(
                timestamp=t0,
                monotonic_time_ns=3_000,
                direction="server_to_client",
                raw_frame=b'{"jsonrpc":"2.0","id":1,"result":{"pong":true}}\n',
            )
        )
    )
    fin, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=4_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin)
    indexed = tuple(
        IndexedLogEvent(event=ev, line_number=i, byte_offset=i * 10, byte_length=10)
        for i, ev in enumerate(events, start=1)
    )
    read_res = JsonlReadResult(
        execution_id=exec_id,
        header=norm.build_header(),
        summary=summary,
        manifest=None,
        events=indexed,
        corruptions=(),
        byte_size=len(indexed) * 10,
        line_count=len(indexed),
        last_valid_sequence=indexed[-1].event.sequence,
        events_file_sha256="0" * 64,
        unclean_shutdown=False,
    )
    return build_cassette_from_read_result(read_res)


@pytest.mark.parametrize(
    ("sig", "expected_rc"),
    [
        (signal.SIGINT, 130),
        (signal.SIGTERM, 143),
    ],
)
def test_cli_replay_serve_idle_open_stdin_exits_cleanly_on_signal(
    tmp_path: Path,
    sig: signal.Signals,
    expected_rc: int,
) -> None:
    """CLI ``aerlog replay --serve`` with open idle stdin exits immediately on SIGINT/SIGTERM."""
    data_dir = tmp_path / "data"
    cassette = _make_ping_cassette()
    cassette_path = save_cassette(cassette, data_dir=data_dir)

    proc = subprocess.Popen(
        [
            PYTHON,
            "-m",
            "aerlog",
            "replay",
            "--cassette",
            str(cassette_path),
            "--serve",
            "--match",
            "tolerant",
            "--no-save-report",
            "--data-dir",
            str(data_dir),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdin is not None
        assert proc.stdout is not None

        # Write one request & await its response to prove the event loop is active & awaiting stdin.
        proc.stdin.write(b'{"jsonrpc":"2.0","id":7,"method":"ping"}\n')
        proc.stdin.flush()
        reply_line = proc.stdout.readline()
        assert json.loads(reply_line.decode("utf-8")) == {
            "jsonrpc": "2.0",
            "id": 7,
            "result": {"pong": True},
        }

        # Leave stdin OPEN and idle, then deliver SIGINT / SIGTERM.
        proc.send_signal(sig)
        rc = proc.wait(timeout=3.0)
        assert rc == expected_rc
        err_text = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        assert "Traceback" not in err_text
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=3.0)
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()


def test_cli_replay_serve_works_with_regular_file_and_devnull_redirects(tmp_path: Path) -> None:
    """CLI ``aerlog replay --serve`` works cleanly when stdin/stdout are redirected to files."""
    data_dir = tmp_path / "data"
    cassette = _make_ping_cassette()
    cassette_path = save_cassette(cassette, data_dir=data_dir)

    in_file = tmp_path / "requests.jsonl"
    out_file = tmp_path / "responses.jsonl"
    in_file.write_bytes(b'{"jsonrpc":"2.0","id":42,"method":"ping"}\n')

    with in_file.open("rb") as f_in, out_file.open("wb") as f_out:
        res = subprocess.run(
            [
                PYTHON,
                "-m",
                "aerlog",
                "replay",
                "--cassette",
                str(cassette_path),
                "--serve",
                "--match",
                "tolerant",
                "--no-save-report",
                "--data-dir",
                str(data_dir),
            ],
            stdin=f_in,
            stdout=f_out,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    assert res.returncode == 0
    assert json.loads(out_file.read_text(encoding="utf-8").strip()) == {
        "jsonrpc": "2.0",
        "id": 42,
        "result": {"pong": True},
    }

    with Path(os.devnull).open("wb") as f_null:
        res_null = subprocess.run(
            [
                PYTHON,
                "-m",
                "aerlog",
                "replay",
                "--cassette",
                str(cassette_path),
                "--serve",
                "--no-save-report",
                "--data-dir",
                str(data_dir),
            ],
            stdin=subprocess.DEVNULL,
            stdout=f_null,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    assert res_null.returncode == 0


async def test_serve_cassette_stdio_active_pipe_read_first_signal_precedence_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIGINT while awaiting open pipe wakes immediately; repeated signal preserves first."""
    cassette = _make_ping_cassette()
    in_r, in_w = os.pipe()
    out_r, out_w = os.pipe()
    loop = asyncio.get_running_loop()
    loop_exceptions: list[dict[str, Any]] = []
    orig_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _l, ctx: loop_exceptions.append(ctx))

    try:
        with (
            os.fdopen(in_r, "rb", closefd=True) as f_in_r,
            os.fdopen(in_w, "wb", buffering=0, closefd=True) as f_in_w,
            os.fdopen(out_w, "wb", buffering=0, closefd=True) as f_out_w,
            os.fdopen(out_r, "rb", buffering=0, closefd=True) as f_out_r,
        ):
            monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=f_in_r))
            monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=f_out_w))

            serve_task = asyncio.create_task(serve_cassette_stdio(cassette, match_mode="tolerant"))
            # Wait one tick so signal handlers attach, then send one frame to synchronize.
            await asyncio.sleep(0.02)
            f_in_w.write(b'{"jsonrpc":"2.0","id":11,"method":"ping"}\n')
            first_reply = await asyncio.to_thread(f_out_r.readline)
            assert json.loads(first_reply.decode("utf-8"))["id"] == 11

            # Deliver SIGINT while reader sits idle on open in_r, followed quickly by SIGTERM.
            os.kill(os.getpid(), signal.SIGINT)
            os.kill(os.getpid(), signal.SIGTERM)

            with pytest.raises(ReplayInterruptedError) as exc_info:
                await asyncio.wait_for(serve_task, timeout=2.0)

            assert exc_info.value.signal_num == signal.SIGINT.value
            assert exc_info.value.exit_code == 130

            # Original pipe FDs owned by caller remain open; loop signal handlers removed.
            assert loop.remove_signal_handler(signal.SIGINT) is False
            assert loop.remove_signal_handler(signal.SIGTERM) is False

            current = asyncio.current_task()
            assert [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()] == []
            gc.collect()
            await asyncio.sleep(0.02)
            assert loop_exceptions == []
    finally:
        loop.set_exception_handler(orig_handler)


async def test_serve_cassette_stdio_interrupts_during_protocol_batch_cleanly() -> None:
    """SIGINT arriving during frame processing stops cleanly after current write."""
    cassette = _make_ping_cassette()
    two_frames = (
        b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        + b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    )
    chunks = [two_frames, b""]
    idx = 0
    written: list[bytes] = []

    def _read_chunk() -> bytes:
        nonlocal idx
        item = chunks[idx]
        idx += 1
        return item

    def _write_and_interrupt(data: bytes) -> None:
        written.append(data)
        if len(written) == 1:
            os.kill(os.getpid(), signal.SIGINT)

    with pytest.raises(ReplayInterruptedError) as exc_info:
        await asyncio.wait_for(
            serve_cassette_stdio(
                cassette,
                match_mode="tolerant",
                read_chunk=_read_chunk,
                write_frame=_write_and_interrupt,
            ),
            timeout=2.0,
        )

    assert exc_info.value.exit_code == 130
    assert len(written) == 1
    assert json.loads(written[0].decode("utf-8"))["id"] == 1


async def test_serve_cassette_stdio_external_cancel_precedence_and_repeated_cancel_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External task cancellation propagates cleanly through repeated cancels without FD leaks."""
    cassette = _make_ping_cassette()
    in_r, in_w = os.pipe()
    out_file = tmp_path / "out.jsonl"

    loop = asyncio.get_running_loop()
    loop_exceptions: list[dict[str, Any]] = []
    orig_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _l, ctx: loop_exceptions.append(ctx))

    cleanup_entered = asyncio.Event()
    cleanup_steps: list[str] = []

    try:
        with (
            os.fdopen(in_r, "rb", closefd=True) as f_in_r,
            os.fdopen(in_w, "wb", buffering=0, closefd=True),
            out_file.open("wb") as f_out,
        ):
            orig_open_in = sp.open_stdin_stream
            orig_open_out = sp.open_stdout_stream

            async def wrapped_open_in(target_loop: Any, cs: int) -> Any:
                handle = await orig_open_in(target_loop, cs, stream=f_in_r)
                orig_aclose = handle.aclose

                async def slow_aclose() -> None:
                    cleanup_steps.append("stdin_start")
                    cleanup_entered.set()
                    await asyncio.sleep(0.08)
                    await orig_aclose()
                    cleanup_steps.append("stdin_done")

                monkeypatch.setattr(handle, "aclose", slow_aclose)
                return handle

            async def wrapped_open_out(target_loop: Any, cs: int) -> Any:
                writer = await orig_open_out(target_loop, cs, stream=f_out)
                orig_wc = writer.wait_closed

                async def tracked_wc() -> None:
                    await orig_wc()
                    cleanup_steps.append("stdout_done")

                monkeypatch.setattr(writer, "wait_closed", tracked_wc)
                return writer

            from aerlog.replay import runner as runner_mod

            monkeypatch.setattr(runner_mod, "open_stdin_stream", wrapped_open_in)
            monkeypatch.setattr(runner_mod, "open_stdout_stream", wrapped_open_out)

            task = asyncio.create_task(serve_cassette_stdio(cassette, match_mode="tolerant"))
            await asyncio.sleep(0.02)

            # Cancel externally while idle on open pipe, then cancel repeatedly during cleanup.
            task.cancel("ext-1")
            await asyncio.wait_for(cleanup_entered.wait(), timeout=2.0)
            task.cancel("ext-2")
            await asyncio.sleep(0.01)
            task.cancel("ext-3")

            with pytest.raises(asyncio.CancelledError):
                await task

            assert cleanup_steps == ["stdin_start", "stdin_done", "stdout_done"]
            assert loop.remove_signal_handler(signal.SIGINT) is False
            assert loop.remove_signal_handler(signal.SIGTERM) is False

            current = asyncio.current_task()
            assert [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()] == []
            gc.collect()
            await asyncio.sleep(0.02)
            assert loop_exceptions == []
    finally:
        loop.set_exception_handler(orig_handler)


async def test_serve_cassette_stdio_handles_unsupported_signal_handlers_gracefully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unsupported loop.add_signal_handler (NotImplementedError/RuntimeError) degrades safely."""
    cassette = _make_ping_cassette()
    loop = asyncio.get_running_loop()

    def _no_sig(*_args: Any) -> None:
        raise NotImplementedError("signals unsupported")

    monkeypatch.setattr(loop, "add_signal_handler", _no_sig)

    chunks = [b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n', b""]
    idx = 0
    written: list[bytes] = []

    def _read_chunk() -> bytes:
        nonlocal idx
        item = chunks[idx]
        idx += 1
        return item

    report = await serve_cassette_stdio(
        cassette,
        match_mode="tolerant",
        read_chunk=_read_chunk,
        write_frame=written.append,
    )
    assert report.matched_count == 1
    assert len(written) == 1
