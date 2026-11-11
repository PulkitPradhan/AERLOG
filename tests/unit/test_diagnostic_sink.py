"""Unit tests for the bounded off-stdout DiagnosticSink."""

from __future__ import annotations

import io
import json
import stat
from pathlib import Path

import pytest

from aerlog.proxy.diagnostics import (
    DiagnosticConfig,
    DiagnosticFatalWriteError,
    DiagnosticSink,
)


class _FailingTextIO(io.StringIO):
    """Test stream raising OSError on writes."""

    def write(self, s: str) -> int:
        raise OSError("simulated disk full")


async def test_file_sink_writes_with_restricted_permissions(tmp_path: Path) -> None:
    log_path = tmp_path / "logs" / "proxy.jsonl"
    sink = DiagnosticSink(DiagnosticConfig(log_file=log_path))
    await sink.start()
    await sink.emit("server_started", pid=1234)
    await sink.close()

    mode = stat.S_IMODE(log_path.stat().st_mode)
    assert mode == 0o600
    lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 1
    assert lines[0]["event"] == "server_started"
    assert sink.is_complete is True


async def test_drop_with_gap_emits_explicit_gap_record() -> None:
    stream = io.StringIO()
    sink = DiagnosticSink(
        DiagnosticConfig(queue_size=2, backpressure_policy="drop_with_gap"),
        stream=stream,
    )
    await sink.start()

    # Flood before the writer task gets scheduled.
    for idx in range(10):
        await sink.emit("burst", seq=idx)
    await sink.close()

    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    gaps = [r for r in records if r["event"] == "diagnostic_backpressure_gap"]
    assert sink.dropped_count > 0
    assert sink.is_complete is False
    assert sum(int(g["dropped_count"]) for g in gaps) == sink.dropped_count


async def test_block_backpressure_delivers_all_records() -> None:
    stream = io.StringIO()
    sink = DiagnosticSink(
        DiagnosticConfig(queue_size=2, backpressure_policy="block"),
        stream=stream,
    )
    await sink.start()
    for idx in range(20):
        await sink.emit("ordered", seq=idx)
    await sink.close()

    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert [r["seq"] for r in records] == list(range(20))
    assert sink.dropped_count == 0
    assert sink.is_complete is True


async def test_degrade_policy_survives_write_failures_even_under_block_mode() -> None:
    failing_stream = _FailingTextIO()
    fallback_stderr = io.StringIO()
    sink = DiagnosticSink(
        DiagnosticConfig(
            queue_size=2,
            write_policy="degrade",
            backpressure_policy="block",
        ),
        stream=failing_stream,
        fallback_stderr=fallback_stderr,
    )
    await sink.start()
    for idx in range(10):
        await sink.emit("test_event", seq=idx)
    await sink.close()

    assert sink.write_errors >= 1
    assert sink.is_complete is False
    assert sink.fatal_error is None
    assert "diagnostic_write_failed" in fallback_stderr.getvalue()


async def test_strict_policy_signals_fatal_error_on_write_failure(tmp_path: Path) -> None:
    failing_stream = _FailingTextIO()
    fallback_stderr = io.StringIO()
    sink = DiagnosticSink(
        DiagnosticConfig(write_policy="strict"),
        stream=failing_stream,
        fallback_stderr=fallback_stderr,
    )
    await sink.start()
    await sink.emit("trigger_fail")
    await sink.fatal_event.wait()
    await sink.close()

    assert sink.fatal_error is not None
    assert "diagnostic_write_failed" in fallback_stderr.getvalue()

    # Opening a directory as a log file under strict mode raises immediately.
    bad_sink = DiagnosticSink(
        DiagnosticConfig(log_file=tmp_path, write_policy="strict"),
        fallback_stderr=fallback_stderr,
    )
    with pytest.raises(DiagnosticFatalWriteError):
        await bad_sink.start()
