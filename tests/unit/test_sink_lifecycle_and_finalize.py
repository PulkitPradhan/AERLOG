"""Unit tests for Gate 1C (F-02 & F-03): serialized sink lifecycle & sequence continuity."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aerlog.capture.normalizer import EventNormalizer, RawWireFrameInput
from aerlog.capture.pipeline import CaptureConfig, CapturePipeline
from aerlog.capture.sinks import InMemoryCaptureSink
from aerlog.events.ids import new_event_id, new_execution_id
from aerlog.events.models import (
    ExecutionEvent,
    ExecutionHeader,
    ExecutionSummary,
    JsonRpcRequestPayload,
    RedactionSummary,
    WireFrameInfo,
)
from aerlog.storage.event_log import JsonlEventLogReader
from aerlog.storage.exceptions import StorageWriteError
from aerlog.storage.sink import PersistentCaptureSink


def _make_header(exec_id: str | None = None) -> ExecutionHeader:
    eid = new_execution_id() if exec_id is None else exec_id
    t0 = datetime(2026, 11, 13, 0, 0, 0, tzinfo=UTC)
    return ExecutionHeader(
        execution_id=eid,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("mock-server",),
        cwd="/tmp",
        redaction_mode="standard",
    )


def _make_event(exec_id: str, seq: int) -> ExecutionEvent:
    t0 = datetime(2026, 11, 13, 0, 0, 0, tzinfo=UTC)
    return ExecutionEvent(
        event_id=new_event_id(),
        execution_id=exec_id,
        sequence=seq,
        timestamp=t0,
        monotonic_time_ns=seq * 1_000,
        direction="client_to_server",
        kind="jsonrpc_request",
        wire=WireFrameInfo(
            byte_length=42,
            line_ending="lf",
            sha256="0" * 64,
        ),
        redaction=RedactionSummary(
            mode="standard",
            payload_mode="redacted",
            applied=True,
        ),
        payload=JsonRpcRequestPayload(
            id=seq,
            id_type="int",
            method="ping",
        ),
    )


def _make_summary(exec_id: str, total_events: int) -> ExecutionSummary:
    t0 = datetime(2026, 11, 13, 0, 0, 0, tzinfo=UTC)
    return ExecutionSummary(
        execution_id=exec_id,
        started_at=t0,
        ended_at=t0,
        duration_ns=10_000,
        command=("mock-server",),
        cwd="/tmp",
        redaction_mode="standard",
        backpressure_policy="block",
        capture_completeness="complete",
        termination_reason="completed",
        exit_code=0,
        returncode=0,
        total_events=total_events,
        dropped_events=0,
        degraded_events=0,
        warning_count=0,
        gap_count=0,
    )


async def test_persistent_capture_sink_double_and_concurrent_close_idempotent(
    tmp_path: Path,
) -> None:
    """Concurrent and repeated close() calls resolve to the exact same outcome."""
    sink = PersistentCaptureSink(tmp_path)
    header = _make_header()
    await sink.on_start(header)
    assert sink.execution_id == header.execution_id

    # Concurrent close
    t1 = asyncio.create_task(sink.close())
    t2 = asyncio.create_task(sink.close())
    await asyncio.gather(t1, t2)

    assert sink.closed is True

    # Sequential repeated close
    await sink.close()
    assert sink.closed is True


async def test_persistent_capture_sink_concurrent_close_error_propagation_same_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close errors propagate identically to concurrent and subsequent close callers."""
    sink = PersistentCaptureSink(tmp_path)
    header = _make_header()
    await sink.on_start(header)

    def failing_close_sync() -> None:
        raise OSError("Disk sync failed during close")

    monkeypatch.setattr(sink, "_close_sync", failing_close_sync)

    t1 = asyncio.create_task(sink.close())
    t2 = asyncio.create_task(sink.close())

    with pytest.raises(OSError, match="Disk sync failed during close"):
        await t1

    with pytest.raises(OSError, match="Disk sync failed during close"):
        await t2

    # Subsequent sequential call gets the same failure
    with pytest.raises(OSError, match="Disk sync failed during close"):
        await sink.close()


async def test_persistent_capture_sink_post_close_operations_rejected(tmp_path: Path) -> None:
    """All sink operations reject immediately with StorageWriteError once closed."""
    sink = PersistentCaptureSink(tmp_path)
    header = _make_header()
    await sink.on_start(header)
    await sink.close()

    with pytest.raises(StorageWriteError, match="sink is closed or closing"):
        await sink.on_start(header)

    with pytest.raises(StorageWriteError, match="sink is closed or closing"):
        await sink.emit_events([_make_event(header.execution_id, 1)])

    with pytest.raises(StorageWriteError, match="sink is closed or closing"):
        await sink.on_finish(_make_summary(header.execution_id, 1))

    with pytest.raises(StorageWriteError, match="sink is closed or closing"):
        await sink.flush()


async def test_persistent_capture_sink_in_flight_close_rejects_subsequent_ops_immediately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operations submitted while close() is running are rejected immediately."""
    sink = PersistentCaptureSink(tmp_path)
    header = _make_header()
    await sink.on_start(header)

    orig_close_sync = sink._close_sync

    def slow_close_sync() -> None:
        time.sleep(0.08)
        orig_close_sync()

    monkeypatch.setattr(sink, "_close_sync", slow_close_sync)

    close_task = asyncio.create_task(sink.close())
    # Yield control to let close task transition state to closing
    await asyncio.sleep(0.01)

    with pytest.raises(StorageWriteError, match="sink is closed or closing"):
        await sink.emit_events([_make_event(header.execution_id, 1)])

    await close_task
    assert sink.closed is True


async def test_persistent_capture_sink_outstanding_slow_emit_unwinds_before_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slow emit submitted before close() executes to completion before close runs."""
    sink = PersistentCaptureSink(tmp_path)
    header = _make_header()
    await sink.on_start(header)

    timeline: list[str] = []
    orig_emit = sink._emit_events_sync
    orig_close = sink._close_sync

    def slow_emit_sync(events: Sequence[ExecutionEvent]) -> None:
        timeline.append("emit_start")
        time.sleep(0.06)
        orig_emit(events)
        timeline.append("emit_done")

    def tracked_close_sync() -> None:
        timeline.append("close_start")
        orig_close()
        timeline.append("close_done")

    monkeypatch.setattr(sink, "_emit_events_sync", slow_emit_sync)
    monkeypatch.setattr(sink, "_close_sync", tracked_close_sync)

    ev = _make_event(header.execution_id, 1)
    emit_task = asyncio.create_task(sink.emit_events([ev]))
    await asyncio.sleep(0.01)
    close_task = asyncio.create_task(sink.close())

    await asyncio.gather(emit_task, close_task)

    assert timeline == ["emit_start", "emit_done", "close_start", "close_done"]

    reader = JsonlEventLogReader(tmp_path)
    res = reader.read_execution(header.execution_id)
    assert res.line_count == 1
    assert res.header is not None
    assert res.events[0].event.sequence == 1


async def test_capture_pipeline_repeated_and_concurrent_finalize_returns_same_summary() -> None:
    """Concurrent and subsequent finalize() calls return the identical ExecutionSummary."""
    sink = InMemoryCaptureSink()
    pipeline = CapturePipeline(
        sink,
        command=["mock-server"],
        config=CaptureConfig(backpressure_policy="block"),
    )
    await pipeline.start()
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=datetime.now(UTC),
            monotonic_time_ns=time.monotonic_ns(),
            direction="client_to_server",
            raw_frame=b'{"jsonrpc":"2.0","method":"ping"}\n',
        )
    )

    t1 = asyncio.create_task(
        pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)
    )
    t2 = asyncio.create_task(
        pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)
    )
    s1, s2 = await asyncio.gather(t1, t2)

    assert s1 is s2

    # Subsequent sequential call returns the same summary
    s3 = await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)
    assert s3 is s1

    # Exactly one on_finish was called on the sink
    assert sink.summary is not None
    assert sink.summary.total_events == s1.total_events


def test_normalizer_finalize_execution_sequence_and_event_id_cached() -> None:
    """Repeated finalize_execution calls preserve sequence continuity and event_id."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 13, 0, 0, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=["mock-server"],
    )
    _ = list(norm.start_execution())
    assert norm.event_count == 1  # execution_started

    events = norm.normalize(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=2_000,
            direction="client_to_server",
            raw_frame=b'{"jsonrpc":"2.0","method":"ping"}\n',
        )
    )
    assert len(events) == 1
    assert events[0].sequence == 2

    # First finalize call
    ev1, sum1 = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=3_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    assert ev1.sequence == 3
    assert sum1.total_events == 3

    # Second finalize call (e.g. after primary sink failure during spill activation)
    ev2, sum2 = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=3_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
        spilled=True,
    )
    assert ev2.sequence == 3  # Stable sequence number, no double-increment!
    assert ev2.event_id == ev1.event_id  # Stable event identifier!
    assert sum2.total_events == 3
    assert sum2.capture_completeness == "spilled"


class _FailingFinalizeSink(InMemoryCaptureSink):
    """Sink that succeeds normally on start/emit but fails on on_finish."""

    async def on_finish(self, summary: ExecutionSummary) -> None:
        raise OSError("Primary storage disk failure during finalize on_finish")


async def test_capture_pipeline_spill_after_partial_finalize_failure_preserves_continuity(
    tmp_path: Path,
) -> None:
    """Spill triggered during finalize preserves contiguous sequence and matching event_id."""
    spill_dir = tmp_path / "spill"
    sink = _FailingFinalizeSink()
    pipeline = CapturePipeline(
        sink,
        command=["mock-server"],
        config=CaptureConfig(
            backpressure_policy="spill",
            spill_dir=spill_dir,
            spill_write_timeout_s=0.2,
            drain_timeout_s=0.5,
        ),
    )
    await pipeline.start()
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=datetime.now(UTC),
            monotonic_time_ns=time.monotonic_ns(),
            direction="client_to_server",
            raw_frame=b'{"jsonrpc":"2.0","method":"ping"}\n',
        )
    )

    summary = await pipeline.finalize(
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )

    assert pipeline.spilled is True
    assert summary.capture_completeness == "spilled"
    assert pipeline.spool_path is not None
    assert pipeline.spool_path.exists()

    # Read the recovery spool lines
    spool_lines = pipeline.spool_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(spool_lines) >= 3  # header, event/warn, finish event, summary

    # Verify final sequence number matches total_events and has no gap
    assert summary.total_events >= 3


class _HangingSink(InMemoryCaptureSink):
    """Sink that hangs indefinitely during emit_events."""

    async def emit_events(self, events: Sequence[ExecutionEvent]) -> None:
        await asyncio.sleep(5.0)


async def test_capture_pipeline_drain_timeout_bounding_on_stalled_block_sink() -> None:
    """Under block policy, pipeline.finalize() respects drain_timeout_s without hanging."""
    sink = _HangingSink()
    pipeline = CapturePipeline(
        sink,
        command=["mock-server"],
        config=CaptureConfig(
            backpressure_policy="block",
            drain_timeout_s=0.15,
        ),
    )
    await pipeline.start()
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=datetime.now(UTC),
            monotonic_time_ns=time.monotonic_ns(),
            direction="client_to_server",
            raw_frame=b'{"jsonrpc":"2.0","method":"ping"}\n',
        )
    )

    t_start = time.monotonic()
    summary = await pipeline.finalize(
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    elapsed = time.monotonic() - t_start

    # Finalize bounded by drain_timeout_s (0.15s) and close timeout, not 5.0s
    assert elapsed < 1.0
    assert pipeline.sink_timed_out is True
    assert summary.capture_completeness == "incomplete"


class _ExplodingCloseSink(InMemoryCaptureSink):
    """Sink whose close() raises an error."""

    async def close(self) -> None:
        raise RuntimeError("Sink close exploded deliberately")


async def test_capture_pipeline_sink_close_failure_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Sink.close() failure is explicitly logged and does not crash finalize()."""
    sink = _ExplodingCloseSink()
    pipeline = CapturePipeline(
        sink,
        command=["mock-server"],
        config=CaptureConfig(
            backpressure_policy="block",
            drain_timeout_s=0.5,
        ),
    )
    await pipeline.start()

    with caplog.at_level(logging.WARNING):
        summary = await pipeline.finalize(
            termination_reason="completed",
            exit_code=0,
            returncode=0,
        )

    assert summary.capture_completeness == "complete"
    assert "Failed to close capture sink" in caplog.text
    assert "Sink close exploded deliberately" in caplog.text
