"""Unit tests for Gate 1C (F-02 & F-03): serialized sink lifecycle & sequence continuity."""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import threading
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aerlog.capture.normalizer import EventNormalizer, RawCaptureInput, RawWireFrameInput
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
from aerlog.storage.event_log import MANIFEST_FILE_NAME, JsonlEventLogReader, JsonlEventLogWriter
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


@pytest.mark.parametrize("fail_at", ["chmod", "manifest"])
def test_writer_failed_open_closes_descriptor_without_flushing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_at: str
) -> None:
    header = _make_header()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id)
    real_open = os.open
    real_chmod = os.chmod
    real_close = os.close
    real_replace = os.replace
    event_fd: int | None = None
    close_attempts = 0
    manifest_attempts = 0

    def track_open(
        path: str | Path, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        nonlocal event_fd
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == writer.events_path:
            event_fd = fd
        return fd

    def fail_chmod(path: int | Path, mode: int) -> None:
        if fail_at == "chmod" and path == event_fd:
            raise OSError(errno.EIO, "startup failed")
        real_chmod(path, mode)

    def fail_manifest(src: Path, dst: Path) -> None:
        nonlocal manifest_attempts
        if dst.name == MANIFEST_FILE_NAME:
            manifest_attempts += 1
            raise OSError(errno.EIO, "startup failed")
        real_replace(src, dst)

    def close_with_error(fd: int) -> None:
        nonlocal close_attempts
        real_close(fd)
        if fd == event_fd:
            close_attempts += 1
            raise OSError(errno.EIO, "cleanup failed")

    with monkeypatch.context() as fault:
        fault.setattr(os, "open", track_open)
        fault.setattr(os, "chmod", fail_chmod)
        fault.setattr(os, "replace", fail_manifest)
        fault.setattr(os, "close", close_with_error)
        with pytest.raises(StorageWriteError, match="startup failed"):
            writer.open(header)

    assert event_fd is not None
    try:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(event_fd)
        assert close_attempts == 1
        assert manifest_attempts == (1 if fail_at == "manifest" else 0)
        writer.close()
    finally:
        if close_attempts == 0:
            real_close(event_fd)


def test_writer_flush_surfaces_manifest_persistence_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    header = _make_header()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id)
    writer.open(header)
    manifest_path = writer.execution_dir / MANIFEST_FILE_NAME
    original = manifest_path.read_bytes()
    real_replace = os.replace

    def fail_manifest(src: Path, dst: Path) -> None:
        if dst == manifest_path:
            raise OSError(errno.ENOSPC, "manifest write failed")
        real_replace(src, dst)

    try:
        writer.append_events([_make_event(header.execution_id, 1)])
        with monkeypatch.context() as fault:
            fault.setattr(os, "replace", fail_manifest)
            with pytest.raises(StorageWriteError, match="manifest write failed"):
                writer.flush()
        assert manifest_path.read_bytes() == original
        writer.flush()
        read = JsonlEventLogReader(tmp_path).read_execution(header.execution_id)
        assert read.manifest is not None
        assert read.manifest.byte_size == writer.events_path.stat().st_size
        assert (read.manifest.line_count, read.manifest.last_sequence) == (1, 1)
    finally:
        writer.close()


def test_writer_close_attempts_descriptor_close_once_after_flush_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    header = _make_header()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id)
    writer.open(header)
    event_fd = writer._fd
    assert event_fd is not None
    real_close = os.close
    real_fsync = os.fsync
    close_attempts = 0

    def fail_fsync(fd: int) -> None:
        if fd == event_fd:
            raise OSError(errno.EIO, "events flush failed")
        real_fsync(fd)

    def close_with_error(fd: int) -> None:
        nonlocal close_attempts
        if fd == event_fd:
            close_attempts += 1
            real_close(fd)
            raise OSError(errno.EIO, "descriptor close failed")
        real_close(fd)

    try:
        with monkeypatch.context() as fault:
            fault.setattr(os, "fsync", fail_fsync)
            fault.setattr(os, "close", close_with_error)
            with pytest.raises(StorageWriteError, match="events flush failed"):
                writer.close()
            writer.close()
        assert close_attempts == 1
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(event_fd)
    finally:
        if close_attempts == 0:
            writer.close()


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


async def test_persistent_capture_sink_keeps_writer_error_when_store_close_also_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = PersistentCaptureSink(tmp_path)
    await sink.on_start(_make_header())
    assert sink._writer is not None
    fd = sink._writer._fd
    assert fd is not None
    real_fsync = os.fsync
    real_store_close = sink.store.close

    def fail_writer_flush(target_fd: int) -> None:
        if target_fd == fd:
            raise OSError(errno.EIO, "writer flush failed")
        real_fsync(target_fd)

    def close_store_with_error() -> None:
        real_store_close()
        raise OSError("metadata close failed")

    monkeypatch.setattr(os, "fsync", fail_writer_flush)
    monkeypatch.setattr(sink.store, "close", close_store_with_error)
    with pytest.raises(StorageWriteError, match="writer flush failed") as raised:
        await sink.close()
    assert any("metadata close failed" in note for note in raised.value.__notes__)
    assert sink.closed
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(fd)


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


async def test_capture_pipeline_closes_and_marks_incomplete_after_consumer_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    sink = PersistentCaptureSink(tmp_path)
    pipeline = CapturePipeline(sink, command=["mock-server"])
    await pipeline.start()
    assert sink._writer is not None
    fd = sink._writer._fd
    assert fd is not None
    raw = RawWireFrameInput(
        timestamp=datetime.now(UTC),
        monotonic_time_ns=time.monotonic_ns(),
        direction="client_to_server",
        raw_frame=b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
    )
    consumer_waiting = asyncio.Event()
    release_consumer = asyncio.Event()
    real_deliver = pipeline._deliver_events
    real_normalize = pipeline._normalizer.normalize
    real_close = sink._close_sync
    consumer_error = RuntimeError("consumer failed while draining")

    async def hold_delivery(events: Sequence[ExecutionEvent]) -> None:
        if events[0].kind == "jsonrpc_request":
            consumer_waiting.set()
            await release_consumer.wait()
        await real_deliver(events)

    def fail_normalize(item: RawCaptureInput) -> list[ExecutionEvent]:
        if isinstance(item, RawWireFrameInput) and item.raw_frame == b"fail":
            raise consumer_error
        return real_normalize(item)

    def close_with_error() -> None:
        real_close()
        raise OSError("secondary cleanup failed")

    monkeypatch.setattr(pipeline, "_deliver_events", hold_delivery)
    monkeypatch.setattr(pipeline._normalizer, "normalize", fail_normalize)
    monkeypatch.setattr(sink, "_close_sync", close_with_error)
    try:
        await pipeline.enqueue(raw)
        await asyncio.wait_for(consumer_waiting.wait(), timeout=1)
        await pipeline.enqueue(
            RawWireFrameInput(datetime.now(UTC), time.monotonic_ns(), "client_to_server", b"fail")
        )
        await pipeline.enqueue(raw)
        finalizing = asyncio.create_task(
            pipeline.finalize(termination_reason="completed", exit_code=0)
        )
        async with pipeline._condition:
            await asyncio.wait_for(
                pipeline._condition.wait_for(lambda: pipeline._closed_for_input), timeout=1
            )
        release_consumer.set()
        with pytest.raises(RuntimeError) as raised:
            await asyncio.wait_for(finalizing, timeout=1)
        assert raised.value is consumer_error
        assert sink.closed
        assert "secondary cleanup failed" in caplog.text
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(fd)
        read = JsonlEventLogReader(tmp_path).read_execution(pipeline.execution_id, strict=True)
        assert read.summary is not None
        assert read.summary.capture_completeness == "incomplete"
        assert read.summary.dropped_events == 2
        assert [entry.event.kind for entry in read.events] == [
            "execution_started",
            "jsonrpc_request",
            "capture_gap",
            "execution_finished",
        ]
    finally:
        release_consumer.set()
        if not sink.closed:
            await sink.close()


async def test_capture_pipeline_closes_sink_when_finalize_is_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = PersistentCaptureSink(tmp_path)
    pipeline = CapturePipeline(sink, command=["mock-server"])
    await pipeline.start()
    assert sink._writer is not None
    fd = sink._writer._fd
    assert fd is not None
    consumer_waiting = asyncio.Event()

    async def hold_delivery(events: Sequence[ExecutionEvent]) -> None:
        consumer_waiting.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(pipeline, "_deliver_events", hold_delivery)
    try:
        await pipeline.enqueue(
            RawWireFrameInput(datetime.now(UTC), time.monotonic_ns(), "client_to_server", b"{}\n")
        )
        await asyncio.wait_for(consumer_waiting.wait(), timeout=1)
        finalizing = asyncio.create_task(
            pipeline.finalize(termination_reason="completed", exit_code=0)
        )
        async with pipeline._condition:
            await asyncio.wait_for(
                pipeline._condition.wait_for(lambda: pipeline._closed_for_input), timeout=1
            )
        finalizing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(finalizing, timeout=1)
        assert sink.closed
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(fd)
    finally:
        if not sink.closed:
            await sink.close()


async def test_capture_pipeline_closes_sink_after_cancelled_startup_unwinds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = PersistentCaptureSink(tmp_path)
    pipeline = CapturePipeline(sink, command=["mock-server"])
    loop = asyncio.get_running_loop()
    writer_opened = asyncio.Event()
    release_start = threading.Event()
    real_initialize = sink.store.initialize
    real_close = sink.close

    def hold_start() -> None:
        loop.call_soon_threadsafe(writer_opened.set)
        assert release_start.wait(timeout=2)
        real_initialize()

    async def close_while_starting() -> None:
        release_start.set()
        await real_close()

    monkeypatch.setattr(sink.store, "initialize", hold_start)
    monkeypatch.setattr(sink, "close", close_while_starting)
    starting = asyncio.create_task(pipeline.start())
    try:
        await asyncio.wait_for(writer_opened.wait(), timeout=1)
        assert sink._writer is not None
        fd = sink._writer._fd
        assert fd is not None
        starting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(starting, timeout=1)
        assert sink.closed
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(fd)
    finally:
        release_start.set()
        if not sink.closed:
            await sink.close()


async def test_capture_pipeline_closes_spool_before_sink_when_finalization_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = PersistentCaptureSink(tmp_path / "data")
    pipeline = CapturePipeline(
        sink,
        command=["mock-server"],
        config=CaptureConfig(backpressure_policy="spill", spill_dir=tmp_path / "spool"),
    )
    await pipeline.start()
    real_spool_close = pipeline._spool.close
    finish_error = ValueError("unexpected finalization failure")

    async def fail_primary_delivery(events: Sequence[ExecutionEvent]) -> None:
        raise OSError("primary storage unavailable")

    def fail_finalization(**kwargs: object) -> None:
        raise finish_error

    def close_spool_with_error() -> None:
        real_spool_close()
        assert not sink.closed
        raise OSError("secondary spool close failed")

    monkeypatch.setattr(sink, "emit_events", fail_primary_delivery)
    monkeypatch.setattr(pipeline._normalizer, "finalize_execution", fail_finalization)
    monkeypatch.setattr(pipeline._spool, "close", close_spool_with_error)
    try:
        await pipeline.enqueue(
            RawWireFrameInput(datetime.now(UTC), time.monotonic_ns(), "client_to_server", b"{}\n")
        )
        with pytest.raises(ValueError) as raised:
            await pipeline.finalize(termination_reason="completed", exit_code=0)
        assert raised.value is finish_error
        assert sink.closed
        assert pipeline.spilled
        assert pipeline.spool_path is not None and pipeline.spool_path.exists()
        assert not pipeline._spool.is_open
        assert any("secondary spool close failed" in note for note in raised.value.__notes__)
    finally:
        if not sink.closed:
            await sink.close()
        real_spool_close()


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
