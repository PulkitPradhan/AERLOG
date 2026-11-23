"""Faults at the boundary between event serialization and persistent evidence."""

from __future__ import annotations

import asyncio
import errno
import json
import os
import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aerlog.capture.normalizer import EventNormalizer
from aerlog.capture.pipeline import CaptureConfig, CapturePipeline
from aerlog.events import new_execution_id
from aerlog.events.models import ExecutionEvent, ExecutionHeader, ExecutionSummary
from aerlog.storage import JsonlEventLogReader, JsonlEventLogWriter, RecordingRepository
from aerlog.storage.exceptions import StorageDiskFullError, StorageWriteError
from aerlog.storage.sink import PersistentCaptureSink


def recording() -> tuple[ExecutionHeader, list[ExecutionEvent], ExecutionSummary]:
    now = datetime.now(UTC)
    normalizer = EventNormalizer(
        execution_id=new_execution_id(), started_at=now, monotonic_start_ns=1, command=["server"]
    )
    started = normalizer.start_execution()
    finished, summary = normalizer.finalize_execution(
        ended_at=now, monotonic_end_ns=2, termination_reason="completed", exit_code=0
    )
    return normalizer.build_header(), [*started, finished], summary


def test_interrupted_short_writes_preserve_slices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    header, events, _ = recording()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id, fsync_policy="none")
    writer.open(header)
    real_write = os.write
    interrupted = False

    def write(fd: int, data: memoryview) -> int:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise InterruptedError(errno.EINTR, "signal")
        return real_write(fd, data[:11])

    try:
        with monkeypatch.context() as fault:
            fault.setattr(os, "write", write)
            slices = writer.append_events(events)
        lines = writer.events_path.read_bytes().splitlines(keepends=True)
        assert isinstance(slices, tuple)
        assert [(item.byte_offset, item.byte_length) for item in slices] == [
            (0, len(lines[0])),
            (len(lines[0]), len(lines[1])),
        ]
        assert [json.loads(line)["event"]["event_id"] for line in lines] == [
            event.event_id for event in events
        ]
    finally:
        writer.close()


def test_zero_progress_keeps_same_writer_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    header, events, _ = recording()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id)
    writer.open(header)
    try:
        with monkeypatch.context() as fault:
            fault.setattr(os, "write", lambda fd, data: 0)
            with pytest.raises(StorageWriteError) as failed:
                writer.append_events(events)
        assert (writer.line_count, writer.last_sequence, writer.byte_offset) == (0, 0, 0)
        assert failed.value.append_outcome is not None
        assert failed.value.append_outcome.accepted_bytes == 0
        assert failed.value.append_outcome.complete_slices == ()
        assert not failed.value.append_outcome.requires_verification
        assert len(writer.append_events(events)) == 2
        assert writer.line_count == 2
    finally:
        writer.close()


@pytest.mark.parametrize("fault_point", ["partial", "fsync"])
def test_changed_log_blocks_mutation_until_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_point: str
) -> None:
    header, events, summary = recording()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id, fsync_policy="every_batch")
    writer.open(header)
    manifest_path = writer.execution_dir / "manifest.json"
    manifest = manifest_path.read_bytes()
    real_write = os.write
    accepted = 0

    def partial(fd: int, data: memoryview) -> int:
        nonlocal accepted
        if accepted:
            raise OSError(errno.ENOSPC, "disk full")
        accepted = real_write(fd, data[: bytes(data).index(b"\n") + 5])
        return accepted

    def fail_sync(fd: int) -> None:
        raise OSError(errno.EIO, "writeback failed")

    try:
        with monkeypatch.context() as fault:
            if fault_point == "partial":
                fault.setattr(os, "write", partial)
            else:
                fault.setattr(os, "fsync", fail_sync)
            with pytest.raises(
                StorageDiskFullError if fault_point == "partial" else StorageWriteError
            ) as failed:
                writer.append_events(events)
        evidence = writer.events_path.read_bytes()
        complete_count = 1 if fault_point == "partial" else 2
        assert evidence.count(b"\n") == complete_count
        assert (writer.line_count, writer.last_sequence) == (complete_count, complete_count)
        outcome = failed.value.append_outcome
        assert outcome is not None
        assert outcome.accepted_bytes == len(evidence)
        assert outcome.requires_verification
        assert outcome.sync_failed == (fault_point == "fsync")
        assert [s.event.event_id for s in outcome.complete_slices] == [
            ev.event_id for ev in events[:complete_count]
        ]
        for operation in (
            lambda: writer.append_events(events),
            lambda: writer.append_tail_fragment(b"\n"),
            writer.flush,
            lambda: writer.finalize(summary),
        ):
            with pytest.raises(StorageWriteError):
                operation()
        assert writer.events_path.read_bytes() == evidence
    finally:
        writer.close()
    assert manifest_path.read_bytes() == manifest
    with pytest.raises(StorageWriteError):
        writer.open(header)


@pytest.mark.parametrize("failure", ["emit_timeout", "finish", "flush"])
async def test_terminal_spill_imports_same_record_after_late_primary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    data = tmp_path / "data"
    sink = PersistentCaptureSink(data)
    pipeline = CapturePipeline(
        sink,
        command=["server"],
        config=CaptureConfig(
            backpressure_policy="spill",
            spill_dir=tmp_path / "spool",
            spill_write_timeout_s=0.05,
            drain_timeout_s=2,
        ),
    )
    await pipeline.start()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    spool_written = asyncio.Event()
    real_spool_summary = pipeline._spool.write_summary

    def signal_spool(summary: ExecutionSummary) -> None:
        real_spool_summary(summary)
        loop.call_soon_threadsafe(spool_written.set)

    monkeypatch.setattr(pipeline._spool, "write_summary", signal_spool)
    real_emit = sink._emit_events_sync

    def late_emit(events: Sequence[ExecutionEvent]) -> None:
        if events[-1].kind == "execution_finished":
            assert release.wait(5)
        real_emit(events)

    async def fail(*args: object) -> None:
        raise OSError(errno.EIO, "terminal operation failed")

    if failure == "emit_timeout":
        monkeypatch.setattr(sink, "_emit_events_sync", late_emit)
    else:
        monkeypatch.setattr(sink, "on_finish" if failure == "finish" else "flush", fail)
    task = asyncio.create_task(pipeline.finalize(termination_reason="completed", exit_code=0))
    try:
        await asyncio.wait_for(spool_written.wait(), 3)
    finally:
        release.set()
        result = await task

    assert pipeline.spilled
    assert pipeline.spool_path is not None
    repo = RecordingRepository(data)
    try:
        first = repo.import_recovery_spool(pipeline.spool_path, tail_policy="reject")
        again = repo.import_recovery_spool(pipeline.spool_path, tail_policy="reject")
    finally:
        repo.close()
    assert first.imported_events == again.imported_events == 0
    log = JsonlEventLogReader(data).read_execution(result.execution_id, strict=True)
    assert [item.event.kind for item in log.events] == ["execution_started", "execution_finished"]
    assert log.summary is not None and log.summary.total_events == 2


def test_partial_fragment_preserves_bytes_for_verified_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    header, events, _ = recording()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id)
    writer.open(header)
    writer.append_events(events)
    writer.close()
    full = writer.events_path.read_bytes()
    boundary = full.index(b"\n") + 1
    prefix = full[: boundary + 12]
    writer.events_path.write_bytes(prefix)
    recovering = JsonlEventLogWriter(
        tmp_path, header.execution_id, seed_line_count=1, seed_last_sequence=1
    )
    recovering.open(header)
    real_write = os.write
    calls = 0

    def partial(fd: int, data: memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(fd, data[:5])
        raise OSError(errno.ENOSPC, "disk full")

    try:
        with monkeypatch.context() as fault:
            fault.setattr(os, "write", partial)
            with pytest.raises(StorageDiskFullError) as failed:
                recovering.append_tail_fragment(full[len(prefix) :])
        assert recovering.events_path.read_bytes() == full[: len(prefix) + 5]
        outcome = failed.value.append_outcome
        assert outcome is not None
        assert (outcome.accepted_bytes, outcome.complete_slices) == (5, ())
        assert outcome.requires_verification
        with pytest.raises(StorageWriteError):
            recovering.append_events(events[1:])
    finally:
        recovering.close()

    reopened = JsonlEventLogWriter(
        tmp_path, header.execution_id, seed_line_count=1, seed_last_sequence=1
    )
    reopened.open(header)
    try:
        (recovered,) = reopened.append_events(events[1:])
        assert (recovered.byte_offset, recovered.byte_length) == (boundary, len(full) - boundary)
        assert reopened.line_count == 2
    finally:
        reopened.close()
    assert reopened.events_path.read_bytes() == full


def test_cold_writer_reconstructs_counters_from_complete_prefix(tmp_path: Path) -> None:
    header, events, _ = recording()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id)
    writer.open(header)
    manifest_path = writer.execution_dir / "manifest.json"
    before_append = manifest_path.read_bytes()
    writer.append_events(events[:1])
    writer.close()
    # State left by a writer which closed its descriptor after failed sync.
    manifest_path.write_bytes(before_append)
    reopened = JsonlEventLogWriter(tmp_path, header.execution_id)
    reopened.open(header)
    try:
        assert (reopened.line_count, reopened.last_sequence) == (1, 1)
        reopened.append_events(events[1:])
        assert (reopened.line_count, reopened.last_sequence) == (2, 2)
    finally:
        reopened.close()


def test_quarantine_short_write_preserves_whole_tail_before_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    header, events, _ = recording()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id)
    writer.open(header)
    writer.append_events(events[:1])
    writer.close()
    damaged = b"unrecoverable trailing data"
    with writer.events_path.open("ab") as stream:
        stream.write(damaged)
    reopened = JsonlEventLogWriter(tmp_path, header.execution_id)
    reopened.open(header)
    real_write = os.write

    def short(fd: int, data: memoryview) -> int:
        return real_write(fd, data[:7])

    try:
        with monkeypatch.context() as fault:
            fault.setattr(os, "write", short)
            reopened.append_events(events[1:])
        (quarantine,) = reopened.execution_dir.glob("*.quarantine")
        assert quarantine.read_bytes() == damaged
    finally:
        reopened.close()


def test_valid_record_without_newline_survives_mismatching_append(tmp_path: Path) -> None:
    from aerlog.storage import StorageCorruptionError

    header, events, _ = recording()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id)
    writer.open(header)
    writer.append_events(events[:1])
    writer.close()
    intact_record = writer.events_path.read_bytes().removesuffix(b"\n")
    writer.events_path.write_bytes(intact_record)
    reopened = JsonlEventLogWriter(tmp_path, header.execution_id)
    reopened.open(header)
    try:
        with pytest.raises(StorageCorruptionError):
            reopened.append_events(events[1:])
        assert reopened.events_path.read_bytes() == intact_record
    finally:
        reopened.close()


def test_failed_seek_after_quarantine_blocks_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    header, events, summary = recording()
    writer = JsonlEventLogWriter(tmp_path, header.execution_id)
    writer.open(header)
    writer.append_events(events[:1])
    writer.close()
    prefix = writer.events_path.read_bytes()
    writer.events_path.write_bytes(prefix + b"broken tail")
    reopened = JsonlEventLogWriter(tmp_path, header.execution_id)
    reopened.open(header)

    def fail_seek(fd: int, offset: int, whence: int) -> int:
        raise OSError(errno.EIO, "seek failed")

    try:
        with monkeypatch.context() as fault:
            fault.setattr(os, "lseek", fail_seek)
            with pytest.raises(StorageWriteError) as failure:
                reopened.append_events(events[1:])
        assert failure.value.append_outcome is not None
        assert failure.value.append_outcome.accepted_bytes == 0
        assert failure.value.append_outcome.requires_verification
        with pytest.raises(StorageWriteError):
            reopened.finalize(summary)
        assert reopened.events_path.read_bytes() == prefix
    finally:
        reopened.close()
