"""Sync and restart checks on a running local Linux system."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn
from unittest.mock import patch

import pytest

from aerlog.capture import CaptureConfig, CapturePipeline, RawWireFrameInput, RecoverySpool
from aerlog.capture.normalizer import EventNormalizer
from aerlog.events import ExecutionEvent, ExecutionHeader, ExecutionSummary, new_execution_id
from aerlog.storage import event_log
from aerlog.storage.event_log import (
    EVENTS_FILE_NAME,
    EXECUTION_FILE_NAME,
    MANIFEST_FILE_NAME,
    FsyncPolicy,
    JsonlEventLogWriter,
    resolve_execution_dir,
)
from aerlog.storage.repositories import RecordingRepository
from aerlog.storage.sink import PersistentCaptureSink


def _recording(execution_id: str) -> tuple[ExecutionHeader, list[ExecutionEvent], ExecutionSummary]:
    started_at = datetime(2026, 11, 22, tzinfo=UTC)
    normalizer = EventNormalizer(
        execution_id=execution_id,
        command=("server",),
        started_at=started_at,
        monotonic_start_ns=100,
    )
    header = normalizer.build_header()
    events = normalizer.start_execution()
    terminal, summary = normalizer.finalize_execution(
        ended_at=started_at + timedelta(seconds=1),
        monotonic_end_ns=1_000_000_100,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    return header, [*events, terminal], summary


def _unexpected_sync(fd: int) -> NoReturn:
    pytest.fail(f"Unexpected sync of descriptor {fd}")


@pytest.mark.parametrize("policy", ["lifecycle", "every_batch", "none"])
def test_recording_sync_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy: FsyncPolicy
) -> None:
    execution_id = new_execution_id()
    header, events, summary = _recording(execution_id)
    writer = JsonlEventLogWriter(tmp_path, execution_id, fsync_policy=policy)
    synced: list[str] = []
    real_fsync = os.fsync
    metadata = "execution metadata temporary file"
    manifest = "manifest temporary file"

    def observe_fsync(fd: int) -> None:
        name = Path(os.readlink(f"/proc/self/fd/{fd}")).name
        if name.startswith(f".{EXECUTION_FILE_NAME}.") and name.endswith(".tmp"):
            name = metadata
        elif name.startswith(f".{MANIFEST_FILE_NAME}.") and name.endswith(".tmp"):
            name = manifest
        synced.append(name)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", observe_fsync)
    monkeypatch.setattr(os, "fdatasync", _unexpected_sync)
    try:
        writer.open(header)
        assert synced == ([metadata, manifest] if policy != "none" else [])
        synced.clear()

        assert writer.append_events([]) == ()
        assert synced == []
        for event in events:
            writer.append_events([event])
            assert synced == ([EVENTS_FILE_NAME] if policy == "every_batch" else [])
            synced.clear()

        writer.flush()
        assert synced == ([EVENTS_FILE_NAME, manifest] if policy != "none" else [])
        synced.clear()

        writer.finalize(summary)
        assert synced == ([EVENTS_FILE_NAME, metadata, manifest] if policy != "none" else [])
        synced.clear()

        writer.close()
        assert synced == ([EVENTS_FILE_NAME, manifest] if policy != "none" else [])
    finally:
        writer.close()


def test_spool_flushes_complete_lines_without_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    header, events, summary = _recording(new_execution_id())
    spool = RecoverySpool(tmp_path / "recovery.spool")
    monkeypatch.setattr(os, "fsync", _unexpected_sync)
    monkeypatch.setattr(os, "fdatasync", _unexpected_sync)
    try:
        spool.write_header(header)
        spool.write_events(events)
        spool.write_summary(summary)
        records = [json.loads(line) for line in spool.path.read_bytes().splitlines()]
        assert [record["record_type"] for record in records] == [
            "header",
            "event",
            "event",
            "summary",
        ]
        assert [record["data"]["event_id"] for record in records[1:3]] == [
            event.event_id for event in events
        ]
        spool.flush()
    finally:
        spool.close()


def _kill_at(checkpoint: str) -> NoReturn:
    print(checkpoint, flush=True)
    os.kill(os.getpid(), signal.SIGKILL)
    raise AssertionError("SIGKILL did not terminate child")


async def _write_until_killed(data_dir: Path, spool_path: Path, eid: str, checkpoint: str) -> None:
    sink = PersistentCaptureSink(data_dir)
    if checkpoint == "queue":
        pipeline = CapturePipeline(
            sink, command=("server",), execution_id=eid, config=CaptureConfig(spill_dir=data_dir)
        )
        await pipeline.start()
        await pipeline.enqueue(
            RawWireFrameInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=1_000_000_000_000_000_000,
                direction="client_to_server",
                raw_frame=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n',
            )
        )
        # No yield between appending to the queue and killing this process.
        _kill_at(checkpoint)

    header, events, summary = _recording(eid)
    finalizing = checkpoint in {"summary", "manifest", "spool", "complete-index"}
    written_events = events if finalizing else events[:1]
    spool = RecoverySpool(spool_path)
    spool.write_header(header)
    spool.write_events(written_events)
    if finalizing:
        spool.write_summary(summary)
    if checkpoint == "spool":
        _kill_at(checkpoint)
    spool.close()

    await sink.on_start(header)
    if checkpoint == "append":
        # The sink invokes indexing only after the real log append returned.
        with patch.object(
            sink.store, "insert_event_slices", side_effect=lambda *_: _kill_at(checkpoint)
        ):
            await sink.emit_events(written_events)
    if checkpoint == "sqlite-before-commit":
        conn = sink.store._conn
        assert conn is not None

        def on_statement(sql: str) -> None:
            if sql == "COMMIT":
                _kill_at(checkpoint)

        conn.set_trace_callback(on_statement)
    await sink.emit_events(written_events)
    if checkpoint == "sqlite-after-commit":
        _kill_at(checkpoint)

    write_metadata = event_log.write_atomic_private_json
    target = EXECUTION_FILE_NAME if checkpoint == "summary" else MANIFEST_FILE_NAME

    def write_then_kill(path: Path, payload: dict[str, Any], *, fsync: bool) -> None:
        write_metadata(path, payload, fsync=fsync)
        if path.name == target:
            _kill_at(checkpoint)

    if checkpoint in {"summary", "manifest"}:
        with patch.object(event_log, "write_atomic_private_json", write_then_kill):
            await sink.on_finish(summary)
    if checkpoint == "complete-index":
        await sink.on_finish(summary)
        _kill_at(checkpoint)
    raise AssertionError(f"Did not reach {checkpoint} checkpoint")


def _kill_writer(tmp_path: Path, eid: str, checkpoint: str) -> tuple[Path, Path]:
    data_dir = tmp_path / "data"
    spool_path = tmp_path / "recovery.spool"
    result = subprocess.run(
        [sys.executable, __file__, str(data_dir), str(spool_path), eid, checkpoint],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert (result.returncode, result.stdout.strip()) == (-signal.SIGKILL, checkpoint), (
        result.stderr
    )
    return data_dir, spool_path


@pytest.mark.parametrize(
    ("checkpoint", "file_events", "index_events", "manifest_status", "summary_written"),
    [
        ("queue", 1, 1, "recording", False),
        ("append", 1, 0, "recording", False),
        ("sqlite-before-commit", 1, 0, "recording", False),
        ("sqlite-after-commit", 1, 1, "recording", False),
        ("summary", 2, 2, "recording", True),
        ("manifest", 2, 2, "finalized", True),
    ],
)
def test_process_death_recovers_verified_events(
    tmp_path: Path,
    checkpoint: str,
    file_events: int,
    index_events: int,
    manifest_status: str,
    summary_written: bool,
) -> None:
    eid = new_execution_id()
    data_dir, spool_path = _kill_writer(tmp_path, eid, checkpoint)
    repo = RecordingRepository(data_dir)
    try:
        read = repo.get_execution_events(eid, strict_integrity=True)
        ids = [item.event.event_id for item in read.events]
        assert [item.event.sequence for item in read.events] == list(range(1, file_events + 1))
        assert read.events[0].event.kind == "execution_started"
        assert (read.summary is not None) == summary_written
        assert read.manifest is not None and read.manifest.status == manifest_status
        assert read.unclean_shutdown == (manifest_status == "recording")
        assert len(repo.store.query_event_index(execution_id=eid)) == index_events
        before = repo.store.get_execution_row(eid)
        assert before is not None and before.capture_completeness == "recording"
        assert (before.last_indexed_sequence, before.total_events) == (index_events, index_events)

        path = resolve_execution_dir(data_dir, eid) / EVENTS_FILE_NAME
        original_bytes = path.read_bytes()
        assert repo.reconcile_execution(eid) == read
        expected = "complete" if manifest_status == "finalized" else "incomplete"
        after = repo.store.get_execution_row(eid)
        assert after is not None and after.capture_completeness == expected
        assert [event.event_id for event in repo.query_events(execution_id=eid).events] == ids

        if checkpoint != "queue":
            # The summary checkpoint has enough evidence to finish metadata on exact retry.
            report = repo.import_recovery_spool(spool_path)
            assert report.imported_events == 0 and report.skipped_duplicates == file_events
            assert report.final_status == ("complete" if summary_written else "incomplete")
            assert repo.import_recovery_spool(spool_path) == report
        else:
            assert repo.reconcile_execution(eid) == read
        assert path.read_bytes() == original_bytes
        assert [event.event_id for event in repo.query_events(execution_id=eid).events] == ids
    finally:
        repo.close()


def test_process_death_after_spool_flush_leaves_importable_records(tmp_path: Path) -> None:
    eid = new_execution_id()
    data_dir, spool_path = _kill_writer(tmp_path, eid, "spool")
    repo = RecordingRepository(data_dir)
    try:
        first = repo.import_recovery_spool(spool_path)
        assert first.imported_events == 2 and first.final_status == "complete"
        path = resolve_execution_dir(data_dir, eid) / EVENTS_FILE_NAME
        original_bytes = path.read_bytes()

        retry = repo.import_recovery_spool(spool_path)
        assert retry.imported_events == 0 and retry.skipped_duplicates == 2
        assert retry.final_status == "complete"
        assert path.read_bytes() == original_bytes

        read = repo.get_execution_events(eid, strict_integrity=True)
        assert [item.event.kind for item in read.events] == [
            "execution_started",
            "execution_finished",
        ]
    finally:
        repo.close()


def test_committed_index_cannot_supply_missing_recording_bytes(tmp_path: Path) -> None:
    eid = new_execution_id()
    data_dir, _ = _kill_writer(tmp_path, eid, "complete-index")
    repo = RecordingRepository(data_dir)
    try:
        before = repo.store.get_execution_row(eid)
        assert before is not None and before.capture_completeness == "complete"

        # Model unavailable file bytes separately from death of a process on the running OS.
        (resolve_execution_dir(data_dir, eid) / EVENTS_FILE_NAME).unlink()
        result = repo.query_events(execution_id=eid)
        assert result.events == ()
        assert result.missing_jsonl_execution_ids == (eid,)

        read = repo.reconcile_execution(eid)
        assert read is not None and read.events == ()
        after = repo.store.get_execution_row(eid)
        assert after is not None and after.capture_completeness == "corrupted"
        assert repo.store.query_event_index(execution_id=eid) == ()
    finally:
        repo.close()


if __name__ == "__main__":
    asyncio.run(_write_until_killed(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]))
