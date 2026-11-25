"""Recovery import keeps complete destination logs out of memory."""

from __future__ import annotations

import asyncio
import json
import tempfile
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aerlog.events import ExecutionEvent, ExecutionHeader, JsonRpcRequestPayload, new_execution_id
from aerlog.storage import EVENTS_FILE_NAME, JsonlEventLogWriter, RecordingRepository
from aerlog.storage.event_log import WrittenEventSlice
from aerlog.storage.exceptions import StorageCorruptionError, StorageDiskFullError
from aerlog.storage.repositories import _derive_execution_row_from_jsonl


def _prepare_recording(path: Path, *, retained_count: int, incoming_count: int) -> tuple[str, Path]:
    execution_id = new_execution_id()
    timestamp = datetime(2026, 11, 20, tzinfo=UTC)
    header = ExecutionHeader(
        execution_id=execution_id,
        started_at=timestamp,
        monotonic_start_ns=1,
        command=("fixture",),
    )
    events = [
        ExecutionEvent(
            execution_id=execution_id,
            sequence=sequence,
            timestamp=timestamp,
            monotonic_time_ns=sequence,
            direction="client_to_server",
            kind="jsonrpc_request",
            payload=JsonRpcRequestPayload(
                id=sequence, id_type="int", method="fixtures/echo", has_params=False
            ),
        )
        for sequence in range(1, incoming_count + 1)
    ]
    writer = JsonlEventLogWriter(path, execution_id, fsync_policy="none")
    writer.open(header)
    writer.append_events(events[:retained_count])
    writer.close()
    spool_path = path / "spool.ndjson"
    spool_path.write_text(
        "".join(
            json.dumps({"record_type": "event", "data": event.model_dump(mode="json")}) + "\n"
            for event in reversed(events)
        ),
        encoding="utf-8",
    )
    spool_path.chmod(0o600)
    return execution_id, spool_path


@pytest.mark.parametrize("with_suffix", [False, True])
def test_recovery_import_streams_existing_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, with_suffix: bool
) -> None:
    execution_id, spool_path = _prepare_recording(
        tmp_path, retained_count=2, incoming_count=2 + int(with_suffix)
    )
    original = Path.read_bytes

    def read_bytes(path: Path) -> bytes:
        assert path.name != EVENTS_FILE_NAME, "Recovery loaded the complete destination log"
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    repo = RecordingRepository(tmp_path)
    try:
        result = repo.import_recovery_spool(spool_path, fsync_policy="none")
        read = repo.get_execution_events(execution_id)
        assert result.skipped_duplicates == 2
        assert not result.corrupt_lines
        assert result.imported_events == int(with_suffix)
        assert result.final_status == "incomplete"
        assert [item.event.sequence for item in read.events] == list(range(1, 3 + int(with_suffix)))
        assert not read.corruptions
        indexed = sorted(
            repo.store.query_event_index(execution_id=execution_id), key=lambda row: row.sequence
        )
        assert [(item.byte_offset, item.byte_length) for item in read.events] == [
            (row.jsonl_byte_offset, row.jsonl_byte_length) for row in indexed
        ]
    finally:
        repo.close()


@pytest.mark.parametrize(
    "failure", [StorageDiskFullError("fixture ENOSPC"), asyncio.CancelledError()]
)
def test_recovery_cleans_scratch_and_retries_an_interrupted_suffix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    execution_id, spool_path = _prepare_recording(tmp_path, retained_count=2, incoming_count=572)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    append = JsonlEventLogWriter.append_events
    committed_batch_size = 0

    def interrupt_next_batch(
        writer: JsonlEventLogWriter, events: Sequence[ExecutionEvent]
    ) -> tuple[WrittenEventSlice, ...]:
        nonlocal committed_batch_size
        if committed_batch_size:
            raise failure
        artifacts = tuple(scratch.glob("aerlog-recovery-*/stage.sqlite3"))
        assert len(artifacts) == 1
        assert artifacts[0].stat().st_mode & 0o777 == 0o600
        assert artifacts[0].parent.stat().st_mode & 0o777 == 0o700
        committed_batch_size = len(events)
        return append(writer, events)

    repo = RecordingRepository(tmp_path)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(JsonlEventLogWriter, "append_events", interrupt_next_batch)
            with pytest.raises(type(failure)):
                repo.import_recovery_spool(spool_path, fsync_policy="none")
        assert 0 < committed_batch_size < 570
        assert not tuple(scratch.iterdir())
        report = repo.import_recovery_spool(spool_path, fsync_policy="none")
        assert report.skipped_duplicates == 2 + committed_batch_size
        assert report.imported_events == 570 - committed_batch_size
        assert not report.corrupt_lines
        assert not tuple(scratch.iterdir())
        read = repo.get_execution_events(execution_id)
        assert len(read.events) == 572
        assert not read.corruptions
    finally:
        repo.close()


def test_reject_cleans_scratch_without_changing_recording(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution_id, spool_path = _prepare_recording(tmp_path, retained_count=2, incoming_count=2)
    raw = spool_path.read_text(encoding="utf-8").splitlines()
    conflict = json.loads(raw[0])
    conflict["data"]["event_id"] = "another-event-id"
    spool_path.write_text("\n".join((*raw, json.dumps(conflict))) + "\n", encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    repo = RecordingRepository(tmp_path)
    try:
        before = repo.get_execution_events(execution_id)
        with pytest.raises(StorageCorruptionError, match="Duplicate sequence"):
            repo.import_recovery_spool(spool_path, fsync_policy="none", tail_policy="reject")
        assert repo.get_execution_events(execution_id) == before
        assert not tuple(scratch.iterdir())
        assert not repo.store.db_path.exists()
    finally:
        repo.close()


def test_index_replacement_rolls_back_if_slice_iteration_is_interrupted(tmp_path: Path) -> None:
    execution_id, _ = _prepare_recording(tmp_path, retained_count=2, incoming_count=2)
    repo = RecordingRepository(tmp_path)
    try:
        read = repo.reconcile_execution(execution_id)
        assert read is not None
        previous = repo.store.query_event_index(execution_id=execution_id)

        def interrupted() -> Iterator[WrittenEventSlice]:
            item = read.events[0]
            yield WrittenEventSlice(item.event, item.byte_offset, item.byte_length)
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            repo.store.replace_execution_index(
                execution_row=_derive_execution_row_from_jsonl(read_result=read, persist_cwd=False),
                slices=interrupted(),
                corruptions=(),
            )
        assert repo.store.query_event_index(execution_id=execution_id) == previous
    finally:
        repo.close()
