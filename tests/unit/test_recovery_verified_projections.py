"""Regression coverage for exact retries against retained and derived evidence."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aerlog.capture.normalizer import EventNormalizer
from aerlog.capture.sinks import RecoverySpool
from aerlog.events import new_execution_id
from aerlog.events.models import ExecutionHeader
from aerlog.events.types import CaptureCompleteness
from aerlog.storage import JsonlEventLogWriter, RecordingRepository, StorageWriteError
from aerlog.storage.event_log import TailPolicy


@pytest.fixture
def repository(tmp_path: Path) -> Iterator[RecordingRepository]:
    repo = RecordingRepository(tmp_path / "recordings")
    try:
        yield repo
    finally:
        repo.close()


def _record_and_spool(
    repository: RecordingRepository,
    spool_path: Path,
    *,
    terminal_spilled: bool = False,
    summary_status: CaptureCompleteness = "complete",
) -> tuple[JsonlEventLogWriter, str]:
    execution_id = new_execution_id()
    timestamp = datetime(2026, 11, 22, tzinfo=UTC)
    command = ("fixture-server", "--check")
    normalizer = EventNormalizer(
        execution_id=execution_id,
        started_at=timestamp,
        monotonic_start_ns=10,
        command=command,
    )
    start = normalizer.start_execution()
    finished, summary = normalizer.finalize_execution(
        ended_at=timestamp + timedelta(seconds=1),
        monotonic_end_ns=1_000_000_010,
        termination_reason="clean_exit",
        exit_code=0,
        spilled=terminal_spilled,
    )
    events = [*start, finished]
    writer = JsonlEventLogWriter(repository.data_dir, execution_id)
    writer.open(
        ExecutionHeader(
            execution_id=execution_id, started_at=timestamp, monotonic_start_ns=10, command=command
        )
    )
    try:
        writer.append_events(events)
        writer.finalize(summary.model_copy(update={"capture_completeness": summary_status}))
    finally:
        writer.close()
    spool = RecoverySpool(spool_path)
    try:
        spool.write_events(events)
    finally:
        spool.close()
    return writer, execution_id


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
@pytest.mark.parametrize(
    ("terminal_spilled", "summary_status", "expected"),
    [
        (False, "spilled", "incomplete"),
        (False, "degraded", "incomplete"),
        (True, "spilled", "spilled"),
    ],
)
def test_exact_retry_checks_retained_completion_against_terminal(
    tmp_path: Path,
    repository: RecordingRepository,
    policy: TailPolicy,
    terminal_spilled: bool,
    summary_status: CaptureCompleteness,
    expected: CaptureCompleteness,
) -> None:
    spool = tmp_path / "events.spool"
    writer, execution_id = _record_and_spool(
        repository, spool, terminal_spilled=terminal_spilled, summary_status=summary_status
    )
    before = {path: path.read_bytes() for path in writer.execution_dir.iterdir()}

    retry = repository.import_recovery_spool(spool, tail_policy=policy)

    assert (retry.imported_events, retry.skipped_duplicates, retry.final_status) == (0, 2, expected)
    row = repository.store.get_execution_row(execution_id)
    assert row is not None and row.capture_completeness == expected
    assert {path: path.read_bytes() for path in writer.execution_dir.iterdir()} == before


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_exact_retry_removes_stale_index_corruption_reports(
    tmp_path: Path, repository: RecordingRepository, policy: TailPolicy
) -> None:
    spool = tmp_path / "events.spool"
    writer, execution_id = _record_and_spool(repository, spool)
    before = {path: path.read_bytes() for path in writer.execution_dir.iterdir()}
    repository.reconcile_execution(execution_id)
    events = repository.store.query_event_index(execution_id=execution_id)
    with closing(sqlite3.connect(repository.store.db_path)) as conn, conn:
        conn.execute(
            """
            INSERT INTO execution_corruptions (
                execution_id, line_number, byte_offset, byte_length, issue_kind,
                excerpt_sha256, details, detected_at
            ) VALUES (?, 1, 0, 1, 'invalid_json', '', 'stale report', '2026-11-22T00:00:00Z')
            """,
            (execution_id,),
        )
        conn.execute(
            """
            CREATE TRIGGER fail_corruption_repair BEFORE DELETE ON execution_corruptions
            BEGIN
                SELECT RAISE(ABORT, 'interrupted index repair');
            END
            """
        )
    assert len(repository.get_execution(execution_id).corruptions) == 1
    assert repository.get_execution_events(execution_id).corruptions == ()

    with pytest.raises(StorageWriteError, match="interrupted index repair"):
        repository.import_recovery_spool(spool, tail_policy=policy)
    assert repository.store.query_event_index(execution_id=execution_id) == events
    assert len(repository.get_execution(execution_id).corruptions) == 1

    with closing(sqlite3.connect(repository.store.db_path)) as conn, conn:
        conn.execute("DROP TRIGGER fail_corruption_repair")
    for _ in range(2):
        retry = repository.import_recovery_spool(spool, tail_policy=policy)
        assert (retry.imported_events, retry.skipped_duplicates, retry.final_status) == (
            0,
            2,
            "complete",
        )
        assert repository.get_execution(execution_id).corruptions == ()
        assert repository.store.query_event_index(execution_id=execution_id) == events
    assert {path: path.read_bytes() for path in writer.execution_dir.iterdir()} == before


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_exact_retry_rebuilds_deeply_nested_index_json(
    tmp_path: Path, repository: RecordingRepository, policy: TailPolicy
) -> None:
    spool = tmp_path / "events.spool"
    writer, execution_id = _record_and_spool(repository, spool)
    before = {path: path.read_bytes() for path in writer.execution_dir.iterdir()}
    repository.reconcile_execution(execution_id)
    expected = repository.store.get_execution_row(execution_id)
    assert expected is not None
    deeply_nested = "[" * 10_000 + "]" * 10_000
    with closing(sqlite3.connect(repository.store.db_path)) as conn, conn:
        conn.execute(
            "UPDATE executions SET command_json = ? WHERE execution_id = ?",
            (deeply_nested, execution_id),
        )

    retry = repository.import_recovery_spool(spool, tail_policy=policy)

    assert (retry.imported_events, retry.skipped_duplicates, retry.final_status) == (
        0,
        2,
        "complete",
    )
    assert repository.store.get_execution_row(execution_id) == expected
    assert {path: path.read_bytes() for path in writer.execution_dir.iterdir()} == before
