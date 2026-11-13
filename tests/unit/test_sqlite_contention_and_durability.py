"""Unit and concurrency tests for Gate 1F: SQLite cold-start reliability & JSONL durability."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from aerlog.events.ids import new_event_id, new_execution_id
from aerlog.events.models import (
    ExecutionEvent,
    ExecutionFinishedPayload,
    ExecutionHeader,
    ExecutionSummary,
    JsonRpcRequestPayload,
    RedactionSummary,
    WireFrameInfo,
)
from aerlog.storage.database import (
    DB_FILE_NAME,
    SQLiteMetadataStore,
    _is_transient_sqlite_lock_error,
)
from aerlog.storage.event_log import JsonlEventLogReader, JsonlEventLogWriter
from aerlog.storage.exceptions import (
    StorageCorruptionError,
    StorageDiskFullError,
    StorageWriteError,
    UnsupportedSchemaVersionError,
)
from aerlog.storage.repositories import RecordingRepository
from aerlog.storage.sink import PersistentCaptureSink, _is_sqlite_metadata_error

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PYTHON = sys.executable


def _make_header(exec_id: str | None = None) -> ExecutionHeader:
    eid = new_execution_id() if exec_id is None else exec_id
    t0 = datetime(2026, 11, 14, 0, 0, 0, tzinfo=UTC)
    return ExecutionHeader(
        execution_id=eid,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("mock-server",),
        cwd="/tmp",
        redaction_mode="standard",
    )


def _make_summary(exec_id: str, total_events: int = 1) -> ExecutionSummary:
    t0 = datetime(2026, 11, 14, 0, 0, 0, tzinfo=UTC)
    t1 = datetime(2026, 11, 14, 0, 0, 1, tzinfo=UTC)
    return ExecutionSummary(
        execution_id=exec_id,
        started_at=t0,
        ended_at=t1,
        duration_ns=1_000_000_000,
        command=("mock-server",),
        cwd="/tmp",
        exit_code=0,
        returncode=0,
        capture_completeness="complete",
        termination_reason="completed",
        total_events=total_events,
        dropped_events=0,
        degraded_events=0,
        warning_count=0,
        gap_count=0,
        redaction_mode="standard",
        backpressure_policy="block",
    )


def _make_event(exec_id: str, seq: int) -> ExecutionEvent:
    t0 = datetime(2026, 11, 14, 0, 0, 0, tzinfo=UTC)
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


def _make_finished_event(exec_id: str, seq: int, total_events: int = 2) -> ExecutionEvent:
    t0 = datetime(2026, 11, 14, 0, 0, 1, tzinfo=UTC)
    return ExecutionEvent(
        event_id=new_event_id(),
        execution_id=exec_id,
        sequence=seq,
        timestamp=t0,
        monotonic_time_ns=seq * 1_000,
        direction="proxy",
        kind="execution_finished",
        payload=ExecutionFinishedPayload(
            termination_reason="completed",
            exit_code=0,
            returncode=0,
            completeness="complete",
            total_events=total_events,
        ),
    )


def _make_sqlite_error(
    message: str,
    *,
    errorcode: int | None = None,
    errorname: str | None = None,
) -> sqlite3.OperationalError:
    exc = sqlite3.OperationalError(message)
    if errorcode is not None:
        exc.sqlite_errorcode = errorcode
    if errorname is not None:
        exc.sqlite_errorname = errorname
    return exc


def test_is_transient_sqlite_lock_error_extended_codes() -> None:
    """Extended error codes with low-order byte 5 (BUSY) or 6 (LOCKED) must return True."""
    # 5: SQLITE_BUSY, extended: SQLITE_BUSY_RECOVERY (261), SQLITE_BUSY_SNAPSHOT (517)
    for code in (5, 5 | (1 << 8), 5 | (2 << 8), 5 | (3 << 8)):
        err = _make_sqlite_error("operational error", errorcode=code)
        assert _is_transient_sqlite_lock_error(err) is True

    # 6: SQLITE_LOCKED, extended: SQLITE_LOCKED_SHAREDCACHE (262), SQLITE_LOCKED_VTAB (518)
    for code in (6, 6 | (1 << 8), 6 | (2 << 8)):
        err = _make_sqlite_error("operational error", errorcode=code)
        assert _is_transient_sqlite_lock_error(err) is True


def test_is_transient_sqlite_lock_error_non_transient_rejected() -> None:
    """Non-busy numeric error codes are authoritative and must return False immediately."""
    non_transient = [
        1,  # SQLITE_ERROR
        10,  # SQLITE_IOERR
        10 | (1 << 8),  # SQLITE_IOERR_READ
        11,  # SQLITE_CORRUPT
        14,  # SQLITE_CANTOPEN
        19,  # SQLITE_CONSTRAINT
    ]
    for code in non_transient:
        # Even if message says "database is locked", numeric code is authoritative
        err = _make_sqlite_error("database is locked", errorcode=code)
        assert _is_transient_sqlite_lock_error(err) is False


def test_is_transient_sqlite_lock_error_fallback_strings() -> None:
    """Narrow fallback check is only used when numeric code is unavailable."""
    # Fallback to sqlite_errorname (authoritative when present)
    err_busy = _make_sqlite_error("some error", errorname="SQLITE_BUSY")
    assert _is_transient_sqlite_lock_error(err_busy) is True

    err_locked = _make_sqlite_error("some error", errorname="SQLITE_LOCKED")
    assert _is_transient_sqlite_lock_error(err_locked) is True

    # Authoritative rejection: non-transient error name rejects even if message matches
    err_other_name = _make_sqlite_error("database is locked", errorname="SQLITE_CORRUPT")
    assert _is_transient_sqlite_lock_error(err_other_name) is False

    # Fallback to message ONLY when neither errorcode nor errorname is available
    err_msg_busy = _make_sqlite_error("database is locked")
    assert _is_transient_sqlite_lock_error(err_msg_busy) is True

    err_msg_tbl = _make_sqlite_error("database table is locked")
    assert _is_transient_sqlite_lock_error(err_msg_tbl) is True

    err_unrelated = _make_sqlite_error("no such table: executions")
    assert _is_transient_sqlite_lock_error(err_unrelated) is False


def test_connect_locked_retries_on_wal_lock_and_succeeds(tmp_path: Path) -> None:
    """_connect_locked retries on transient WAL lock, closes failed conns, and succeeds."""
    store = SQLiteMetadataStore(tmp_path)
    call_count = 0
    orig_connect = sqlite3.connect
    created_conns: list[MockConn] = []

    class MockConn:
        def __init__(self, real: sqlite3.Connection) -> None:
            self._real = real
            self.row_factory = real.row_factory
            self.closed = False
            created_conns.append(self)

        def execute(self, sql: str, *params: Any) -> sqlite3.Cursor:
            nonlocal call_count
            if "PRAGMA journal_mode = WAL" in sql:
                call_count += 1
                if call_count <= 2:
                    raise _make_sqlite_error("database is locked", errorcode=5)
            return self._real.execute(sql, *params)

        def close(self) -> None:
            self.closed = True
            self._real.close()

        def __getattr__(self, name: str) -> object:
            return getattr(self._real, name)

        def __setattr__(self, name: str, value: object) -> None:
            if name in ("_real", "row_factory", "closed"):
                super().__setattr__(name, value)
            else:
                setattr(self._real, name, value)

    def fake_connect(*args: Any, **kwargs: Any) -> Any:
        return MockConn(orig_connect(*args, **kwargs))

    with (
        patch("sqlite3.connect", side_effect=fake_connect),
        patch("time.sleep") as mock_sleep,
    ):
        conn = store._connect_locked()
        assert conn is not None
        assert call_count == 3
        assert mock_sleep.call_count == 2
        # Assert each failed connection was closed before the next retry
        assert len(created_conns) == 3
        assert created_conns[0].closed is True
        assert created_conns[1].closed is True
        assert created_conns[2].closed is False

    store.close()
    assert created_conns[2].closed is True


def test_connect_locked_retries_on_migration_lock_rolls_back_and_succeeds(
    tmp_path: Path,
) -> None:
    """Transient lock during migration triggers rollback, connection closure, and clean retry."""
    store = SQLiteMetadataStore(tmp_path)
    orig_connect = sqlite3.connect
    created_conns: list[MockMigrationConn] = []
    attempt_count = 0

    class MockMigrationConn:
        def __init__(self, real: sqlite3.Connection) -> None:
            self._real = real
            self.row_factory = real.row_factory
            self.closed = False
            self.rollbacks = 0
            self.commits = 0
            created_conns.append(self)

        def execute(self, sql: str, *params: Any) -> sqlite3.Cursor:
            nonlocal attempt_count
            if "INSERT INTO schema_migrations" in sql and attempt_count == 0:
                attempt_count += 1
                raise _make_sqlite_error("database table is locked", errorcode=6)
            return self._real.execute(sql, *params)

        def rollback(self) -> None:
            self.rollbacks += 1
            self._real.rollback()

        def commit(self) -> None:
            self.commits += 1
            self._real.commit()

        def close(self) -> None:
            self.closed = True
            self._real.close()

        def __getattr__(self, name: str) -> object:
            return getattr(self._real, name)

        def __setattr__(self, name: str, value: object) -> None:
            if name in ("_real", "row_factory", "closed", "rollbacks", "commits"):
                super().__setattr__(name, value)
            else:
                setattr(self._real, name, value)

    def fake_connect(*args: Any, **kwargs: Any) -> Any:
        return MockMigrationConn(orig_connect(*args, **kwargs))

    with (
        patch("sqlite3.connect", side_effect=fake_connect),
        patch("time.sleep") as mock_sleep,
    ):
        conn = store._connect_locked()
        assert conn is not None
        assert mock_sleep.call_count == 1

        # Attempt 1 failed inside migration: must have rolled back and closed
        assert len(created_conns) == 2
        conn1, conn2 = created_conns
        assert conn1.rollbacks == 1
        assert conn1.closed is True

        # Attempt 2: fresh connection re-inspected state and cleanly committed
        assert conn2.commits == 1
        assert conn2.closed is False

    # Verify on-disk migration state was cleanly applied exactly once
    raw_conn = sqlite3.connect(str(store.db_path))
    try:
        user_ver = raw_conn.execute("PRAGMA user_version").fetchone()[0]
        assert user_ver == 1
        rows = raw_conn.execute("SELECT version, name FROM schema_migrations").fetchall()
        assert rows == [(1, "0001_initial")]
        # Target table exists and is queryable
        raw_conn.execute("SELECT COUNT(*) FROM executions").fetchone()
    finally:
        raw_conn.close()

    store.close()
    assert conn2.closed is True


def test_connect_locked_exhausts_retries_and_raises(tmp_path: Path) -> None:
    """_connect_locked raises the transient error after 5 failed attempts and closes all conns."""
    store = SQLiteMetadataStore(tmp_path)
    orig_connect = sqlite3.connect
    created_conns: list[MockConn] = []

    class MockConn:
        def __init__(self, real: sqlite3.Connection) -> None:
            self._real = real
            self.row_factory = real.row_factory
            self.closed = False
            created_conns.append(self)

        def execute(self, sql: str, *params: Any) -> sqlite3.Cursor:
            if "PRAGMA journal_mode = WAL" in sql:
                raise _make_sqlite_error("database is locked", errorcode=5)
            return self._real.execute(sql, *params)

        def close(self) -> None:
            self.closed = True
            self._real.close()

        def __getattr__(self, name: str) -> object:
            return getattr(self._real, name)

        def __setattr__(self, name: str, value: object) -> None:
            if name in ("_real", "row_factory", "closed"):
                super().__setattr__(name, value)
            else:
                setattr(self._real, name, value)

    def fake_connect(*args: Any, **kwargs: Any) -> Any:
        return MockConn(orig_connect(*args, **kwargs))

    with (
        patch("sqlite3.connect", side_effect=fake_connect),
        patch("time.sleep") as mock_sleep,
        pytest.raises(sqlite3.OperationalError, match="database is locked"),
    ):
        store._connect_locked()

    assert mock_sleep.call_count == 4  # 5 attempts = 4 backoff sleeps
    # Assert every failed connection was closed cleanly
    assert len(created_conns) == 5
    assert all(c.closed for c in created_conns)
    store.close()


def test_is_sqlite_metadata_error_classification() -> None:
    """_is_sqlite_metadata_error accurately distinguishes SQLite errors from other errors."""
    sql_err = sqlite3.OperationalError("database is locked")
    assert _is_sqlite_metadata_error(sql_err) is True

    schema_err = UnsupportedSchemaVersionError("Unsupported schema version: 99")
    assert _is_sqlite_metadata_error(schema_err) is True

    # StorageWriteError wrapping sqlite3.Error
    wrapped_sql = StorageWriteError("SQLite write failed")
    wrapped_sql.__cause__ = sql_err
    assert _is_sqlite_metadata_error(wrapped_sql) is True

    # StorageDiskFullError wrapping sqlite3.Error
    disk_sql = StorageDiskFullError("Disk full during SQLite write")
    disk_sql.__cause__ = sql_err
    assert _is_sqlite_metadata_error(disk_sql) is True

    # StorageWriteError wrapping OSError (e.g. from JSONL filesystem write)
    fs_err = StorageWriteError("JSONL write failed")
    fs_err.__cause__ = OSError(28, "No space left on device")
    assert _is_sqlite_metadata_error(fs_err) is False

    # No cause
    no_cause = StorageWriteError("Unknown error")
    assert _is_sqlite_metadata_error(no_cause) is False

    # StorageCorruptionError
    corrupt = StorageCorruptionError("Corrupt JSON line")
    assert _is_sqlite_metadata_error(corrupt) is False

    # Generic programming errors
    assert _is_sqlite_metadata_error(TypeError("bad type")) is False
    assert _is_sqlite_metadata_error(ValueError("bad value")) is False
    assert _is_sqlite_metadata_error(KeyError("missing key")) is False


@pytest.mark.asyncio
async def test_sink_on_start_jsonl_open_failure_propagates_and_unsets_handles(
    tmp_path: Path,
) -> None:
    """A fatal JSONL writer-open error propagates immediately without swallowing handles."""
    mock_store = MagicMock(spec=SQLiteMetadataStore)
    sink = PersistentCaptureSink(tmp_path, store=mock_store)
    header = _make_header()

    with (
        patch.object(
            JsonlEventLogWriter,
            "open",
            side_effect=StorageWriteError("Fatal disk permission error opening events.jsonl"),
        ),
        pytest.raises(
            StorageWriteError,
            match=r"Fatal disk permission error opening events\.jsonl",
        ),
    ):
        await sink.on_start(header)

    # Must NOT be marked as SQLite divergence (it's a primary recording failure)
    assert sink.sqlite_diverged is False
    # Handles must remain unset
    assert sink.execution_id is None
    assert sink._writer is None
    # Store must never have been touched
    mock_store.initialize.assert_not_called()
    mock_store.insert_execution_start.assert_not_called()
    await sink.close()


@pytest.mark.asyncio
async def test_sink_on_start_sqlite_init_failure_preserves_jsonl(tmp_path: Path) -> None:
    """If SQLite initialization fails on start, JSONL capture continues and finalizes cleanly."""
    mock_store = MagicMock(spec=SQLiteMetadataStore)
    mock_store.initialize.side_effect = _make_sqlite_error("database is locked", errorcode=5)

    sink = PersistentCaptureSink(tmp_path, store=mock_store)
    header = _make_header()
    eid = header.execution_id

    # on_start must NOT raise even though SQLite initialize failed
    await sink.on_start(header)
    assert sink.sqlite_diverged is True

    # Events can be emitted and are written to JSONL
    event = _make_event(eid, 1)
    fin_event = _make_finished_event(eid, 2, total_events=2)
    await sink.emit_events([event, fin_event])

    # Store's insert_event_slices must NOT be called since diverged is True
    mock_store.insert_event_slices.assert_not_called()

    # on_finish must finalize JSONL and skip update_execution_finish
    summary = _make_summary(eid, total_events=2)
    await sink.on_finish(summary)
    mock_store.update_execution_finish.assert_not_called()
    await sink.close()

    # Verify JSONL on-disk integrity
    reader = JsonlEventLogReader(tmp_path)
    res = reader.read_execution(eid, strict=True)
    assert res.execution_id == eid
    assert len(res.events) == 2
    assert res.manifest is not None
    assert res.manifest.status == "finalized"
    assert res.unclean_shutdown is False


@pytest.mark.asyncio
async def test_sink_on_start_insert_start_failure_preserves_jsonl(tmp_path: Path) -> None:
    """If insert_execution_start fails, JSONL recording remains intact and diverged is marked."""
    mock_store = MagicMock(spec=SQLiteMetadataStore)
    mock_store.initialize.return_value = 1
    sql_cause = _make_sqlite_error("database is locked", errorcode=5)
    write_err = StorageWriteError("SQLite error during insert_execution_start: database is locked")
    write_err.__cause__ = sql_cause
    mock_store.insert_execution_start.side_effect = write_err

    sink = PersistentCaptureSink(tmp_path, store=mock_store)
    header = _make_header()
    eid = header.execution_id

    await sink.on_start(header)
    assert sink.sqlite_diverged is True

    summary = _make_summary(eid)
    await sink.on_finish(summary)
    mock_store.update_execution_finish.assert_not_called()
    await sink.close()

    reader = JsonlEventLogReader(tmp_path)
    res = reader.read_execution(eid, strict=True)
    assert res.manifest is not None
    assert res.manifest.status == "finalized"


@pytest.mark.asyncio
async def test_sink_emit_events_sqlite_failure_preserves_jsonl(tmp_path: Path) -> None:
    """If insert_event_slices fails, emit_events does not raise and preserves JSONL."""
    mock_store = MagicMock(spec=SQLiteMetadataStore)
    mock_store.initialize.return_value = 1
    mock_store.insert_execution_start.return_value = None

    sql_cause = _make_sqlite_error("database is locked", errorcode=5)
    write_err = StorageWriteError("SQLite error during insert_event_slices: database is locked")
    write_err.__cause__ = sql_cause
    mock_store.insert_event_slices.side_effect = write_err

    sink = PersistentCaptureSink(tmp_path, store=mock_store)
    header = _make_header()
    eid = header.execution_id

    await sink.on_start(header)
    assert sink.sqlite_diverged is False

    event = _make_event(eid, 1)
    # emit_events must NOT raise
    await sink.emit_events([event])
    assert sink.sqlite_diverged is True

    summary = _make_summary(eid)
    await sink.on_finish(summary)
    mock_store.update_execution_finish.assert_not_called()
    await sink.close()

    reader = JsonlEventLogReader(tmp_path)
    res = reader.read_execution(eid, strict=True)
    assert len(res.events) == 1
    assert res.manifest is not None
    assert res.manifest.status == "finalized"


@pytest.mark.asyncio
async def test_sink_on_finish_sqlite_failure_preserves_finalized_jsonl(tmp_path: Path) -> None:
    """If update_execution_finish fails, on_finish does not raise and JSONL is finalized."""
    mock_store = MagicMock(spec=SQLiteMetadataStore)
    mock_store.initialize.return_value = 1
    mock_store.insert_execution_start.return_value = None
    mock_store.insert_event_slices.return_value = None

    sql_cause = _make_sqlite_error("database is locked", errorcode=5)
    write_err = StorageWriteError("SQLite error during update_execution_finish: database is locked")
    write_err.__cause__ = sql_cause
    mock_store.update_execution_finish.side_effect = write_err

    sink = PersistentCaptureSink(tmp_path, store=mock_store)
    header = _make_header()
    eid = header.execution_id

    await sink.on_start(header)
    event = _make_event(eid, 1)
    await sink.emit_events([event])
    assert sink.sqlite_diverged is False

    summary = _make_summary(eid)
    # on_finish must NOT raise
    await sink.on_finish(summary)
    assert sink.sqlite_diverged is True
    await sink.close()

    reader = JsonlEventLogReader(tmp_path)
    res = reader.read_execution(eid, strict=True)
    assert len(res.events) == 1
    assert res.manifest is not None
    assert res.manifest.status == "finalized"
    assert res.manifest.events_file_sha256 is not None


@pytest.mark.asyncio
async def test_sink_on_start_unexpected_error_cleans_up_and_reconciles_incomplete(
    tmp_path: Path,
) -> None:
    """Unexpected error after writer.open() cleans up handles and leaves recording incomplete."""
    mock_store = MagicMock(spec=SQLiteMetadataStore)
    mock_store.initialize.side_effect = TypeError("Unexpected programming bug")

    sink = PersistentCaptureSink(tmp_path, store=mock_store)
    header = _make_header()
    eid = header.execution_id

    # on_start must re-raise the unexpected error
    with pytest.raises(TypeError, match="Unexpected programming bug"):
        await sink.on_start(header)

    # Sink handles must be reset to None
    assert sink.execution_id is None
    assert sink._writer is None
    await sink.close()

    # On disk: manifest exists with status="recording"
    reader = JsonlEventLogReader(tmp_path)
    res = reader.read_execution(eid)
    assert res.manifest is not None
    assert res.manifest.status == "recording"
    assert res.summary is None
    assert res.unclean_shutdown is True

    # Reconciliation must resolve to incomplete (never complete)
    repo = RecordingRepository(tmp_path)
    reconciled_res = repo.reconcile_execution(eid)
    assert reconciled_res is not None
    assert reconciled_res.unclean_shutdown is True
    row = repo.store.get_execution_row(eid)
    assert row is not None
    assert row.capture_completeness == "incomplete"
    assert row.termination_reason == "unclean_shutdown"
    assert row.index_status == "recovered"
    repo.close()


def test_reconcile_diverged_execution_recovers_sqlite_index(tmp_path: Path) -> None:
    """A diverged execution (JSONL finalized, missing SQLite row) is recovered into SQLite."""
    store = SQLiteMetadataStore(tmp_path)
    store.initialize()

    # Create a diverged recording directly via PersistentCaptureSink with diverged store
    mock_store = MagicMock(spec=SQLiteMetadataStore)
    mock_store.initialize.side_effect = _make_sqlite_error("database is locked", errorcode=5)
    sink = PersistentCaptureSink(tmp_path, store=mock_store)

    header = _make_header()
    eid = header.execution_id

    async def _run() -> None:
        await sink.on_start(header)
        event = _make_event(eid, 1)
        fin_event = _make_finished_event(eid, 2, total_events=2)
        await sink.emit_events([event, fin_event])
        await sink.on_finish(_make_summary(eid, total_events=2))
        await sink.close()

    asyncio.run(_run())

    # Verify SQLite currently lacks the execution row
    assert store.get_execution_row(eid) is None

    # Reconcile from authoritative JSONL
    repo = RecordingRepository(tmp_path)
    reconciled_res = repo.reconcile_execution(eid)
    assert reconciled_res is not None
    assert reconciled_res.unclean_shutdown is False

    # Verify SQLite now contains the recovered execution
    stored = repo.store.get_execution_row(eid)
    assert stored is not None
    assert stored.execution_id == eid
    assert stored.capture_completeness == "complete"
    assert stored.index_status == "indexed"
    repo.close()
    store.close()


def test_concurrent_cold_start_sqlite_contention_10x_repetitions(tmp_path: Path) -> None:
    """Stress test 4 concurrent processes racing cold-start SQLite DB creation (10 iterations)."""
    echo_srv = tmp_path / "echo_srv.py"
    echo_srv.write_text(
        "import sys, json\n"
        "for line in sys.stdin:\n"
        "    req = json.loads(line)\n"
        "    resp = {'jsonrpc': '2.0', 'id': req.get('id'), 'result': 'ok'}\n"
        "    sys.stdout.write(json.dumps(resp) + '\\n')\n"
        "    sys.stdout.flush()\n",
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO_ROOT / "src")

    payload = (
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}})
        + "\n"
    )

    for iteration in range(1, 11):
        iter_dir = tmp_path / f"iter_{iteration}"
        iter_dir.mkdir(parents=True, exist_ok=True)
        exec_ids = [new_execution_id() for _ in range(4)]

        # Launch 4 concurrent aerlog run processes racing on cold-start shared DB
        procs = [
            subprocess.Popen(
                [
                    _PYTHON,
                    "-m",
                    "aerlog",
                    "run",
                    "--quiet",
                    "--execution-id",
                    eid,
                    "--data-dir",
                    str(iter_dir),
                    "--",
                    _PYTHON,
                    str(echo_srv),
                ],
                cwd=_REPO_ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for eid in exec_ids
        ]

        # Launch concurrent list reader
        list_proc = subprocess.Popen(
            [_PYTHON, "-m", "aerlog", "list", "--data-dir", str(iter_dir), "--json"],
            cwd=_REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        for idx, proc in enumerate(procs):
            out, err = proc.communicate(input=payload, timeout=20)
            err_msg = f"Iter {iteration} worker {idx} failed rc={proc.returncode}: {err}"
            assert proc.returncode == 0, err_msg
            lines = [line for line in out.splitlines() if line.strip()]
            assert len(lines) == 2

        _list_out, _ = list_proc.communicate(timeout=20)
        assert list_proc.returncode == 0

        # Verify DB exists
        db_path = iter_dir / DB_FILE_NAME
        assert db_path.is_file(), f"Iter {iteration} aerlog.db not created"

        # Verify all 4 executions appear in SQLite listing
        list_res = subprocess.run(
            [_PYTHON, "-m", "aerlog", "list", "--data-dir", str(iter_dir), "--json"],
            cwd=_REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        listed_ids = {r["execution_id"] for r in json.loads(list_res.stdout)["executions"]}
        assert set(exec_ids).issubset(listed_ids), (
            f"Iter {iteration}: missing executions from SQLite: {set(exec_ids) - listed_ids}"
        )

        # Verify all 4 executions have intact JSONL recordings
        reader = JsonlEventLogReader(iter_dir)
        for eid in exec_ids:
            res = reader.read_execution(eid, strict=True)
            assert res.manifest is not None
            assert res.manifest.status == "finalized"
            assert len(res.events) >= 4
            assert res.unclean_shutdown is False
