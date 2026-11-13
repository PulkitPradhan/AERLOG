"""SQLite metadata and rebuildable event-index store with restricted WAL permissions."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from aerlog.events.models import (
    ExecutionEvent,
    ExecutionHeader,
    ExecutionSummary,
    JsonRpcErrorPayload,
    JsonRpcNotificationPayload,
    JsonRpcRequestPayload,
    JsonRpcResponsePayload,
)
from aerlog.storage.event_log import (
    STORAGE_SCHEMA_VERSION,
    CorruptRecordReport,
    WrittenEventSlice,
    relative_recording_dir,
    sanitize_header_for_persistence,
    sanitize_summary_for_persistence,
    validate_execution_id,
)
from aerlog.storage.exceptions import StorageDiskFullError, StorageWriteError
from aerlog.storage.migrations import LATEST_DB_SCHEMA_VERSION, apply_migrations

DB_FILE_NAME = "aerlog.db"
SqliteSynchronousMode = Literal["NORMAL", "FULL"]


def _is_transient_sqlite_lock_error(exc: sqlite3.Error) -> bool:
    """Determine whether a SQLite error represents a transient lock/busy collision."""
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int):
        return (code & 0xFF) in (5, 6)

    name = getattr(exc, "sqlite_errorname", None)
    if isinstance(name, str):
        return name in ("SQLITE_BUSY", "SQLITE_LOCKED")

    msg = str(exc).lower()
    return "database is locked" in msg or "database table is locked" in msg


def _translate_sqlite_error(exc: sqlite3.Error, *, context: str) -> StorageWriteError:
    msg = str(exc).lower()
    if "disk is full" in msg or "enospc" in msg:
        return StorageDiskFullError(f"Disk full during SQLite {context}: {exc}")
    return StorageWriteError(f"SQLite error during {context}: {exc}")


@dataclass(frozen=True, slots=True)
class IndexedExecutionRow:
    """Row projected cleanly from SQLite ``executions``."""

    execution_id: str
    schema_version: str
    storage_schema_version: str
    started_at: datetime
    ended_at: datetime | None
    duration_ns: int | None
    command: tuple[str, ...]
    cwd: str | None
    transport: str
    redaction_mode: str
    backpressure_policy: str
    capture_completeness: str
    termination_reason: str | None
    exit_code: int | None
    returncode: int | None
    total_events: int
    dropped_events: int
    degraded_events: int
    warning_count: int
    gap_count: int
    unanswered_request_ids: tuple[str, ...]
    observed_trace_ids: tuple[str, ...]
    observed_mcp_versions: tuple[str, ...]
    recording_dir: str
    jsonl_byte_offset: int
    jsonl_sha256: str | None
    last_indexed_sequence: int
    index_status: str


@dataclass(frozen=True, slots=True)
class IndexedEventRow:
    """Row projected cleanly from SQLite ``events_index``."""

    execution_id: str
    event_id: str
    sequence: int
    timestamp: datetime
    monotonic_time_ns: int
    direction: str
    kind: str
    method: str | None
    jsonrpc_id_type: str | None
    jsonrpc_id_text: str | None
    observed_trace_id: str | None
    observed_parent_span_id: str | None
    synthetic_execution_trace_id: str | None
    correlation_status: str | None
    matched_request_event_id: str | None
    tool_is_error: bool | None
    degraded: bool
    jsonl_byte_offset: int
    jsonl_byte_length: int


def _extract_index_fields(
    event: ExecutionEvent,
) -> tuple[str | None, str | None, str | None]:
    """Return ``(method, id_type, id_text)`` without extracting raw payloads."""
    payload = event.payload
    if isinstance(payload, JsonRpcRequestPayload):
        id_text = None if payload.id is None else str(payload.id)
        return payload.method, payload.id_type, id_text
    if isinstance(payload, JsonRpcNotificationPayload):
        return payload.method, None, None
    if isinstance(payload, JsonRpcResponsePayload | JsonRpcErrorPayload):
        id_text = None if payload.id is None else str(payload.id)
        return None, payload.id_type, id_text
    return None, None, None


class SQLiteMetadataStore:
    """Thread-safe SQLite metadata and event-index manager."""

    def __init__(
        self,
        data_dir: Path,
        *,
        db_path: Path | None = None,
        synchronous: SqliteSynchronousMode = "NORMAL",
        persist_cwd: bool = False,
        busy_timeout_ms: int = 5000,
    ) -> None:
        if synchronous not in ("NORMAL", "FULL"):
            raise ValueError(f"Unsupported sqlite_synchronous mode: {synchronous!r}")
        if busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be non-negative")
        self._data_dir = data_dir
        self._db_path = (data_dir / DB_FILE_NAME) if db_path is None else db_path
        self._synchronous: SqliteSynchronousMode = synchronous
        self._persist_cwd = persist_cwd
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    @property
    def db_path(self) -> Path:
        """Path to the SQLite database file."""
        return self._db_path

    @property
    def is_open(self) -> bool:
        """Whether a SQLite connection is currently active."""
        return self._conn is not None

    def _restrict_sqlite_files(self) -> None:
        """Apply ``0o600`` to ``aerlog.db`` and any SQLite ``-wal`` / ``-shm`` sidecars."""
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self._db_path}{suffix}")
            if candidate.exists():
                with suppress(OSError):
                    os.chmod(candidate, 0o600)

    def _connect_locked(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self._db_path.parent, 0o700)
        if not self._db_path.exists():
            fd = os.open(self._db_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                os.chmod(fd, 0o600)
            finally:
                os.close(fd)
        else:
            os.chmod(self._db_path, 0o600)

        max_attempts = 5
        backoffs = (0.02, 0.04, 0.08, 0.16)

        for attempt in range(max_attempts):
            conn = sqlite3.connect(
                str(self._db_path),
                timeout=self._busy_timeout_ms / 1000.0,
                isolation_level=None,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            try:
                conn.execute(f"PRAGMA busy_timeout = {int(self._busy_timeout_ms)}")
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute(f"PRAGMA synchronous = {self._synchronous}")
                apply_migrations(conn)
            except sqlite3.Error as exc:
                conn.close()
                self._restrict_sqlite_files()
                if _is_transient_sqlite_lock_error(exc) and attempt < max_attempts - 1:
                    time.sleep(backoffs[attempt])
                    continue
                raise
            except Exception:
                conn.close()
                self._restrict_sqlite_files()
                raise

            self._conn = conn
            self._restrict_sqlite_files()
            return conn

        raise StorageWriteError("Failed to initialize SQLite connection after retry exhaustion")

    def initialize(self) -> int:
        """Open connection, configure WAL/permissions, apply migrations, and return version."""
        with self._lock:
            self._connect_locked()
            return LATEST_DB_SCHEMA_VERSION

    def _conn_or_init(self) -> sqlite3.Connection:
        return self._connect_locked()

    def close(self) -> None:
        """Checkpoint WAL if open cleanly and close the SQLite connection."""
        with self._lock:
            if self._conn is not None:
                try:
                    with suppress(sqlite3.Error):
                        self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
                    self._conn.close()
                finally:
                    self._conn = None
                self._restrict_sqlite_files()

    def compact(self) -> None:
        """Run ``WAL`` truncation checkpoint and ``VACUUM``, preserving ``0o600`` modes."""
        with self._lock:
            conn = self._conn_or_init()
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.execute("VACUUM")
            except sqlite3.Error as exc:
                raise _translate_sqlite_error(exc, context="compacting database") from exc
            finally:
                self._restrict_sqlite_files()

    def insert_execution_start(self, header: ExecutionHeader) -> None:
        """Insert or update the initial `'recording'` execution catalog entry."""
        clean_id = validate_execution_id(header.execution_id)
        safe_header = sanitize_header_for_persistence(header, persist_cwd=self._persist_cwd)
        cmd_json = json.dumps(list(safe_header.command), ensure_ascii=False)
        rel_dir = relative_recording_dir(clean_id)

        with self._lock:
            conn = self._conn_or_init()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO executions (
                        execution_id, schema_version, storage_schema_version,
                        started_at, command_json, cwd, transport,
                        redaction_mode, backpressure_policy, capture_completeness,
                        recording_dir, jsonl_byte_offset, last_indexed_sequence, index_status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'recording', ?, 0, 0, 'in_progress')
                    ON CONFLICT(execution_id) DO UPDATE SET
                        schema_version = excluded.schema_version,
                        storage_schema_version = excluded.storage_schema_version,
                        started_at = excluded.started_at,
                        command_json = excluded.command_json,
                        cwd = excluded.cwd,
                        transport = excluded.transport,
                        redaction_mode = excluded.redaction_mode,
                        backpressure_policy = excluded.backpressure_policy,
                        capture_completeness = 'recording',
                        recording_dir = excluded.recording_dir,
                        index_status = 'in_progress'
                    """,
                    (
                        clean_id,
                        safe_header.schema_version,
                        STORAGE_SCHEMA_VERSION,
                        safe_header.started_at.isoformat(),
                        cmd_json,
                        safe_header.cwd,
                        safe_header.transport,
                        safe_header.redaction_mode,
                        safe_header.backpressure_policy,
                        rel_dir,
                    ),
                )
                conn.commit()
            except sqlite3.Error as exc:
                with suppress(sqlite3.Error):
                    conn.rollback()
                raise _translate_sqlite_error(exc, context="insert_execution_start") from exc
            finally:
                self._restrict_sqlite_files()

    def insert_event_slices(
        self,
        execution_id: str,
        slices: Sequence[WrittenEventSlice],
    ) -> None:
        """Atomically index an ordered batch of appended JSONL event slices."""
        if not slices:
            return
        clean_id = validate_execution_id(execution_id)
        rows: list[tuple[Any, ...]] = []
        max_seq = 0
        end_offset = 0
        for item in slices:
            ev = item.event
            method, id_type, id_text = _extract_index_fields(ev)
            observed_trace = ev.trace.observed_trace_id if ev.trace else None
            observed_span = ev.trace.observed_parent_span_id if ev.trace else None
            synth_trace = ev.trace.synthetic_execution_trace_id if ev.trace else None
            corr_status = ev.correlation.status if ev.correlation else None
            matched_req = ev.correlation.matched_request_event_id if ev.correlation else None
            tool_err: int | None = None
            if ev.derived is not None and ev.derived.tool_is_error is not None:
                tool_err = 1 if ev.derived.tool_is_error else 0

            rows.append(
                (
                    clean_id,
                    ev.event_id,
                    ev.sequence,
                    ev.timestamp.isoformat(),
                    ev.monotonic_time_ns,
                    ev.direction,
                    ev.kind,
                    method,
                    id_type,
                    id_text,
                    observed_trace,
                    observed_span,
                    synth_trace,
                    corr_status,
                    matched_req,
                    tool_err,
                    1 if ev.degraded else 0,
                    item.byte_offset,
                    item.byte_length,
                )
            )
            max_seq = max(max_seq, ev.sequence)
            end_offset = max(end_offset, item.byte_offset + item.byte_length)

        with self._lock:
            conn = self._conn_or_init()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO events_index (
                        execution_id, event_id, sequence, timestamp, monotonic_time_ns,
                        direction, kind, method, jsonrpc_id_type, jsonrpc_id_text,
                        observed_trace_id, observed_parent_span_id, synthetic_execution_trace_id,
                        correlation_status, matched_request_event_id, tool_is_error, degraded,
                        jsonl_byte_offset, jsonl_byte_length
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                conn.execute(
                    """
                    UPDATE executions
                    SET
                        last_indexed_sequence = MAX(last_indexed_sequence, ?),
                        jsonl_byte_offset = MAX(jsonl_byte_offset, ?),
                        total_events = MAX(total_events, ?)
                    WHERE execution_id = ?
                    """,
                    (max_seq, end_offset, max_seq, clean_id),
                )
                conn.commit()
            except sqlite3.Error as exc:
                with suppress(sqlite3.Error):
                    conn.rollback()
                raise _translate_sqlite_error(exc, context="insert_event_slices") from exc
            finally:
                self._restrict_sqlite_files()

    def update_execution_finish(
        self,
        summary: ExecutionSummary,
        *,
        jsonl_byte_offset: int,
        jsonl_sha256: str | None,
        index_status: str = "indexed",
    ) -> None:
        """Atomically update finalized execution summary and file digest in SQLite."""
        clean_id = validate_execution_id(summary.execution_id)
        safe_summary = sanitize_summary_for_persistence(summary, persist_cwd=self._persist_cwd)
        cmd_json = json.dumps(list(safe_summary.command), ensure_ascii=False)

        with self._lock:
            conn = self._conn_or_init()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    UPDATE executions
                    SET
                        ended_at = ?,
                        duration_ns = ?,
                        command_json = ?,
                        cwd = ?,
                        capture_completeness = ?,
                        termination_reason = ?,
                        exit_code = ?,
                        returncode = ?,
                        total_events = ?,
                        dropped_events = ?,
                        degraded_events = ?,
                        warning_count = ?,
                        gap_count = ?,
                        unanswered_request_ids_json = ?,
                        observed_trace_ids_json = ?,
                        observed_mcp_versions_json = ?,
                        jsonl_byte_offset = ?,
                        jsonl_sha256 = ?,
                        last_indexed_sequence = MAX(last_indexed_sequence, ?),
                        index_status = ?
                    WHERE execution_id = ?
                    """,
                    (
                        safe_summary.ended_at.isoformat(),
                        safe_summary.duration_ns,
                        cmd_json,
                        safe_summary.cwd,
                        safe_summary.capture_completeness,
                        safe_summary.termination_reason,
                        safe_summary.exit_code,
                        safe_summary.returncode,
                        safe_summary.total_events,
                        safe_summary.dropped_events,
                        safe_summary.degraded_events,
                        safe_summary.warning_count,
                        safe_summary.gap_count,
                        json.dumps(list(safe_summary.unanswered_request_ids), ensure_ascii=False),
                        json.dumps(list(safe_summary.observed_trace_ids), ensure_ascii=False),
                        json.dumps(
                            list(safe_summary.observed_mcp_protocol_versions), ensure_ascii=False
                        ),
                        jsonl_byte_offset,
                        jsonl_sha256,
                        safe_summary.total_events,
                        index_status,
                        clean_id,
                    ),
                )
                conn.commit()
            except sqlite3.Error as exc:
                with suppress(sqlite3.Error):
                    conn.rollback()
                raise _translate_sqlite_error(exc, context="update_execution_finish") from exc
            finally:
                self._restrict_sqlite_files()

    def replace_execution_index(
        self,
        *,
        execution_row: dict[str, Any],
        slices: Sequence[WrittenEventSlice],
        corruptions: Sequence[CorruptRecordReport],
    ) -> None:
        """Atomically rebuild all SQLite rows for one execution from authoritative JSONL."""
        clean_id = validate_execution_id(str(execution_row["execution_id"]))
        now_iso = datetime.now(UTC).isoformat()

        with self._lock:
            conn = self._conn_or_init()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DELETE FROM events_index WHERE execution_id = ?", (clean_id,))
                conn.execute(
                    "DELETE FROM execution_corruptions WHERE execution_id = ?", (clean_id,)
                )
                conn.execute(
                    """
                    INSERT INTO executions (
                        execution_id, schema_version, storage_schema_version,
                        started_at, ended_at, duration_ns, command_json, cwd, transport,
                        redaction_mode, backpressure_policy, capture_completeness,
                        termination_reason, exit_code, returncode,
                        total_events, dropped_events, degraded_events, warning_count, gap_count,
                        unanswered_request_ids_json, observed_trace_ids_json,
                        observed_mcp_versions_json, recording_dir,
                        jsonl_byte_offset, jsonl_sha256, last_indexed_sequence, index_status
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(execution_id) DO UPDATE SET
                        schema_version = excluded.schema_version,
                        storage_schema_version = excluded.storage_schema_version,
                        started_at = excluded.started_at,
                        ended_at = excluded.ended_at,
                        duration_ns = excluded.duration_ns,
                        command_json = excluded.command_json,
                        cwd = excluded.cwd,
                        transport = excluded.transport,
                        redaction_mode = excluded.redaction_mode,
                        backpressure_policy = excluded.backpressure_policy,
                        capture_completeness = excluded.capture_completeness,
                        termination_reason = excluded.termination_reason,
                        exit_code = excluded.exit_code,
                        returncode = excluded.returncode,
                        total_events = excluded.total_events,
                        dropped_events = excluded.dropped_events,
                        degraded_events = excluded.degraded_events,
                        warning_count = excluded.warning_count,
                        gap_count = excluded.gap_count,
                        unanswered_request_ids_json = excluded.unanswered_request_ids_json,
                        observed_trace_ids_json = excluded.observed_trace_ids_json,
                        observed_mcp_versions_json = excluded.observed_mcp_versions_json,
                        recording_dir = excluded.recording_dir,
                        jsonl_byte_offset = excluded.jsonl_byte_offset,
                        jsonl_sha256 = excluded.jsonl_sha256,
                        last_indexed_sequence = excluded.last_indexed_sequence,
                        index_status = excluded.index_status
                    """,
                    (
                        clean_id,
                        execution_row["schema_version"],
                        execution_row["storage_schema_version"],
                        execution_row["started_at"],
                        execution_row.get("ended_at"),
                        execution_row.get("duration_ns"),
                        execution_row["command_json"],
                        execution_row.get("cwd"),
                        execution_row["transport"],
                        execution_row["redaction_mode"],
                        execution_row["backpressure_policy"],
                        execution_row["capture_completeness"],
                        execution_row.get("termination_reason"),
                        execution_row.get("exit_code"),
                        execution_row.get("returncode"),
                        execution_row["total_events"],
                        execution_row["dropped_events"],
                        execution_row["degraded_events"],
                        execution_row["warning_count"],
                        execution_row["gap_count"],
                        execution_row["unanswered_request_ids_json"],
                        execution_row["observed_trace_ids_json"],
                        execution_row["observed_mcp_versions_json"],
                        execution_row["recording_dir"],
                        execution_row["jsonl_byte_offset"],
                        execution_row.get("jsonl_sha256"),
                        execution_row["last_indexed_sequence"],
                        execution_row["index_status"],
                    ),
                )

                if slices:
                    event_rows = []
                    for item in slices:
                        ev = item.event
                        method, id_type, id_text = _extract_index_fields(ev)
                        observed_trace = ev.trace.observed_trace_id if ev.trace else None
                        observed_span = ev.trace.observed_parent_span_id if ev.trace else None
                        synth_trace = ev.trace.synthetic_execution_trace_id if ev.trace else None
                        corr_status = ev.correlation.status if ev.correlation else None
                        matched_req = (
                            ev.correlation.matched_request_event_id if ev.correlation else None
                        )
                        tool_err: int | None = None
                        if ev.derived is not None and ev.derived.tool_is_error is not None:
                            tool_err = 1 if ev.derived.tool_is_error else 0
                        event_rows.append(
                            (
                                clean_id,
                                ev.event_id,
                                ev.sequence,
                                ev.timestamp.isoformat(),
                                ev.monotonic_time_ns,
                                ev.direction,
                                ev.kind,
                                method,
                                id_type,
                                id_text,
                                observed_trace,
                                observed_span,
                                synth_trace,
                                corr_status,
                                matched_req,
                                tool_err,
                                1 if ev.degraded else 0,
                                item.byte_offset,
                                item.byte_length,
                            )
                        )
                    conn.executemany(
                        """
                        INSERT INTO events_index (
                            execution_id, event_id, sequence, timestamp, monotonic_time_ns,
                            direction, kind, method, jsonrpc_id_type, jsonrpc_id_text,
                            observed_trace_id, observed_parent_span_id,
                            synthetic_execution_trace_id, correlation_status,
                            matched_request_event_id, tool_is_error, degraded,
                            jsonl_byte_offset, jsonl_byte_length
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        event_rows,
                    )

                if corruptions:
                    corr_rows = [
                        (
                            clean_id,
                            c.line_number,
                            c.byte_offset,
                            c.byte_length,
                            c.issue_kind,
                            c.excerpt_sha256,
                            c.details,
                            now_iso,
                        )
                        for c in corruptions
                    ]
                    conn.executemany(
                        """
                        INSERT INTO execution_corruptions (
                            execution_id, line_number, byte_offset, byte_length,
                            issue_kind, excerpt_sha256, details, detected_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        corr_rows,
                    )
                conn.commit()
            except sqlite3.Error as exc:
                with suppress(sqlite3.Error):
                    conn.rollback()
                raise _translate_sqlite_error(exc, context="replace_execution_index") from exc
            finally:
                self._restrict_sqlite_files()

    def mark_missing_jsonl(self, execution_id: str) -> None:
        """Flag an indexed execution whose directory/JSONL log disappeared on disk."""
        clean_id = validate_execution_id(execution_id)
        with self._lock:
            conn = self._conn_or_init()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    UPDATE executions
                    SET capture_completeness = 'corrupted', index_status = 'missing_jsonl'
                    WHERE execution_id = ?
                    """,
                    (clean_id,),
                )
                conn.commit()
            except sqlite3.Error as exc:
                with suppress(sqlite3.Error):
                    conn.rollback()
                raise _translate_sqlite_error(exc, context="mark_missing_jsonl") from exc
            finally:
                self._restrict_sqlite_files()

    def delete_executions(self, execution_ids: Sequence[str]) -> int:
        """Delete specified executions cleanly from SQLite (with ON DELETE CASCADE)."""
        if not execution_ids:
            return 0
        clean_ids = [validate_execution_id(eid) for eid in execution_ids]
        deleted = 0
        with self._lock:
            conn = self._conn_or_init()
            try:
                conn.execute("BEGIN IMMEDIATE")
                for offset in range(0, len(clean_ids), 500):
                    chunk = clean_ids[offset : offset + 500]
                    placeholders = ", ".join("?" for _ in chunk)
                    cur = conn.execute(
                        f"DELETE FROM executions WHERE execution_id IN ({placeholders})",
                        chunk,
                    )
                    deleted += cur.rowcount
                conn.commit()
                return deleted
            except sqlite3.Error as exc:
                with suppress(sqlite3.Error):
                    conn.rollback()
                raise _translate_sqlite_error(exc, context="delete_executions") from exc
            finally:
                self._restrict_sqlite_files()

    def get_execution_row(self, execution_id: str) -> IndexedExecutionRow | None:
        """Fetch one execution metadata row from SQLite."""
        clean_id = validate_execution_id(execution_id)
        with self._lock:
            conn = self._conn_or_init()
            row = conn.execute(
                "SELECT * FROM executions WHERE execution_id = ?",
                (clean_id,),
            ).fetchone()
        return _row_to_execution(row) if row is not None else None

    def list_execution_rows(
        self,
        *,
        completeness: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        command_contains: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[IndexedExecutionRow, ...]:
        """List execution rows ordered newest-first with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if completeness is not None:
            clauses.append("capture_completeness = ?")
            params.append(completeness)
        if since is not None:
            clauses.append("started_at >= ?")
            params.append(since.astimezone(UTC).isoformat())
        if until is not None:
            clauses.append("started_at <= ?")
            params.append(until.astimezone(UTC).isoformat())
        if command_contains is not None:
            clauses.append("command_json LIKE ? ESCAPE '\\'")
            escaped = command_contains.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{escaped}%")

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT * FROM executions {where_sql} "
            "ORDER BY started_at DESC, rowid DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])

        with self._lock:
            conn = self._conn_or_init()
            rows = conn.execute(sql, params).fetchall()
        return tuple(_row_to_execution(r) for r in rows)

    def query_event_index(
        self,
        *,
        execution_id: str | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
        request_id: int | str | None = None,
        id_type: str | None = None,
        matched_request_event_id: str | None = None,
        kind: str | None = None,
        method: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> tuple[IndexedEventRow, ...]:
        """Query indexed events across execution, trace, span, request ID, and time range."""
        clauses: list[str] = []
        params: list[Any] = []

        if execution_id is not None:
            clauses.append("execution_id = ?")
            params.append(validate_execution_id(execution_id))
        if trace_id is not None:
            clauses.append("(observed_trace_id = ? OR synthetic_execution_trace_id = ?)")
            params.extend([trace_id, trace_id])
        if span_id is not None:
            clauses.append("observed_parent_span_id = ?")
            params.append(span_id)
        if matched_request_event_id is not None:
            clauses.append("(matched_request_event_id = ? OR event_id = ?)")
            params.extend([matched_request_event_id, matched_request_event_id])
        if request_id is not None:
            clauses.append("jsonrpc_id_text = ?")
            params.append(str(request_id))
        if id_type is not None:
            clauses.append("jsonrpc_id_type = ?")
            params.append(id_type)
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        if method is not None:
            clauses.append("method = ?")
            params.append(method)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since.astimezone(UTC).isoformat())
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(until.astimezone(UTC).isoformat())

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT * FROM events_index {where_sql} "
            "ORDER BY timestamp ASC, execution_id ASC, sequence ASC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])

        with self._lock:
            conn = self._conn_or_init()
            rows = conn.execute(sql, params).fetchall()
        return tuple(_row_to_event(r) for r in rows)

    def get_corruptions(self, execution_id: str) -> tuple[CorruptRecordReport, ...]:
        """Return persisted corruption reports indexed for ``execution_id``."""
        clean_id = validate_execution_id(execution_id)
        with self._lock:
            conn = self._conn_or_init()
            rows = conn.execute(
                """
                SELECT line_number, byte_offset, byte_length, issue_kind, excerpt_sha256, details
                FROM execution_corruptions
                WHERE execution_id = ?
                ORDER BY line_number ASC, id ASC
                """,
                (clean_id,),
            ).fetchall()
        return tuple(
            CorruptRecordReport(
                execution_id=clean_id,
                line_number=int(r["line_number"]),
                byte_offset=int(r["byte_offset"]),
                byte_length=int(r["byte_length"]),
                issue_kind=r["issue_kind"],
                excerpt_sha256=r["excerpt_sha256"] or "",
                details=r["details"],
            )
            for r in rows
        )


def _row_to_execution(row: sqlite3.Row) -> IndexedExecutionRow:
    return IndexedExecutionRow(
        execution_id=str(row["execution_id"]),
        schema_version=str(row["schema_version"]),
        storage_schema_version=str(row["storage_schema_version"]),
        started_at=datetime.fromisoformat(str(row["started_at"])),
        ended_at=datetime.fromisoformat(str(row["ended_at"])) if row["ended_at"] else None,
        duration_ns=int(row["duration_ns"]) if row["duration_ns"] is not None else None,
        command=tuple(json.loads(str(row["command_json"]))),
        cwd=str(row["cwd"]) if row["cwd"] is not None else None,
        transport=str(row["transport"]),
        redaction_mode=str(row["redaction_mode"]),
        backpressure_policy=str(row["backpressure_policy"]),
        capture_completeness=str(row["capture_completeness"]),
        termination_reason=(
            str(row["termination_reason"]) if row["termination_reason"] is not None else None
        ),
        exit_code=int(row["exit_code"]) if row["exit_code"] is not None else None,
        returncode=int(row["returncode"]) if row["returncode"] is not None else None,
        total_events=int(row["total_events"]),
        dropped_events=int(row["dropped_events"]),
        degraded_events=int(row["degraded_events"]),
        warning_count=int(row["warning_count"]),
        gap_count=int(row["gap_count"]),
        unanswered_request_ids=tuple(json.loads(str(row["unanswered_request_ids_json"]))),
        observed_trace_ids=tuple(json.loads(str(row["observed_trace_ids_json"]))),
        observed_mcp_versions=tuple(json.loads(str(row["observed_mcp_versions_json"]))),
        recording_dir=str(row["recording_dir"]),
        jsonl_byte_offset=int(row["jsonl_byte_offset"]),
        jsonl_sha256=str(row["jsonl_sha256"]) if row["jsonl_sha256"] is not None else None,
        last_indexed_sequence=int(row["last_indexed_sequence"]),
        index_status=str(row["index_status"]),
    )


def _row_to_event(row: sqlite3.Row) -> IndexedEventRow:
    raw_tool_err = row["tool_is_error"]
    tool_err: bool | None = None if raw_tool_err is None else bool(int(raw_tool_err))
    return IndexedEventRow(
        execution_id=str(row["execution_id"]),
        event_id=str(row["event_id"]),
        sequence=int(row["sequence"]),
        timestamp=datetime.fromisoformat(str(row["timestamp"])),
        monotonic_time_ns=int(row["monotonic_time_ns"]),
        direction=str(row["direction"]),
        kind=str(row["kind"]),
        method=str(row["method"]) if row["method"] is not None else None,
        jsonrpc_id_type=str(row["jsonrpc_id_type"]) if row["jsonrpc_id_type"] is not None else None,
        jsonrpc_id_text=str(row["jsonrpc_id_text"]) if row["jsonrpc_id_text"] is not None else None,
        observed_trace_id=(
            str(row["observed_trace_id"]) if row["observed_trace_id"] is not None else None
        ),
        observed_parent_span_id=(
            str(row["observed_parent_span_id"])
            if row["observed_parent_span_id"] is not None
            else None
        ),
        synthetic_execution_trace_id=(
            str(row["synthetic_execution_trace_id"])
            if row["synthetic_execution_trace_id"] is not None
            else None
        ),
        correlation_status=(
            str(row["correlation_status"]) if row["correlation_status"] is not None else None
        ),
        matched_request_event_id=(
            str(row["matched_request_event_id"])
            if row["matched_request_event_id"] is not None
            else None
        ),
        tool_is_error=tool_err,
        degraded=bool(int(row["degraded"])),
        jsonl_byte_offset=int(row["jsonl_byte_offset"]),
        jsonl_byte_length=int(row["jsonl_byte_length"]),
    )


__all__ = [
    "DB_FILE_NAME",
    "IndexedEventRow",
    "IndexedExecutionRow",
    "SQLiteMetadataStore",
    "SqliteSynchronousMode",
]
