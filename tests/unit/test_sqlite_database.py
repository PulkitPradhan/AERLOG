"""Unit tests for SQLiteMetadataStore, schema migrations, WAL permissions, and index queries."""

from __future__ import annotations

import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aerlog.capture import CaptureConfig, CapturePipeline, RawWireFrameInput
from aerlog.capture.redaction import REDACTED_MARKER
from aerlog.config import load_config
from aerlog.events import (
    CorrelationInfo,
    DerivedMetadata,
    ExecutionEvent,
    ExecutionHeader,
    ExecutionSummary,
    JsonRpcRequestPayload,
    JsonRpcResponsePayload,
    TraceContext,
    new_execution_id,
)
from aerlog.storage.database import SQLiteMetadataStore
from aerlog.storage.event_log import JsonlEventLogWriter
from aerlog.storage.exceptions import ExecutionNotFoundError, UnsupportedSchemaVersionError
from aerlog.storage.migrations import LATEST_DB_SCHEMA_VERSION
from aerlog.storage.repositories import RecordingRepository
from aerlog.storage.retention import RetentionPolicy, apply_retention, compact_database
from aerlog.storage.sink import PersistentCaptureSink


def test_sqlite_migrations_wal_and_sidecar_permissions_0o600(tmp_path: Path) -> None:
    """DB, WAL, and SHM sidecar files stay restricted to 0o600 with foreign keys & WAL enabled."""
    store = SQLiteMetadataStore(tmp_path)
    version = store.initialize()
    assert version == LATEST_DB_SCHEMA_VERSION

    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 17, 15, 0, tzinfo=UTC)
    header = ExecutionHeader(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=100,
        command=("python", "server.py", "--token", "raw_secret_token"),
        cwd="/home/bob/secret-repo",
    )
    store.insert_execution_start(header)

    if os.name == "posix":
        assert stat.S_IMODE(store.db_path.stat().st_mode) == 0o600
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{store.db_path}{suffix}")
            if sidecar.exists():
                assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600

    # Concurrent reader sees committed WAL rows and SQLite contains no raw command secrets or cwd.
    reader_conn = sqlite3.connect(str(store.db_path))
    row = reader_conn.execute(
        "SELECT command_json, cwd, recording_dir FROM executions WHERE execution_id = ?",
        (exec_id,),
    ).fetchone()
    reader_conn.close()
    assert row is not None
    assert "raw_secret_token" not in row[0]
    assert REDACTED_MARKER in row[0]
    assert row[1] is None
    assert row[2] == f"executions/{exec_id}"

    store.compact()
    store.close()
    if os.name == "posix":
        assert stat.S_IMODE(store.db_path.stat().st_mode) == 0o600


def test_rejects_database_with_newer_unknown_schema_version(tmp_path: Path) -> None:
    """Opening an existing database with a higher user_version fails explicitly."""
    db_path = tmp_path / "aerlog.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA user_version = 999")
    conn.close()

    store = SQLiteMetadataStore(tmp_path, db_path=db_path)
    with pytest.raises(UnsupportedSchemaVersionError):
        store.initialize()


def test_sqlite_index_queries_cover_trace_span_request_id_and_time_range(tmp_path: Path) -> None:
    """Indexes accurately filter by execution, trace, span, request_id/id_type, and time range."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 17, 20, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=1)
    t2 = t0 + timedelta(seconds=2)

    header = ExecutionHeader(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=100,
        command=("server.py",),
    )
    req_int = ExecutionEvent(
        execution_id=exec_id,
        sequence=1,
        timestamp=t0,
        monotonic_time_ns=100,
        direction="client_to_server",
        kind="jsonrpc_request",
        trace=TraceContext(
            trace_source="w3c_meta",
            observed_trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
            observed_parent_span_id="00f067aa0ba902b7",
        ),
        payload=JsonRpcRequestPayload(
            id=1,
            id_type="int",
            method="tools/call",
            has_params=True,
            params={"name": "echo", "api_key": REDACTED_MARKER},
        ),
    )
    req_str = ExecutionEvent(
        execution_id=exec_id,
        sequence=2,
        timestamp=t1,
        monotonic_time_ns=200,
        direction="client_to_server",
        kind="jsonrpc_request",
        payload=JsonRpcRequestPayload(id="1", id_type="str", method="tools/list"),
    )
    resp_int = ExecutionEvent(
        execution_id=exec_id,
        sequence=3,
        timestamp=t2,
        monotonic_time_ns=350,
        direction="server_to_client",
        kind="jsonrpc_response",
        trace=TraceContext(
            trace_source="w3c_meta",
            observed_trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
            observed_parent_span_id="00f067aa0ba902b7",
        ),
        correlation=CorrelationInfo(
            status="matched",
            confidence="exact",
            basis="exact_opposite_direction_id",
            matched_request_event_id=req_int.event_id,
            matched_request_sequence=1,
            matched_request_method="tools/call",
            origin_direction="client_to_server",
            latency_ns=250,
        ),
        derived=DerivedMetadata(tool_is_error=False),
        payload=JsonRpcResponsePayload(id=1, id_type="int", result={"ok": True}),
    )

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    slices = writer.append_events([req_int, req_str, resp_int])
    summary = ExecutionSummary(
        execution_id=exec_id,
        started_at=t0,
        ended_at=t2,
        duration_ns=250,
        command=("server.py",),
        capture_completeness="complete",
        termination_reason="completed",
        exit_code=0,
        returncode=0,
        total_events=3,
        observed_trace_ids=("4bf92f3577b34da6a3ce929d0e0e4736",),
    )
    manifest = writer.finalize(summary)
    writer.close()

    store = SQLiteMetadataStore(tmp_path)
    store.initialize()
    store.insert_execution_start(header)
    store.insert_event_slices(exec_id, slices)
    store.update_execution_finish(
        summary,
        jsonl_byte_offset=manifest.byte_size,
        jsonl_sha256=manifest.events_file_sha256,
    )

    by_trace = store.query_event_index(trace_id="4bf92f3577b34da6a3ce929d0e0e4736")
    assert [r.sequence for r in by_trace] == [1, 3]

    by_span = store.query_event_index(span_id="00f067aa0ba902b7")
    assert [r.sequence for r in by_span] == [1, 3]

    by_req_int = store.query_event_index(execution_id=exec_id, request_id=1, id_type="int")
    assert [r.sequence for r in by_req_int] == [1, 3]

    by_req_str = store.query_event_index(execution_id=exec_id, request_id="1", id_type="str")
    assert [r.sequence for r in by_req_str] == [2]

    by_corr = store.query_event_index(matched_request_event_id=req_int.event_id)
    assert [r.sequence for r in by_corr] == [1, 3]

    by_time = store.query_event_index(execution_id=exec_id, since=t1, until=t2)
    assert [r.sequence for r in by_time] == [2, 3]

    listed = store.list_execution_rows(completeness="complete")
    assert len(listed) == 1
    assert listed[0].execution_id == exec_id

    repo = RecordingRepository(tmp_path, store=store)
    record = repo.get_execution(exec_id)
    assert record.diverged is False
    assert record.jsonl_exists is True
    assert record.summary is not None

    hydrated = repo.query_events(execution_id=exec_id, request_id=1, id_type="int")
    assert [e.sequence for e in hydrated.events] == [1, 3]
    assert isinstance(hydrated.events[0].payload, JsonRpcRequestPayload)
    assert hydrated.events[0].payload.params["name"] == "echo"

    with pytest.raises(ExecutionNotFoundError):
        repo.get_execution(new_execution_id())

    store.close()


async def test_persistent_capture_sink_integrates_with_capture_pipeline_and_config(
    tmp_path: Path,
) -> None:
    """CapturePipeline + PersistentCaptureSink persists redacted logs cleanly off-loop."""
    import json

    cfg_path = tmp_path / "aerlog.toml"
    cfg_path.write_text(
        '[storage]\nfsync_policy = "every_batch"\npersist_cwd = false\n',
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    assert cfg.storage.fsync_policy == "every_batch"
    assert cfg.storage.persist_cwd is False

    data_dir = tmp_path / "data"
    sink = PersistentCaptureSink(
        data_dir,
        fsync_policy=cfg.storage.fsync_policy,
        sqlite_synchronous=cfg.storage.sqlite_synchronous,
        persist_cwd=cfg.storage.persist_cwd,
    )
    pipeline = CapturePipeline(
        sink,
        command=("python", "server.py", "--api-key", "sk-secret-cli-flag-9999"),
        cwd="/home/alice/secret-workspace",
        env_overrides={"SECRET_ENV": "topsecret_env_value"},
        config=CaptureConfig(),
    )
    await pipeline.start()
    frame = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {"name": "demo", "arguments": {"password": "hunter2_password"}},
            }
        )
        + "\n"
    ).encode("utf-8")
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=datetime.now(UTC),
            monotonic_time_ns=5_000,
            direction="client_to_server",
            raw_frame=frame,
        )
    )
    summary = await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)
    assert summary.capture_completeness == "complete"

    repo = RecordingRepository(data_dir)
    repo.initialize()
    rec = repo.get_execution(summary.execution_id)
    assert rec.diverged is False
    assert rec.summary is not None
    assert rec.summary.capture_completeness == "complete"

    # Verify zero secrets, zero env overrides, and zero private cwd on disk or in SQLite.
    exec_dir = data_dir / "executions" / summary.execution_id
    for artifact in (
        exec_dir / "events.jsonl",
        exec_dir / "execution.json",
        exec_dir / "manifest.json",
    ):
        text = artifact.read_text(encoding="utf-8")
        assert "sk-secret-cli-flag-9999" not in text
        assert "SECRET_ENV" not in text
        assert "topsecret_env_value" not in text
        assert "hunter2_password" not in text
        assert "/home/alice/secret-workspace" not in text

    res = repo.get_execution_events(summary.execution_id)
    assert not res.has_corruptions
    assert res.events[-1].event.kind == "execution_finished"
    repo.close()


def test_retention_defaults_dry_run_protects_recording_and_requires_confirm(
    tmp_path: Path,
) -> None:
    """Retention defaults to dry_run=True, protects active/incomplete runs, and compacts DB."""
    data_dir = tmp_path / "ret_data"
    store = SQLiteMetadataStore(data_dir)
    store.initialize()

    base = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)
    ids: list[str] = []
    for idx, completeness in enumerate(["complete", "complete", "incomplete", "recording"]):
        eid = new_execution_id()
        ids.append(eid)
        ts = base + timedelta(days=idx)
        hdr = ExecutionHeader(
            execution_id=eid,
            started_at=ts,
            monotonic_start_ns=100,
            command=("server.py",),
        )
        writer = JsonlEventLogWriter(data_dir, eid)
        writer.open(hdr)
        ev = ExecutionEvent(
            execution_id=eid,
            sequence=1,
            timestamp=ts,
            monotonic_time_ns=100,
            direction="proxy",
            kind="jsonrpc_request",
            payload=JsonRpcRequestPayload(id=1, id_type="int", method="ping"),
        )
        slices = writer.append_events([ev])
        store.insert_execution_start(hdr)
        store.insert_event_slices(eid, slices)

        if completeness != "recording":
            smry = ExecutionSummary(
                execution_id=eid,
                started_at=ts,
                ended_at=ts,
                duration_ns=10,
                command=("server.py",),
                capture_completeness=completeness,  # type: ignore[arg-type]
                termination_reason="completed",
                exit_code=0,
                total_events=1,
            )
            manifest = writer.finalize(smry)
            store.update_execution_finish(
                smry,
                jsonl_byte_offset=manifest.byte_size,
                jsonl_sha256=manifest.events_file_sha256,
            )
        writer.close()

    # Default policy has dry_run=True -> zero deletions
    dry_report = apply_retention(
        data_dir,
        store,
        RetentionPolicy(max_executions=1, protect_incomplete=True),
    )
    assert dry_report.dry_run is True
    assert dry_report.candidate_execution_ids == (ids[0],)
    assert dry_report.deleted_execution_ids == ()
    assert set(dry_report.protected_execution_ids) == {ids[2], ids[3]}
    assert (data_dir / "executions" / ids[0]).exists()

    # Destructive run without confirm=True must fail explicitly
    with pytest.raises(ValueError, match="confirm=True"):
        apply_retention(
            data_dir,
            store,
            RetentionPolicy(max_executions=1, dry_run=False),
            confirm=False,
        )

    # Confirmed deletion deletes ONLY oldest completed run, keeps incomplete & active recording.
    applied = apply_retention(
        data_dir,
        store,
        RetentionPolicy(max_executions=1, dry_run=False),
        confirm=True,
        vacuum=True,
    )
    assert applied.deleted_execution_ids == (ids[0],)
    assert applied.compacted is True
    assert not (data_dir / "executions" / ids[0]).exists()
    assert (data_dir / "executions" / ids[1]).exists()
    assert (data_dir / "executions" / ids[2]).exists()
    assert (data_dir / "executions" / ids[3]).exists()

    compact_database(store)
    store.close()
