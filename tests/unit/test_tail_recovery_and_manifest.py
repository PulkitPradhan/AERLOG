"""Unit tests for Gate 1D (F-06): Data-preserving tail recovery & manifest consistency."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from aerlog.capture.normalizer import EventNormalizer, RawWireFrameInput
from aerlog.capture.redaction import RedactionConfig
from aerlog.capture.sinks import RecoverySpool
from aerlog.events import new_event_id, new_execution_id
from aerlog.events.models import (
    CaptureGapPayload,
    CorrelationInfo,
    ExecutionEvent,
    ExecutionFinishedPayload,
    ExecutionHeader,
    ExecutionStartedPayload,
    ExecutionSummary,
    JsonRpcRequestPayload,
    RedactionSummary,
    TraceContext,
    WireFrameInfo,
)
from aerlog.events.types import RedactionMode
from aerlog.storage import (
    EVENTS_FILE_NAME,
    MANIFEST_FILE_NAME,
    JsonlEventLogReader,
    JsonlEventLogWriter,
    RecordingRepository,
    StorageCorruptionError,
    StorageWriteError,
    UnsupportedSchemaVersionError,
)
from aerlog.storage.event_log import TailPolicy, resolve_execution_dir, write_atomic_private_json


def _make_header(exec_id: str, started_at: datetime | None = None) -> ExecutionHeader:
    t0 = started_at or datetime(2026, 11, 13, 4, 0, 0, tzinfo=UTC)
    return ExecutionHeader(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("test-server", "--flag"),
        redaction_mode="standard",
        backpressure_policy="spill",
    )


def _make_summary(
    exec_id: str,
    started_at: datetime | None = None,
    completeness: str = "complete",
) -> ExecutionSummary:
    t0 = started_at or datetime(2026, 11, 13, 4, 0, 0, tzinfo=UTC)
    t1 = datetime(2026, 11, 13, 4, 0, 10, tzinfo=UTC)
    return ExecutionSummary(
        execution_id=exec_id,
        started_at=t0,
        ended_at=t1,
        duration_ns=10_000_000_000,
        termination_reason="clean_exit",
        total_events=3,
        exit_code=0,
        capture_completeness=completeness,  # type: ignore[arg-type]
        command=("test-server", "--flag"),
        redaction_mode="standard",
    )


def _make_event(
    exec_id: str,
    seq: int,
    *,
    event_id: str | None = None,
    timestamp: datetime | None = None,
    method: str = "tools/call",
) -> ExecutionEvent:
    t = timestamp or datetime(2026, 11, 13, 4, 0, seq, tzinfo=UTC)
    return ExecutionEvent(
        execution_id=exec_id,
        sequence=seq,
        event_id=event_id or new_event_id(),
        timestamp=t,
        monotonic_time_ns=seq * 1_000_000,
        direction="client_to_server",
        kind="jsonrpc_request",
        redaction=RedactionSummary(mode="standard", payload_mode="redacted", applied=True),
        payload=JsonRpcRequestPayload(
            id=seq,
            id_type="int",
            method=method,
            has_params=True,
            params={"seq": seq},
        ),
    )


# -----------------------------------------------------------------------------
# 1. Parse failure preservation: A tail record remains intact after parse failure
# -----------------------------------------------------------------------------
def test_parse_failure_preservation_tail_not_truncated(tmp_path: Path) -> None:
    """A tail record remains intact after parsing fails; it is not truncated or discarded."""
    exec_id = new_execution_id()
    header = _make_header(exec_id)
    ev1 = _make_event(exec_id, 1)
    ev2 = _make_event(exec_id, 2)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events([ev1, ev2])
    writer.close()

    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    events_path = exec_dir / EVENTS_FILE_NAME
    original_bytes = events_path.read_bytes()

    # Append a corrupted tail record (invalid JSON wrapper ending with newline)
    corrupted_tail = b'{"record_schema_version": "1.0.0", "record_type": "event", "bad_json": \n'
    events_path.write_bytes(original_bytes + corrupted_tail)
    corrupted_total_bytes = events_path.read_bytes()

    # Reader reports corruption
    reader = JsonlEventLogReader(tmp_path)
    res = reader.read_execution(exec_id, strict=False)
    assert res.has_corruptions is True
    assert len(res.corruptions) == 1
    assert [e.event.sequence for e in res.events] == [1, 2]

    # Attempting recovery under reject policy must raise without truncating
    repo = RecordingRepository(tmp_path)
    with pytest.raises(StorageCorruptionError):
        repo.recover_tail(exec_id, tail_policy="reject")

    # Verify bytes on disk remain completely intact (NOT truncated)
    assert events_path.read_bytes() == corrupted_total_bytes
    repo.close()


# -----------------------------------------------------------------------------
# 2. Incomplete trailing line: Retained and combined with the next append
# -----------------------------------------------------------------------------
def test_incomplete_trailing_line_retained_and_combined_on_next_append(
    tmp_path: Path,
) -> None:
    """An incomplete final JSON line is retained and correctly combined with the next append."""
    exec_id = new_execution_id()
    header = _make_header(exec_id)
    ev1 = _make_event(exec_id, 1)
    ev2 = _make_event(exec_id, 2)
    ev3 = _make_event(exec_id, 3)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events([ev1, ev2])
    writer.close()

    # Simulate crash mid-write of event 3:
    # First serialize event 3 to see its exact full line bytes
    probe_writer = JsonlEventLogWriter(tmp_path / "probe", exec_id)
    probe_writer.open(header)
    probe_writer.append_events([ev3])
    probe_writer.close()
    probe_path = resolve_execution_dir(tmp_path / "probe", exec_id) / EVENTS_FILE_NAME
    ev3_full_line = probe_path.read_bytes()

    # Write the first 45 bytes of event 3 (without newline) onto the target events.jsonl
    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    events_path = exec_dir / EVENTS_FILE_NAME
    initial_bytes = events_path.read_bytes()
    partial_frag = ev3_full_line[:45]
    events_path.write_bytes(initial_bytes + partial_frag)

    # Next append cycle opens writer and appends ev3
    writer2 = JsonlEventLogWriter(
        tmp_path,
        exec_id,
        seed_line_count=2,
        seed_last_sequence=2,
    )
    writer2.open(header)
    assert writer2._retained_tail == partial_frag

    # Appending ev3 combines the retained tail and writes only the missing suffix
    appended_slices = writer2.append_events([ev3])
    assert len(appended_slices) == 1
    assert appended_slices[0].byte_length == len(ev3_full_line)
    summary = _make_summary(exec_id)
    manifest = writer2.finalize(summary)
    writer2.close()

    # Verify events.jsonl on disk: 3 valid lines, zero byte duplication
    reader = JsonlEventLogReader(tmp_path)
    res = reader.read_execution(exec_id, strict=True)
    assert res.has_corruptions is False
    assert len(res.events) == 3
    assert [e.event.sequence for e in res.events] == [1, 2, 3]

    # Verify file content is exact concatenation of clean lines without duplicate bytes
    expected_bytes = initial_bytes + ev3_full_line
    assert events_path.read_bytes() == expected_bytes
    assert manifest.line_count == 3
    assert manifest.last_sequence == 3


def test_incomplete_trailing_fragment_combined_via_append_tail_fragment(
    tmp_path: Path,
) -> None:
    """Calling append_tail_fragment completes an unterminated tail line cleanly."""
    exec_id = new_execution_id()
    header = _make_header(exec_id)
    ev1 = _make_event(exec_id, 1)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events([ev1])
    writer.close()

    # Create event 2 line
    probe = JsonlEventLogWriter(tmp_path / "probe2", exec_id)
    probe.open(header)
    probe.append_events([_make_event(exec_id, 2)])
    probe.close()
    ev2_line = (resolve_execution_dir(tmp_path / "probe2", exec_id) / EVENTS_FILE_NAME).read_bytes()

    # Append first 30 bytes
    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    events_path = exec_dir / EVENTS_FILE_NAME
    base_bytes = events_path.read_bytes()
    events_path.write_bytes(base_bytes + ev2_line[:30])

    writer2 = JsonlEventLogWriter(tmp_path, exec_id, seed_line_count=1, seed_last_sequence=1)
    writer2.open(header)
    # Feed the remaining fragment
    completed_slice = writer2.append_tail_fragment(ev2_line[30:])
    assert completed_slice is not None
    assert completed_slice.event.sequence == 2
    writer2.close()

    reader = JsonlEventLogReader(tmp_path)
    read_res = reader.read_execution(exec_id, strict=True)
    assert [e.event.sequence for e in read_res.events] == [1, 2]


# -----------------------------------------------------------------------------
# 3. Sequence continuity: Manifest sequence continuity is validated before accept
# -----------------------------------------------------------------------------
def test_sequence_continuity_validated_before_accepting_recovered_tail(
    tmp_path: Path,
) -> None:
    """Discontinuous sequence numbers in recovered tails are rejected or quarantined."""
    exec_id = new_execution_id()
    header = _make_header(exec_id)
    ev1 = _make_event(exec_id, 1)
    ev2 = _make_event(exec_id, 2)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events([ev1, ev2])
    writer.close()

    # Spool contains sequence 5 (gap: 3 and 4 are missing!)
    ev5 = _make_event(exec_id, 5)
    spool_path = tmp_path / f"{exec_id}.ndjson.spool"
    spool_lines = [
        json.dumps({"record_type": "header", "data": header.model_dump(mode="json")}),
        json.dumps({"record_type": "event", "data": ev5.model_dump(mode="json")}),
    ]
    spool_path.write_text("\n".join(spool_lines) + "\n", encoding="utf-8")

    repo = RecordingRepository(tmp_path)

    # Under reject policy: raises StorageCorruptionError, manifest untouched
    with pytest.raises(StorageCorruptionError, match="Sequence gap"):
        repo.import_recovery_spool(spool_path, tail_policy="reject")

    rec = repo.get_execution(exec_id)
    assert rec.manifest is not None
    assert rec.manifest.last_sequence == 2
    assert rec.manifest.line_count == 2

    # Under quarantine policy: discontinuous events are quarantined, not accepted into log
    report = repo.import_recovery_spool(spool_path, tail_policy="quarantine")
    assert report.imported_events == 0
    assert report.final_status == "incomplete"
    assert any(c.issue_kind == "sequence_gap" for c in report.corrupt_lines)

    # Manifest remains at last_sequence 2
    rec2 = repo.get_execution(exec_id)
    assert rec2.manifest is not None
    assert rec2.manifest.last_sequence == 2
    assert rec2.manifest.line_count == 2

    # Quarantine artifact was persisted
    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    q_files = list(exec_dir.glob("corrupted_tail_*.quarantine"))
    assert len(q_files) >= 1
    repo.close()


# -----------------------------------------------------------------------------
# 4. Event ID uniqueness: Duplicate event_id values detected and rejected/spilled
# -----------------------------------------------------------------------------
def test_event_id_uniqueness_detected_and_rejected_or_spilled(tmp_path: Path) -> None:
    """Duplicate event_id values with conflicting sequences are rejected or quarantined."""
    exec_id = new_execution_id()
    header = _make_header(exec_id)
    shared_id = new_event_id()
    ev1 = _make_event(exec_id, 1, event_id=shared_id)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events([ev1])
    writer.close()

    # Spool contains sequence 2 with the SAME event_id as sequence 1!
    ev2_dup_id = _make_event(exec_id, 2, event_id=shared_id)
    spool_path = tmp_path / f"{exec_id}.ndjson.spool"
    spool_lines = [
        json.dumps({"record_type": "header", "data": header.model_dump(mode="json")}),
        json.dumps({"record_type": "event", "data": ev2_dup_id.model_dump(mode="json")}),
    ]
    spool_path.write_text("\n".join(spool_lines) + "\n", encoding="utf-8")

    repo = RecordingRepository(tmp_path)

    # Under reject: raises StorageCorruptionError
    with pytest.raises(StorageCorruptionError, match="Duplicate event_id"):
        repo.import_recovery_spool(spool_path, tail_policy="reject")

    # Under quarantine: quarantined, not accepted into log
    report = repo.import_recovery_spool(spool_path, tail_policy="quarantine")
    assert report.imported_events == 0
    assert report.final_status == "incomplete"
    assert any(c.issue_kind == "event_validation_failed" for c in report.corrupt_lines)

    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    q_files = list(exec_dir.glob("corrupted_tail_*.quarantine"))
    assert len(q_files) >= 1
    repo.close()


# -----------------------------------------------------------------------------
# 5. Inconsistent tail handling: Spilled or rejected, never silently dropped
# -----------------------------------------------------------------------------
def test_inconsistent_tail_handling_quarantine_and_reject_policies(
    tmp_path: Path,
) -> None:
    """An inconsistent tail is spilled or rejected, never silently dropped."""
    exec_id = new_execution_id()
    header = _make_header(exec_id)
    ev1 = _make_event(exec_id, 1)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events([ev1])
    writer.close()

    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    events_path = exec_dir / EVENTS_FILE_NAME
    base_bytes = events_path.read_bytes()

    # Append corrupt partial tail bytes (no newline)
    corrupt_tail = b'{"corrupted_tail_token": \xff\xfe'
    events_path.write_bytes(base_bytes + corrupt_tail)

    repo = RecordingRepository(tmp_path)

    # Policy 'reject' leaves file untouched and raises
    with pytest.raises(StorageCorruptionError):
        repo.recover_tail(exec_id, tail_policy="reject")
    assert events_path.read_bytes() == base_bytes + corrupt_tail

    # Policy 'quarantine' spills raw bytes and rewinds log
    res = repo.recover_tail(exec_id, tail_policy="quarantine")
    assert res.action_taken == "quarantined"
    assert res.quarantine_path is not None
    assert res.quarantine_path.exists()
    assert res.quarantine_path.read_bytes() == corrupt_tail

    # Verify permissions of quarantine artifact
    if os.name == "posix":
        assert stat.S_IMODE(res.quarantine_path.stat().st_mode) == 0o600

    # Companion metadata sidecar exists
    meta_path = res.quarantine_path.with_suffix(".meta.json")
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["execution_id"] == exec_id
    assert meta["byte_length"] == len(corrupt_tail)

    # Log is rewound to valid prefix ending cleanly at newline
    assert events_path.read_bytes() == base_bytes
    rec = repo.get_execution(exec_id)
    assert rec.manifest is not None
    assert rec.manifest.status == "incomplete"
    assert rec.manifest.corruption_count == 1
    repo.close()


def test_unterminated_valid_tail_record_completed_with_newline(tmp_path: Path) -> None:
    """A valid JSONL tail record missing only the trailing newline is cleanly completed."""
    exec_id = new_execution_id()
    header = _make_header(exec_id)
    ev1 = _make_event(exec_id, 1)
    ev2 = _make_event(exec_id, 2)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events([ev1])
    writer.close()

    # Get valid ev2 line bytes
    probe = JsonlEventLogWriter(tmp_path / "probe_v", exec_id)
    probe.open(header)
    probe.append_events([ev2])
    probe.close()
    ev2_line_full = (
        resolve_execution_dir(tmp_path / "probe_v", exec_id) / EVENTS_FILE_NAME
    ).read_bytes()
    # Strip the trailing newline
    assert ev2_line_full.endswith(b"\n")
    ev2_unterminated = ev2_line_full[:-1]

    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    events_path = exec_dir / EVENTS_FILE_NAME
    base_bytes = events_path.read_bytes()
    events_path.write_bytes(base_bytes + ev2_unterminated)

    repo = RecordingRepository(tmp_path)
    res = repo.recover_tail(exec_id, tail_policy="quarantine")
    assert res.action_taken == "completed_newline"
    assert res.recovered_event is not None
    assert res.recovered_event.sequence == 2

    # Verify events.jsonl now ends with \n and has 2 valid events
    assert events_path.read_bytes() == base_bytes + ev2_line_full
    rec = repo.get_execution(exec_id)
    assert rec.manifest is not None
    assert rec.manifest.line_count == 2
    assert rec.manifest.last_sequence == 2
    repo.close()


# -----------------------------------------------------------------------------
# 6. Valid spool compatibility: Existing valid recovery-spool records unaffected
# -----------------------------------------------------------------------------
def test_valid_spool_compatibility_unaffected_by_tail_logic(tmp_path: Path) -> None:
    """Existing valid recovery-spool records remain completely unaffected by the new tail logic."""
    exec_id = new_execution_id()
    header = _make_header(exec_id)
    ev1 = _make_event(exec_id, 1)
    ev2 = _make_event(exec_id, 2)
    summary = _make_summary(exec_id).model_copy(update={"returncode": 0})
    ev3 = ExecutionEvent(
        execution_id=exec_id,
        sequence=3,
        event_id=new_event_id(),
        timestamp=summary.ended_at,
        monotonic_time_ns=3_000_000,
        direction="proxy",
        kind="execution_finished",
        payload=ExecutionFinishedPayload(
            termination_reason="clean_exit",
            exit_code=0,
            returncode=0,
            total_events=3,
            completeness="complete",
        ),
    )
    # Event 1 already written
    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events([ev1])
    writer.close()

    # Spool contains Event 1 (duplicate to skip), Event 2, Event 3, and Summary
    spool_path = tmp_path / f"{exec_id}.ndjson.spool"
    spool_lines = [
        json.dumps({"record_type": "header", "data": header.model_dump(mode="json")}),
        json.dumps({"record_type": "event", "data": ev1.model_dump(mode="json")}),
        json.dumps({"record_type": "event", "data": ev2.model_dump(mode="json")}),
        json.dumps({"record_type": "event", "data": ev3.model_dump(mode="json")}),
        json.dumps({"record_type": "summary", "data": summary.model_dump(mode="json")}),
    ]
    spool_path.write_text("\n".join(spool_lines) + "\n", encoding="utf-8")

    repo = RecordingRepository(tmp_path)
    report = repo.import_recovery_spool(spool_path, redaction_mode="standard")

    assert report.execution_id == exec_id
    assert report.imported_events == 2
    assert report.skipped_duplicates == 1
    assert len(report.corrupt_lines) == 0
    assert report.final_status == "complete"

    rec = repo.get_execution(exec_id)
    assert rec.manifest is not None
    assert rec.manifest.line_count == 3
    assert rec.manifest.last_sequence == 3
    assert rec.manifest.status == "finalized"

    events_res = repo.get_execution_events(exec_id)
    assert [e.event.sequence for e in events_res.events] == [1, 2, 3]
    original = _stored_bytes(tmp_path, exec_id)
    retry = repo.import_recovery_spool(spool_path)
    assert retry.imported_events == 0
    assert retry.skipped_duplicates == 3
    assert _stored_bytes(tmp_path, exec_id) == original
    repo.close()


# -----------------------------------------------------------------------------
# 7. Repeated recovery: Idempotent, no duplication, loss, or corruption
# -----------------------------------------------------------------------------
def test_repeated_recovery_idempotence_no_duplication_or_corruption(
    tmp_path: Path,
) -> None:
    """Running recovery more than once does not duplicate, lose, or corrupt retained bytes."""
    exec_id = new_execution_id()
    header = _make_header(exec_id)
    ev1 = _make_event(exec_id, 1)
    ev2 = _make_event(exec_id, 2)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events([ev1])
    writer.close()

    spool_path = tmp_path / f"{exec_id}.ndjson.spool"
    spool_lines = [
        json.dumps({"record_type": "header", "data": header.model_dump(mode="json")}),
        json.dumps({"record_type": "event", "data": ev1.model_dump(mode="json")}),
        json.dumps({"record_type": "event", "data": ev2.model_dump(mode="json")}),
    ]
    spool_path.write_text("\n".join(spool_lines) + "\n", encoding="utf-8")

    repo = RecordingRepository(tmp_path)
    report1 = repo.import_recovery_spool(spool_path)
    assert report1.imported_events == 1
    assert report1.skipped_duplicates == 1

    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    events_path = exec_dir / EVENTS_FILE_NAME
    bytes_after_first = events_path.read_bytes()
    manifest_after_first = (exec_dir / MANIFEST_FILE_NAME).read_text(encoding="utf-8")

    # Second recovery pass
    report2 = repo.import_recovery_spool(spool_path)
    assert report2.imported_events == 0
    assert report2.skipped_duplicates == 2

    # Assert exact byte preservation and identical manifest
    assert events_path.read_bytes() == bytes_after_first
    assert (exec_dir / MANIFEST_FILE_NAME).read_text(encoding="utf-8") == manifest_after_first
    repo.close()


# -----------------------------------------------------------------------------
# 8. Failure safety: Error during recovery does not corrupt manifest or tail
# -----------------------------------------------------------------------------
def test_failure_safety_atomic_manifest_and_tail_preservation(tmp_path: Path) -> None:
    """An error during recovery preserves original manifest and tail intact."""
    exec_id = new_execution_id()
    header = _make_header(exec_id)
    ev1 = _make_event(exec_id, 1)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events([ev1])
    writer.close()

    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    manifest_path = exec_dir / MANIFEST_FILE_NAME
    events_path = exec_dir / EVENTS_FILE_NAME
    initial_manifest = manifest_path.read_text(encoding="utf-8")
    initial_events = events_path.read_bytes()

    # Append a corrupt tail
    corrupt_tail = b'{"broken_tail": true'
    events_path.write_bytes(initial_events + corrupt_tail)
    corrupted_total = events_path.read_bytes()

    repo = RecordingRepository(tmp_path)

    # Simulate atomic write failure during quarantine / recovery
    with (
        patch(
            "aerlog.storage.event_log.write_atomic_private_json",
            side_effect=StorageWriteError("Simulated disk error"),
        ),
        pytest.raises(StorageWriteError),
    ):
        repo.recover_tail(exec_id, tail_policy="quarantine")

    # Verify manifest was NOT left in a half-written/corrupted state
    assert manifest_path.read_text(encoding="utf-8") == initial_manifest
    # Verify events.jsonl still preserves the tail bytes
    assert events_path.read_bytes() == corrupted_total
    repo.close()


def _write_event_spool(
    path: Path, *events: ExecutionEvent | dict[str, Any], summary: ExecutionSummary | None = None
) -> Path:
    records = [
        {
            "record_type": "event",
            "data": event.model_dump(mode="json") if isinstance(event, ExecutionEvent) else event,
        }
        for event in events
    ]
    if summary is not None:
        records.append({"record_type": "summary", "data": summary.model_dump(mode="json")})
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def _stored_bytes(data_dir: Path, execution_id: str) -> dict[str, bytes]:
    return {
        name: (data_dir / "executions" / execution_id / name).read_bytes()
        for name in (EVENTS_FILE_NAME, "execution.json", MANIFEST_FILE_NAME)
    }


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
@pytest.mark.parametrize(
    "change",
    ["cross-pair", "different-id", "payload", "timing", "wire", "trace", "correlation", "outcome"],
)
def test_import_conflicting_persisted_event(
    tmp_path: Path, policy: TailPolicy, change: str
) -> None:
    eid = new_execution_id()
    first = _make_event(eid, 1).model_copy(
        update={"wire": WireFrameInfo(byte_length=10, line_ending="lf", sha256="a" * 64)}
    )
    second = ExecutionEvent(
        execution_id=eid,
        sequence=2,
        timestamp=first.timestamp,
        monotonic_time_ns=2_000_000,
        direction="proxy",
        kind="execution_finished",
        payload=ExecutionFinishedPayload(
            termination_reason="clean_exit", exit_code=0, total_events=2, completeness="complete"
        ),
    )
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(_make_header(eid))
    writer.append_events([first, second])
    summary = _make_summary(eid).model_copy(update={"total_events": 2})
    writer.finalize(summary)
    writer.close()

    edits: dict[str, dict[str, Any]] = {
        "cross-pair": {"sequence": 2},
        "different-id": {"event_id": new_event_id()},
        "payload": {"payload": first.payload.model_copy(update={"method": "changed"})},
        "timing": {"monotonic_time_ns": 100},
        "wire": {"wire": WireFrameInfo(byte_length=10, line_ending="lf", sha256="b" * 64)},
        "trace": {"trace": TraceContext(synthetic_execution_trace_id="changed")},
        "correlation": {
            "correlation": CorrelationInfo(status="invalid_id", confidence="none", basis="changed")
        },
        "outcome": {"payload": second.payload.model_copy(update={"exit_code": 77})},
    }
    original_event = second if change == "outcome" else first
    spool = _write_event_spool(
        tmp_path / "events.spool", original_event.model_copy(update=edits[change]), summary=summary
    )
    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        original = _stored_bytes(tmp_path, eid)
        row = repo.store.get_execution_row(eid)
        rows = repo.store.query_event_index(execution_id=eid)
        if policy == "reject":
            db = tmp_path / "aerlog.db"
            wal = tmp_path / "aerlog.db-wal"
            before_db = {p: p.read_bytes() for p in (db, wal) if p.exists()}
            with pytest.raises(StorageCorruptionError, match="conflict"):
                repo.import_recovery_spool(spool, tail_policy=policy)
            assert {p: p.read_bytes() for p in before_db} == before_db
        else:
            report = repo.import_recovery_spool(spool, tail_policy=policy)
            assert (report.imported_events, report.skipped_duplicates, report.final_status) == (
                0,
                0,
                "incomplete",
            )
            assert len(report.corrupt_lines) == 1
            assert list(writer.execution_dir.glob("*.quarantine"))
        assert _stored_bytes(tmp_path, eid) == original
        assert repo.store.get_execution_row(eid) == row
        assert repo.store.query_event_index(execution_id=eid) == rows
    finally:
        repo.close()


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_import_duplicate_and_conflict_within_spool(tmp_path: Path, policy: TailPolicy) -> None:
    eid = new_execution_id()
    event = _make_event(eid, 1)
    changed = event.model_copy(update={"payload": event.payload.model_copy(update={"id": 99})})
    spool = _write_event_spool(tmp_path / "events.spool", event, event, changed)
    repo = RecordingRepository(tmp_path)
    try:
        if policy == "reject":
            with pytest.raises(StorageCorruptionError, match="conflict"):
                repo.import_recovery_spool(spool, tail_policy=policy)
            assert not resolve_execution_dir(tmp_path, eid).exists()
            assert not repo.store.db_path.exists()
        else:
            report = repo.import_recovery_spool(spool, tail_policy=policy)
            assert (
                report.imported_events
                == report.skipped_duplicates
                == len(report.corrupt_lines)
                == 1
            )
            assert report.final_status == "incomplete"
            assert [item.event for item in repo.get_execution_events(eid).events] == [event]
    finally:
        repo.close()


@pytest.mark.parametrize("unterminated", [False, True])
@pytest.mark.parametrize("repeated", ["id", "sequence"])
def test_import_refuses_ambiguous_destination_identity(
    tmp_path: Path, repeated: str, unterminated: bool
) -> None:
    eid = new_execution_id()
    first = _make_event(eid, 1)
    second = (
        _make_event(eid, 2, event_id=first.event_id) if repeated == "id" else _make_event(eid, 1)
    )
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(_make_header(eid))
    writer.append_events([first, second])
    writer.close()
    if unterminated:
        writer.events_path.write_bytes(writer.events_path.read_bytes()[:-1])
    original = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(tmp_path / "events.spool", first)
    repo = RecordingRepository(tmp_path)
    try:
        with pytest.raises(StorageCorruptionError, match="Ambiguous"):
            repo.import_recovery_spool(spool)
        assert _stored_bytes(tmp_path, eid) == original
        assert not repo.store.db_path.exists()
    finally:
        repo.close()


def test_import_reports_missing_explicit_event_identity(tmp_path: Path) -> None:
    eid = new_execution_id()
    event = _make_event(eid, 1)
    missing_id = event.model_dump(mode="json", exclude={"event_id"})
    spool = _write_event_spool(tmp_path / "events.spool", missing_id, event)
    repo = RecordingRepository(tmp_path)
    try:
        report = repo.import_recovery_spool(spool)
        assert report.imported_events == 1
        assert report.skipped_duplicates == 0
        assert report.final_status == "incomplete"
        assert len(report.corrupt_lines) == 1
        issue = report.corrupt_lines[0]
        assert issue.line_number == 1
        assert "event_id" in issue.details
        assert repo.get_execution_events(eid).events[0].event.event_id == event.event_id
    finally:
        repo.close()


def test_import_preflights_valid_unterminated_tail(tmp_path: Path) -> None:
    eid = new_execution_id()
    first, tail = _make_event(eid, 1), _make_event(eid, 2)
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(_make_header(eid))
    writer.append_events([first, tail])
    writer.close()
    before = writer.events_path.read_bytes()
    writer.events_path.write_bytes(before[:-1])
    original = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(
        tmp_path / "events.spool", tail.model_copy(update={"monotonic_time_ns": 99})
    )
    repo = RecordingRepository(tmp_path)
    try:
        with pytest.raises(StorageCorruptionError, match="conflict"):
            repo.import_recovery_spool(spool, tail_policy="reject")
        assert _stored_bytes(tmp_path, eid) == original
        assert not repo.store.db_path.exists()

        report = repo.import_recovery_spool(_write_event_spool(spool, tail), tail_policy="reject")
        assert report.skipped_duplicates == 1
        assert report.imported_events == 0
        assert writer.events_path.read_bytes() == before
        assert len(repo.store.query_event_index(execution_id=eid)) == 2
    finally:
        repo.close()


@pytest.mark.parametrize(
    ("mode", "import_mode"),
    [
        ("standard", "standard"),
        ("strict_hash_only", "strict_hash_only"),
        ("strict_hash_only", "standard"),
    ],
)
def test_import_retry_matches_real_redacted_spool(
    tmp_path: Path, mode: RedactionMode, import_mode: RedactionMode
) -> None:
    eid = new_execution_id()
    header = _make_header(eid)
    t0 = header.started_at
    config = RedactionConfig(mode=mode)
    norm = EventNormalizer(
        execution_id=eid,
        started_at=t0,
        monotonic_start_ns=1,
        command=("test-server",),
        redaction_config=config,
    )
    (event,) = norm.normalize(
        RawWireFrameInput(
            t0,
            2,
            "client_to_server",
            b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"token":"fake","value":"test"}}\n',
        )
    )
    writer = JsonlEventLogWriter(tmp_path, eid, redaction_mode=mode)
    writer.open(header.model_copy(update={"redaction_mode": mode}))
    writer.append_events([event])
    writer.close()
    spool = RecoverySpool(tmp_path / "events.spool", redaction_config=config)
    spool.write_events([event])
    spool.close()
    repo = RecordingRepository(tmp_path)
    try:
        report = repo.import_recovery_spool(
            spool.path, tail_policy="reject", redaction_mode=import_mode
        )
        assert report.skipped_duplicates == 1
        assert report.imported_events == 0
        assert not report.corrupt_lines
    finally:
        repo.close()


@pytest.mark.parametrize("append_event", [True, False])
def test_import_exact_retry_repairs_stale_index(tmp_path: Path, append_event: bool) -> None:
    eid = new_execution_id()
    first, second = _make_event(eid, 1), _make_event(eid, 2)
    summary = None if append_event else _make_summary(eid).model_copy(update={"total_events": 1})
    if summary is not None:
        first = ExecutionEvent(
            execution_id=eid,
            sequence=1,
            timestamp=summary.ended_at,
            monotonic_time_ns=summary.duration_ns,
            direction="proxy",
            kind="execution_finished",
            payload=ExecutionFinishedPayload(
                termination_reason="clean_exit",
                exit_code=0,
                total_events=1,
                completeness="complete",
            ),
        )
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(_make_header(eid))
    writer.append_events([first])
    writer.close()
    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        events = [first, second] if append_event else [first]
        spool = _write_event_spool(tmp_path / "events.spool", *events, summary=summary)
        with (
            patch.object(repo.store, "replace_execution_index", side_effect=StorageWriteError),
            pytest.raises(StorageWriteError),
        ):
            repo.import_recovery_spool(spool, tail_policy="reject")
        original = _stored_bytes(tmp_path, eid)
        assert len(repo.store.query_event_index(execution_id=eid)) == 1

        report = repo.import_recovery_spool(spool, tail_policy="reject")
        assert report.skipped_duplicates == len(events)
        assert report.imported_events == 0
        row = repo.store.get_execution_row(eid)
        assert row is not None
        assert row.ended_at == (summary.ended_at if summary is not None else None)
        assert sorted(row.sequence for row in repo.store.query_event_index(execution_id=eid)) == [
            event.sequence for event in events
        ]
        assert _stored_bytes(tmp_path, eid) == original
    finally:
        repo.close()


def test_conflict_only_quarantine_cannot_finalize_existing_recording(tmp_path: Path) -> None:
    eid = new_execution_id()
    event = _make_event(eid, 1)
    changed = event.model_copy(update={"monotonic_time_ns": 99})
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(_make_header(eid))
    writer.append_events([event])
    writer.close()
    original = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(tmp_path / "events.spool", changed, summary=_make_summary(eid))
    repo = RecordingRepository(tmp_path)
    try:
        report = repo.import_recovery_spool(spool)
        assert report.imported_events == report.skipped_duplicates == 0
        assert len(report.corrupt_lines) == 2
        assert any("summary conflicts" in issue.details for issue in report.corrupt_lines)
        assert report.final_status == "incomplete"
        assert _stored_bytes(tmp_path, eid) == original
    finally:
        repo.close()


def test_import_rejects_mismatched_destination_header_before_tail_repair(tmp_path: Path) -> None:
    eid = new_execution_id()
    event = _make_event(eid, 1)
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(_make_header(eid))
    writer.append_events([event])
    writer.close()
    writer.events_path.write_bytes(writer.events_path.read_bytes()[:-1])
    (writer.execution_dir / "execution.json").write_text(
        _make_header(new_execution_id()).model_dump_json(), encoding="utf-8"
    )
    original = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(tmp_path / "events.spool", event)
    repo = RecordingRepository(tmp_path)
    try:
        with pytest.raises(StorageCorruptionError, match="Destination metadata"):
            repo.import_recovery_spool(spool, tail_policy="reject")
        assert _stored_bytes(tmp_path, eid) == original
        assert not repo.store.db_path.exists()
    finally:
        repo.close()


def test_import_torn_spool_retry_repairs_index_without_appending(tmp_path: Path) -> None:
    eid = new_execution_id()
    first, second = _make_event(eid, 1), _make_event(eid, 2)
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(_make_header(eid))
    writer.append_events([first])
    writer.close()
    spool = _write_event_spool(tmp_path / "events.spool", first, second)
    with spool.open("ab") as handle:
        handle.write(b"{")

    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        with (
            patch.object(repo.store, "replace_execution_index", side_effect=StorageWriteError),
            pytest.raises(StorageWriteError),
        ):
            repo.import_recovery_spool(spool, tail_policy="reject")
        original = _stored_bytes(tmp_path, eid)
        prior = repo.get_execution_events(eid)
        assert [item.event for item in prior.events] == [first, second]
        assert prior.summary is None
        assert prior.manifest is not None and prior.manifest.status == "recording"
        assert [row.sequence for row in repo.store.query_event_index(execution_id=eid)] == [1]

        retry = repo.import_recovery_spool(spool, tail_policy="reject")
        assert (retry.imported_events, retry.skipped_duplicates, retry.final_status) == (
            0,
            2,
            "incomplete",
        )
        assert [issue.issue_kind for issue in retry.corrupt_lines] == ["missing_newline"]
        assert [row.sequence for row in repo.store.query_event_index(execution_id=eid)] == [1, 2]
        assert _stored_bytes(tmp_path, eid) == original
        assert spool.read_bytes().endswith(b"{")
    finally:
        repo.close()


@pytest.mark.parametrize(
    ("evidence", "expected_status"),
    [
        ("complete", "finalized"),
        ("incomplete", "incomplete"),
        ("different_outcome", "recording"),
        ("different_outcome_unterminated", "recording"),
        ("different_count", "recording"),
        ("gap_event", "recording"),
        ("missing_terminal_event", "recording"),
    ],
)
def test_import_event_only_retries_pending_manifest(
    tmp_path: Path, evidence: str, expected_status: str
) -> None:
    eid = new_execution_id()
    completeness = "incomplete" if evidence == "incomplete" else "complete"
    summary = _make_summary(eid, completeness=completeness).model_copy(update={"total_events": 2})
    first = _make_event(eid, 1)
    if evidence == "gap_event":
        first = ExecutionEvent(
            execution_id=eid,
            sequence=1,
            timestamp=first.timestamp,
            monotonic_time_ns=first.monotonic_time_ns,
            direction="system",
            kind="capture_gap",
            payload=CaptureGapPayload(
                dropped_count=1,
                reason="test gap",
                first_gap_monotonic_ns=first.monotonic_time_ns,
                last_gap_monotonic_ns=first.monotonic_time_ns,
            ),
        )
    last = (
        _make_event(eid, 2)
        if evidence == "missing_terminal_event"
        else ExecutionEvent(
            execution_id=eid,
            sequence=2,
            timestamp=summary.ended_at,
            monotonic_time_ns=10_000_000_000,
            direction="proxy",
            kind="execution_finished",
            payload=ExecutionFinishedPayload(
                termination_reason="clean_exit",
                exit_code=1 if evidence.startswith("different_outcome") else 0,
                total_events=3 if evidence == "different_count" else 2,
                completeness="incomplete" if evidence == "incomplete" else "complete",
            ),
        )
    )
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(_make_header(eid))
    writer.append_events([first, last])

    def fail_manifest(path: Path, data: dict[str, Any], *, fsync: bool) -> None:
        if path.name == MANIFEST_FILE_NAME:
            raise StorageWriteError("injected manifest failure")
        write_atomic_private_json(path, data, fsync=fsync)

    with (
        patch("aerlog.storage.event_log.write_atomic_private_json", side_effect=fail_manifest),
        pytest.raises(StorageWriteError, match="injected manifest failure"),
    ):
        writer.finalize(summary)
    writer.close()
    original = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(tmp_path / "events.spool", first, last)
    assert b'"record_type": "summary"' not in spool.read_bytes()
    repo = RecordingRepository(tmp_path)
    try:
        prior = repo.reconcile_execution(eid)
        assert prior is not None and prior.summary == summary
        assert prior.manifest is not None and prior.manifest.status == "recording"
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.capture_completeness == "incomplete"

        # A rejected conflict must not trigger pending manifest repair or touch SQLite.
        rejected_spool = _write_event_spool(
            tmp_path / "conflict.spool", first, last.model_copy(update={"monotonic_time_ns": 99})
        )
        before_hashes = {
            path: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (tmp_path / "aerlog.db", tmp_path / "aerlog.db-wal", writer.events_path)
            if path.exists()
        }
        before_hashes.update(
            {
                writer.execution_dir / name: hashlib.sha256(data).hexdigest()
                for name, data in original.items()
            }
        )
        with pytest.raises(StorageCorruptionError, match="Content conflict"):
            repo.import_recovery_spool(rejected_spool, tail_policy="reject")
        assert {
            path: hashlib.sha256(path.read_bytes()).hexdigest() for path in before_hashes
        } == before_hashes

        if evidence.endswith("_unterminated"):
            writer.events_path.write_bytes(original[EVENTS_FILE_NAME][:-1])
        retry = repo.import_recovery_spool(spool, tail_policy="reject")
        assert retry.imported_events == 0 and retry.skipped_duplicates == 2
        assert not retry.corrupt_lines
        result = repo.get_execution_events(eid)
        assert result.summary == summary
        assert result.manifest is not None and result.manifest.status == expected_status
        assert result.unclean_shutdown is (expected_status == "recording")
        if expected_status != "recording":
            assert result.manifest.events_file_sha256 == result.events_file_sha256
            assert result.manifest.byte_size == len(original[EVENTS_FILE_NAME])
            assert result.manifest.line_count == result.manifest.last_sequence == 2
        assert [item.event for item in result.events] == [first, last]
        assert writer.events_path.read_bytes() == original[EVENTS_FILE_NAME]
        assert (writer.execution_dir / "execution.json").read_bytes() == original["execution.json"]
        assert [row.sequence for row in repo.store.query_event_index(execution_id=eid)] == [1, 2]
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.ended_at == summary.ended_at
        assert row.capture_completeness == retry.final_status
        assert retry.final_status == (
            "complete" if expected_status == "finalized" else "incomplete"
        )
    finally:
        repo.close()


def test_import_event_only_retries_interrupted_tail_manifest(tmp_path: Path) -> None:
    eid = new_execution_id()
    event = _make_event(eid, 1)
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(_make_header(eid))
    writer.append_events([event])
    writer.close()
    original = _stored_bytes(tmp_path, eid)
    writer.events_path.write_bytes(original[EVENTS_FILE_NAME][:-1])
    (writer.execution_dir / MANIFEST_FILE_NAME).unlink()
    spool = _write_event_spool(tmp_path / "events.spool", event)

    repo = RecordingRepository(tmp_path)
    try:
        with (
            patch(
                "aerlog.storage.repositories.write_atomic_private_json",
                side_effect=StorageWriteError("injected manifest failure"),
            ),
            pytest.raises(StorageWriteError, match="injected manifest failure"),
        ):
            repo.import_recovery_spool(spool, tail_policy="reject")
        assert writer.events_path.read_bytes() == original[EVENTS_FILE_NAME]

        retry = repo.import_recovery_spool(spool, tail_policy="reject")
        assert (retry.imported_events, retry.skipped_duplicates, retry.final_status) == (
            0,
            1,
            "incomplete",
        )
        assert not retry.corrupt_lines
        stored = repo.get_execution_events(eid)
        assert stored.summary is None
        assert stored.manifest is not None and stored.manifest.status == "incomplete"
        assert stored.manifest.events_file_sha256 == stored.events_file_sha256
        assert writer.events_path.read_bytes() == original[EVENTS_FILE_NAME]
        assert (writer.execution_dir / "execution.json").read_bytes() == original["execution.json"]
        assert [row.sequence for row in repo.store.query_event_index(execution_id=eid)] == [1]
    finally:
        repo.close()


@pytest.mark.parametrize(
    "damage", ["missing", "event_id", "sequence", "offset", "length", "method"]
)
def test_import_exact_retry_checks_event_index_projection(tmp_path: Path, damage: str) -> None:
    eid = new_execution_id()
    first, second = _make_event(eid, 1), _make_event(eid, 2)
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(_make_header(eid))
    writer.append_events([first, second])
    writer.close()
    original = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(tmp_path / "events.spool", first, second)

    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        execution = repo.store.get_execution_row(eid)
        expected = repo.store.query_event_index(execution_id=eid)
        statements = {
            "missing": "DELETE FROM events_index",
            "event_id": "UPDATE events_index SET event_id = 'different'",
            "sequence": "UPDATE events_index SET sequence = 3",
            "offset": "UPDATE events_index SET jsonl_byte_offset = jsonl_byte_offset + 1",
            "length": "UPDATE events_index SET jsonl_byte_length = jsonl_byte_length + 1",
            "method": "UPDATE events_index SET method = 'different'",
        }
        with sqlite3.connect(repo.store.db_path) as conn:
            conn.execute(statements[damage] + " WHERE execution_id = ? AND sequence = 2", (eid,))
        assert repo.store.get_execution_row(eid) == execution

        report = repo.import_recovery_spool(spool, tail_policy="reject")
        assert report.imported_events == 0 and report.skipped_duplicates == 2
        assert repo.store.query_event_index(execution_id=eid) == expected
        assert _stored_bytes(tmp_path, eid) == original
    finally:
        repo.close()


@pytest.mark.parametrize("material_change", [False, True])
def test_import_retry_compares_decoded_unicode_index_metadata(
    tmp_path: Path, material_change: bool
) -> None:
    eid = new_execution_id()
    first = _make_event(eid, 1)
    command = ("tést-server", "例")
    header = _make_header(eid).model_copy(update={"command": command})
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(header)
    writer.append_events([first])
    writer.close()
    original = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(tmp_path / "events.spool", first)

    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        with sqlite3.connect(repo.store.db_path) as conn:
            (stored_json,) = conn.execute(
                "SELECT command_json FROM executions WHERE execution_id = ?", (eid,)
            ).fetchone()
            assert "例" in stored_json
            edited = json.dumps((*command, "changed") if material_change else command)
            assert r"\u4f8b" in edited
            conn.execute(
                "UPDATE executions SET command_json = ? WHERE execution_id = ?", (edited, eid)
            )

        with patch.object(
            repo.store, "replace_execution_index", wraps=repo.store.replace_execution_index
        ) as rebuild:
            retry = repo.import_recovery_spool(spool, tail_policy="reject")
        assert retry.imported_events == 0 and retry.skipped_duplicates == 1
        assert rebuild.call_count == int(material_change)
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.command == command
        assert _stored_bytes(tmp_path, eid) == original
    finally:
        repo.close()


@pytest.mark.parametrize(
    "change", ["none", "payload", "trace", "wire", "identity", "outcome", "provenance", "pending"]
)
def test_import_retry_legacy_strict_spool_under_standard_provenance(
    tmp_path: Path, change: str
) -> None:
    eid = new_execution_id()
    header = _make_header(eid)
    config = RedactionConfig(mode="strict_hash_only")
    normalizer = EventNormalizer(
        execution_id=eid,
        started_at=header.started_at,
        monotonic_start_ns=1,
        command=header.command,
        redaction_config=config,
    )
    (event,) = normalizer.normalize(
        RawWireFrameInput(
            header.started_at,
            2,
            "client_to_server",
            b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"token":"fixture"}}\n',
        )
    )
    finished, summary = normalizer.finalize_execution(
        ended_at=header.started_at, monotonic_end_ns=3, termination_reason="clean_exit", exit_code=0
    )
    # The pre-A1 default importer stored this withheld event under standard provenance.
    legacy_redaction = event.redaction.model_copy(
        update={"mode": "standard", "payload_mode": "redacted"}
    )
    legacy = event.model_copy(update={"redaction": legacy_redaction})
    writer = JsonlEventLogWriter(tmp_path, eid)
    writer.open(header)
    writer.append_events(
        [
            legacy,
            finished.model_copy(
                update={
                    "redaction": finished.redaction.model_copy(
                        update={"mode": "standard", "payload_mode": "redacted"}
                    )
                }
            ),
        ]
    )
    writer.close()
    if change == "pending":
        write_atomic_private_json(
            writer.execution_dir / "execution.json", summary.model_dump(mode="json")
        )
    original = _stored_bytes(tmp_path, eid)
    changes: dict[str, dict[str, Any]] = {
        "none": {},
        "pending": {},
        "payload": {"payload": event.payload.model_copy(update={"method": "other"})},
        "trace": {"trace": TraceContext(synthetic_execution_trace_id="different")},
        "wire": {"wire": WireFrameInfo(byte_length=10, line_ending="lf", sha256="b" * 64)},
        "identity": {"event_id": new_event_id()},
        "provenance": {
            "redaction": event.redaction.model_copy(update={"payload_mode": "redacted"})
        },
    }
    if change == "provenance":
        # Bypass spool normalization only for the incorrectly labelled fixture.
        spool = _write_event_spool(
            tmp_path / "events.spool", event.model_copy(update=changes[change])
        )
    else:
        recovery = RecoverySpool(tmp_path / "events.spool", redaction_config=config)
        changed = (
            finished.model_copy(
                update={"payload": finished.payload.model_copy(update={"exit_code": 1})}
            )
            if change == "outcome"
            else event.model_copy(update=changes[change])
        )
        recovery.write_events([changed, finished] if change == "pending" else [changed])
        recovery.close()
        spool = recovery.path

    repo = RecordingRepository(tmp_path)
    try:
        if change in ("none", "pending"):
            result = repo.import_recovery_spool(spool, tail_policy="reject")
            assert (result.imported_events, result.skipped_duplicates) == (
                0,
                2 if change == "pending" else 1,
            )
            assert not result.corrupt_lines
            assert repo.get_execution_events(eid).events[0].event.redaction == legacy_redaction
        else:
            with pytest.raises(StorageCorruptionError, match="conflict"):
                repo.import_recovery_spool(spool, tail_policy="reject")
        after = _stored_bytes(tmp_path, eid)
        if change == "pending":
            actual = repo.get_execution_events(eid)
            assert actual.summary == summary
            assert actual.manifest is not None and actual.manifest.status == "finalized"
            assert (row := repo.store.get_execution_row(eid)) is not None
            assert row.capture_completeness == "complete"
            assert after[EVENTS_FILE_NAME] == original[EVENTS_FILE_NAME]
            assert after["execution.json"] == original["execution.json"]
        else:
            assert after == original
    finally:
        repo.close()


def _finished_recording(
    data: Path, *, finalized: bool
) -> tuple[JsonlEventLogWriter, ExecutionEvent, ExecutionEvent, ExecutionSummary]:
    eid = new_execution_id()
    first = _make_event(eid, 1)
    summary = _make_summary(eid).model_copy(update={"total_events": 2})
    last = ExecutionEvent(
        execution_id=eid,
        sequence=2,
        timestamp=summary.ended_at,
        monotonic_time_ns=summary.duration_ns,
        direction="proxy",
        kind="execution_finished",
        payload=ExecutionFinishedPayload(
            termination_reason="clean_exit", exit_code=0, total_events=2, completeness="complete"
        ),
    )
    writer = JsonlEventLogWriter(data, eid)
    writer.open(_make_header(eid))
    writer.append_events([first, last])
    if finalized:
        writer.finalize(summary)
    else:
        with (
            patch(
                "aerlog.storage.event_log.write_atomic_private_json",
                side_effect=StorageWriteError("summary write interrupted"),
            ),
            pytest.raises(StorageWriteError, match="summary write interrupted"),
        ):
            writer.finalize(summary)
    writer.close()
    return writer, first, last, summary


def _index_file_hashes(data: Path) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (data / "aerlog.db", data / "aerlog.db-wal")
        if path.exists()
    }


@pytest.mark.parametrize("finalized", [True, False])
@pytest.mark.parametrize(
    "change",
    ["exit", "count", "outcome", "execution", "completeness", "metadata", "torn", "duplicate"],
)
def test_recovery_preflights_supplied_summary(tmp_path: Path, finalized: bool, change: str) -> None:
    writer, first, last, summary = _finished_recording(tmp_path, finalized=finalized)
    eid = first.execution_id
    changes: dict[str, dict[str, Any]] = {
        "exit": {"exit_code": 7},
        "count": {"total_events": 12},
        "outcome": {"termination_reason": "unexpected_exit"},
        "execution": {"execution_id": new_execution_id()},
        "completeness": {"capture_completeness": "spilled"},
        "metadata": {"command": ("different-command",)},
        "torn": {"exit_code": 7},
        "duplicate": {"exit_code": 7},
    }
    spool = _write_event_spool(
        tmp_path / "retry.spool", first, last, summary=summary.model_copy(update=changes[change])
    )
    if change in ("torn", "duplicate"):
        with spool.open("ab") as handle:
            handle.write(
                b"{"
                if change == "torn"
                else (
                    json.dumps({"record_type": "summary", "data": summary.model_dump(mode="json")})
                    + "\n"
                ).encode()
            )
    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        before = _stored_bytes(tmp_path, eid), _index_file_hashes(tmp_path)
        with pytest.raises(StorageCorruptionError):
            repo.import_recovery_spool(spool, tail_policy="reject")
        assert (_stored_bytes(tmp_path, eid), _index_file_hashes(tmp_path)) == before
        if change != "execution":
            report = repo.import_recovery_spool(spool, tail_policy="quarantine")
            assert report.imported_events == 0
            assert report.final_status == "incomplete"
            assert report.corrupt_lines and list(writer.execution_dir.glob("*.quarantine"))
            assert _stored_bytes(tmp_path, eid) == before[0]
            actual = repo.get_execution_events(eid)
            assert actual.summary == (summary if finalized else None)
            assert actual.manifest is not None
            assert actual.manifest.status == ("finalized" if finalized else "recording")
    finally:
        repo.close()


@pytest.mark.parametrize("evidence", ["valid", "missing_terminal", "invalid_summary"])
def test_recovery_after_interrupted_summary_write(tmp_path: Path, evidence: str) -> None:
    writer, first, last, summary = _finished_recording(tmp_path, finalized=False)
    eid = first.execution_id
    if evidence == "missing_terminal":
        writer.events_path.write_bytes(writer.events_path.read_bytes().splitlines(keepends=True)[0])
    original = _stored_bytes(tmp_path, eid)
    repo = RecordingRepository(tmp_path)
    try:
        spool = _write_event_spool(
            tmp_path / "retry.spool",
            *((first,) if evidence == "missing_terminal" else (first, last)),
        )
        assert repo.import_recovery_spool(spool, tail_policy="reject").final_status == "incomplete"
        assert _stored_bytes(tmp_path, eid) == original
        if evidence == "invalid_summary":
            with spool.open("ab") as handle:
                handle.write(b'{"record_type":"summary","data":{}}\n')
        else:
            _write_event_spool(
                spool,
                *((first,) if evidence == "missing_terminal" else (first, last)),
                summary=summary,
            )
        if evidence != "valid":
            with pytest.raises(StorageCorruptionError):
                repo.import_recovery_spool(spool, tail_policy="reject")
            assert _stored_bytes(tmp_path, eid) == original
        else:
            report = repo.import_recovery_spool(spool, tail_policy="reject")
            assert report.final_status == "complete"
            actual = repo.get_execution_events(eid)
            assert actual.summary == summary
            assert actual.manifest is not None and actual.manifest.status == "finalized"
            assert (row := repo.store.get_execution_row(eid)) is not None
            assert row.capture_completeness == "complete" and row.total_events == 2
            assert writer.events_path.read_bytes() == original[EVENTS_FILE_NAME]
            after = _stored_bytes(tmp_path, eid)
            assert repo.import_recovery_spool(spool, tail_policy="reject").imported_events == 0
            assert _stored_bytes(tmp_path, eid) == after
    finally:
        repo.close()


def test_recovery_keeps_tail_quarantine_incomplete_across_retries(tmp_path: Path) -> None:
    writer, first, last, summary = _finished_recording(tmp_path, finalized=True)
    eid = first.execution_id
    original = writer.events_path.read_bytes()
    writer.events_path.write_bytes(original + b"{broken-tail")
    spool = _write_event_spool(tmp_path / "retry.spool", first, last)
    repo = RecordingRepository(tmp_path)
    try:
        for attempt in range(3):
            if attempt == 2:
                writer.events_path.write_bytes(original[:-1])
                with sqlite3.connect(repo.store.db_path) as conn:
                    conn.execute("DELETE FROM events_index WHERE sequence = 2")
            report = repo.import_recovery_spool(spool, tail_policy="quarantine")
            assert report.skipped_duplicates == 2 and report.imported_events == 0
            assert report.final_status == "incomplete"
            result = repo.get_execution_events(eid)
            assert result.summary == summary
            assert result.manifest is not None and result.manifest.status == "incomplete"
            assert result.manifest.corruption_count == 1
            assert writer.events_path.read_bytes() == original
            assert len(list(writer.execution_dir.glob("*.quarantine"))) == 1
            assert (row := repo.store.get_execution_row(eid)) is not None
            assert row.capture_completeness == "incomplete"
            assert [x.event_id for x in repo.store.query_event_index(execution_id=eid)] == [
                first.event_id,
                last.event_id,
            ]
    finally:
        repo.close()


def test_recovery_preserves_verified_manifest_when_restoring_newline(tmp_path: Path) -> None:
    writer, first, last, _ = _finished_recording(tmp_path, finalized=True)
    eid = first.execution_id
    original = _stored_bytes(tmp_path, eid)
    writer.events_path.write_bytes(original[EVENTS_FILE_NAME][:-1])
    # Filename alone provides no evidence that this artifact came from the destination log.
    (writer.execution_dir / "corrupted_tail_offset_0_stale.quarantine").write_bytes(b"unrelated")
    bad_digest = "f" * 64
    stem = f"corrupted_tail_offset_1_{bad_digest[:12]}"
    (writer.execution_dir / f"{stem}.quarantine").write_bytes(b"unrelated")
    write_atomic_private_json(
        writer.execution_dir / f"{stem}.meta.json",
        {
            "execution_id": eid,
            "byte_offset": 1,
            "byte_length": len(b"unrelated"),
            "sha256": bad_digest,
            "reason": "Destination log tail: invalid test evidence",
        },
    )
    spool = _write_event_spool(tmp_path / "retry.spool", first, last)
    repo = RecordingRepository(tmp_path)
    try:
        assert repo.import_recovery_spool(spool).final_status == "complete"
        assert _stored_bytes(tmp_path, eid) == original
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.capture_completeness == "complete"
    finally:
        repo.close()


@pytest.mark.parametrize(
    "damage", ["missing", "timestamp", "command", "multiple", "offset", "length"]
)
def test_recovery_rebuilds_damaged_index(tmp_path: Path, damage: str) -> None:
    _, first, last, _ = _finished_recording(tmp_path, finalized=True)
    eid = first.execution_id
    original = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(tmp_path / "retry.spool", first, last)
    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        expected_row = repo.store.get_execution_row(eid)
        expected_events = repo.store.query_event_index(execution_id=eid)
        with sqlite3.connect(repo.store.db_path) as conn:
            if damage == "missing":
                conn.execute("DELETE FROM events_index WHERE sequence = 2")
            if damage in ("offset", "length"):
                field = "jsonl_byte_offset" if damage == "offset" else "jsonl_byte_length"
                conn.execute(f"UPDATE events_index SET {field} = {field} + 1 WHERE sequence = 2")
            if damage in ("timestamp", "multiple"):
                conn.execute("UPDATE events_index SET timestamp = 'invalid timestamp'")
            if damage in ("command", "multiple"):
                conn.execute("UPDATE executions SET command_json = '['")
        damaged = _index_file_hashes(tmp_path)
        with (
            patch.object(repo.store, "replace_execution_index", side_effect=StorageWriteError),
            pytest.raises(StorageWriteError),
        ):
            repo.import_recovery_spool(spool, tail_policy="reject")
        assert _stored_bytes(tmp_path, eid) == original
        assert _index_file_hashes(tmp_path) == damaged

        with patch.object(
            repo.store, "replace_execution_index", wraps=repo.store.replace_execution_index
        ) as rebuild:
            for _ in range(2):
                report = repo.import_recovery_spool(spool, tail_policy="reject")
                assert report.final_status == "complete" and report.imported_events == 0
            assert rebuild.call_count == 1
        assert repo.store.get_execution_row(eid) == expected_row
        assert repo.store.query_event_index(execution_id=eid) == expected_events
        assert _stored_bytes(tmp_path, eid) == original
    finally:
        repo.close()


@pytest.mark.parametrize("malformed", [False, True])
def test_recovery_repairs_verified_index_with_quarantined_candidate(
    tmp_path: Path, malformed: bool
) -> None:
    writer, first, last, _ = _finished_recording(tmp_path, finalized=True)
    eid = first.execution_id
    conflicting = first.model_copy(update={"monotonic_time_ns": 13})
    spool = _write_event_spool(tmp_path / "retry.spool", first, last, conflicting)
    original = _stored_bytes(tmp_path, eid)
    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        with sqlite3.connect(repo.store.db_path) as conn:
            conn.execute("DELETE FROM events_index WHERE sequence = 2")
            conn.execute("UPDATE executions SET total_events = 99")
            if malformed:
                conn.execute("UPDATE executions SET command_json = '['")
        damaged = _index_file_hashes(tmp_path)
        with pytest.raises(StorageCorruptionError):
            repo.import_recovery_spool(spool, tail_policy="reject")
        assert _index_file_hashes(tmp_path) == damaged
        assert _stored_bytes(tmp_path, eid) == original
        with patch.object(
            repo.store, "replace_execution_index", wraps=repo.store.replace_execution_index
        ) as rebuild:
            for _ in range(2):
                report = repo.import_recovery_spool(spool, tail_policy="quarantine")
                assert (report.skipped_duplicates, report.imported_events, report.final_status) == (
                    2,
                    0,
                    "incomplete",
                )
                assert len(report.corrupt_lines) == 1
            assert rebuild.call_count == 1
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.total_events == 2
        assert [x.event_id for x in repo.store.query_event_index(execution_id=eid)] == [
            first.event_id,
            last.event_id,
        ]
        assert len(list(writer.execution_dir.glob("*.quarantine"))) == 1
        assert _stored_bytes(tmp_path, eid) == original
    finally:
        repo.close()


def test_recovery_repairs_retained_summary_after_quarantining_candidate(tmp_path: Path) -> None:
    writer, first, last, summary = _finished_recording(tmp_path, finalized=False)
    eid = first.execution_id
    write_atomic_private_json(
        writer.execution_dir / "execution.json", summary.model_dump(mode="json")
    )
    original = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(
        tmp_path / "retry.spool", first, last, first.model_copy(update={"monotonic_time_ns": 13})
    )
    repo = RecordingRepository(tmp_path)
    try:
        report = repo.import_recovery_spool(spool, tail_policy="quarantine")
        assert report.final_status == "incomplete" and report.corrupt_lines
        assert _stored_bytes(tmp_path, eid) == original
        assert len(list(writer.execution_dir.glob("*.quarantine"))) == 1
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.capture_completeness == "incomplete" and row.total_events == 2

        _write_event_spool(spool, first, last)
        retry = repo.import_recovery_spool(spool, tail_policy="reject")
        assert (retry.imported_events, retry.skipped_duplicates, retry.final_status) == (
            0,
            2,
            "complete",
        )
        after = _stored_bytes(tmp_path, eid)
        assert after[EVENTS_FILE_NAME] == original[EVENTS_FILE_NAME]
        assert after["execution.json"] == original["execution.json"]
        actual = repo.get_execution_events(eid)
        assert actual.manifest is not None and actual.manifest.status == "finalized"
        assert actual.manifest.corruption_count == 0
        assert len(list(writer.execution_dir.glob("*.quarantine"))) == 1
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.capture_completeness == "complete"
    finally:
        repo.close()


@pytest.mark.parametrize(
    "error",
    [
        sqlite3.OperationalError("database is locked"),
        sqlite3.OperationalError("disk I/O error"),
        sqlite3.DatabaseError("database disk image is malformed"),
        TypeError("unexpected programming error"),
    ],
)
def test_recovery_propagates_nondecoding_index_errors(tmp_path: Path, error: Exception) -> None:
    _, first, last, _ = _finished_recording(tmp_path, finalized=True)
    eid = first.execution_id
    spool = _write_event_spool(tmp_path / "retry.spool", first, last)
    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        before = _stored_bytes(tmp_path, eid), _index_file_hashes(tmp_path)
        with (
            patch.object(repo.store, "query_event_index", side_effect=error),
            patch.object(repo.store, "replace_execution_index") as rebuild,
            pytest.raises(type(error), match=str(error)),
        ):
            repo.import_recovery_spool(spool, tail_policy="reject")
        rebuild.assert_not_called()
        assert (_stored_bytes(tmp_path, eid), _index_file_hashes(tmp_path)) == before
    finally:
        repo.close()


@pytest.mark.parametrize("damage", ["seal", "summary", "version"])
def test_recovery_refuses_unverified_authoritative_metadata(tmp_path: Path, damage: str) -> None:
    writer, first, last, summary = _finished_recording(tmp_path, finalized=True)
    eid = first.execution_id
    manifest_path = writer.execution_dir / MANIFEST_FILE_NAME
    if damage == "summary":
        (writer.execution_dir / "execution.json").write_text("[]", encoding="utf-8")
    else:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if damage == "seal":
            manifest["events_file_sha256"] = "a" * 64
        else:
            manifest["storage_schema_version"] = "99.0.0"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    before = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(tmp_path / "retry.spool", first, last, summary=summary)
    repo = RecordingRepository(tmp_path)
    try:
        error = UnsupportedSchemaVersionError if damage == "version" else StorageCorruptionError
        with (
            patch.object(repo.store, "replace_execution_index") as rebuild,
            pytest.raises(error),
        ):
            repo.import_recovery_spool(spool, tail_policy="reject")
        rebuild.assert_not_called()
        assert _stored_bytes(tmp_path, eid) == before
        assert not repo.store.db_path.exists()
    finally:
        repo.close()


@pytest.mark.parametrize("failure", ["append", "manifest"])
def test_recovery_preserves_quarantine_when_append_fails(tmp_path: Path, failure: str) -> None:
    _, first, last, summary = _finished_recording(tmp_path, finalized=False)
    eid = first.execution_id
    events_path = resolve_execution_dir(tmp_path, eid) / EVENTS_FILE_NAME
    prefix = events_path.read_bytes().splitlines(keepends=True)[0]
    events_path.write_bytes(prefix + b"{interrupted")
    spool = _write_event_spool(tmp_path / "retry.spool", first)
    repo = RecordingRepository(tmp_path)
    try:
        assert (
            repo.import_recovery_spool(spool, tail_policy="quarantine").final_status == "incomplete"
        )
        _write_event_spool(spool, first, last, summary=summary)
        fault = (
            patch.object(JsonlEventLogWriter, "append_events", side_effect=StorageWriteError)
            if failure == "append"
            else patch(
                "aerlog.storage.repositories.write_atomic_private_json",
                side_effect=StorageWriteError,
            )
        )
        with fault, pytest.raises(StorageWriteError):
            repo.import_recovery_spool(spool, tail_policy="reject")
        after_failure = repo.get_execution_events(eid)
        assert after_failure.manifest is not None
        if failure == "append":
            assert after_failure.manifest.corruption_count == 1
        assert events_path.read_bytes() == prefix

        report = repo.import_recovery_spool(spool, tail_policy="reject")
        assert report.imported_events == 1 and report.final_status == "incomplete"
        actual = repo.get_execution_events(eid)
        assert actual.summary == summary
        assert actual.manifest is not None and actual.manifest.status == "incomplete"
        assert actual.manifest.corruption_count == 1
        assert [item.event for item in actual.events] == [first, last]
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.capture_completeness == "incomplete"
    finally:
        repo.close()


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
@pytest.mark.parametrize("indexed", [True, False])
def test_recovery_reconciles_verified_summary_only_retry(
    tmp_path: Path, policy: TailPolicy, indexed: bool
) -> None:
    _, first, last, summary = _finished_recording(tmp_path, finalized=False)
    eid = first.execution_id
    spool = _write_event_spool(tmp_path / "summary.spool", summary=summary)
    repo = RecordingRepository(tmp_path)
    try:
        if indexed:
            repo.reconcile_execution(eid)
        old_index = repo.store.get_execution_row(eid)
        if indexed:
            assert old_index is not None and old_index.ended_at is None
        else:
            assert old_index is None
        with (
            patch.object(repo.store, "replace_execution_index", side_effect=StorageWriteError),
            pytest.raises(StorageWriteError),
        ):
            repo.import_recovery_spool(spool, tail_policy=policy)
        assert repo.store.get_execution_row(eid) == old_index
        finalized = _stored_bytes(tmp_path, eid)

        with patch.object(
            repo.store, "replace_execution_index", wraps=repo.store.replace_execution_index
        ) as rebuild:
            for _ in range(2):
                report = repo.import_recovery_spool(spool, tail_policy=policy)
                assert (report.imported_events, report.skipped_duplicates, report.final_status) == (
                    0,
                    0,
                    "complete",
                )
        assert rebuild.call_count == 1
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.capture_completeness == "complete" and row.ended_at == summary.ended_at
        assert [item.event_id for item in repo.store.query_event_index(execution_id=eid)] == [
            first.event_id,
            last.event_id,
        ]
        assert _stored_bytes(tmp_path, eid) == finalized
    finally:
        repo.close()


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
@pytest.mark.parametrize("persisted_terminal", [True, False])
def test_recovery_preflights_after_terminal(
    tmp_path: Path, policy: TailPolicy, persisted_terminal: bool
) -> None:
    writer, first, last, summary = _finished_recording(tmp_path, finalized=False)
    eid = first.execution_id
    if not persisted_terminal:
        writer.events_path.write_bytes(writer.events_path.read_bytes().splitlines(keepends=True)[0])
    suffix = _make_event(eid, 3)
    spool = _write_event_spool(tmp_path / "retry.spool", first, last, suffix, summary=summary)
    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        before = _stored_bytes(tmp_path, eid), _index_file_hashes(tmp_path)
        if policy == "reject":
            with pytest.raises(StorageCorruptionError, match="terminal"):
                repo.import_recovery_spool(spool, tail_policy=policy)
            assert (_stored_bytes(tmp_path, eid), _index_file_hashes(tmp_path)) == before
        else:
            for _ in range(2):
                report = repo.import_recovery_spool(spool, tail_policy=policy)
                assert report.final_status == "incomplete"
                assert any("terminal" in issue.details for issue in report.corrupt_lines)
                result = repo.get_execution_events(eid)
                assert [item.event for item in result.events] == [first, last]
                assert [
                    item.event_id for item in repo.store.query_event_index(execution_id=eid)
                ] == [first.event_id, last.event_id]
            after = _stored_bytes(tmp_path, eid)[EVENTS_FILE_NAME]
            if persisted_terminal:
                assert after == before[0][EVENTS_FILE_NAME]
            archived = list(writer.execution_dir.glob("*.quarantine"))
            assert len(archived) == 1 and suffix.event_id.encode() in archived[0].read_bytes()
    finally:
        repo.close()


def test_recovery_detects_unterminated_suffix_after_persisted_terminal(tmp_path: Path) -> None:
    writer, first, last, _ = _finished_recording(tmp_path, finalized=False)
    eid = first.execution_id
    sealed_prefix = writer.events_path.read_bytes()
    suffix = _make_event(eid, 3)
    fixture = JsonlEventLogWriter(tmp_path / "fixture", eid)
    fixture.open(_make_header(eid))
    fixture.append_events([suffix])
    fixture.close()
    raw_suffix = fixture.events_path.read_bytes()[:-1]
    writer.events_path.write_bytes(sealed_prefix + raw_suffix)
    spool = _write_event_spool(tmp_path / "retry.spool", first, last)
    before = _stored_bytes(tmp_path, eid)
    repo = RecordingRepository(tmp_path)
    try:
        with pytest.raises(StorageCorruptionError, match="terminal"):
            repo.import_recovery_spool(spool, tail_policy="reject")
        assert _stored_bytes(tmp_path, eid) == before and not repo.store.db_path.exists()
        report = repo.import_recovery_spool(spool, tail_policy="quarantine")
        assert report.final_status == "incomplete" and report.imported_events == 0
        assert writer.events_path.read_bytes() == sealed_prefix
        assert [item.sequence for item in repo.store.query_event_index(execution_id=eid)] == [1, 2]
        archives = list(writer.execution_dir.glob("*.quarantine"))
        assert len(archives) == 1 and archives[0].read_bytes() == raw_suffix
    finally:
        repo.close()


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
@pytest.mark.parametrize("recorded_start", [False, True])
def test_recovery_distinguishes_placeholder_from_recorded_command(
    tmp_path: Path, policy: TailPolicy, recorded_start: bool
) -> None:
    _, first, last, summary = _finished_recording(tmp_path / "source", finalized=False)
    eid = first.execution_id
    if recorded_start:
        # This is a real command with the same text as the synthetic spelling.
        first = first.model_copy(
            update={
                "kind": "execution_started",
                "direction": "proxy",
                "payload": ExecutionStartedPayload(
                    command=("recovered-spool",),
                    redaction_mode="standard",
                    backpressure_policy="spill",
                ),
            }
        )
        summary = summary.model_copy(
            update={
                "started_at": first.timestamp,
                "duration_ns": last.monotonic_time_ns - first.monotonic_time_ns,
                "backpressure_policy": "spill",
            }
        )
    root = tmp_path / "destination"
    spool = _write_event_spool(tmp_path / "retry.spool", first, last)
    repo = RecordingRepository(root)
    try:
        repo.import_recovery_spool(spool, tail_policy=policy)
        before = _stored_bytes(root, eid), _index_file_hashes(root)
        _write_event_spool(spool, first, last, summary=summary)
        if recorded_start:
            if policy == "reject":
                with pytest.raises(StorageCorruptionError, match="summary conflicts"):
                    repo.import_recovery_spool(spool, tail_policy=policy)
                assert _index_file_hashes(root) == before[1]
            else:
                assert (
                    repo.import_recovery_spool(spool, tail_policy=policy).final_status
                    == "incomplete"
                )
            assert _stored_bytes(root, eid) == before[0]
            return
        for _ in range(2):
            result = repo.import_recovery_spool(spool, tail_policy=policy)
            assert result.final_status == "complete" and result.imported_events == 0
        assert _stored_bytes(root, eid)[EVENTS_FILE_NAME] == before[0][EVENTS_FILE_NAME]
        read = repo.get_execution_events(eid)
        assert (
            read.summary == summary
            and read.manifest is not None
            and read.manifest.status == "finalized"
        )
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.command == summary.command and row.capture_completeness == "complete"
    finally:
        repo.close()


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
@pytest.mark.parametrize("persisted_summary", [False, True])
def test_recovery_refuses_summary_with_contradictory_terminal_time(
    tmp_path: Path, policy: TailPolicy, persisted_summary: bool
) -> None:
    writer, first, last, summary = _finished_recording(tmp_path, finalized=False)
    eid = first.execution_id
    later = summary.model_copy(update={"ended_at": summary.ended_at + timedelta(days=1)})
    if persisted_summary:
        write_atomic_private_json(
            writer.execution_dir / "execution.json", later.model_dump(mode="json")
        )
    spool = _write_event_spool(
        tmp_path / "retry.spool", first, last, summary=None if persisted_summary else later
    )
    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        before = _stored_bytes(tmp_path, eid), _index_file_hashes(tmp_path)
        if not persisted_summary and policy == "reject":
            with pytest.raises(StorageCorruptionError, match="summary conflicts"):
                repo.import_recovery_spool(spool, tail_policy=policy)
            assert _index_file_hashes(tmp_path) == before[1]
        else:
            report = repo.import_recovery_spool(spool, tail_policy=policy)
            assert report.final_status == "incomplete"
            if not persisted_summary:
                assert report.corrupt_lines
        assert _stored_bytes(tmp_path, eid) == before[0]
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.capture_completeness == "incomplete"
    finally:
        repo.close()


def test_recovery_keeps_matching_legacy_sealed_summary_on_retry(tmp_path: Path) -> None:
    writer, first, last, summary = _finished_recording(tmp_path, finalized=True)
    eid = first.execution_id
    older = summary.model_copy(update={"ended_at": summary.ended_at + timedelta(seconds=1)})
    write_atomic_private_json(
        writer.execution_dir / "execution.json", older.model_dump(mode="json")
    )
    before = _stored_bytes(tmp_path, eid)
    spool = _write_event_spool(tmp_path / "retry.spool", first, last, summary=older)
    repo = RecordingRepository(tmp_path)
    try:
        report = repo.import_recovery_spool(spool, tail_policy="reject")
        assert report.final_status == "complete" and report.imported_events == 0
        assert _stored_bytes(tmp_path, eid) == before
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.ended_at == older.ended_at
    finally:
        repo.close()


@pytest.mark.parametrize(
    ("column", "invalid"),
    [
        ("command_json", "null"),
        ("command_json", "17"),
        ("command_json", '["test-server",17]'),
        ("unanswered_request_ids_json", '{"invalid":"shape"}'),
        ("observed_trace_ids_json", '"not-an-array"'),
        ("observed_mcp_versions_json", "false"),
    ],
)
def test_recovery_rebuilds_wrong_shaped_index_json(
    tmp_path: Path, column: str, invalid: str
) -> None:
    _, first, last, summary = _finished_recording(tmp_path, finalized=True)
    eid = first.execution_id
    spool = _write_event_spool(tmp_path / "retry.spool", first, last)
    before = _stored_bytes(tmp_path, eid)
    repo = RecordingRepository(tmp_path)
    try:
        repo.reconcile_execution(eid)
        expected = repo.store.get_execution_row(eid)
        with sqlite3.connect(repo.store.db_path) as conn:
            conn.execute(f"UPDATE executions SET {column}=? WHERE execution_id=?", (invalid, eid))
        with patch.object(
            repo.store, "replace_execution_index", wraps=repo.store.replace_execution_index
        ) as rebuild:
            for _ in range(2):
                assert (
                    repo.import_recovery_spool(spool, tail_policy="reject").final_status
                    == "complete"
                )
        assert rebuild.call_count == 1
        assert repo.store.get_execution_row(eid) == expected
        assert _stored_bytes(tmp_path, eid) == before
        assert (
            row := repo.store.get_execution_row(eid)
        ) is not None and row.ended_at == summary.ended_at
    finally:
        repo.close()


@pytest.mark.parametrize("same_tail", [True, False])
def test_recovery_reuses_only_matching_quarantine_after_failed_rename(
    tmp_path: Path, same_tail: bool
) -> None:
    writer, first, last, _ = _finished_recording(tmp_path, finalized=True)
    eid = first.execution_id
    prefix = writer.events_path.read_bytes()
    torn = b"{initial"
    writer.events_path.write_bytes(prefix + torn)
    spool = _write_event_spool(tmp_path / "retry.spool", first, last)
    real_replace = os.replace

    def fail_tail_rename(src: Path, dst: Path) -> None:
        if Path(dst) == writer.events_path:
            raise OSError("tail rename interrupted")
        real_replace(src, dst)

    repo = RecordingRepository(tmp_path)
    try:
        with (
            patch("aerlog.storage.repositories.os.replace", side_effect=fail_tail_rename),
            pytest.raises(OSError, match="tail rename interrupted"),
        ):
            repo.import_recovery_spool(spool, tail_policy="quarantine")
        interrupted = repo.get_execution_events(eid)
        assert interrupted.manifest is not None and interrupted.manifest.corruption_count == 1
        assert writer.events_path.read_bytes() == prefix + torn
        (initial_artifact,) = writer.execution_dir.glob("*.quarantine")
        initial_sidecar = initial_artifact.with_suffix(".meta.json")
        initial_evidence = initial_artifact.read_bytes(), initial_sidecar.read_bytes()
        if not same_tail:
            writer.events_path.write_bytes(prefix + b"{different")
        report = repo.import_recovery_spool(spool, tail_policy="quarantine")
        assert report.final_status == "incomplete" and len(report.corrupt_lines) == 1
        assert writer.events_path.read_bytes() == prefix
        result = repo.get_execution_events(eid)
        assert result.manifest is not None
        assert result.manifest.corruption_count == (1 if same_tail else 2)
        assert (initial_artifact.read_bytes(), initial_sidecar.read_bytes()) == initial_evidence
        assert {path.read_bytes() for path in writer.execution_dir.glob("*.quarantine")} == (
            {torn} if same_tail else {torn, b"{different"}
        )
        assert (row := repo.store.get_execution_row(eid)) is not None
        assert row.capture_completeness == "incomplete"
    finally:
        repo.close()


@pytest.mark.parametrize("wrong_command", [False, True])
def test_recovery_compares_recorded_start_after_strict_redaction(
    tmp_path: Path, wrong_command: bool
) -> None:
    eid = new_execution_id()
    started_at = _make_header(eid).started_at
    norm = EventNormalizer(
        execution_id=eid,
        started_at=started_at,
        monotonic_start_ns=1,
        command=("test-server", "--ordinary"),
        redaction_config=RedactionConfig(mode="standard"),
    )
    start_events = norm.start_execution()
    finished, summary = norm.finalize_execution(
        ended_at=started_at + timedelta(seconds=1),
        monotonic_end_ns=1_000_000_001,
        termination_reason="clean_exit",
        exit_code=0,
    )
    if wrong_command:
        summary = summary.model_copy(update={"command": ("different-server", "--ordinary")})
    path = _write_event_spool(tmp_path / "retry.spool", *start_events, finished, summary=summary)
    repo = RecordingRepository(tmp_path)
    try:
        if wrong_command:
            with pytest.raises(StorageCorruptionError, match="summary conflicts"):
                repo.import_recovery_spool(
                    path, redaction_mode="strict_hash_only", tail_policy="reject"
                )
            assert not resolve_execution_dir(tmp_path, eid).exists()
            assert not repo.store.db_path.exists()
        else:
            report = repo.import_recovery_spool(
                path, redaction_mode="strict_hash_only", tail_policy="reject"
            )
            assert report.final_status == "complete"
            read = repo.get_execution_events(eid)
            assert read.events[0].event.payload == start_events[0].payload.model_copy(
                update={"command": ("test-server", "[REDACTED_ARGS]")}
            )
            assert read.summary == summary
            before = _stored_bytes(tmp_path, eid), _index_file_hashes(tmp_path)
            retry = repo.import_recovery_spool(
                path, redaction_mode="strict_hash_only", tail_policy="reject"
            )
            assert retry.final_status == "complete" and retry.imported_events == 0
            assert (_stored_bytes(tmp_path, eid), _index_file_hashes(tmp_path)) == before
    finally:
        repo.close()


def test_recovery_never_reuses_conflicting_quarantine_artifact(tmp_path: Path) -> None:
    writer, first, last, _ = _finished_recording(tmp_path, finalized=True)
    eid = first.execution_id
    prefix = writer.events_path.read_bytes()
    tail = b"{corrupt"
    writer.events_path.write_bytes(prefix + tail)
    spool = _write_event_spool(tmp_path / "retry.spool", first, last)
    digest = hashlib.sha256(tail).hexdigest()
    artifact = (
        writer.execution_dir / f"corrupted_tail_offset_{len(prefix)}_{digest[:12]}.quarantine"
    )
    artifact.write_bytes(b"other retained evidence")
    before = _stored_bytes(tmp_path, eid)
    repo = RecordingRepository(tmp_path)
    try:
        with pytest.raises(StorageCorruptionError, match="artifact conflicts"):
            repo.import_recovery_spool(spool, tail_policy="quarantine")
        assert _stored_bytes(tmp_path, eid) == before
        assert artifact.read_bytes() == b"other retained evidence"
        assert not repo.store.db_path.exists()
    finally:
        repo.close()
