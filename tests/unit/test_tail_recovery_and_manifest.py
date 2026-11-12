"""Unit tests for Gate 1D (F-06): Data-preserving tail recovery & manifest consistency."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from aerlog.events import new_event_id, new_execution_id
from aerlog.events.models import (
    ExecutionEvent,
    ExecutionFinishedPayload,
    ExecutionHeader,
    ExecutionSummary,
    JsonRpcRequestPayload,
    RedactionSummary,
)
from aerlog.storage import (
    EVENTS_FILE_NAME,
    MANIFEST_FILE_NAME,
    JsonlEventLogReader,
    JsonlEventLogWriter,
    RecordingRepository,
    StorageCorruptionError,
    StorageWriteError,
)
from aerlog.storage.event_log import resolve_execution_dir


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
    ev3 = ExecutionEvent(
        execution_id=exec_id,
        sequence=3,
        event_id=new_event_id(),
        timestamp=datetime(2026, 11, 13, 4, 0, 3, tzinfo=UTC),
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
    summary = _make_summary(exec_id)

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
