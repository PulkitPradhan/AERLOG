"""Unit tests for Phase 5A append-only JSONL event log, permissions, and corruption checks."""

from __future__ import annotations

import errno
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aerlog.capture.redaction import REDACTED_MARKER
from aerlog.events import (
    ExecutionEvent,
    ExecutionFinishedPayload,
    ExecutionHeader,
    ExecutionStartedPayload,
    ExecutionSummary,
    JsonRpcRequestPayload,
    RedactionSummary,
    new_execution_id,
)
from aerlog.storage.event_log import (
    EVENTS_FILE_NAME,
    EXECUTION_FILE_NAME,
    MANIFEST_FILE_NAME,
    STORAGE_SCHEMA_VERSION,
    JsonlEventLogReader,
    JsonlEventLogWriter,
    resolve_execution_dir,
    write_atomic_private_json,
)
from aerlog.storage.exceptions import (
    InvalidExecutionIdError,
    StorageCorruptionError,
    StorageDiskFullError,
    UnsupportedSchemaVersionError,
)


def _sample_events(
    exec_id: str, now: datetime
) -> tuple[ExecutionHeader, list[ExecutionEvent], ExecutionSummary]:
    header = ExecutionHeader(
        execution_id=exec_id,
        started_at=now,
        monotonic_start_ns=100,
        command=("python", "server.py", "--api-key", "raw-flag-secret"),
        cwd="/home/alice/private-project",
    )
    e1 = ExecutionEvent(
        execution_id=exec_id,
        sequence=1,
        timestamp=now,
        monotonic_time_ns=100,
        direction="proxy",
        kind="execution_started",
        payload=ExecutionStartedPayload(
            command=("python", "server.py", "--api-key", REDACTED_MARKER),
            cwd="/home/alice/private-project",
            redaction_mode="standard",
            backpressure_policy="block",
            env_override_keys=("OPENAI_API_KEY",),
            redacted_env_overrides={"OPENAI_API_KEY": REDACTED_MARKER},
        ),
    )
    e2 = ExecutionEvent(
        execution_id=exec_id,
        sequence=2,
        timestamp=now,
        monotonic_time_ns=200,
        direction="client_to_server",
        kind="jsonrpc_request",
        payload=JsonRpcRequestPayload(
            id=1,
            id_type="int",
            method="tools/call",
            has_params=True,
            params={"name": "echo", "arguments": {"text": "hi"}},
        ),
    )
    e3 = ExecutionEvent(
        execution_id=exec_id,
        sequence=3,
        timestamp=now,
        monotonic_time_ns=300,
        direction="proxy",
        kind="execution_finished",
        payload=ExecutionFinishedPayload(
            termination_reason="completed",
            exit_code=0,
            returncode=0,
            completeness="complete",
            total_events=3,
        ),
    )
    summary = ExecutionSummary(
        execution_id=exec_id,
        started_at=now,
        ended_at=now,
        duration_ns=200,
        command=("python", "server.py", "--api-key", "raw-flag-secret"),
        cwd="/home/alice/private-project",
        capture_completeness="complete",
        termination_reason="completed",
        exit_code=0,
        returncode=0,
        total_events=3,
    )
    return header, [e1, e2, e3], summary


def test_jsonl_writer_reader_round_trip_permissions_and_privacy(tmp_path: Path) -> None:
    """Writer enforces 0o700/0o600 permissions, wraps records with SHA-256, and strips env/cwd."""
    exec_id = new_execution_id()
    now = datetime(2026, 11, 11, 17, 0, 0, tzinfo=UTC)
    header, events, summary = _sample_events(exec_id, now)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    slices = writer.append_events(events)
    manifest = writer.finalize(summary)
    writer.close()

    assert len(slices) == 3
    assert manifest.storage_schema_version == STORAGE_SCHEMA_VERSION
    assert manifest.status == "finalized"
    assert manifest.recording_dir == f"executions/{exec_id}"

    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    if os.name == "posix":
        assert stat.S_IMODE(exec_dir.stat().st_mode) == 0o700
        for fname in (EVENTS_FILE_NAME, EXECUTION_FILE_NAME, MANIFEST_FILE_NAME):
            assert stat.S_IMODE((exec_dir / fname).stat().st_mode) == 0o600

    # Requirement C: no plaintext secrets, no env keys/values, and cwd omitted by default.
    for fname in (EVENTS_FILE_NAME, EXECUTION_FILE_NAME, MANIFEST_FILE_NAME):
        text = (exec_dir / fname).read_text(encoding="utf-8")
        assert "raw-flag-secret" not in text
        assert "OPENAI_API_KEY" not in text
        assert "/home/alice/private-project" not in text

    reader = JsonlEventLogReader(tmp_path)
    result = reader.read_execution(exec_id)
    assert result.has_corruptions is False
    assert result.unclean_shutdown is False
    assert [item.event.sequence for item in result.events] == [1, 2, 3]
    assert result.summary is not None
    assert result.summary.cwd is None

    # Direct byte-slice lookup works cleanly
    second = reader.read_event_at(
        exec_id,
        byte_offset=slices[1].byte_offset,
        byte_length=slices[1].byte_length,
    )
    assert second == slices[1].event


def test_execution_id_rejects_path_traversal_and_invalid_uuids(tmp_path: Path) -> None:
    """Path traversal or malformed execution IDs fail closed."""
    for bad in ("../escape", "a/b", "", "not-a-uuid", new_execution_id().upper()):
        with pytest.raises(InvalidExecutionIdError):
            resolve_execution_dir(tmp_path, bad)


def test_jsonl_reader_detects_partial_corrupt_checksum_and_sequence_gaps_preserving_valid(
    tmp_path: Path,
) -> None:
    """Corrupt/truncated/tampered JSONL lines report cleanly while preserving valid rows."""
    exec_id = new_execution_id()
    now = datetime(2026, 11, 11, 17, 5, 0, tzinfo=UTC)
    header, events, summary = _sample_events(exec_id, now)

    writer = JsonlEventLogWriter(tmp_path, exec_id)
    writer.open(header)
    writer.append_events(events)
    writer.finalize(summary)
    writer.close()

    events_path = resolve_execution_dir(tmp_path, exec_id) / EVENTS_FILE_NAME
    original_lines = events_path.read_bytes().splitlines(keepends=True)

    # Corrupt line 2 checksum cleanly without invalidating line 2 JSON syntax.
    tampered = json.loads(original_lines[1].decode("utf-8"))
    tampered["event"]["payload"]["method"] = "tampered/method"
    tampered_line = (json.dumps(tampered) + "\n").encode("utf-8")

    # Inject a corrupt JSON line and a truncated trailing partial line (no newline)
    rebuilt = (
        original_lines[0]
        + tampered_line
        + b"{corrupt_json_middle\n"
        + original_lines[2]
        + b'{"partial_tail": true'
    )
    events_path.write_bytes(rebuilt)

    reader = JsonlEventLogReader(tmp_path)
    tolerant = reader.read_execution(exec_id, strict=False)
    assert tolerant.has_corruptions is True
    kinds = [c.issue_kind for c in tolerant.corruptions]
    assert "checksum_mismatch" in kinds
    assert "invalid_json" in kinds
    assert "sequence_gap" in kinds  # event 1 -> event 3 (since tampered event 2 failed checksum)
    assert "missing_newline" in kinds
    # Valid events 1 and 3 are preserved!
    assert [item.event.sequence for item in tolerant.events] == [1, 3]

    with pytest.raises(StorageCorruptionError):
        reader.read_execution(exec_id, strict=True)


def test_rejects_unredacted_event_and_incompatible_schema_version(tmp_path: Path) -> None:
    """Unredacted events fail under standard mode, and unknown major schema versions raise."""
    exec_id = new_execution_id()
    now = datetime(2026, 11, 11, 17, 10, 0, tzinfo=UTC)
    header, events, _ = _sample_events(exec_id, now)

    writer = JsonlEventLogWriter(tmp_path, exec_id, redaction_mode="standard")
    writer.open(header)
    bad_evt = events[1].model_copy(
        update={
            "redaction": RedactionSummary(
                mode="explicit_unredacted",
                payload_mode="full_unredacted",
                applied=False,
            )
        }
    )
    with pytest.raises(ValueError, match="Refusing to persist unredacted event"):
        writer.append_events([bad_evt])
    writer.close()

    exec_dir = resolve_execution_dir(tmp_path, exec_id)
    future_manifest = json.loads((exec_dir / MANIFEST_FILE_NAME).read_text(encoding="utf-8"))
    future_manifest["storage_schema_version"] = "99.0.0"
    (exec_dir / MANIFEST_FILE_NAME).write_text(json.dumps(future_manifest), encoding="utf-8")

    reader = JsonlEventLogReader(tmp_path)
    with pytest.raises(UnsupportedSchemaVersionError):
        reader.read_execution(exec_id)


def test_atomic_write_and_append_handle_enospc_safely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ENOSPC cleans incomplete temp files, keeps prior metadata, and raises DiskFull."""
    target = tmp_path / "execution.json"
    write_atomic_private_json(target, {"ok": 1}, fsync=False)

    def _raise_enospc(_fd: int, _data: object) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "write", _raise_enospc)
    with pytest.raises(StorageDiskFullError):
        write_atomic_private_json(target, {"ok": 2}, fsync=False)

    # Prior committed file remains untouched and zero leftover .tmp files remain
    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": 1}
    leftovers = [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []
