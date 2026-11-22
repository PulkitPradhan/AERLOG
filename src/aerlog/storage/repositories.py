"""Recording retrieval, indexed event queries, reconciliation, and recovery APIs."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from aerlog.capture.redaction import (
    REDACTION_FAILED_MARKER,
    EventRedactor,
    RedactionConfig,
    merge_redaction_summaries,
    scrub_event_dict_withheld,
)
from aerlog.events.models import (
    ExecutionEvent,
    ExecutionFinishedPayload,
    ExecutionHeader,
    ExecutionStartedPayload,
    ExecutionSummary,
)
from aerlog.events.types import EVENT_SCHEMA_VERSION, CaptureCompleteness, RedactionMode
from aerlog.storage.database import (
    DB_FILE_NAME,
    IndexedEventRow,
    IndexedExecutionRow,
    SQLiteMetadataStore,
    _extract_index_fields,
)
from aerlog.storage.event_log import (
    EVENTS_FILE_NAME,
    EXECUTION_FILE_NAME,
    EXECUTIONS_DIR_NAME,
    MANIFEST_FILE_NAME,
    STORAGE_SCHEMA_VERSION,
    CorruptionIssueKind,
    CorruptRecordReport,
    ExecutionManifest,
    FsyncPolicy,
    JsonlEventLogReader,
    JsonlEventLogWriter,
    JsonlReadResult,
    TailPolicy,
    TailRecoveryResult,
    WrittenEventSlice,
    _parse_jsonl_line,
    canonical_event_sha256,
    compute_file_sha256,
    quarantine_tail_bytes,
    relative_recording_dir,
    resolve_execution_dir,
    sanitize_event_for_persistence,
    sanitize_header_for_persistence,
    sanitize_summary_for_persistence,
    validate_execution_id,
    write_atomic_private_json,
)
from aerlog.storage.exceptions import (
    ExecutionNotFoundError,
    StorageCorruptionError,
)


@dataclass(frozen=True, slots=True)
class StoredExecutionRecord:
    """Combined view of an execution's SQLite index row and on-disk companion files."""

    execution_id: str
    index_row: IndexedExecutionRow | None
    header: ExecutionHeader | None
    summary: ExecutionSummary | None
    manifest: ExecutionManifest | None
    corruptions: tuple[CorruptRecordReport, ...]
    jsonl_exists: bool
    diverged: bool


@dataclass(frozen=True, slots=True)
class EventQueryResult:
    """Retrieved events along with any corruption or divergence findings."""

    events: tuple[ExecutionEvent, ...]
    index_rows: tuple[IndexedEventRow, ...]
    corruptions: tuple[CorruptRecordReport, ...]
    missing_jsonl_execution_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    """Summary of index verification and repair performed from authoritative JSONL."""

    reconciled_execution_ids: tuple[str, ...]
    missing_jsonl_execution_ids: tuple[str, ...]
    discovered_execution_ids: tuple[str, ...]
    corruptions_found: int
    unclean_shutdown_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SpoolImportReport:
    """Outcome summary returned after importing a ``0o600`` recovery spool safely."""

    execution_id: str
    imported_events: int
    skipped_duplicates: int
    corrupt_lines: tuple[CorruptRecordReport, ...]
    final_status: str


@dataclass(frozen=True, slots=True)
class _TailRepair:
    prefix_len: int
    event: ExecutionEvent | None
    issue: CorruptRecordReport | None


_DESTINATION_TAIL_REASON = "Destination log tail: "
_RECOVERED_SPOOL_COMMAND = ("recovered-spool",)


def _verified_destination_quarantine(
    sidecar: Path, execution_id: str
) -> tuple[int, int, str] | None:
    if sidecar.is_symlink() or not sidecar.is_file():
        return None
    try:
        metadata = json.loads(sidecar.read_text(encoding="utf-8"))
    except (ValueError, RecursionError):
        return None
    if not isinstance(metadata, dict) or metadata.get("execution_id") != execution_id:
        return None
    offset, size, digest, reason = (
        metadata.get(field) for field in ("byte_offset", "byte_length", "sha256", "reason")
    )
    if (
        type(offset) is not int
        or offset < 0
        or type(size) is not int
        or size <= 0
        or not isinstance(digest, str)
        or len(digest) != 64
        or not isinstance(reason, str)
        # Historical spool candidates used offset zero. New destination artifacts
        # at that offset carry an explicit reason prefix to distinguish them.
        or (offset == 0 and not reason.startswith(_DESTINATION_TAIL_REASON))
    ):
        return None
    stem = f"corrupted_tail_offset_{offset}_{digest[:12]}"
    if sidecar.name != f"{stem}.meta.json":
        return None
    artifact = sidecar.with_name(f"{stem}.quarantine")
    if (
        not artifact.is_symlink()
        and artifact.is_file()
        and artifact.stat().st_size == size
        and compute_file_sha256(artifact) == digest
    ):
        return offset, size, digest
    return None


def _destination_quarantine_count(exec_dir: Path, execution_id: str) -> int:
    """Count verified destination artifacts independently of the append writer's manifest."""
    return sum(
        _verified_destination_quarantine(sidecar, execution_id) is not None
        for sidecar in exec_dir.glob("corrupted_tail_*.meta.json")
    )


def _inspect_tail(
    prior: JsonlReadResult,
    file_bytes: bytes,
    *,
    tail_policy: TailPolicy,
    require_unambiguous: bool = False,
) -> _TailRepair | None:
    """Plan tail repair without changing the log, its companions, or SQLite."""
    if not file_bytes or file_bytes.endswith(b"\n"):
        if prior.corruptions and tail_policy == "reject":
            raise StorageCorruptionError(
                f"Corruption detected in {prior.execution_id}: {prior.corruptions[0].details}"
            )
        return None

    prefix_len = file_bytes.rfind(b"\n") + 1
    if tail_policy == "reject":
        for corruption in prior.corruptions:
            if corruption.byte_offset < prefix_len:
                raise StorageCorruptionError(
                    f"Corruption detected in {prior.execution_id}: {corruption.details}"
                )
    raw_tail = file_bytes[prefix_len:]
    event, issue = _parse_jsonl_line(
        execution_id=prior.execution_id,
        raw_line=raw_tail + b"\n",
        line_number=len(prior.events) + 1,
        byte_offset=prefix_len,
        verify_checksum=True,
    )
    if issue is None and event is not None:
        has_id = "event_id" in event.model_fields_set and bool(event.event_id.strip())
        reused_id = any(item.event.event_id == event.event_id for item in prior.events)
        if (
            require_unambiguous
            and event.execution_id == prior.execution_id
            and (
                not has_id
                or reused_id
                or any(item.event.sequence == event.sequence for item in prior.events)
            )
        ):
            raise StorageCorruptionError(
                f"Ambiguous destination identity in {prior.execution_id} "
                f"at sequence {event.sequence}"
            )
        expected_seq = prior.last_valid_sequence + 1
        issue_kind: CorruptionIssueKind = "event_validation_failed"
        if event.execution_id != prior.execution_id:
            details = "Tail event belongs to a different execution"
        elif not has_id:
            details = "Tail event lacks an explicit event_id"
        elif any(item.event.kind == "execution_finished" for item in prior.events):
            details = "Tail event follows the terminal event"
        elif event.sequence != expected_seq:
            details = f"Sequence gap: expected {expected_seq}, got {event.sequence}"
            issue_kind = "sequence_gap"
        elif reused_id:
            details = f"Duplicate event_id: {event.event_id!r}"
        else:
            return _TailRepair(prefix_len, event, None)
        issue = CorruptRecordReport(
            execution_id=prior.execution_id,
            line_number=len(prior.events) + 1,
            byte_offset=prefix_len,
            byte_length=len(raw_tail),
            issue_kind=issue_kind,
            excerpt_sha256=hashlib.sha256(raw_tail).hexdigest(),
            details=details,
        )

    if tail_policy == "reject":
        details = issue.details if issue else "Inconsistent tail"
        raise StorageCorruptionError(f"Inconsistent tail in {prior.execution_id}: {details}")
    return _TailRepair(prefix_len, None, issue)


def _recovery_event_digest(event: ExecutionEvent) -> str:
    """Compare persisted evidence, ignoring audit changes from repeated redaction."""
    data = event.model_dump(mode="json")
    del data["redaction"]["findings_count"], data["redaction"]["redacted_paths"]
    return canonical_event_sha256(data)


def _is_recovery_duplicate(
    stored: ExecutionEvent, incoming: ExecutionEvent, *, allow_legacy_strict: bool
) -> bool:
    incoming_digest = _recovery_event_digest(incoming)
    if _recovery_event_digest(stored) == incoming_digest:
        return True
    if (
        allow_legacy_strict
        and stored.redaction.mode == "standard"
        and stored.redaction.payload_mode == "redacted"
        and stored.redaction.applied
        and not stored.redaction.degraded
    ):
        # Older default imports relabelled withheld events as standard. Compare all
        # retained evidence with only those two historical labels translated.
        legacy_redaction = stored.redaction.model_copy(
            update={"mode": "strict_hash_only", "payload_mode": "strict_hash_only"}
        )
        return (
            _recovery_event_digest(stored.model_copy(update={"redaction": legacy_redaction}))
            == incoming_digest
        )
    return False


def _has_matching_final_summary(
    events: Sequence[ExecutionEvent],
    summary: ExecutionSummary,
    *,
    allow_legacy_end_time: bool = False,
) -> bool:
    if not events:
        return False
    terminal = events[-1]
    payload = terminal.payload
    first = events[0]
    started = first.payload
    summary_command = summary.command
    if (
        isinstance(started, ExecutionStartedPayload)
        and first.redaction.mode == "strict_hash_only"
        and summary.redaction_mode != "strict_hash_only"
    ):
        # A recovery import can withhold arguments still present in the source summary.
        redactor = EventRedactor(RedactionConfig(mode="strict_hash_only"))
        summary_command, _ = redactor.redact_command(summary_command)
    return (
        isinstance(payload, ExecutionFinishedPayload)
        and terminal.direction == "proxy"
        and all(
            event.execution_id == summary.execution_id and event.sequence == sequence
            for sequence, event in enumerate(events, start=1)
        )
        and not any(event.kind == "execution_finished" for event in events[:-1])
        and summary.started_at <= terminal.timestamp
        and (
            summary.ended_at == terminal.timestamp
            or (
                allow_legacy_end_time
                and not isinstance(started, ExecutionStartedPayload)
                and terminal.timestamp < summary.ended_at
            )
        )
        and summary.total_events == payload.total_events == terminal.sequence
        and summary.capture_completeness == payload.completeness
        and summary.termination_reason == payload.termination_reason
        and summary.exit_code == payload.exit_code
        and summary.returncode == payload.returncode
        and summary.dropped_events == payload.dropped_events
        and summary.degraded_events == payload.degraded_events
        and summary.unanswered_request_ids == payload.unanswered_request_ids
        and summary.spool_file == payload.spool_file
        and (
            not isinstance(started, ExecutionStartedPayload)
            or (
                summary.started_at == first.timestamp
                and summary.transport == started.transport
                and summary.backpressure_policy == started.backpressure_policy
                and summary.redaction_mode == started.redaction_mode
                and summary_command == started.command
                and summary.duration_ns
                == max(0, terminal.monotonic_time_ns - first.monotonic_time_ns)
            )
        )
        and (
            summary.capture_completeness != "complete"
            or (
                summary.dropped_events == summary.gap_count == summary.degraded_events == 0
                and not any(event.kind == "capture_gap" or event.degraded for event in events)
            )
        )
    )


def _matches_manifest(
    manifest: ExecutionManifest, *, byte_size: int, line_count: int, last_sequence: int, digest: str
) -> bool:
    return (
        manifest.recording_dir == relative_recording_dir(manifest.execution_id)
        and manifest.byte_size == byte_size
        and manifest.line_count == line_count
        and manifest.last_sequence == last_sequence
        and manifest.events_file_sha256 == digest
    )


def _has_seal_mismatch(read: JsonlReadResult) -> bool:
    manifest = read.manifest
    return (
        manifest is not None
        and (manifest.events_file_sha256 is not None or manifest.status == "finalized")
        and not _matches_manifest(
            manifest,
            byte_size=read.byte_size,
            line_count=read.line_count,
            last_sequence=read.last_valid_sequence,
            digest=read.events_file_sha256,
        )
    )


def _recording_completeness(read: JsonlReadResult) -> str:
    manifest, summary = read.manifest, read.summary
    if (
        read.has_corruptions
        or _has_seal_mismatch(read)
        or (manifest is not None and manifest.status == "corrupted")
    ):
        return "corrupted"
    if (
        read.unclean_shutdown
        or summary is None
        or manifest is None
        or manifest.corruption_count > 0
        or (summary.capture_completeness == "complete" and manifest.status != "finalized")
        or not _has_matching_final_summary(
            [item.event for item in read.events],
            summary,
            allow_legacy_end_time=manifest.finalized_at is not None,
        )
    ):
        return "incomplete"
    return summary.capture_completeness


def _derive_execution_row_from_jsonl(
    *,
    read_result: JsonlReadResult,
    persist_cwd: bool,
) -> dict[str, Any]:
    """Construct an authoritative ``executions`` index dict from JSONL and companions."""
    clean_id = read_result.execution_id
    summary = read_result.summary
    header = read_result.header
    events = read_result.events

    started_at = (
        summary.started_at
        if summary is not None
        else header.started_at
        if header is not None
        else events[0].event.timestamp
        if events
        else datetime.now(UTC)
    )
    redaction_mode: RedactionMode = (
        summary.redaction_mode
        if summary is not None
        else header.redaction_mode
        if header is not None
        else events[0].event.redaction.mode
        if events
        else "standard"
    )
    backpressure_policy = (
        summary.backpressure_policy
        if summary is not None
        else header.backpressure_policy
        if header is not None
        else "block"
    )

    raw_cmd: tuple[str, ...] = ("unknown",)
    raw_cwd: str | None = None
    if summary is not None:
        raw_cmd = summary.command
        raw_cwd = summary.cwd
    elif header is not None:
        raw_cmd = header.command
        raw_cwd = header.cwd

    redactor = EventRedactor(RedactionConfig(mode=redaction_mode))
    safe_cmd, _ = redactor.redact_command(raw_cmd)
    safe_cwd = raw_cwd if persist_cwd and redaction_mode != "strict_hash_only" else None

    completeness = _recording_completeness(read_result)

    observed_traces: list[str] = list(summary.observed_trace_ids) if summary is not None else []
    if not observed_traces:
        for item in events:
            t_id = item.event.trace.observed_trace_id if item.event.trace else None
            if t_id is not None and t_id not in observed_traces:
                observed_traces.append(t_id)

    degraded_count = (
        summary.degraded_events
        if summary is not None
        else sum(1 for item in events if item.event.degraded)
    )
    warning_count = (
        summary.warning_count
        if summary is not None
        else sum(1 for item in events if item.event.kind == "capture_warning")
    )
    gap_count = (
        summary.gap_count
        if summary is not None
        else sum(1 for item in events if item.event.kind == "capture_gap")
    )

    return {
        "execution_id": clean_id,
        "schema_version": summary.schema_version
        if summary is not None
        else header.schema_version
        if header is not None
        else EVENT_SCHEMA_VERSION,
        "storage_schema_version": STORAGE_SCHEMA_VERSION,
        "started_at": started_at.astimezone(UTC).isoformat(),
        "ended_at": summary.ended_at.astimezone(UTC).isoformat() if summary else None,
        "duration_ns": summary.duration_ns if summary else None,
        "command_json": json.dumps(list(safe_cmd), ensure_ascii=False),
        "cwd": safe_cwd,
        "transport": summary.transport if summary else header.transport if header else "stdio",
        "redaction_mode": redaction_mode,
        "backpressure_policy": backpressure_policy,
        "capture_completeness": completeness,
        "termination_reason": (
            summary.termination_reason
            if summary is not None
            else "unclean_shutdown"
            if read_result.unclean_shutdown
            else None
        ),
        "exit_code": summary.exit_code if summary is not None else None,
        "returncode": summary.returncode if summary is not None else None,
        "total_events": max(len(events), summary.total_events if summary is not None else 0),
        "dropped_events": summary.dropped_events if summary is not None else 0,
        "degraded_events": degraded_count,
        "warning_count": warning_count,
        "gap_count": gap_count,
        "unanswered_request_ids_json": json.dumps(
            list(summary.unanswered_request_ids) if summary is not None else [],
            ensure_ascii=False,
        ),
        "observed_trace_ids_json": json.dumps(observed_traces, ensure_ascii=False),
        "observed_mcp_versions_json": json.dumps(
            list(summary.observed_mcp_protocol_versions) if summary is not None else [],
            ensure_ascii=False,
        ),
        "recording_dir": relative_recording_dir(clean_id),
        "jsonl_byte_offset": read_result.byte_size,
        "jsonl_sha256": read_result.events_file_sha256,
        "last_indexed_sequence": read_result.last_valid_sequence,
        "index_status": "recovered"
        if read_result.unclean_shutdown
        or completeness == "corrupted"
        or (read_result.manifest is not None and read_result.manifest.corruption_count > 0)
        else "indexed",
    }


def _recovery_index_matches(
    store: SQLiteMetadataStore,
    row: IndexedExecutionRow,
    prior: JsonlReadResult,
    *,
    persist_cwd: bool,
) -> bool:
    """Compare execution metadata and event slices to their JSONL projections."""
    expected = _derive_execution_row_from_jsonl(read_result=prior, persist_cwd=persist_cwd)
    actual = asdict(row)
    for field in ("started_at", "ended_at"):
        value = actual[field]
        actual[field] = value.astimezone(UTC).isoformat() if value is not None else None
    for field in (
        "command",
        "unanswered_request_ids",
        "observed_trace_ids",
        "observed_mcp_versions",
    ):
        actual[f"{field}_json"] = json.dumps(list(actual.pop(field)), ensure_ascii=False)
    if actual != expected:
        return False

    # One extra result detects surplus rows. SQL orders by timestamp, so use sequence keys.
    try:
        rows = store.query_event_index(execution_id=prior.execution_id, limit=len(prior.events) + 1)
        corruptions = store.get_corruptions(prior.execution_id)
    except ValueError:
        # SQLite returned values that the typed index reader could not decode.
        return False
    if len(rows) != len(prior.events) or corruptions != prior.corruptions:
        return False
    indexed = {item.sequence: item for item in rows}
    for item in prior.events:
        event = item.event
        method, id_type, id_text = _extract_index_fields(event)
        trace, correlation, derived = event.trace, event.correlation, event.derived
        if indexed.get(event.sequence) != IndexedEventRow(
            execution_id=prior.execution_id,
            event_id=event.event_id,
            sequence=event.sequence,
            timestamp=event.timestamp,
            monotonic_time_ns=event.monotonic_time_ns,
            direction=event.direction,
            kind=event.kind,
            method=method,
            jsonrpc_id_type=id_type,
            jsonrpc_id_text=id_text,
            observed_trace_id=trace.observed_trace_id if trace else None,
            observed_parent_span_id=trace.observed_parent_span_id if trace else None,
            synthetic_execution_trace_id=trace.synthetic_execution_trace_id if trace else None,
            correlation_status=correlation.status if correlation else None,
            matched_request_event_id=correlation.matched_request_event_id if correlation else None,
            tool_is_error=derived.tool_is_error if derived else None,
            degraded=event.degraded,
            jsonl_byte_offset=item.byte_offset,
            jsonl_byte_length=item.byte_length,
        ):
            return False
    return True


def _recovery_manifest(
    prior: JsonlReadResult, summary: ExecutionSummary | None
) -> ExecutionManifest:
    manifest = prior.manifest
    corruption_count = manifest.corruption_count if manifest else 0
    finalized_at = manifest.finalized_at if manifest else None
    return ExecutionManifest(
        execution_id=prior.execution_id,
        recording_dir=relative_recording_dir(prior.execution_id),
        status=(
            "finalized"
            if summary and summary.capture_completeness == "complete" and not corruption_count
            else "incomplete"
        ),
        created_at=(
            manifest.created_at
            if manifest
            else summary.started_at
            if summary
            else prior.header.started_at
            if prior.header
            else prior.events[0].event.timestamp
            if prior.events
            else datetime.now(UTC)
        ),
        finalized_at=(finalized_at or datetime.now(UTC)) if summary else None,
        byte_size=prior.byte_size,
        line_count=prior.line_count,
        last_sequence=prior.last_valid_sequence,
        events_file_sha256=prior.events_file_sha256,
        corruption_count=corruption_count,
    )


class RecordingRepository:
    """High-level retrieval, indexed querying, integrity verification, and recovery API."""

    def __init__(
        self,
        data_dir: Path,
        *,
        store: SQLiteMetadataStore | None = None,
        persist_cwd: bool = False,
    ) -> None:
        self._data_dir = data_dir
        self._persist_cwd = persist_cwd
        self._store = (
            store if store is not None else SQLiteMetadataStore(data_dir, persist_cwd=persist_cwd)
        )
        self._reader = JsonlEventLogReader(data_dir)
        self._owns_store = store is None

    @property
    def data_dir(self) -> Path:
        """Root AERLOG data directory managed by this repository."""
        return self._data_dir

    @property
    def store(self) -> SQLiteMetadataStore:
        """SQLite metadata store backing indexed queries."""
        return self._store

    def initialize(self) -> None:
        """Ensure SQLite metadata store and migrations are initialized."""
        self._store.initialize()

    def has_existing_storage(self) -> bool:
        """Return True if an SQLite DB or any valid execution dir already exists on disk.

        Never creates directories or database files when storage has not been created yet.
        """
        if self._store.is_open or (self._data_dir / DB_FILE_NAME).exists():
            return True
        exec_root = self._data_dir / EXECUTIONS_DIR_NAME
        if not exec_root.is_dir():
            return False
        return bool(self._reader.discover_execution_ids())

    def close(self) -> None:
        """Close owned SQLite resources if created by this repository."""
        if self._owns_store:
            self._store.close()

    def list_executions(
        self,
        *,
        completeness: CaptureCompleteness | Literal["recording", "corrupted"] | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        command_contains: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[IndexedExecutionRow, ...]:
        """List stored execution metadata rows matching optional filters."""
        return self._store.list_execution_rows(
            completeness=completeness,
            since=since,
            until=until,
            command_contains=command_contains,
            limit=limit,
            offset=offset,
        )

    def get_execution(self, execution_id: str) -> StoredExecutionRecord:
        """Retrieve combined SQLite index row, companion files, and divergence state."""
        clean_id = validate_execution_id(execution_id)
        db_exists = self._store.is_open or self._store.db_path.exists()
        row = self._store.get_execution_row(clean_id) if db_exists else None
        exec_dir = resolve_execution_dir(self._data_dir, clean_id)
        events_path = exec_dir / EVENTS_FILE_NAME
        jsonl_exists = events_path.exists()

        header, summary, manifest = self._reader.read_metadata(clean_id)
        if (
            row is None
            and not jsonl_exists
            and header is None
            and summary is None
            and manifest is None
        ):
            raise ExecutionNotFoundError(f"Execution {clean_id!r} not found")

        corruptions = self._store.get_corruptions(clean_id) if row is not None else ()
        diverged = False
        if row is not None:
            if not jsonl_exists:
                diverged = True
            else:
                disk_size = events_path.stat().st_size
                if disk_size != row.jsonl_byte_offset:
                    diverged = True
                if manifest is not None and manifest.last_sequence != row.last_indexed_sequence:
                    diverged = True
        elif jsonl_exists:
            diverged = True

        return StoredExecutionRecord(
            execution_id=clean_id,
            index_row=row,
            header=header,
            summary=summary,
            manifest=manifest,
            corruptions=corruptions,
            jsonl_exists=jsonl_exists,
            diverged=diverged,
        )

    def get_execution_events(
        self,
        execution_id: str,
        *,
        strict_integrity: bool = False,
        verify_checksums: bool = True,
        mark_missing: bool = True,
    ) -> JsonlReadResult:
        """Read and verify all events directly from authoritative ``events.jsonl``."""
        clean_id = validate_execution_id(execution_id)
        exec_dir = resolve_execution_dir(self._data_dir, clean_id)
        if not exec_dir.exists():
            if mark_missing and (self._store.is_open or self._store.db_path.exists()):
                row = self._store.get_execution_row(clean_id)
                if row is not None:
                    self._store.mark_missing_jsonl(clean_id)
            raise ExecutionNotFoundError(f"Execution directory missing for {clean_id!r}")
        return self._reader.read_execution(
            clean_id,
            strict=strict_integrity,
            verify_checksums=verify_checksums,
        )

    def get_event_by_sequence(
        self,
        execution_id: str,
        sequence: int,
        *,
        verify_checksum: bool = True,
        strict_integrity: bool = False,
    ) -> ExecutionEvent:
        """Retrieve a single stored event by ``execution_id`` and 1-based ``sequence``."""
        if sequence < 1:
            raise ValueError(f"sequence must be >= 1, got {sequence}")
        read_res = self.get_execution_events(
            execution_id,
            strict_integrity=strict_integrity,
            verify_checksums=verify_checksum,
            mark_missing=False,
        )
        for item in read_res.events:
            if item.event.sequence == sequence:
                return item.event
        for issue in read_res.corruptions:
            if issue.line_number == sequence:
                raise StorageCorruptionError(
                    f"Event sequence {sequence} in {execution_id!r} is corrupt: {issue.details}"
                )
        raise ExecutionNotFoundError(
            f"Event sequence {sequence} not found in execution {execution_id!r}"
        )

    def query_events(
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
        strict_integrity: bool = False,
        verify_checksums: bool = True,
    ) -> EventQueryResult:
        """Query indexed events via SQLite and hydrate verified objects from ``events.jsonl``."""
        rows = self._store.query_event_index(
            execution_id=execution_id,
            trace_id=trace_id,
            span_id=span_id,
            request_id=request_id,
            id_type=id_type,
            matched_request_event_id=matched_request_event_id,
            kind=kind,
            method=method,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )

        events: list[ExecutionEvent] = []
        valid_rows: list[IndexedEventRow] = []
        corruptions: list[CorruptRecordReport] = []
        missing_execs: list[str] = []

        for row in rows:
            try:
                exec_dir = resolve_execution_dir(self._data_dir, row.execution_id)
                events_path = exec_dir / EVENTS_FILE_NAME
                if not events_path.exists():
                    if row.execution_id not in missing_execs:
                        missing_execs.append(row.execution_id)
                    if strict_integrity:
                        raise StorageCorruptionError(
                            f"Missing events.jsonl for indexed execution {row.execution_id!r}"
                        )
                    continue

                evt = self._reader.read_event_at(
                    row.execution_id,
                    byte_offset=row.jsonl_byte_offset,
                    byte_length=row.jsonl_byte_length,
                    verify_checksum=verify_checksums,
                )
                events.append(evt)
                valid_rows.append(row)
            except StorageCorruptionError as exc:
                if strict_integrity:
                    raise
                corruptions.append(
                    CorruptRecordReport(
                        execution_id=row.execution_id,
                        line_number=row.sequence,
                        byte_offset=row.jsonl_byte_offset,
                        byte_length=row.jsonl_byte_length,
                        issue_kind="checksum_mismatch",
                        excerpt_sha256="",
                        details=str(exc),
                    )
                )

        return EventQueryResult(
            events=tuple(events),
            index_rows=tuple(valid_rows),
            corruptions=tuple(corruptions),
            missing_jsonl_execution_ids=tuple(missing_execs),
        )

    def recover_tail(
        self,
        execution_id: str,
        *,
        tail_policy: TailPolicy = "quarantine",
    ) -> TailRecoveryResult:
        """Inspect and recover an incomplete, malformed, or inconsistent JSONL tail safely.

        - If the tail is a valid JSONL record missing only the trailing newline, appends
          the newline, validates manifest consistency, updates the manifest, and indexes it.
        - If the tail is incomplete, malformed, or violates sequence continuity or event_id
          uniqueness:
          - Under 'reject', raises StorageCorruptionError leaving the log untouched.
          - Under 'quarantine', spills the raw corrupted bytes to a 0o600 quarantine artifact
            with companion forensic JSON metadata, rewinds events.jsonl to the verified prefix,
            and marks the manifest status as 'incomplete'.
        """
        clean_id = validate_execution_id(execution_id)
        exec_dir = resolve_execution_dir(self._data_dir, clean_id)
        events_path = exec_dir / EVENTS_FILE_NAME
        prior = self._reader.read_execution(clean_id, strict=False, verify_checksums=True)
        file_bytes = events_path.read_bytes() if events_path.exists() else b""
        repair = _inspect_tail(prior, file_bytes, tail_policy=tail_policy)
        return self._apply_tail_repair(exec_dir, prior, file_bytes, repair)

    def _apply_tail_repair(
        self,
        exec_dir: Path,
        prior: JsonlReadResult,
        file_bytes: bytes,
        repair: _TailRepair | None,
        *,
        update_index: bool = True,
    ) -> TailRecoveryResult:
        clean_id = prior.execution_id
        prior_line_count = len(prior.events)
        prior_last_seq = prior.last_valid_sequence
        if repair is None:
            return TailRecoveryResult(
                execution_id=clean_id,
                action_taken="none",
                recovered_event=None,
                quarantined_report=None,
                quarantine_path=None,
                bytes_recovered=0,
                prior_line_count=prior_line_count,
                final_line_count=prior_line_count,
                prior_last_sequence=prior_last_seq,
                final_last_sequence=prior_last_seq,
            )

        events_path = exec_dir / EVENTS_FILE_NAME
        manifest_path = exec_dir / MANIFEST_FILE_NAME
        prefix_len = repair.prefix_len
        raw_tail = file_bytes[prefix_len:]
        decoded = repair.event
        issue = repair.issue
        previous = prior.manifest
        created_at = (
            previous.created_at
            if previous
            else prior.header.started_at
            if prior.header
            else prior.summary.started_at
            if prior.summary
            else datetime.now(UTC)
        )
        if decoded is not None:
            digest = hashlib.sha256(file_bytes)
            digest.update(b"\n")
            restored_sha = digest.hexdigest()
            new_line_count = prior.line_count
            new_last_seq = decoded.sequence
            same_manifest = (
                previous is not None
                and previous.execution_id == clean_id
                and _matches_manifest(
                    previous,
                    byte_size=len(file_bytes) + 1,
                    line_count=new_line_count,
                    last_sequence=new_last_seq,
                    digest=restored_sha,
                )
            )
            if previous is not None and previous.status == "finalized" and not same_manifest:
                raise StorageCorruptionError(
                    "Restored newline would not match the finalized manifest"
                )
            with events_path.open("ab") as f:
                f.write(b"\n")
                f.flush()
                os.fsync(f.fileno())
            if not same_manifest:
                manifest = ExecutionManifest(
                    execution_id=clean_id,
                    recording_dir=relative_recording_dir(clean_id),
                    status=(
                        previous.status
                        if previous
                        else "recording"
                        if prior.summary
                        else "incomplete"
                    ),
                    created_at=created_at,
                    finalized_at=previous.finalized_at if previous else None,
                    byte_size=len(file_bytes) + 1,
                    line_count=new_line_count,
                    last_sequence=new_last_seq,
                    events_file_sha256=restored_sha,
                    corruption_count=previous.corruption_count if previous else 0,
                )
                write_atomic_private_json(
                    manifest_path, manifest.model_dump(mode="json"), fsync=True
                )
            if update_index:
                self._reconcile_internal(clean_id)

            return TailRecoveryResult(
                execution_id=clean_id,
                action_taken="completed_newline",
                recovered_event=decoded,
                quarantined_report=None,
                quarantine_path=None,
                bytes_recovered=len(raw_tail),
                prior_line_count=prior_line_count,
                final_line_count=new_line_count,
                prior_last_sequence=prior_last_seq,
                final_last_sequence=new_last_seq,
            )

        prefix = file_bytes[:prefix_len]
        prefix_digest = hashlib.sha256(prefix).hexdigest()
        tail_digest = hashlib.sha256(raw_tail).hexdigest()
        stem = f"corrupted_tail_offset_{prefix_len}_{tail_digest[:12]}"
        sidecar = exec_dir / f"{stem}.meta.json"
        q_path = exec_dir / f"{stem}.quarantine"
        evidence_matches = _verified_destination_quarantine(sidecar, clean_id) == (
            prefix_len,
            len(raw_tail),
            tail_digest,
        )
        matches_previous_decision = (
            evidence_matches
            and previous is not None
            and previous.execution_id == clean_id
            and previous.status == "incomplete"
            and previous.corruption_count > 0
            and _matches_manifest(
                previous,
                byte_size=prefix_len,
                line_count=prior.line_count - 1,
                last_sequence=prior_last_seq,
                digest=prefix_digest,
            )
        )
        reason = _DESTINATION_TAIL_REASON + (issue.details if issue else "Inconsistent tail")
        issue_kind = issue.issue_kind if issue else "invalid_json"
        if evidence_matches:
            q_report = CorruptRecordReport(
                execution_id=clean_id,
                line_number=-1,
                byte_offset=prefix_len,
                byte_length=len(raw_tail),
                issue_kind=issue_kind,
                excerpt_sha256=tail_digest,
                details=f"Quarantined tail: {reason}",
            )
        else:
            if q_path.is_symlink() or (
                q_path.exists()
                and (not q_path.is_file() or compute_file_sha256(q_path) != tail_digest)
            ):
                raise StorageCorruptionError("Quarantine artifact conflicts with the damaged tail")
            q_path, _, q_report = quarantine_tail_bytes(
                exec_dir=exec_dir,
                execution_id=clean_id,
                raw_tail=raw_tail,
                byte_offset=prefix_len,
                reason=reason,
                issue_kind=issue_kind,
            )
        if matches_previous_decision:
            assert previous is not None
            manifest = previous
        else:
            manifest = ExecutionManifest(
                execution_id=clean_id,
                recording_dir=relative_recording_dir(clean_id),
                status="incomplete",
                created_at=created_at,
                finalized_at=previous.finalized_at if previous else None,
                byte_size=prefix_len,
                line_count=prior.line_count - 1,
                last_sequence=prior_last_seq,
                events_file_sha256=prefix_digest,
                corruption_count=(previous.corruption_count if previous else 0) + 1,
            )
        tmp_events = exec_dir / f".events.jsonl.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
        fd = os.open(tmp_events, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(prefix)
                handle.flush()
                os.fsync(handle.fileno())
            # Persist a new quarantine decision before removing the original tail bytes.
            if manifest != previous:
                write_atomic_private_json(
                    manifest_path, manifest.model_dump(mode="json"), fsync=True
                )
            os.replace(tmp_events, events_path)
        finally:
            tmp_events.unlink(missing_ok=True)
        if update_index:
            self._reconcile_internal(clean_id)

        return TailRecoveryResult(
            execution_id=clean_id,
            action_taken="quarantined",
            recovered_event=None,
            quarantined_report=q_report,
            quarantine_path=q_path,
            bytes_recovered=0,
            prior_line_count=prior_line_count,
            final_line_count=prior_line_count,
            prior_last_sequence=prior_last_seq,
            final_last_sequence=prior_last_seq,
        )

    def reconcile_execution(self, execution_id: str) -> JsonlReadResult | None:
        """Rebuild SQLite index state for one execution from authoritative ``events.jsonl``."""
        clean_id = validate_execution_id(execution_id)
        return self._reconcile_internal(clean_id)

    def _reconcile_internal(self, clean_id: str) -> JsonlReadResult | None:
        exec_dir = resolve_execution_dir(self._data_dir, clean_id)
        events_path = exec_dir / EVENTS_FILE_NAME
        has_disk = exec_dir.exists() and (
            events_path.exists() or (exec_dir / EXECUTION_FILE_NAME).exists()
        )
        if not has_disk:
            if self._store.get_execution_row(clean_id) is not None:
                self._store.mark_missing_jsonl(clean_id)
                return None
            raise ExecutionNotFoundError(f"Execution {clean_id!r} not found in DB or on disk")

        read_result = self._reader.read_execution(
            clean_id,
            strict=False,
            verify_checksums=True,
        )
        self._replace_verified_index(read_result)
        return read_result

    def _replace_verified_index(self, read_result: JsonlReadResult) -> None:
        execution_row = _derive_execution_row_from_jsonl(
            read_result=read_result,
            persist_cwd=self._persist_cwd,
        )
        slices = [
            WrittenEventSlice(
                event=item.event,
                byte_offset=item.byte_offset,
                byte_length=item.byte_length,
            )
            for item in read_result.events
        ]
        self._store.replace_execution_index(
            execution_row=execution_row,
            slices=slices,
            corruptions=read_result.corruptions,
        )

    def reconcile_all_executions(self) -> ReconciliationReport:
        """Scan SQLite and filesystem executions, repairing divergence from JSONL truth."""
        self._store.initialize()
        disk_ids = set(self._reader.discover_execution_ids())
        db_rows = self._store.list_execution_rows(limit=1_000_000, offset=0)
        db_ids = {r.execution_id for r in db_rows}

        reconciled: list[str] = []
        missing_jsonl: list[str] = []
        discovered: list[str] = []
        unclean: list[str] = []
        corruptions_total = 0

        for eid in sorted(disk_ids | db_ids):
            was_on_disk_only = eid in disk_ids and eid not in db_ids
            res = self.reconcile_execution(eid)
            if res is None:
                missing_jsonl.append(eid)
                continue
            reconciled.append(eid)
            if was_on_disk_only:
                discovered.append(eid)
            if res.unclean_shutdown:
                unclean.append(eid)
            corruptions_total += len(res.corruptions)

        return ReconciliationReport(
            reconciled_execution_ids=tuple(reconciled),
            missing_jsonl_execution_ids=tuple(missing_jsonl),
            discovered_execution_ids=tuple(discovered),
            corruptions_found=corruptions_total,
            unclean_shutdown_ids=tuple(unclean),
        )

    def import_recovery_spool(
        self,
        spool_path: Path,
        *,
        redaction_mode: RedactionMode = "standard",
        fsync_policy: FsyncPolicy = "lifecycle",
        tail_policy: TailPolicy = "quarantine",
    ) -> SpoolImportReport:
        """Validate, redact, deduplicate, and import a ``0o600`` local recovery spool."""
        if spool_path.is_symlink():
            raise StorageCorruptionError(f"Refusing symlink recovery spool: {spool_path}")
        if not spool_path.exists():
            raise ExecutionNotFoundError(f"Recovery spool not found: {spool_path}")

        redactor = EventRedactor(RedactionConfig(mode=redaction_mode))
        parsed_header: ExecutionHeader | None = None
        parsed_summary: ExecutionSummary | None = None
        conflicting_summaries: list[ExecutionSummary] = []
        parsed_events: list[tuple[ExecutionEvent, bool]] = []
        corrupt_lines: list[CorruptRecordReport] = []
        observed_exec_ids: set[str] = set()

        with spool_path.open("rb") as handle:
            offset = 0
            for line_no, raw_line in enumerate(handle, start=1):
                line_len = len(raw_line)
                line_hash = hashlib.sha256(raw_line).hexdigest()
                if not raw_line.endswith(b"\n"):
                    corrupt_lines.append(
                        CorruptRecordReport(
                            execution_id="unknown",
                            line_number=line_no,
                            byte_offset=offset,
                            byte_length=line_len,
                            issue_kind="missing_newline",
                            excerpt_sha256=line_hash,
                            details=f"Spool line {line_no} truncated without newline",
                        )
                    )
                    offset += line_len
                    continue

                body = raw_line[:-1].rstrip(b"\r")
                try:
                    decoded = json.loads(body.decode("utf-8", errors="strict"))
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                    corrupt_lines.append(
                        CorruptRecordReport(
                            execution_id="unknown",
                            line_number=line_no,
                            byte_offset=offset,
                            byte_length=line_len,
                            issue_kind=(
                                "invalid_utf8"
                                if isinstance(exc, UnicodeDecodeError)
                                else "invalid_json"
                            ),
                            excerpt_sha256=line_hash,
                            details=f"Spool line {line_no} malformed: {type(exc).__name__}",
                        )
                    )
                    offset += line_len
                    continue

                if not isinstance(decoded, dict) or not isinstance(decoded.get("data"), dict):
                    corrupt_lines.append(
                        CorruptRecordReport(
                            execution_id="unknown",
                            line_number=line_no,
                            byte_offset=offset,
                            byte_length=line_len,
                            issue_kind="invalid_record_envelope",
                            excerpt_sha256=line_hash,
                            details=f"Spool line {line_no} invalid spool wrapper",
                        )
                    )
                    offset += line_len
                    continue

                rec_type = decoded.get("record_type")
                rec_data = decoded["data"]
                try:
                    if rec_type == "header":
                        hdr = ExecutionHeader.model_validate(rec_data)
                        clean_eid = validate_execution_id(hdr.execution_id)
                        observed_exec_ids.add(clean_eid)
                        parsed_header = sanitize_header_for_persistence(
                            hdr, persist_cwd=self._persist_cwd
                        )
                    elif rec_type == "summary":
                        smry = ExecutionSummary.model_validate(rec_data)
                        clean_eid = validate_execution_id(smry.execution_id)
                        observed_exec_ids.add(clean_eid)
                        safe_summary = sanitize_summary_for_persistence(
                            smry, persist_cwd=self._persist_cwd
                        )
                        if parsed_summary is None:
                            parsed_summary = safe_summary
                        elif safe_summary != parsed_summary:
                            conflicting_summaries.append(safe_summary)
                    elif rec_type == "event":
                        if (
                            not isinstance(event_id := rec_data.get("event_id"), str)
                            or not event_id.strip()
                        ):
                            raise ValueError("Recovery event requires an explicit event_id")
                        ev = ExecutionEvent.model_validate(rec_data)
                        clean_eid = validate_execution_id(ev.execution_id)
                        observed_exec_ids.add(clean_eid)
                        safe_event = sanitize_event_for_persistence(
                            _re_redact_event(ev, redactor=redactor),
                            redaction_mode=redaction_mode,
                            persist_cwd=self._persist_cwd,
                        )
                        legacy_strict_candidate = (
                            redaction_mode == "standard"
                            and ev.redaction.mode == "strict_hash_only"
                            and ev.redaction.payload_mode == "strict_hash_only"
                            and ev.redaction.applied
                            and not ev.redaction.degraded
                        )
                        parsed_events.append((safe_event, legacy_strict_candidate))
                    else:
                        corrupt_lines.append(
                            CorruptRecordReport(
                                execution_id="unknown",
                                line_number=line_no,
                                byte_offset=offset,
                                byte_length=line_len,
                                issue_kind="invalid_record_envelope",
                                excerpt_sha256=line_hash,
                                details=f"Spool line {line_no} unknown record_type {rec_type!r}",
                            )
                        )
                except (ValidationError, ValueError) as exc:
                    if rec_type == "summary" and tail_policy == "reject":
                        raise StorageCorruptionError(
                            f"Invalid recovery summary on line {line_no}"
                        ) from None
                    if isinstance(exc, ValidationError):
                        err_summary = f"ValidationError ({exc.error_count()} errors)"
                    elif rec_type == "event" and not rec_data.get("event_id"):
                        err_summary = "missing explicit event_id"
                    else:
                        err_summary = "ValueError (invalid identity or event data)"
                    corrupt_lines.append(
                        CorruptRecordReport(
                            execution_id="unknown",
                            line_number=line_no,
                            byte_offset=offset,
                            byte_length=line_len,
                            issue_kind="event_validation_failed",
                            excerpt_sha256=line_hash,
                            details=f"Spool line {line_no} validation failed: {err_summary}",
                        )
                    )
                offset += line_len

        if not observed_exec_ids:
            raise StorageCorruptionError(f"Spool {spool_path} contains no valid execution records")
        if len(observed_exec_ids) > 1:
            raise StorageCorruptionError(
                f"Spool {spool_path} mixes multiple execution IDs: {sorted(observed_exec_ids)}"
            )

        exec_id = next(iter(observed_exec_ids))
        fixed_corruptions = tuple(
            CorruptRecordReport(
                execution_id=exec_id,
                line_number=c.line_number,
                byte_offset=c.byte_offset,
                byte_length=c.byte_length,
                issue_kind=c.issue_kind,
                excerpt_sha256=c.excerpt_sha256,
                details=c.details,
            )
            for c in corrupt_lines
        )

        exec_dir = resolve_execution_dir(self._data_dir, exec_id)
        events_path = exec_dir / EVENTS_FILE_NAME
        has_destination = events_path.exists() or (exec_dir / EXECUTION_FILE_NAME).exists()
        prior = self._reader.read_execution(exec_id, strict=False, verify_checksums=True)
        if (
            (exec_dir / EXECUTION_FILE_NAME).exists()
            and prior.header is None
            and prior.summary is None
        ):
            raise StorageCorruptionError("Destination execution metadata is invalid")
        if (exec_dir / MANIFEST_FILE_NAME).exists() and prior.manifest is None:
            raise StorageCorruptionError("Destination manifest is invalid")
        for companion in (prior.header, prior.summary, prior.manifest):
            if companion is not None and companion.execution_id != exec_id:
                raise StorageCorruptionError(
                    f"Destination metadata belongs to a different execution: {exec_id}"
                )
        file_bytes = events_path.read_bytes() if events_path.exists() else b""
        repair = _inspect_tail(prior, file_bytes, tail_policy=tail_policy, require_unambiguous=True)

        prior_events = [item.event for item in prior.events]
        prior_last_seq = prior.last_valid_sequence
        if repair is not None and repair.event is not None:
            prior_events.append(repair.event)
            prior_last_seq = repair.event.sequence
        by_id: dict[str, ExecutionEvent] = {}
        by_seq: dict[int, ExecutionEvent] = {}
        for event in prior_events:
            if (
                "event_id" not in event.model_fields_set
                or not event.event_id.strip()
                or event.event_id in by_id
                or event.sequence in by_seq
            ):
                raise StorageCorruptionError(
                    f"Ambiguous destination identity in {exec_id} at sequence {event.sequence}"
                )
            by_id[event.event_id] = by_seq[event.sequence] = event

        extra_corruptions: list[CorruptRecordReport] = [
            issue
            for issue in prior.corruptions
            if repair is None or issue.byte_offset < repair.prefix_len
        ]
        quarantines: list[
            tuple[Sequence[ExecutionEvent | ExecutionSummary], str, CorruptionIssueKind]
        ] = []
        new_events: list[ExecutionEvent] = []
        skipped_dups = 0
        for ev, legacy_strict_candidate in parsed_events:
            same_id = by_id.get(ev.event_id)
            same_seq = by_seq.get(ev.sequence)
            if same_id is None and same_seq is None:
                by_id[ev.event_id] = by_seq[ev.sequence] = ev
                new_events.append(ev)
                continue
            if same_id is not None and same_id is same_seq:
                if _is_recovery_duplicate(
                    same_id,
                    ev,
                    allow_legacy_strict=legacy_strict_candidate and ev.sequence <= prior_last_seq,
                ):
                    skipped_dups += 1
                    continue
                reason = f"Content conflict for event at sequence {ev.sequence}"
                issue_kind: CorruptionIssueKind = "event_validation_failed"
            elif same_id is not None:
                reason = f"Duplicate event_id conflict at sequence {ev.sequence}"
                issue_kind = "event_validation_failed"
            else:
                reason = f"Duplicate sequence {ev.sequence} conflicts with a different event_id"
                issue_kind = "sequence_gap"

            if tail_policy == "reject":
                raise StorageCorruptionError(reason)
            quarantines.append(([ev], reason, issue_kind))

        new_events.sort(key=lambda e: e.sequence)
        terminal_seen = bool(new_events) and any(
            event.kind == "execution_finished" for event in prior_events
        )
        for index, ev in enumerate(new_events):
            expected_seq = prior_last_seq + index + 1
            if terminal_seen:
                reason = f"Recovery event at sequence {ev.sequence} follows the terminal event"
                issue_kind = "event_validation_failed"
            elif ev.sequence != expected_seq:
                reason = (
                    f"Sequence gap in recovery spool: expected {expected_seq}, got {ev.sequence}"
                )
                issue_kind = "sequence_gap"
            else:
                terminal_seen = ev.kind == "execution_finished"
                continue
            if tail_policy == "reject":
                raise StorageCorruptionError(reason)
            quarantines.append((new_events[index:], reason, issue_kind))
            new_events = new_events[:index]
            break

        # Validate summaries against the records that would survive this import. A supplied
        # summary cannot replace a different retained summary or authorize an append to it.
        retained_summary = prior.summary
        manifest = prior.manifest
        if manifest is not None and manifest.status == "corrupted":
            raise StorageCorruptionError("Recovery cannot import into a recording marked corrupted")
        source_matches_seal = not _has_seal_mismatch(prior)
        if not source_matches_seal and manifest is not None and repair is not None:
            digest = hashlib.sha256(
                file_bytes if repair.event is not None else file_bytes[: repair.prefix_len]
            )
            if repair.event is not None:
                digest.update(b"\n")
            source_matches_seal = _matches_manifest(
                manifest,
                byte_size=len(file_bytes) + 1 if repair.event is not None else repair.prefix_len,
                line_count=prior.line_count if repair.event is not None else prior.line_count - 1,
                last_sequence=prior_last_seq,
                digest=digest.hexdigest(),
            )

        if new_events and (
            (manifest is not None and manifest.status == "finalized")
            or (
                retained_summary is not None
                and (
                    extra_corruptions
                    or not _has_matching_final_summary(prior_events + new_events, retained_summary)
                )
            )
        ):
            reason = "Recovery append conflicts with finalized recording or retained summary"
            if tail_policy == "reject":
                raise StorageCorruptionError(reason)
            quarantines.append((new_events, reason, "event_validation_failed"))
            new_events = []

        supplied_summary = parsed_summary
        summary_header = prior.header or parsed_header
        if (
            prior.header is not None
            and prior_events
            and prior.header.command == _RECOVERED_SPOOL_COMMAND
            and prior.header.backpressure_policy == "spill"
            and prior.header.cwd is None
            and prior.header.started_at == prior_events[0].timestamp
            and prior.header.monotonic_start_ns == prior_events[0].monotonic_time_ns
        ):
            # Old fallback headers have no explicit provenance. Treat this exact shape
            # as ambiguous. A recorded start event still supplies independent evidence.
            summary_header = parsed_header
        if supplied_summary is not None and (
            conflicting_summaries
            or (retained_summary is not None and supplied_summary != retained_summary)
            or (
                summary_header is not None
                and (
                    supplied_summary.started_at != summary_header.started_at
                    or supplied_summary.command != summary_header.command
                )
            )
            or extra_corruptions
            or not source_matches_seal
            or not _has_matching_final_summary(
                prior_events + new_events,
                supplied_summary,
                allow_legacy_end_time=(
                    not new_events
                    and supplied_summary == retained_summary
                    and manifest is not None
                    and manifest.status == "finalized"
                    and manifest.finalized_at is not None
                    and manifest.corruption_count == 0
                ),
            )
        ):
            reason = "Recovery summary conflicts with verified execution evidence"
            if tail_policy == "reject":
                raise StorageCorruptionError(reason)
            summaries = [supplied_summary, *conflicting_summaries]
            quarantines.append((summaries, reason, "event_validation_failed"))
            supplied_summary = None

        if repair is None and not source_matches_seal:
            raise StorageCorruptionError(
                "Recovery cannot verify the recording against its manifest"
            )

        # Rejected imports return before modifying the recording, its companions, or SQLite.
        tail_quarantined = False
        if repair is not None:
            tail_res = self._apply_tail_repair(
                exec_dir, prior, file_bytes, repair, update_index=False
            )
            if tail_res.quarantined_report is not None:
                tail_quarantined = True
                extra_corruptions.append(tail_res.quarantined_report)
            prior = self._reader.read_execution(exec_id, strict=False, verify_checksums=True)

        fsync = fsync_policy != "none"
        # A failed append can reset recording metadata before it carries the count forward.
        # Recover that count from complete, verified destination artifacts, not spool rejects.
        manifest = prior.manifest
        artifact_count = _destination_quarantine_count(exec_dir, exec_id)
        restored_quarantine = artifact_count > (manifest.corruption_count if manifest else 0)
        if restored_quarantine:
            manifest = (manifest or _recovery_manifest(prior, None)).model_copy(
                update={"status": "incomplete", "corruption_count": artifact_count}
            )
            write_atomic_private_json(
                exec_dir / MANIFEST_FILE_NAME, manifest.model_dump(mode="json"), fsync=fsync
            )
            prior = replace(prior, manifest=manifest)

        for records, reason, kind in quarantines:
            payloads = (
                record.model_dump(mode="json")
                if isinstance(record, ExecutionEvent)
                else {
                    "record_type": "summary",
                    "sha256": canonical_event_sha256(record.model_dump(mode="json")),
                }
                for record in records
            )
            _, _, report = quarantine_tail_bytes(
                exec_dir=exec_dir,
                execution_id=exec_id,
                raw_tail=b"".join(
                    (json.dumps(payload) + "\n").encode("utf-8") for payload in payloads
                ),
                byte_offset=0,
                reason=reason,
                issue_kind=kind,
            )
            extra_corruptions.append(report)

        if new_events:
            if _has_seal_mismatch(prior):
                raise StorageCorruptionError("Recovery append would bypass a mismatched manifest")
            header = prior.header or parsed_header
            if header is None:
                first_event = prior_events[0] if prior_events else new_events[0]
                header = ExecutionHeader(
                    execution_id=exec_id,
                    started_at=supplied_summary.started_at
                    if supplied_summary
                    else first_event.timestamp,
                    monotonic_start_ns=first_event.monotonic_time_ns,
                    command=supplied_summary.command
                    if supplied_summary
                    else _RECOVERED_SPOOL_COMMAND,
                    redaction_mode=redaction_mode,
                    backpressure_policy=supplied_summary.backpressure_policy
                    if supplied_summary
                    else "spill",
                )
            previous_manifest = prior.manifest
            writer = JsonlEventLogWriter(
                self._data_dir,
                exec_id,
                fsync_policy=fsync_policy,
                redaction_mode=redaction_mode,
                persist_cwd=self._persist_cwd,
                tail_policy=tail_policy,
                seed_line_count=len(prior.events),
                seed_last_sequence=prior.last_valid_sequence,
                created_at=previous_manifest.created_at if previous_manifest else None,
            )
            try:
                opened_manifest = writer.open(header)
                if previous_manifest is not None and previous_manifest.corruption_count:
                    # The writer's recording manifest starts at zero. Carry the destination's
                    # quarantine decision forward before another append can fail.
                    updated = opened_manifest.model_copy(
                        update={"corruption_count": previous_manifest.corruption_count}
                    )
                    write_atomic_private_json(
                        exec_dir / MANIFEST_FILE_NAME, updated.model_dump(mode="json"), fsync=fsync
                    )
                writer.append_events(new_events)
            finally:
                writer.close()
            prior = self._reader.read_execution(exec_id, strict=False, verify_checksums=True)

        manifest = prior.manifest
        clean_recording = not prior.has_corruptions and not _has_seal_mismatch(prior)
        summary = supplied_summary or retained_summary
        should_finalize = (
            clean_recording
            and summary is not None
            and (supplied_summary is not None or (not quarantines and (skipped_dups or new_events)))
            and (manifest is None or manifest.status == "recording" or prior.summary is None)
            and _has_matching_final_summary([item.event for item in prior.events], summary)
        )
        if should_finalize:
            assert summary is not None
            if summary != prior.summary:
                write_atomic_private_json(
                    exec_dir / EXECUTION_FILE_NAME, summary.model_dump(mode="json"), fsync=fsync
                )
            final_manifest = _recovery_manifest(prior, summary)
            if final_manifest != manifest:
                write_atomic_private_json(
                    exec_dir / MANIFEST_FILE_NAME,
                    final_manifest.model_dump(mode="json"),
                    fsync=fsync,
                )
            prior = self._reader.read_execution(exec_id, strict=False, verify_checksums=True)
        elif manifest is None and prior.summary is None and clean_recording and skipped_dups:
            write_atomic_private_json(
                exec_dir / MANIFEST_FILE_NAME,
                _recovery_manifest(prior, None).model_dump(mode="json"),
                fsync=fsync,
            )
            prior = self._reader.read_execution(exec_id, strict=False, verify_checksums=True)

        if new_events or tail_quarantined or restored_quarantine or should_finalize:
            self._replace_verified_index(prior)
        elif (
            has_destination
            and (skipped_dups or repair is not None or supplied_summary is not None)
            and clean_recording
        ):
            try:
                row = self._store.get_execution_row(exec_id)
            except ValueError:
                # The execution row is derived data; SQLite transport errors propagate.
                row = None
            if row is None or not _recovery_index_matches(
                self._store, row, prior, persist_cwd=self._persist_cwd
            ):
                self._replace_verified_index(prior)

        all_corruptions = fixed_corruptions + tuple(extra_corruptions)
        return SpoolImportReport(
            execution_id=exec_id,
            imported_events=len(new_events),
            skipped_duplicates=skipped_dups,
            corrupt_lines=all_corruptions,
            final_status="incomplete" if all_corruptions else _recording_completeness(prior),
        )


def _re_redact_event(event: ExecutionEvent, *, redactor: EventRedactor) -> ExecutionEvent:
    """Apply ``redactor`` cleanly across an imported spool event before persistence."""
    mode = redactor.config.mode
    if mode == "explicit_unredacted":
        return event
    if mode == "standard" and event.redaction.mode == "strict_hash_only":
        # A default import cannot restore withheld content or change its provenance.
        mode = "strict_hash_only"
        redactor = EventRedactor(RedactionConfig(mode=mode))

    raw_event = event.model_dump(mode="python")
    if mode == "strict_hash_only":
        scrubbed = scrub_event_dict_withheld(raw_event, redactor=redactor)
        scrubbed["redaction"] = event.redaction.model_copy(
            update={"mode": mode, "payload_mode": "strict_hash_only", "applied": True}
        ).model_dump(mode="python")
        return ExecutionEvent.model_validate(scrubbed)

    raw_payload = event.payload.model_dump(mode="json")
    outcome = redactor.redact_value(raw_payload, root_path="spool.payload")
    if outcome.summary.degraded or not isinstance(outcome.value, dict):
        merged = merge_redaction_summaries(mode, [event.redaction, outcome.summary])
        # Fail closed: never allow raw payload/trace/otel fields through when redaction fails.
        scrubbed = scrub_event_dict_withheld(
            raw_event,
            redactor=redactor,
            failure_replacement=REDACTION_FAILED_MARKER,
        )
        scrubbed["degraded"] = True
        scrubbed["redaction"] = merged.model_copy(
            update={"applied": False, "degraded": True, "payload_mode": "redaction_failed"}
        ).model_dump(mode="python")
        return ExecutionEvent.model_validate(scrubbed)

    redacted_payload_dict = dict(outcome.value)
    redacted_payload_dict["kind"] = event.kind
    summaries = [
        event.redaction.model_copy(update={"mode": mode, "applied": True}),
        outcome.summary,
    ]

    trace_dict = raw_event.get("trace")
    if isinstance(trace_dict, dict) and isinstance(trace_dict.get("observed_tracestate"), str):
        ts_out = redactor.redact_text_value(
            trace_dict["observed_tracestate"], path_label="spool.trace.observed_tracestate"
        )
        summaries.append(ts_out.summary)
        trace_dict["observed_tracestate"] = None if ts_out.summary.degraded else ts_out.text

    derived_dict = raw_event.get("derived")
    if isinstance(derived_dict, dict) and isinstance(derived_dict.get("otel_attributes"), dict):
        otel_out = redactor.redact_value(
            derived_dict["otel_attributes"], root_path="spool.derived.otel_attributes"
        )
        summaries.append(otel_out.summary)
        derived_dict["otel_attributes"] = (
            {}
            if otel_out.summary.degraded or not isinstance(otel_out.value, dict)
            else otel_out.value
        )

    merged_summary = merge_redaction_summaries(mode, summaries)
    if merged_summary.degraded:
        scrubbed = scrub_event_dict_withheld(
            raw_event,
            redactor=redactor,
            failure_replacement=REDACTION_FAILED_MARKER,
        )
        scrubbed["degraded"] = True
        scrubbed["redaction"] = merged_summary.model_copy(
            update={"applied": False, "degraded": True, "payload_mode": "redaction_failed"}
        ).model_dump(mode="python")
        return ExecutionEvent.model_validate(scrubbed)

    return ExecutionEvent.model_validate(
        {
            **raw_event,
            "payload": redacted_payload_dict,
            "redaction": merged_summary.model_dump(mode="python"),
        }
    )


__all__ = [
    "EventQueryResult",
    "ReconciliationReport",
    "RecordingRepository",
    "SpoolImportReport",
    "StoredExecutionRecord",
]
