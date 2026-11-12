"""Recording retrieval, indexed event queries, reconciliation, and recovery APIs."""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import uuid
from dataclasses import dataclass
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
    ExecutionHeader,
    ExecutionSummary,
)
from aerlog.events.types import EVENT_SCHEMA_VERSION, CaptureCompleteness, RedactionMode
from aerlog.storage.database import (
    DB_FILE_NAME,
    IndexedEventRow,
    IndexedExecutionRow,
    SQLiteMetadataStore,
)
from aerlog.storage.event_log import (
    EVENTS_FILE_NAME,
    EXECUTION_FILE_NAME,
    EXECUTIONS_DIR_NAME,
    MANIFEST_FILE_NAME,
    STORAGE_SCHEMA_VERSION,
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
    compute_file_sha256,
    quarantine_tail_bytes,
    relative_recording_dir,
    resolve_execution_dir,
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

    if read_result.has_corruptions:
        completeness: str = "corrupted"
    elif read_result.unclean_shutdown:
        completeness = "incomplete"
    elif summary is not None:
        completeness = summary.capture_completeness
    else:
        completeness = "incomplete"

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
        if read_result.has_corruptions or read_result.unclean_shutdown
        else "indexed",
    }


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
        manifest_path = exec_dir / MANIFEST_FILE_NAME

        if not events_path.exists() or events_path.stat().st_size == 0:
            return TailRecoveryResult(
                execution_id=clean_id,
                action_taken="none",
                recovered_event=None,
                quarantined_report=None,
                quarantine_path=None,
                bytes_recovered=0,
                prior_line_count=0,
                final_line_count=0,
                prior_last_sequence=0,
                final_last_sequence=0,
            )

        file_bytes = events_path.read_bytes()
        prior = self._reader.read_execution(clean_id, strict=False, verify_checksums=True)
        prior_line_count = len(prior.events)
        prior_last_seq = prior.last_valid_sequence

        if file_bytes.endswith(b"\n"):
            if prior.corruptions and tail_policy == "reject":
                raise StorageCorruptionError(
                    f"Corruption detected in {clean_id}: {prior.corruptions[0].details}"
                )
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

        last_nl = file_bytes.rfind(b"\n")
        prefix_len = last_nl + 1 if last_nl >= 0 else 0
        raw_tail = file_bytes[prefix_len:]
        tail_offset = prefix_len

        decoded, issue = _parse_jsonl_line(
            execution_id=clean_id,
            raw_line=raw_tail + b"\n",
            line_number=prior_line_count + 1,
            byte_offset=tail_offset,
            verify_checksum=True,
        )

        is_consistent = False
        if issue is None and decoded is not None:
            expected_seq = prior_last_seq + 1
            existing_ids = {e.event.event_id for e in prior.events}
            if decoded.sequence == expected_seq and decoded.event_id not in existing_ids:
                is_consistent = True
            elif decoded.sequence != expected_seq:
                issue = CorruptRecordReport(
                    execution_id=clean_id,
                    line_number=prior_line_count + 1,
                    byte_offset=tail_offset,
                    byte_length=len(raw_tail),
                    issue_kind="sequence_gap",
                    excerpt_sha256=hashlib.sha256(raw_tail).hexdigest(),
                    details=f"Sequence gap: expected {expected_seq}, got {decoded.sequence}",
                )
            else:
                issue = CorruptRecordReport(
                    execution_id=clean_id,
                    line_number=prior_line_count + 1,
                    byte_offset=tail_offset,
                    byte_length=len(raw_tail),
                    issue_kind="event_validation_failed",
                    excerpt_sha256=hashlib.sha256(raw_tail).hexdigest(),
                    details=f"Duplicate event_id: {decoded.event_id!r}",
                )

        if is_consistent and decoded is not None:
            with events_path.open("ab") as f:
                f.write(b"\n")
                f.flush()
                os.fsync(f.fileno())

            new_size = len(file_bytes) + 1
            new_line_count = prior_line_count + 1
            new_last_seq = decoded.sequence
            file_sha = compute_file_sha256(events_path)

            status: Literal["finalized", "incomplete"] = (
                "finalized"
                if prior.summary and prior.summary.capture_completeness == "complete"
                else "incomplete"
            )
            manifest = ExecutionManifest(
                execution_id=clean_id,
                recording_dir=relative_recording_dir(clean_id),
                status=status,
                created_at=prior.header.started_at if prior.header else datetime.now(UTC),
                finalized_at=prior.manifest.finalized_at if prior.manifest else None,
                byte_size=new_size,
                line_count=new_line_count,
                last_sequence=new_last_seq,
                events_file_sha256=file_sha,
                corruption_count=0,
            )
            write_atomic_private_json(manifest_path, manifest.model_dump(mode="json"), fsync=True)
            self._store.initialize()
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

        if tail_policy == "reject":
            details = issue.details if issue else "Inconsistent tail"
            raise StorageCorruptionError(f"Inconsistent tail in {clean_id}: {details}")

        q_path, _, q_report = quarantine_tail_bytes(
            exec_dir=exec_dir,
            execution_id=clean_id,
            raw_tail=raw_tail,
            byte_offset=tail_offset,
            reason=issue.details if issue else "Inconsistent tail",
            issue_kind=issue.issue_kind if issue else "invalid_json",
        )
        tmp_events = exec_dir / f".events.jsonl.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
        fd = os.open(tmp_events, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            if prefix_len > 0:
                os.write(fd, file_bytes[:prefix_len])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_events, events_path)
        os.chmod(events_path, 0o600)

        corr_count = (prior.manifest.corruption_count + 1) if prior.manifest else 1
        manifest = ExecutionManifest(
            execution_id=clean_id,
            recording_dir=relative_recording_dir(clean_id),
            status="incomplete",
            created_at=prior.header.started_at if prior.header else datetime.now(UTC),
            byte_size=prefix_len,
            line_count=prior_line_count,
            last_sequence=prior_last_seq,
            events_file_sha256=compute_file_sha256(events_path) if prefix_len > 0 else None,
            corruption_count=corr_count,
        )
        write_atomic_private_json(manifest_path, manifest.model_dump(mode="json"), fsync=True)
        self._store.initialize()
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
        row = self._store.get_execution_row(clean_id)

        if not has_disk:
            if row is not None:
                self._store.mark_missing_jsonl(clean_id)
                return None
            raise ExecutionNotFoundError(f"Execution {clean_id!r} not found in DB or on disk")

        read_result = self._reader.read_execution(
            clean_id,
            strict=False,
            verify_checksums=True,
        )
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
        return read_result

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
        parsed_events: list[ExecutionEvent] = []
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
                        parsed_summary = sanitize_summary_for_persistence(
                            smry, persist_cwd=self._persist_cwd
                        )
                    elif rec_type == "event":
                        ev = ExecutionEvent.model_validate(rec_data)
                        clean_eid = validate_execution_id(ev.execution_id)
                        observed_exec_ids.add(clean_eid)
                        parsed_events.append(_re_redact_event(ev, redactor=redactor))
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
                    err_summary = (
                        f"ValidationError ({exc.error_count()} errors)"
                        if isinstance(exc, ValidationError)
                        else f"ValueError: {type(exc).__name__}"
                    )
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
        existing_events_ids: set[str] = set()
        existing_seqs: set[int] = set()
        existing_header: ExecutionHeader | None = None
        existing_summary: ExecutionSummary | None = None
        prior_line_count = 0
        prior_last_seq = 0
        extra_corruptions: list[CorruptRecordReport] = []

        if (exec_dir / EVENTS_FILE_NAME).exists():
            tail_res = self.recover_tail(exec_id, tail_policy=tail_policy)
            if tail_res.quarantined_report is not None:
                extra_corruptions.append(tail_res.quarantined_report)

        if (exec_dir / EVENTS_FILE_NAME).exists() or (exec_dir / EXECUTION_FILE_NAME).exists():
            prior = self._reader.read_execution(exec_id, strict=False, verify_checksums=True)
            existing_header = prior.header
            existing_summary = prior.summary
            existing_events_ids = {item.event.event_id for item in prior.events}
            existing_seqs = {item.event.sequence for item in prior.events}
            prior_line_count = len(prior.events)
            prior_last_seq = prior.last_valid_sequence

        new_events: list[ExecutionEvent] = []
        skipped_dups = 0
        for ev in parsed_events:
            if ev.event_id in existing_events_ids and ev.sequence in existing_seqs:
                skipped_dups += 1
                continue
            if ev.event_id in existing_events_ids:
                if tail_policy == "reject":
                    raise StorageCorruptionError(
                        f"Duplicate event_id {ev.event_id!r} with conflicting sequence in spool"
                    )
                _, _, q_report = quarantine_tail_bytes(
                    exec_dir=exec_dir,
                    execution_id=exec_id,
                    raw_tail=json.dumps(ev.model_dump(mode="json")).encode("utf-8"),
                    byte_offset=0,
                    reason=f"Duplicate event_id {ev.event_id!r} conflicts with existing record",
                    issue_kind="event_validation_failed",
                )
                extra_corruptions.append(q_report)
                continue

            if ev.sequence in existing_seqs:
                if tail_policy == "reject":
                    raise StorageCorruptionError(
                        f"Duplicate sequence {ev.sequence} with conflicting event_id in spool"
                    )
                _, _, q_report = quarantine_tail_bytes(
                    exec_dir=exec_dir,
                    execution_id=exec_id,
                    raw_tail=json.dumps(ev.model_dump(mode="json")).encode("utf-8"),
                    byte_offset=0,
                    reason=f"Duplicate sequence {ev.sequence} conflicts with existing record",
                    issue_kind="sequence_gap",
                )
                extra_corruptions.append(q_report)
                continue

            existing_events_ids.add(ev.event_id)
            existing_seqs.add(ev.sequence)
            new_events.append(ev)

        new_events.sort(key=lambda e: e.sequence)

        # Validate sequence continuity before accepting new events
        if new_events:
            expected_seq = prior_last_seq + 1
            if new_events[0].sequence != expected_seq:
                if tail_policy == "reject":
                    raise StorageCorruptionError(
                        f"Sequence gap in recovery spool: expected {expected_seq}, "
                        f"got {new_events[0].sequence}"
                    )
                q_bytes = b"".join(
                    (json.dumps(e.model_dump(mode="json")) + "\n").encode("utf-8")
                    for e in new_events
                )
                _, _, q_report = quarantine_tail_bytes(
                    exec_dir=exec_dir,
                    execution_id=exec_id,
                    raw_tail=q_bytes,
                    byte_offset=0,
                    reason=(
                        f"Sequence gap in spool: expected {expected_seq}, "
                        f"got {new_events[0].sequence}"
                    ),
                    issue_kind="sequence_gap",
                )
                extra_corruptions.append(q_report)
                new_events = []
            else:
                valid_contiguous_prefix = [new_events[0]]
                for prev, curr in itertools.pairwise(new_events):
                    if curr.sequence != prev.sequence + 1:
                        if tail_policy == "reject":
                            raise StorageCorruptionError(
                                f"Sequence gap in spool: expected {prev.sequence + 1}, "
                                f"got {curr.sequence}"
                            )
                        discontinuous = new_events[len(valid_contiguous_prefix) :]
                        q_bytes = b"".join(
                            (json.dumps(e.model_dump(mode="json")) + "\n").encode("utf-8")
                            for e in discontinuous
                        )
                        _, _, q_report = quarantine_tail_bytes(
                            exec_dir=exec_dir,
                            execution_id=exec_id,
                            raw_tail=q_bytes,
                            byte_offset=0,
                            reason=(
                                f"Sequence gap within spool: expected {prev.sequence + 1}, "
                                f"got {curr.sequence}"
                            ),
                            issue_kind="sequence_gap",
                        )
                        extra_corruptions.append(q_report)
                        break
                    valid_contiguous_prefix.append(curr)
                new_events = valid_contiguous_prefix

        all_corruptions = fixed_corruptions + tuple(extra_corruptions)
        if not new_events and parsed_summary is None:
            final_row = self._store.get_execution_row(exec_id)
            final_status = final_row.capture_completeness if final_row else "incomplete"
            if all_corruptions:
                final_status = "incomplete"
            return SpoolImportReport(
                execution_id=exec_id,
                imported_events=0,
                skipped_duplicates=skipped_dups,
                corrupt_lines=all_corruptions,
                final_status=final_status,
            )

        if parsed_header is None:
            if existing_header is not None:
                parsed_header = existing_header
            elif parsed_events:
                parsed_header = ExecutionHeader(
                    execution_id=exec_id,
                    started_at=parsed_events[0].timestamp,
                    monotonic_start_ns=parsed_events[0].monotonic_time_ns,
                    command=("recovered-spool",),
                    redaction_mode=redaction_mode,
                    backpressure_policy="spill",
                )
            else:
                raise StorageCorruptionError(
                    f"Spool {spool_path} lacks header or event metadata for {exec_id!r}"
                )

        if parsed_summary is None and existing_summary is not None:
            parsed_summary = existing_summary

        writer = JsonlEventLogWriter(
            self._data_dir,
            exec_id,
            fsync_policy=fsync_policy,
            redaction_mode=redaction_mode,
            persist_cwd=self._persist_cwd,
            tail_policy=tail_policy,
            seed_line_count=prior_line_count,
            seed_last_sequence=prior_last_seq,
            created_at=existing_header.started_at if existing_header else None,
        )
        writer.open(parsed_header)
        if new_events:
            writer.append_events(new_events)
        all_corruptions = fixed_corruptions + tuple(extra_corruptions)
        if parsed_summary is not None:
            final_summary = parsed_summary
            if all_corruptions:
                final_summary = parsed_summary.model_copy(
                    update={"capture_completeness": "incomplete"}
                )
            writer.finalize(final_summary)
        else:
            writer.flush()
        writer.close()

        self._store.initialize()
        self.reconcile_execution(exec_id)

        final_row = self._store.get_execution_row(exec_id)
        final_status = final_row.capture_completeness if final_row else "incomplete"
        if all_corruptions:
            final_status = "incomplete"
        return SpoolImportReport(
            execution_id=exec_id,
            imported_events=len(new_events),
            skipped_duplicates=skipped_dups,
            corrupt_lines=all_corruptions,
            final_status=final_status,
        )


def _re_redact_event(event: ExecutionEvent, *, redactor: EventRedactor) -> ExecutionEvent:
    """Apply ``redactor`` cleanly across an imported spool event before persistence."""
    mode = redactor.config.mode
    if mode == "explicit_unredacted":
        return event

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
