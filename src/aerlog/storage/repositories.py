"""Recording retrieval, indexed event queries, reconciliation, and recovery APIs."""

from __future__ import annotations

import hashlib
import json
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
    STORAGE_SCHEMA_VERSION,
    CorruptRecordReport,
    ExecutionManifest,
    FsyncPolicy,
    JsonlEventLogReader,
    JsonlEventLogWriter,
    JsonlReadResult,
    WrittenEventSlice,
    relative_recording_dir,
    resolve_execution_dir,
    sanitize_header_for_persistence,
    sanitize_summary_for_persistence,
    validate_execution_id,
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

    def reconcile_execution(self, execution_id: str) -> JsonlReadResult | None:
        """Rebuild SQLite index state for one execution from authoritative ``events.jsonl``."""
        clean_id = validate_execution_id(execution_id)
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
        if (exec_dir / EVENTS_FILE_NAME).exists() or (exec_dir / EXECUTION_FILE_NAME).exists():
            prior = self._reader.read_execution(exec_id, strict=False, verify_checksums=True)
            existing_header = prior.header
            existing_summary = prior.summary
            existing_events_ids = {item.event.event_id for item in prior.events}
            existing_seqs = {item.event.sequence for item in prior.events}

        new_events: list[ExecutionEvent] = []
        skipped_dups = 0
        for ev in parsed_events:
            if ev.event_id in existing_events_ids or ev.sequence in existing_seqs:
                skipped_dups += 1
                continue
            existing_events_ids.add(ev.event_id)
            existing_seqs.add(ev.sequence)
            new_events.append(ev)

        new_events.sort(key=lambda e: e.sequence)

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
        )
        writer.open(parsed_header)
        if new_events:
            writer.append_events(new_events)
        if parsed_summary is not None:
            final_summary = parsed_summary
            if fixed_corruptions:
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
        return SpoolImportReport(
            execution_id=exec_id,
            imported_events=len(new_events),
            skipped_duplicates=skipped_dups,
            corrupt_lines=fixed_corruptions,
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
