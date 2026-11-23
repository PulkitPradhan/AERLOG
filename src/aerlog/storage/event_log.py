"""Append-only JSONL event log, atomic execution metadata, and integrity scanner."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import uuid
from collections.abc import Iterable, Iterator, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aerlog.capture.redaction import EventRedactor, RedactionConfig
from aerlog.events.models import (
    ExecutionEvent,
    ExecutionHeader,
    ExecutionStartedPayload,
    ExecutionSummary,
)
from aerlog.events.types import EVENT_SCHEMA_VERSION, RedactionMode
from aerlog.storage.exceptions import (
    InvalidExecutionIdError,
    StorageCorruptionError,
    StorageDiskFullError,
    StorageWriteError,
    UnsupportedSchemaVersionError,
)
from aerlog.storage.ownership import ExecutionOwnership
from aerlog.storage.ownership import validate_execution_id as validate_execution_id

STORAGE_SCHEMA_VERSION = "1.0.0"

FsyncPolicy = Literal["lifecycle", "every_batch", "none"]
TailPolicy = Literal["quarantine", "reject"]
CorruptionIssueKind = Literal[
    "missing_newline",
    "invalid_utf8",
    "invalid_json",
    "invalid_record_envelope",
    "checksum_mismatch",
    "unsupported_schema_version",
    "event_validation_failed",
    "sequence_gap",
]

EVENTS_FILE_NAME = "events.jsonl"
EXECUTION_FILE_NAME = "execution.json"
MANIFEST_FILE_NAME = "manifest.json"
EXECUTIONS_DIR_NAME = "executions"


def _ensure_private_dir(path: Path) -> None:
    """Create directory hierarchy and restrict leaf/created directories to ``0o700``."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def resolve_execution_dir(data_dir: Path, execution_id: str) -> Path:
    """Resolve `<data_dir>/executions/<execution_id>` with strict path containment."""
    clean_id = validate_execution_id(execution_id)
    executions_root = (data_dir / EXECUTIONS_DIR_NAME).resolve()
    target = (executions_root / clean_id).resolve()
    if not target.is_relative_to(executions_root) or target == executions_root:
        raise InvalidExecutionIdError(f"Path containment violation for execution_id {clean_id!r}")
    return target


def relative_recording_dir(execution_id: str) -> str:
    """Return safe relative recording directory string without host home prefixes."""
    clean_id = validate_execution_id(execution_id)
    return f"{EXECUTIONS_DIR_NAME}/{clean_id}"


def canonical_event_sha256(event_dict: dict[str, Any]) -> str:
    """Compute SHA-256 of canonical JSON serialization for integrity verification."""
    canonical = json.dumps(
        event_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _translate_os_error(exc: OSError, *, context: str) -> StorageWriteError:
    if exc.errno == errno.ENOSPC:
        return StorageDiskFullError(f"Disk full while {context}: {exc}")
    return StorageWriteError(f"Storage write failed while {context}: {exc}")


def _write_chunks(fd: int, data: bytes, path: Path) -> Iterator[int]:
    """Write all bytes, reporting each successful syscall before trying the next."""
    remaining = memoryview(data)
    while remaining:
        try:
            size = os.write(fd, remaining)
        except InterruptedError:
            continue
        if size <= 0:
            raise StorageWriteError(f"Zero-byte write to {path}")
        yield size
        remaining = remaining[size:]


def write_atomic_private_json(
    target_path: Path,
    payload: dict[str, Any],
    *,
    fsync: bool = True,
) -> None:
    """Atomically write JSON to ``target_path`` with ``0o600`` permissions.

    On ``ENOSPC`` or write error, removes only the temporary file so any
    previously committed file remains intact.
    """
    _ensure_private_dir(target_path.parent)
    encoded = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    tmp_name = f".{target_path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    tmp_path = target_path.parent / tmp_name

    fd: int | None = None
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.chmod(fd, 0o600)
        for _ in _write_chunks(fd, encoded, tmp_path):
            pass
        if fsync:
            os.fsync(fd)
        fd_to_close, fd = fd, None
        os.close(fd_to_close)
        os.replace(tmp_path, target_path)
        os.chmod(target_path, 0o600)
    except BaseException as exc:
        if fd is not None:
            with suppress(OSError):
                os.close(fd)
        with suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise _translate_os_error(exc, context=f"writing {target_path.name}") from exc
        raise


def sanitize_event_for_persistence(
    event: ExecutionEvent,
    *,
    redaction_mode: RedactionMode,
    persist_cwd: bool = False,
) -> ExecutionEvent:
    """Verify redaction compliance and strip environment variables / private paths."""
    if redaction_mode != "explicit_unredacted":
        if not event.redaction.applied and event.redaction.payload_mode != "redaction_failed":
            raise ValueError(
                f"Refusing to persist unredacted event {event.event_id!r} under "
                f"redaction_mode={redaction_mode!r}"
            )
        if event.redaction.mode == "explicit_unredacted":
            raise ValueError(
                f"Refusing to persist explicit_unredacted event {event.event_id!r} under "
                f"redaction_mode={redaction_mode!r}"
            )

    if isinstance(event.payload, ExecutionStartedPayload):
        redactor = EventRedactor(RedactionConfig(mode=redaction_mode))
        safe_cmd, _ = redactor.redact_command(event.payload.command)
        safe_cwd = (
            event.payload.cwd if persist_cwd and redaction_mode != "strict_hash_only" else None
        )
        # Requirement C: do not persist environment variable keys or values in persistent logs,
        # including environment variable names inside redaction path breadcrumbs.
        clean_payload = event.payload.model_copy(
            update={
                "command": safe_cmd,
                "cwd": safe_cwd,
                "env_override_keys": (),
                "redacted_env_overrides": {},
            }
        )
        clean_paths = tuple(
            p for p in event.redaction.redacted_paths if p != "env" and not p.startswith("env.")
        )
        clean_redaction = event.redaction.model_copy(update={"redacted_paths": clean_paths})
        return event.model_copy(update={"payload": clean_payload, "redaction": clean_redaction})
    return event


def sanitize_header_for_persistence(
    header: ExecutionHeader,
    *,
    persist_cwd: bool = False,
) -> ExecutionHeader:
    """Redact command arguments and restrict optional ``cwd`` in stored headers."""
    redactor = EventRedactor(RedactionConfig(mode=header.redaction_mode))
    safe_cmd, _ = redactor.redact_command(header.command)
    safe_cwd = header.cwd if persist_cwd and header.redaction_mode != "strict_hash_only" else None
    return header.model_copy(update={"command": safe_cmd, "cwd": safe_cwd})


def sanitize_summary_for_persistence(
    summary: ExecutionSummary,
    *,
    persist_cwd: bool = False,
) -> ExecutionSummary:
    """Redact command arguments and restrict optional ``cwd`` in stored summaries."""
    redactor = EventRedactor(RedactionConfig(mode=summary.redaction_mode))
    safe_cmd, _ = redactor.redact_command(summary.command)
    safe_cwd = summary.cwd if persist_cwd and summary.redaction_mode != "strict_hash_only" else None
    return summary.model_copy(update={"command": safe_cmd, "cwd": safe_cwd})


class ExecutionManifest(BaseModel):
    """Integrity manifest stored alongside ``events.jsonl`` inside an execution dir."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    storage_schema_version: str = STORAGE_SCHEMA_VERSION
    event_schema_version: str = EVENT_SCHEMA_VERSION
    execution_id: str
    recording_dir: str
    status: Literal["recording", "finalized", "incomplete", "corrupted"]
    created_at: datetime
    finalized_at: datetime | None = None
    byte_size: int = Field(default=0, ge=0)
    line_count: int = Field(default=0, ge=0)
    last_sequence: int = Field(default=0, ge=0)
    events_file_sha256: str | None = None
    corruption_count: int = Field(default=0, ge=0)


@dataclass(frozen=True, slots=True)
class WrittenEventSlice:
    """Exact file byte span written for one appended JSONL event record."""

    event: ExecutionEvent
    byte_offset: int
    byte_length: int


@dataclass(frozen=True, slots=True)
class CorruptRecordReport:
    """Structured description of one partial, malformed, or corrupted JSONL line."""

    execution_id: str
    line_number: int
    byte_offset: int
    byte_length: int
    issue_kind: CorruptionIssueKind
    excerpt_sha256: str
    details: str


@dataclass(frozen=True, slots=True)
class IndexedLogEvent:
    """Decoded JSONL event paired with its exact file byte offset and byte length."""

    event: ExecutionEvent
    line_number: int
    byte_offset: int
    byte_length: int


@dataclass(frozen=True, slots=True)
class JsonlReadResult:
    """Complete audit result produced by reading or verifying ``events.jsonl``."""

    execution_id: str
    header: ExecutionHeader | None
    summary: ExecutionSummary | None
    manifest: ExecutionManifest | None
    events: tuple[IndexedLogEvent, ...]
    corruptions: tuple[CorruptRecordReport, ...]
    byte_size: int
    line_count: int
    last_valid_sequence: int
    events_file_sha256: str
    unclean_shutdown: bool

    @property
    def has_corruptions(self) -> bool:
        """Return True if any corrupt, partial, or sequence-gapped line was detected."""
        return bool(self.corruptions)


@dataclass(frozen=True, slots=True)
class TailRecoveryResult:
    """Outcome of inspecting and recovering the tail of an events.jsonl file."""

    execution_id: str
    action_taken: Literal["none", "completed_newline", "quarantined", "retained"]
    recovered_event: ExecutionEvent | None
    quarantined_report: CorruptRecordReport | None
    quarantine_path: Path | None
    bytes_recovered: int
    prior_line_count: int
    final_line_count: int
    prior_last_sequence: int
    final_last_sequence: int


def quarantine_tail_bytes(
    exec_dir: Path,
    execution_id: str,
    raw_tail: bytes,
    byte_offset: int,
    *,
    reason: str,
    issue_kind: CorruptionIssueKind = "invalid_json",
) -> tuple[Path, Path, CorruptRecordReport]:
    """Safely persist exact corrupted tail bytes and companion JSON metadata with 0o600 mode."""
    _ensure_private_dir(exec_dir)
    digest = hashlib.sha256(raw_tail).hexdigest()
    short_hash = digest[:12]
    quarantine_name = f"corrupted_tail_offset_{byte_offset}_{short_hash}.quarantine"
    meta_name = f"corrupted_tail_offset_{byte_offset}_{short_hash}.meta.json"

    quarantine_path = exec_dir / quarantine_name
    meta_path = exec_dir / meta_name

    tmp_q = exec_dir / f".{quarantine_name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    fd = os.open(tmp_q, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            for _ in _write_chunks(fd, raw_tail, tmp_q):
                pass
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_q, quarantine_path)
    finally:
        tmp_q.unlink(missing_ok=True)
    os.chmod(quarantine_path, 0o600)

    meta_payload = {
        "execution_id": execution_id,
        "byte_offset": byte_offset,
        "byte_length": len(raw_tail),
        "sha256": digest,
        "issue_kind": issue_kind,
        "reason": reason,
        "quarantined_at": datetime.now(UTC).isoformat(),
    }
    write_atomic_private_json(meta_path, meta_payload, fsync=True)

    report = CorruptRecordReport(
        execution_id=execution_id,
        line_number=-1,
        byte_offset=byte_offset,
        byte_length=len(raw_tail),
        issue_kind=issue_kind,
        excerpt_sha256=digest,
        details=f"Quarantined tail: {reason}",
    )
    return quarantine_path, meta_path, report


def _check_major_version(found: object, *, expected: str, label: str) -> None:
    if not isinstance(found, str) or "." not in found:
        raise UnsupportedSchemaVersionError(f"Invalid {label}: {found!r}")
    found_major = found.split(".", 1)[0]
    expected_major = expected.split(".", 1)[0]
    if found_major != expected_major:
        raise UnsupportedSchemaVersionError(
            f"Unsupported {label} {found!r}; expected major version {expected_major}.x"
        )


def compute_file_sha256(path: Path) -> str:
    """Stream-hash a file on disk using SHA-256."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65_536):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class AppendFailureOutcome:
    """Bytes accepted by write(2) and complete records within them, before recovery."""

    accepted_bytes: int
    complete_slices: tuple[WrittenEventSlice, ...]
    sync_failed: bool
    requires_verification: bool


class JsonlEventLogWriter:
    """Append-only ``0o600`` JSONL event log writer with atomic companion metadata."""

    def __init__(
        self,
        data_dir: Path,
        execution_id: str,
        *,
        fsync_policy: FsyncPolicy = "lifecycle",
        redaction_mode: RedactionMode = "standard",
        persist_cwd: bool = False,
        tail_policy: TailPolicy = "quarantine",
        seed_line_count: int | None = None,
        seed_last_sequence: int | None = None,
        created_at: datetime | None = None,
        ownership: ExecutionOwnership | None = None,
    ) -> None:
        self._data_dir = data_dir
        self._execution_id = validate_execution_id(execution_id)
        self._parent_ownership = ownership
        self._ownership: ExecutionOwnership | None = None
        self._fsync_policy: FsyncPolicy = fsync_policy
        self._redaction_mode: RedactionMode = redaction_mode
        self._persist_cwd = persist_cwd
        self._tail_policy: TailPolicy = tail_policy

        self._exec_dir = resolve_execution_dir(data_dir, self._execution_id)
        self._events_path = self._exec_dir / EVENTS_FILE_NAME
        self._execution_path = self._exec_dir / EXECUTION_FILE_NAME
        self._manifest_path = self._exec_dir / MANIFEST_FILE_NAME

        self._fd: int | None = None
        self._requires_verification = False
        self._byte_offset = 0
        self._line_count = seed_line_count or 0
        self._last_sequence = seed_last_sequence or 0
        self._created_at: datetime | None = created_at
        self._seed_line_count = seed_line_count
        self._seed_last_sequence = seed_last_sequence

        self._retained_tail: bytes = b""
        self._retained_tail_offset: int = 0

    @property
    def execution_id(self) -> str:
        """Execution UUID targeted by this JSONL log writer."""
        return self._execution_id

    @property
    def execution_dir(self) -> Path:
        """Per-execution storage directory."""
        return self._exec_dir

    @property
    def events_path(self) -> Path:
        """Path to ``events.jsonl`` inside the execution directory."""
        return self._events_path

    @property
    def byte_offset(self) -> int:
        """Current append byte offset within ``events.jsonl``."""
        return self._byte_offset

    @property
    def line_count(self) -> int:
        """Current number of appended lines within ``events.jsonl``."""
        return self._line_count

    @property
    def last_sequence(self) -> int:
        """Maximum sequence number observed and persisted by this writer."""
        return self._last_sequence

    def _check_usable(self) -> None:
        if self._requires_verification:
            raise StorageWriteError(f"Verify {self._events_path} before opening a fresh writer")

    def open(self, header: ExecutionHeader, *, preserve_summary: bool = False) -> ExecutionManifest:
        """Open the private log and write initial metadata, retaining a summary during recovery."""
        self._check_usable()
        if self._fd is not None:
            raise StorageWriteError("JsonlEventLogWriter is already open")
        if header.execution_id != self._execution_id:
            raise InvalidExecutionIdError(
                f"Header execution_id {header.execution_id!r} != {self._execution_id!r}"
            )
        self._ownership = (
            ExecutionOwnership.acquire(self._data_dir, self._execution_id)
            if self._parent_ownership is None
            else self._parent_ownership.share(self._data_dir, self._execution_id)
        )
        try:
            return self._open_owned(header, preserve_summary=preserve_summary)
        except BaseException:
            self._ownership.close()
            self._ownership = None
            raise

    def _open_owned(self, header: ExecutionHeader, *, preserve_summary: bool) -> ExecutionManifest:
        _ensure_private_dir(self._data_dir)
        _ensure_private_dir(self._data_dir / EXECUTIONS_DIR_NAME)
        _ensure_private_dir(self._exec_dir)

        # Inspect pre-existing events file if present before opening
        if self._events_path.exists() and self._events_path.stat().st_size > 0:
            file_bytes = self._events_path.read_bytes()
            if not file_bytes.endswith(b"\n"):
                last_nl = file_bytes.rfind(b"\n")
                prefix_len = last_nl + 1 if last_nl >= 0 else 0
                raw_tail = file_bytes[prefix_len:]
                self._retained_tail_offset = prefix_len
                self._retained_tail = raw_tail

            if self._seed_line_count is None or self._seed_last_sequence is None:
                prior = JsonlEventLogReader(self._data_dir).read_execution(self._execution_id)
                for issue in prior.corruptions:
                    if issue.issue_kind != "missing_newline":
                        raise StorageCorruptionError(issue.details)
                if self._seed_line_count is None:
                    self._line_count = len(prior.events)
                if self._seed_last_sequence is None:
                    self._last_sequence = prior.last_valid_sequence

        try:
            try:
                flags = os.O_RDWR | os.O_CREAT
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                self._fd = os.open(self._events_path, flags, 0o600)
                os.chmod(self._fd, 0o600)
                self._byte_offset = os.lseek(self._fd, 0, os.SEEK_END)
            except OSError as exc:
                raise _translate_os_error(exc, context=f"opening {self._events_path}") from exc

            if not preserve_summary:
                safe_header = sanitize_header_for_persistence(header, persist_cwd=self._persist_cwd)
                write_atomic_private_json(
                    self._execution_path,
                    safe_header.model_dump(mode="json"),
                    fsync=self._fsync_policy != "none",
                )
            self._created_at = self._created_at or header.started_at
            manifest = ExecutionManifest(
                execution_id=self._execution_id,
                recording_dir=relative_recording_dir(self._execution_id),
                status="recording",
                created_at=self._created_at,
                byte_size=self._byte_offset,
                line_count=self._line_count,
                last_sequence=self._last_sequence,
            )
            write_atomic_private_json(
                self._manifest_path,
                manifest.model_dump(mode="json"),
                fsync=self._fsync_policy != "none",
            )
        except BaseException as exc:
            try:
                self._close_descriptor()
            except OSError as close_error:
                exc.add_note(f"Failed to close {self._events_path}: {close_error}")
            raise
        return manifest

    def append_events(self, events: Sequence[ExecutionEvent]) -> tuple[WrittenEventSlice, ...]:
        """Validate redaction, compute checksums, and append newline-delimited JSONL records."""
        self._check_usable()
        if not events:
            return ()
        if self._fd is None:
            raise StorageWriteError("JsonlEventLogWriter is not open")

        # Serialize complete batch before touching disk so memory errors/validation fail cleanly.
        encoded_records: list[tuple[ExecutionEvent, bytes]] = []
        for raw_event in events:
            if raw_event.execution_id != self._execution_id:
                raise InvalidExecutionIdError(
                    f"Event execution_id {raw_event.execution_id!r} != {self._execution_id!r}"
                )
            safe_event = sanitize_event_for_persistence(
                raw_event,
                redaction_mode=self._redaction_mode,
                persist_cwd=self._persist_cwd,
            )
            event_dict = safe_event.model_dump(mode="json")
            checksum = canonical_event_sha256(event_dict)
            wrapper = {
                "record_schema_version": STORAGE_SCHEMA_VERSION,
                "record_type": "event",
                "sha256": checksum,
                "event": event_dict,
            }
            line_bytes = (json.dumps(wrapper, ensure_ascii=False) + "\n").encode("utf-8")
            encoded_records.append((safe_event, line_bytes))

        retained = self._retained_tail
        if retained and not encoded_records[0][1].startswith(retained):
            # A complete record missing only its delimiter belongs to recovery preflight.
            intact, _ = _parse_jsonl_line(
                execution_id=self._execution_id,
                raw_line=retained + b"\n",
                line_number=self._line_count + 1,
                byte_offset=self._retained_tail_offset,
                verify_checksum=True,
            )
            if intact is not None or self._tail_policy == "reject":
                raise StorageCorruptionError(
                    f"Cannot append to {self._events_path}: retained tail needs recovery"
                )
            quarantine_tail_bytes(
                exec_dir=self._exec_dir,
                execution_id=self._execution_id,
                raw_tail=retained,
                byte_offset=self._retained_tail_offset,
                reason="Incomplete tail bytes mismatched next append event",
                issue_kind="invalid_json",
            )
            try:
                os.ftruncate(self._fd, self._retained_tail_offset)
                os.lseek(self._fd, self._retained_tail_offset, os.SEEK_SET)
            except OSError as exc:
                self._requires_verification = True
                error = _translate_os_error(exc, context=f"replacing tail of {self._events_path}")
                error.append_outcome = AppendFailureOutcome(0, (), False, True)
                raise error from exc
            self._byte_offset = self._retained_tail_offset
            self._retained_tail = b""

        cursor = self._byte_offset - len(self._retained_tail)
        slices = []
        for safe_event, line in encoded_records:
            slices.append(
                WrittenEventSlice(event=safe_event, byte_offset=cursor, byte_length=len(line))
            )
            cursor += len(line)
        data = b"".join(line for _, line in encoded_records)[len(self._retained_tail) :]
        self._append_bytes(data, slices, replaced_tail=bool(retained and not self._retained_tail))
        self._retained_tail = b""
        return tuple(slices)

    def _append_bytes(
        self, data: bytes, slices: Sequence[WrittenEventSlice], *, replaced_tail: bool = False
    ) -> None:
        assert self._fd is not None
        accepted = 0
        syncing = False
        try:
            for size in _write_chunks(self._fd, data, self._events_path):
                accepted += size
            if self._fsync_policy == "every_batch":
                syncing = True
                os.fsync(self._fd)
        except OSError as exc:
            self._requires_verification = bool(accepted or replaced_tail or syncing)
            self._byte_offset += accepted
            prefix = tuple(
                item for item in slices if item.byte_offset + item.byte_length <= self._byte_offset
            )
            self._count_records(prefix)
            error = _translate_os_error(exc, context=f"appending to {self._events_path}")
            error.append_outcome = AppendFailureOutcome(
                accepted, prefix, syncing, self._requires_verification
            )
            raise error from exc
        self._byte_offset += accepted
        self._count_records(slices)

    def _count_records(self, slices: Sequence[WrittenEventSlice]) -> None:
        self._line_count += len(slices)
        for item in slices:
            self._last_sequence = max(self._last_sequence, item.event.sequence)

    def append_tail_fragment(self, fragment: bytes) -> WrittenEventSlice | None:
        """Combine an incoming byte fragment with the retained incomplete tail."""
        self._check_usable()
        if self._fd is None:
            raise StorageWriteError("JsonlEventLogWriter is not open")
        if not fragment:
            return None

        offset = self._byte_offset - len(self._retained_tail)
        combined = self._retained_tail + fragment
        if not combined.endswith(b"\n"):
            self._append_bytes(fragment, ())
            self._retained_tail_offset = offset
            self._retained_tail = combined
            return None

        decoded, issue = _parse_jsonl_line(
            execution_id=self._execution_id,
            raw_line=combined,
            line_number=self._line_count + 1,
            byte_offset=offset,
            verify_checksum=True,
        )
        if issue is not None or decoded is None:
            reason = issue.details if issue else "invalid record"
            if self._tail_policy == "reject":
                raise StorageCorruptionError(f"Combined tail fragment invalid: {reason}")
            quarantine_tail_bytes(
                exec_dir=self._exec_dir,
                execution_id=self._execution_id,
                raw_tail=combined,
                byte_offset=offset,
                reason=reason,
                issue_kind=issue.issue_kind if issue else "invalid_json",
            )
            self._append_bytes(fragment, ())
            self._retained_tail = b""
            return None
        result = WrittenEventSlice(event=decoded, byte_offset=offset, byte_length=len(combined))
        self._append_bytes(fragment, (result,))
        self._retained_tail = b""
        return result

    def flush(self) -> None:
        """Sync the open event log as configured and persist its current manifest counters."""
        self._check_usable()
        if self._fd is None:
            return
        if self._fsync_policy != "none":
            try:
                os.fsync(self._fd)
            except OSError as exc:
                self._requires_verification = True
                raise _translate_os_error(exc, context=f"fsyncing {self._events_path}") from exc

        try:
            raw_manifest = self._manifest_path.read_bytes()
        except OSError as exc:
            raise _translate_os_error(exc, context=f"reading {self._manifest_path}") from exc
        try:
            manifest = ExecutionManifest.model_validate_json(raw_manifest)
        except ValidationError as exc:
            raise StorageCorruptionError(f"Invalid manifest at {self._manifest_path}") from exc
        manifest = manifest.model_copy(
            update={
                "byte_size": self._byte_offset,
                "line_count": self._line_count,
                "last_sequence": self._last_sequence,
            }
        )
        write_atomic_private_json(
            self._manifest_path,
            manifest.model_dump(mode="json"),
            fsync=self._fsync_policy != "none",
        )

    def finalize(self, summary: ExecutionSummary) -> ExecutionManifest:
        """Atomically persist final summary and verified manifest metadata."""
        self._check_usable()
        if self._fd is None:
            raise StorageWriteError("JsonlEventLogWriter must be open to finalize")
        if summary.execution_id != self._execution_id:
            raise InvalidExecutionIdError(
                f"Summary execution_id {summary.execution_id!r} != {self._execution_id!r}"
            )
        if self._fd is not None and self._fsync_policy != "none":
            try:
                os.fsync(self._fd)
            except OSError as exc:
                self._requires_verification = True
                raise _translate_os_error(
                    exc, context=f"final fsync on {self._events_path}"
                ) from exc

        safe_summary = sanitize_summary_for_persistence(summary, persist_cwd=self._persist_cwd)
        write_atomic_private_json(
            self._execution_path,
            safe_summary.model_dump(mode="json"),
            fsync=self._fsync_policy != "none",
        )

        file_sha = compute_file_sha256(self._events_path) if self._events_path.exists() else None
        corruption_count = len(list(self._exec_dir.glob("corrupted_tail_*.quarantine")))
        status: Literal["finalized", "incomplete"] = (
            "finalized"
            if (summary.capture_completeness == "complete" and corruption_count == 0)
            else "incomplete"
        )
        manifest = ExecutionManifest(
            execution_id=self._execution_id,
            recording_dir=relative_recording_dir(self._execution_id),
            status=status,
            created_at=self._created_at or summary.started_at,
            finalized_at=datetime.now(UTC),
            byte_size=self._byte_offset,
            line_count=self._line_count,
            last_sequence=self._last_sequence,
            events_file_sha256=file_sha,
            corruption_count=corruption_count,
        )
        write_atomic_private_json(
            self._manifest_path,
            manifest.model_dump(mode="json"),
            fsync=self._fsync_policy != "none",
        )
        return manifest

    def close(self) -> None:
        """Close the underlying JSONL file descriptor cleanly."""
        if self._fd is None:
            return
        try:
            if not self._requires_verification:
                self.flush()
        except BaseException as exc:
            try:
                self._close_descriptor()
            except OSError as close_error:
                exc.add_note(f"Failed to close {self._events_path}: {close_error}")
            raise
        else:
            self._close_descriptor()
        finally:
            if self._ownership is not None:
                self._ownership.close()
                self._ownership = None

    def _close_descriptor(self) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            os.close(fd)


class JsonlEventLogReader:
    """Integrity-aware reader for per-execution ``events.jsonl`` and companion JSON files."""

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir

    def read_metadata(
        self, execution_id: str
    ) -> tuple[ExecutionHeader | None, ExecutionSummary | None, ExecutionManifest | None]:
        """Load ``execution.json`` (header or summary) and ``manifest.json`` safely."""
        exec_dir = resolve_execution_dir(self._data_dir, execution_id)
        exec_path = exec_dir / EXECUTION_FILE_NAME
        manifest_path = exec_dir / MANIFEST_FILE_NAME

        header: ExecutionHeader | None = None
        summary: ExecutionSummary | None = None
        manifest: ExecutionManifest | None = None

        if exec_path.is_symlink():
            raise StorageCorruptionError(f"Refusing symlink metadata file: {exec_path}")
        if exec_path.exists():
            try:
                raw_exec = json.loads(exec_path.read_text(encoding="utf-8"))
                if isinstance(raw_exec, dict):
                    _check_major_version(
                        raw_exec.get("schema_version"),
                        expected=EVENT_SCHEMA_VERSION,
                        label="event schema_version",
                    )
                    if "ended_at" in raw_exec:
                        summary = ExecutionSummary.model_validate(raw_exec)
                    else:
                        header = ExecutionHeader.model_validate(raw_exec)
            except UnsupportedSchemaVersionError:
                raise
            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                RecursionError,
                ValidationError,
            ) as exc:
                raise StorageCorruptionError(
                    f"Corrupt execution metadata file {exec_path}: {type(exc).__name__}"
                ) from exc

        if manifest_path.is_symlink():
            raise StorageCorruptionError(f"Refusing symlink manifest file: {manifest_path}")
        if manifest_path.exists():
            try:
                raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if isinstance(raw_manifest, dict):
                    _check_major_version(
                        raw_manifest.get("storage_schema_version"),
                        expected=STORAGE_SCHEMA_VERSION,
                        label="storage_schema_version",
                    )
                    manifest = ExecutionManifest.model_validate(raw_manifest)
            except UnsupportedSchemaVersionError:
                raise
            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                RecursionError,
                ValidationError,
            ) as exc:
                raise StorageCorruptionError(
                    f"Corrupt execution manifest file {manifest_path}: {type(exc).__name__}"
                ) from exc

        return header, summary, manifest

    def read_event_at(
        self,
        execution_id: str,
        *,
        byte_offset: int,
        byte_length: int,
        verify_checksum: bool = True,
    ) -> ExecutionEvent:
        """Seek directly to one indexed JSONL slice and validate its checksum and schema."""
        if byte_offset < 0 or byte_length <= 0:
            raise StorageCorruptionError(
                f"Invalid event slice bounds offset={byte_offset} len={byte_length}"
            )
        exec_dir = resolve_execution_dir(self._data_dir, execution_id)
        events_path = exec_dir / EVENTS_FILE_NAME
        if events_path.is_symlink():
            raise StorageCorruptionError(f"Refusing symlink events log: {events_path}")
        with events_path.open("rb") as handle:
            handle.seek(byte_offset)
            raw_line = handle.read(byte_length)

        if len(raw_line) != byte_length or not raw_line.endswith(b"\n"):
            raise StorageCorruptionError(
                f"Truncated or missing newline at offset={byte_offset} len={byte_length}"
            )
        decoded, issue = _parse_jsonl_line(
            execution_id=execution_id,
            raw_line=raw_line,
            line_number=1,
            byte_offset=byte_offset,
            verify_checksum=verify_checksum,
        )
        if issue is not None or decoded is None:
            reason = issue.details if issue is not None else "unknown corruption"
            raise StorageCorruptionError(reason)
        return decoded

    def read_execution(
        self,
        execution_id: str,
        *,
        strict: bool = False,
        verify_checksums: bool = True,
    ) -> JsonlReadResult:
        """Scan ``events.jsonl`` completely, preserving valid events and reporting corruptions."""
        clean_id = validate_execution_id(execution_id)
        exec_dir = resolve_execution_dir(self._data_dir, clean_id)
        events_path = exec_dir / EVENTS_FILE_NAME
        if events_path.is_symlink():
            raise StorageCorruptionError(f"Refusing symlink events log: {events_path}")
        header, summary, manifest = self.read_metadata(clean_id)

        valid_events: list[IndexedLogEvent] = []
        corruptions: list[CorruptRecordReport] = []
        file_digest = hashlib.sha256()
        last_seq = 0
        line_count = 0
        total_bytes = 0
        saw_finished_event = False

        if events_path.exists():
            with events_path.open("rb") as handle:
                offset = 0
                for line_no, raw_line in enumerate(handle, start=1):
                    file_digest.update(raw_line)
                    line_len = len(raw_line)
                    total_bytes += line_len
                    line_count += 1

                    decoded, issue = _parse_jsonl_line(
                        execution_id=clean_id,
                        raw_line=raw_line,
                        line_number=line_no,
                        byte_offset=offset,
                        verify_checksum=verify_checksums,
                    )
                    if issue is not None:
                        corruptions.append(issue)
                        if strict:
                            raise StorageCorruptionError(issue.details)
                        offset += line_len
                        continue

                    assert decoded is not None
                    if decoded.execution_id != clean_id:
                        issue_exec = CorruptRecordReport(
                            execution_id=clean_id,
                            line_number=line_no,
                            byte_offset=offset,
                            byte_length=line_len,
                            issue_kind="event_validation_failed",
                            excerpt_sha256=hashlib.sha256(raw_line).hexdigest(),
                            details=(
                                f"Event execution_id {decoded.execution_id!r} != {clean_id!r}"
                            ),
                        )
                        corruptions.append(issue_exec)
                        if strict:
                            raise StorageCorruptionError(issue_exec.details)
                        offset += line_len
                        continue

                    if decoded.sequence != last_seq + 1:
                        seq_issue = CorruptRecordReport(
                            execution_id=clean_id,
                            line_number=line_no,
                            byte_offset=offset,
                            byte_length=line_len,
                            issue_kind="sequence_gap",
                            excerpt_sha256=hashlib.sha256(raw_line).hexdigest(),
                            details=(
                                f"Expected sequence {last_seq + 1}, observed {decoded.sequence}"
                            ),
                        )
                        corruptions.append(seq_issue)
                        if strict:
                            raise StorageCorruptionError(seq_issue.details)

                    last_seq = max(last_seq, decoded.sequence)
                    if decoded.kind == "execution_finished":
                        saw_finished_event = True
                    valid_events.append(
                        IndexedLogEvent(
                            event=decoded,
                            line_number=line_no,
                            byte_offset=offset,
                            byte_length=line_len,
                        )
                    )
                    offset += line_len

        unclean_shutdown = (
            summary is None
            or (manifest is not None and manifest.status == "recording")
            or (bool(valid_events) and not saw_finished_event)
        )
        return JsonlReadResult(
            execution_id=clean_id,
            header=header,
            summary=summary,
            manifest=manifest,
            events=tuple(valid_events),
            corruptions=tuple(corruptions),
            byte_size=total_bytes,
            line_count=line_count,
            last_valid_sequence=last_seq,
            events_file_sha256=file_digest.hexdigest(),
            unclean_shutdown=unclean_shutdown,
        )

    def discover_execution_ids(self) -> tuple[str, ...]:
        """List valid canonical UUID execution directory names present under ``executions/``."""
        root = self._data_dir / EXECUTIONS_DIR_NAME
        if not root.exists():
            return ()
        found: list[str] = []
        for entry in sorted(root.iterdir()):
            if not entry.is_dir():
                continue
            try:
                found.append(validate_execution_id(entry.name))
            except InvalidExecutionIdError:
                continue
        return tuple(found)


def _parse_jsonl_line(
    *,
    execution_id: str,
    raw_line: bytes,
    line_number: int,
    byte_offset: int,
    verify_checksum: bool,
) -> tuple[ExecutionEvent | None, CorruptRecordReport | None]:
    line_len = len(raw_line)
    line_hash = hashlib.sha256(raw_line).hexdigest()

    if not raw_line.endswith(b"\n"):
        return None, CorruptRecordReport(
            execution_id=execution_id,
            line_number=line_number,
            byte_offset=byte_offset,
            byte_length=line_len,
            issue_kind="missing_newline",
            excerpt_sha256=line_hash,
            details=f"Line {line_number} truncated without trailing newline",
        )

    body = raw_line[:-1]
    if body.endswith(b"\r"):
        body = body[:-1]

    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        return None, CorruptRecordReport(
            execution_id=execution_id,
            line_number=line_number,
            byte_offset=byte_offset,
            byte_length=line_len,
            issue_kind="invalid_utf8",
            excerpt_sha256=line_hash,
            details=f"Line {line_number} invalid UTF-8: {exc}",
        )

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        return None, CorruptRecordReport(
            execution_id=execution_id,
            line_number=line_number,
            byte_offset=byte_offset,
            byte_length=line_len,
            issue_kind="invalid_json",
            excerpt_sha256=line_hash,
            details=f"Line {line_number} invalid JSON: {type(exc).__name__}",
        )

    if not isinstance(parsed, dict) or parsed.get("record_type") != "event":
        return None, CorruptRecordReport(
            execution_id=execution_id,
            line_number=line_number,
            byte_offset=byte_offset,
            byte_length=line_len,
            issue_kind="invalid_record_envelope",
            excerpt_sha256=line_hash,
            details=f"Line {line_number} invalid JSONL wrapper envelope",
        )

    rec_ver = parsed.get("record_schema_version")
    try:
        _check_major_version(
            rec_ver, expected=STORAGE_SCHEMA_VERSION, label="record_schema_version"
        )
    except UnsupportedSchemaVersionError as exc:
        return None, CorruptRecordReport(
            execution_id=execution_id,
            line_number=line_number,
            byte_offset=byte_offset,
            byte_length=line_len,
            issue_kind="unsupported_schema_version",
            excerpt_sha256=line_hash,
            details=str(exc),
        )

    event_obj = parsed.get("event")
    if not isinstance(event_obj, dict):
        return None, CorruptRecordReport(
            execution_id=execution_id,
            line_number=line_number,
            byte_offset=byte_offset,
            byte_length=line_len,
            issue_kind="invalid_record_envelope",
            excerpt_sha256=line_hash,
            details=f"Line {line_number} missing event dict",
        )

    try:
        _check_major_version(
            event_obj.get("schema_version"),
            expected=EVENT_SCHEMA_VERSION,
            label="event.schema_version",
        )
    except UnsupportedSchemaVersionError as exc:
        return None, CorruptRecordReport(
            execution_id=execution_id,
            line_number=line_number,
            byte_offset=byte_offset,
            byte_length=line_len,
            issue_kind="unsupported_schema_version",
            excerpt_sha256=line_hash,
            details=str(exc),
        )

    if verify_checksum:
        expected_sha = parsed.get("sha256")
        actual_sha = canonical_event_sha256(event_obj)
        if not isinstance(expected_sha, str) or expected_sha != actual_sha:
            return None, CorruptRecordReport(
                execution_id=execution_id,
                line_number=line_number,
                byte_offset=byte_offset,
                byte_length=line_len,
                issue_kind="checksum_mismatch",
                excerpt_sha256=line_hash,
                details=(
                    f"Line {line_number} SHA-256 mismatch (stored={expected_sha!r}, "
                    f"computed={actual_sha!r})"
                ),
            )

    try:
        validated = ExecutionEvent.model_validate(event_obj)
    except ValidationError as exc:
        locs = ", ".join(
            ".".join(str(part) for part in err.get("loc", ()))
            for err in exc.errors(include_url=False, include_input=False)[:5]
        )
        return None, CorruptRecordReport(
            execution_id=execution_id,
            line_number=line_number,
            byte_offset=byte_offset,
            byte_length=line_len,
            issue_kind="event_validation_failed",
            excerpt_sha256=line_hash,
            details=(
                f"Line {line_number} failed ExecutionEvent validation "
                f"({exc.error_count()} errors" + (f": {locs})" if locs else ")")
            ),
        )

    return validated, None


def iter_jsonl_slices_from_events(events: Iterable[WrittenEventSlice]) -> list[tuple[int, int]]:
    """Helper returning `(byte_offset, byte_length)` pairs for written event slices."""
    return [(s.byte_offset, s.byte_length) for s in events]


__all__ = [
    "EVENTS_FILE_NAME",
    "EXECUTIONS_DIR_NAME",
    "EXECUTION_FILE_NAME",
    "MANIFEST_FILE_NAME",
    "STORAGE_SCHEMA_VERSION",
    "CorruptRecordReport",
    "CorruptionIssueKind",
    "ExecutionManifest",
    "FsyncPolicy",
    "IndexedLogEvent",
    "JsonlEventLogReader",
    "JsonlEventLogWriter",
    "JsonlReadResult",
    "TailPolicy",
    "TailRecoveryResult",
    "WrittenEventSlice",
    "canonical_event_sha256",
    "compute_file_sha256",
    "iter_jsonl_slices_from_events",
    "quarantine_tail_bytes",
    "relative_recording_dir",
    "resolve_execution_dir",
    "sanitize_event_for_persistence",
    "sanitize_header_for_persistence",
    "sanitize_summary_for_persistence",
    "validate_execution_id",
    "write_atomic_private_json",
]
