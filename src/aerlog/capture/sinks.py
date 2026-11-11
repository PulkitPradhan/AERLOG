"""Capture sink interfaces, in-memory sink, and ``0o600`` redacted recovery spool."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol, TextIO

from aerlog.capture.redaction import (
    REDACTION_FAILED_MARKER,
    EventRedactor,
    RedactionConfig,
    scrub_event_dict_withheld,
)
from aerlog.config.schema import default_data_dir
from aerlog.events.models import ExecutionEvent, ExecutionHeader, ExecutionSummary


class CaptureSink(Protocol):
    """Async destination interface for normalized, redacted AERLOG capture records."""

    async def on_start(self, header: ExecutionHeader) -> None:
        """Persist or record execution header metadata at session start."""

    async def emit_events(self, events: Sequence[ExecutionEvent]) -> None:
        """Persist or record an ordered batch of normalized events."""

    async def on_finish(self, summary: ExecutionSummary) -> None:
        """Persist or record the finalized execution summary."""

    async def flush(self) -> None:
        """Flush buffered sink output."""

    async def close(self) -> None:
        """Release underlying sink resources."""


class InMemoryCaptureSink:
    """In-process sink collecting header, events, and final summary for callers/tests."""

    def __init__(self) -> None:
        self.header: ExecutionHeader | None = None
        self.events: list[ExecutionEvent] = []
        self.summary: ExecutionSummary | None = None
        self.flush_count = 0
        self.closed = False

    async def on_start(self, header: ExecutionHeader) -> None:
        """Record execution header in memory."""
        self.header = header

    async def emit_events(self, events: Sequence[ExecutionEvent]) -> None:
        """Append normalized events in memory."""
        self.events.extend(events)

    async def on_finish(self, summary: ExecutionSummary) -> None:
        """Record finalized execution summary in memory."""
        self.summary = summary

    async def flush(self) -> None:
        """Increment in-memory flush counter."""
        self.flush_count += 1

    async def close(self) -> None:
        """Mark the in-memory sink closed."""
        self.closed = True


def _open_strict_spool_file(path: Path) -> TextIO:
    """Open or create ``path`` in append mode strictly restricted to owner ``0o600``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.chmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    return os.fdopen(fd, "a", encoding="utf-8", buffering=1)


def default_spool_path(execution_id: str, spill_dir: Path | None = None) -> Path:
    """Return local recovery spool file path for ``execution_id``."""
    if (
        not execution_id
        or "\x00" in execution_id
        or "/" in execution_id
        or "\\" in execution_id
        or execution_id in {".", ".."}
        or ".." in execution_id
    ):
        raise ValueError(f"Invalid execution_id for recovery spool path: {execution_id!r}")
    root = default_data_dir() / "spool" if spill_dir is None else spill_dir
    resolved_root = root.resolve()
    target = (resolved_root / f"{execution_id}.ndjson.spool").resolve()
    if not target.is_relative_to(resolved_root) or target.parent != resolved_root:
        raise ValueError(f"Path containment violation for spool execution_id: {execution_id!r}")
    return target


class RecoverySpool:
    """Append-only ``0o600`` local NDJSON recovery spool enforcing redaction prior to write."""

    def __init__(
        self,
        spool_path: Path,
        *,
        redaction_config: RedactionConfig | None = None,
    ) -> None:
        self._path = spool_path
        self._redactor = EventRedactor(redaction_config)
        self._stream: TextIO | None = None
        self._record_count = 0

    @property
    def path(self) -> Path:
        """Path to the local recovery spool file."""
        return self._path

    @property
    def record_count(self) -> int:
        """Number of records written to the spool file."""
        return self._record_count

    @property
    def is_open(self) -> bool:
        """Whether the spool file handle is currently open."""
        return self._stream is not None

    def open(self) -> None:
        """Open the ``0o600`` spool file if not already open."""
        if self._stream is None:
            self._stream = _open_strict_spool_file(self._path)

    def _enforce_redacted_event_data(self, event: ExecutionEvent) -> dict[str, Any]:
        raw_obj = event.model_dump(mode="json")
        mode = self._redactor.config.mode
        if mode == "explicit_unredacted":
            return raw_obj

        if not event.redaction.applied and event.redaction.payload_mode != "redaction_failed":
            raise ValueError(
                "Refusing to write unredacted event to recovery spool while "
                f"redaction_mode={mode!r}"
            )

        # Verify serialized payload, derived, and trace fields conform to active redaction.
        if mode == "strict_hash_only":
            return scrub_event_dict_withheld(raw_obj, redactor=self._redactor)

        if event.redaction.payload_mode == "redaction_failed" or event.degraded:
            return scrub_event_dict_withheld(
                raw_obj,
                redactor=self._redactor,
                failure_replacement=REDACTION_FAILED_MARKER,
            )

        payload_dict = raw_obj.get("payload")
        redacted_payload = self._redactor.redact_value(payload_dict, root_path="spool.payload")
        if redacted_payload.summary.degraded:
            secured = scrub_event_dict_withheld(
                raw_obj,
                redactor=self._redactor,
                failure_replacement=REDACTION_FAILED_MARKER,
            )
            secured["degraded"] = True
            return secured
        raw_obj["payload"] = redacted_payload.value

        trace = raw_obj.get("trace")
        if isinstance(trace, dict) and isinstance(trace.get("observed_tracestate"), str):
            ts_out = self._redactor.redact_text_value(
                trace["observed_tracestate"], path_label="spool.trace.observed_tracestate"
            )
            trace["observed_tracestate"] = (
                REDACTION_FAILED_MARKER if ts_out.summary.degraded else ts_out.text
            )
        derived = raw_obj.get("derived")
        if isinstance(derived, dict) and isinstance(derived.get("otel_attributes"), dict):
            otel_out = self._redactor.redact_value(
                derived["otel_attributes"], root_path="spool.derived.otel_attributes"
            )
            derived["otel_attributes"] = {} if otel_out.summary.degraded else otel_out.value
        return raw_obj

    def _write_line(self, record_type: str, data: dict[str, Any]) -> None:
        self.open()
        assert self._stream is not None
        line = (
            json.dumps(
                {"record_type": record_type, "data": data},
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        )
        self._stream.write(line)
        self._stream.flush()
        self._record_count += 1

    def write_header(self, header: ExecutionHeader) -> None:
        """Redact command args if needed and append execution header to spool."""
        data = header.model_dump(mode="json")
        if self._redactor.config.mode != "explicit_unredacted":
            safe_cmd, _ = self._redactor.redact_command(header.command)
            data["command"] = list(safe_cmd)
            if self._redactor.config.mode == "strict_hash_only":
                data["cwd"] = None
        self._write_line("header", data)

    def write_events(self, events: Sequence[ExecutionEvent]) -> None:
        """Enforce redaction policy and append events sequentially to spool."""
        for event in events:
            safe_data = self._enforce_redacted_event_data(event)
            self._write_line("event", safe_data)

    def write_summary(self, summary: ExecutionSummary) -> None:
        """Append finalized execution summary to spool."""
        data = summary.model_dump(mode="json")
        if self._redactor.config.mode != "explicit_unredacted":
            safe_cmd, _ = self._redactor.redact_command(summary.command)
            data["command"] = list(safe_cmd)
            if self._redactor.config.mode == "strict_hash_only":
                data["cwd"] = None
                data["unanswered_request_ids"] = []
                data["observed_mcp_protocol_versions"] = []
            else:
                ids_out = self._redactor.redact_value(
                    list(summary.unanswered_request_ids),
                    root_path="spool.summary.unanswered_request_ids",
                )
                vers_out = self._redactor.redact_value(
                    list(summary.observed_mcp_protocol_versions),
                    root_path="spool.summary.observed_mcp_protocol_versions",
                )
                data["unanswered_request_ids"] = (
                    [] if ids_out.summary.degraded else list(ids_out.value or [])
                )
                data["observed_mcp_protocol_versions"] = (
                    [] if vers_out.summary.degraded else list(vers_out.value or [])
                )
        self._write_line("summary", data)

    def flush(self) -> None:
        """Flush buffered spool output to OS."""
        if self._stream is not None:
            self._stream.flush()

    def close(self) -> None:
        """Close the spool file handle cleanly."""
        if self._stream is not None:
            try:
                self._stream.flush()
            finally:
                try:
                    self._stream.close()
                finally:
                    self._stream = None


__all__ = [
    "CaptureSink",
    "InMemoryCaptureSink",
    "RecoverySpool",
    "default_spool_path",
]
