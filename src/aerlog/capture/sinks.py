"""Capture sink interfaces, in-memory sink, and ``0o600`` redacted recovery spool."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol, TextIO

from aerlog.capture.redaction import EventRedactor, RedactionConfig
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
        self.header = header

    async def emit_events(self, events: Sequence[ExecutionEvent]) -> None:
        self.events.extend(events)

    async def on_finish(self, summary: ExecutionSummary) -> None:
        self.summary = summary

    async def flush(self) -> None:
        self.flush_count += 1

    async def close(self) -> None:
        self.closed = True


def _open_strict_spool_file(path: Path) -> TextIO:
    """Open or create ``path`` in append mode strictly restricted to owner ``0o600``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.chmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    return os.fdopen(fd, "a", encoding="utf-8", buffering=1)


def default_spool_path(execution_id: str, spill_dir: Path | None = None) -> Path:
    """Return local recovery spool file path for ``execution_id``."""
    root = default_data_dir() / "spool" if spill_dir is None else spill_dir
    return root / f"{execution_id}.ndjson.spool"


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

        # Defense in depth: verify serialized payload/derived/wire data conform to active redaction.
        payload_dict = raw_obj.get("payload")
        if mode == "strict_hash_only":
            if isinstance(payload_dict, dict):
                for key in ("params", "result", "error", "body", "text", "value", "extra_fields"):
                    if key in payload_dict and payload_dict[key] is not None:
                        payload_dict[key] = None
        else:
            redacted_payload = self._redactor.redact_value(payload_dict, root_path="spool.payload")
            if redacted_payload.summary.degraded:
                raw_obj["degraded"] = True
                raw_obj["payload"] = {"kind": event.kind}
            else:
                raw_obj["payload"] = redacted_payload.value
        return raw_obj

    def _write_line(self, record_type: str, data: dict[str, Any]) -> None:
        self.open()
        assert self._stream is not None
        line = json.dumps({"record_type": record_type, "data": data}, ensure_ascii=False) + "\n"
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
