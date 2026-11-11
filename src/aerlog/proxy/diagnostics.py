"""Bounded off-stdout diagnostic sink with explicit write-failure and backpressure policies.

Note on Phase boundaries:
    In Phase 3, diagnostic records represent proxy operational telemetry and
    envelope metadata; dropping diagnostic records under ``drop_with_gap`` while
    recording an explicit gap count keeps live protocol forwarding unblocked.
    Phase 4 protocol event capture MUST NOT silently discard protocol events and
    must instead block, spill to durable storage, or mark executions incomplete.

Note on sensitivity:
    Diagnostic logs may still contain sensitive data (for example in server
    ``stderr`` or malformed previews) unless ``include_previews=False`` and
    downstream redaction policies are enabled.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TextIO

DiagnosticWritePolicy = Literal["degrade", "strict"]
BackpressurePolicy = Literal["drop_with_gap", "block"]


class DiagnosticFatalWriteError(Exception):
    """Raised when writing diagnostics fails under ``write_policy='strict'``."""


@dataclass(frozen=True, slots=True)
class DiagnosticConfig:
    """Configuration for the off-stdout diagnostic sink."""

    log_file: Path | None = None
    queue_size: int = 1024
    write_policy: DiagnosticWritePolicy = "degrade"
    backpressure_policy: BackpressurePolicy = "drop_with_gap"
    include_previews: bool = True
    preview_max_chars: int = 120
    preview_max_hex_bytes: int = 32

    def __post_init__(self) -> None:
        if self.queue_size <= 0:
            raise ValueError("queue_size must be a positive integer")
        if self.preview_max_chars < 0:
            raise ValueError("preview_max_chars must be non-negative")
        if self.preview_max_hex_bytes < 0:
            raise ValueError("preview_max_hex_bytes must be non-negative")


def _open_restricted_log_file(path: Path) -> TextIO:
    """Open ``path`` for appending UTF-8 text with ``0o600`` permissions on creation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    return os.fdopen(fd, "a", encoding="utf-8", buffering=1)


class DiagnosticSink:
    """Bounded async diagnostic writer strictly isolated from ``stdout``."""

    def __init__(
        self,
        config: DiagnosticConfig | None = None,
        *,
        stream: TextIO | None = None,
        fallback_stderr: TextIO | None = None,
    ) -> None:
        self._config = config or DiagnosticConfig()
        self._injected_stream = stream
        self._fallback_stderr: TextIO = sys.stderr if fallback_stderr is None else fallback_stderr
        self._stream: TextIO | None = None
        self._owns_stream = False

        self._queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
            maxsize=self._config.queue_size
        )
        self._writer_task: asyncio.Task[None] | None = None
        self._fatal_event = asyncio.Event()
        self._fatal_error: DiagnosticFatalWriteError | None = None

        self._started = False
        self._closed = False
        self._degraded = False
        self._warned_fallback = False
        self._write_errors = 0
        self._dropped_count = 0
        self._pending_gap_count = 0

    @property
    def config(self) -> DiagnosticConfig:
        """Return sink configuration."""
        return self._config

    @property
    def fatal_event(self) -> asyncio.Event:
        """Event set if a fatal write failure occurs under ``strict`` policy."""
        return self._fatal_event

    @property
    def fatal_error(self) -> DiagnosticFatalWriteError | None:
        """Fatal write error captured under ``strict`` policy, if any."""
        return self._fatal_error

    @property
    def write_errors(self) -> int:
        """Number of diagnostic write failures observed."""
        return self._write_errors

    @property
    def dropped_count(self) -> int:
        """Number of diagnostic records dropped under queue backpressure."""
        return self._dropped_count

    @property
    def is_complete(self) -> bool:
        """Whether all diagnostics were written without drops or write errors."""
        return self._write_errors == 0 and self._dropped_count == 0

    async def start(self) -> None:
        """Open the target stream and start the background writer task."""
        if self._started:
            return
        self._started = True

        if self._injected_stream is not None:
            self._stream = self._injected_stream
            self._owns_stream = False
        elif self._config.log_file is not None:
            try:
                self._stream = _open_restricted_log_file(self._config.log_file)
                self._owns_stream = True
            except OSError as exc:
                self._handle_write_failure(exc, context=f"opening {self._config.log_file}")
                if self._fatal_error is not None:
                    raise self._fatal_error from exc
        else:
            self._stream = self._fallback_stderr
            self._owns_stream = False

        self._writer_task = asyncio.create_task(self._writer_loop())

    def emit_nowait(self, event: str, **fields: Any) -> None:
        """Queue one diagnostic record without awaiting (safe in signal callbacks)."""
        if self._closed or self._fatal_error is not None:
            return
        record = {"ts_ns": time.monotonic_ns(), "event": event, **fields}
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            self._dropped_count += 1
            self._pending_gap_count += 1

    async def emit(self, event: str, **fields: Any) -> None:
        """Queue one diagnostic record according to the configured backpressure policy."""
        if self._closed or self._fatal_error is not None:
            return
        record = {"ts_ns": time.monotonic_ns(), "event": event, **fields}

        if self._config.backpressure_policy == "block" and not self._degraded:
            await self._queue.put(record)
            return

        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            self._dropped_count += 1
            self._pending_gap_count += 1

    async def close(self, timeout: float = 2.0) -> None:
        """Flush queued diagnostic records and close owned file handles."""
        if self._closed:
            return
        self._closed = True

        if self._writer_task is not None:
            try:
                await asyncio.wait_for(self._queue.put(None), timeout=max(0.1, timeout / 2))
                await asyncio.wait_for(self._writer_task, timeout=timeout)
            except TimeoutError:
                self._writer_task.cancel()
                with suppress(asyncio.CancelledError):
                    await self._writer_task

        if self._pending_gap_count > 0 and not self._degraded and self._fatal_error is None:
            gap = self._pending_gap_count
            self._pending_gap_count = 0
            self._write_record(
                {
                    "ts_ns": time.monotonic_ns(),
                    "event": "diagnostic_backpressure_gap",
                    "dropped_count": gap,
                }
            )

        if self._owns_stream and self._stream is not None:
            with suppress(OSError):
                self._stream.close()
            self._stream = None

    async def _writer_loop(self) -> None:
        while True:
            item = await self._queue.get()
            if item is None:
                break

            if self._degraded or self._fatal_error is not None:
                continue

            if self._pending_gap_count > 0:
                gap = self._pending_gap_count
                self._pending_gap_count = 0
                if not self._write_record(
                    {
                        "ts_ns": time.monotonic_ns(),
                        "event": "diagnostic_backpressure_gap",
                        "dropped_count": gap,
                    }
                ):
                    continue

            self._write_record(item)

    def _write_record(self, record: dict[str, Any]) -> bool:
        if self._stream is None:
            return False
        line = json.dumps(record, ensure_ascii=False) + "\n"
        try:
            self._stream.write(line)
            self._stream.flush()
            return True
        except OSError as exc:
            self._handle_write_failure(exc, context="writing diagnostic log")
            return False

    def _handle_write_failure(self, exc: OSError, *, context: str) -> None:
        self._write_errors += 1
        if not self._warned_fallback:
            self._warned_fallback = True
            if self._stream is not self._fallback_stderr:
                with suppress(OSError):
                    warning = {
                        "ts_ns": time.monotonic_ns(),
                        "event": "diagnostic_write_failed",
                        "context": context,
                        "policy": self._config.write_policy,
                        "error": repr(exc),
                    }
                    self._fallback_stderr.write(json.dumps(warning) + "\n")
                    self._fallback_stderr.flush()

        if self._config.write_policy == "strict":
            self._fatal_error = DiagnosticFatalWriteError(
                f"Diagnostic sink failed ({context}): {exc}"
            )
            self._fatal_event.set()
        else:
            self._degraded = True
