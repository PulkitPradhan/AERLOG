"""Durability-first bounded capture pipeline with block, spill, and mark_incomplete policies.

Policy guarantees:
    - Protocol events are **never** silently discarded.
    - ``block`` (default): bounded memory, lossless capture; delays upstream forwarding
      when a slow downstream sink saturates queue count or byte limits.
    - ``spill``: preserves redacted events in a ``0o600`` local recovery spool whenever
      the primary sink stalls past ``spill_write_timeout_s``, fails, or fills the buffer.
    - ``mark_incomplete``: optional non-blocking mode under overflow; explicitly records
      ``capture_gap`` markers and sets ``ExecutionSummary.capture_completeness="incomplete"``.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aerlog.capture.normalizer import (
    EventNormalizer,
    RawCaptureInput,
    RawCaptureWarningInput,
    RawFrameTooLargeInput,
    RawIncompleteFrameInput,
    RawProcessExitedInput,
    RawStderrLineInput,
    RawWireFrameInput,
)
from aerlog.capture.redaction import RedactionConfig
from aerlog.capture.sinks import CaptureSink, RecoverySpool, default_spool_path
from aerlog.events.ids import new_execution_id
from aerlog.events.models import ExecutionEvent, ExecutionSummary
from aerlog.events.types import CaptureBackpressurePolicy, RedactionMode

_DEFAULT_MAX_QUEUE_EVENTS = 2048
_DEFAULT_MAX_QUEUE_BYTES = 64 * 1024 * 1024  # 64 MiB


def estimate_raw_input_bytes(item: RawCaptureInput) -> int:
    """Estimate memory footprint in bytes for queue byte-budget accounting."""
    if isinstance(item, RawWireFrameInput):
        return len(item.raw_frame) + 256
    if isinstance(item, RawIncompleteFrameInput):
        return len(item.trailing_bytes) + 256
    if isinstance(item, RawStderrLineInput):
        return len(item.raw_line) + 128
    if isinstance(item, RawFrameTooLargeInput):
        return 256
    return 256


@dataclass(frozen=True, slots=True)
class CaptureConfig:
    """Runtime configuration for :class:`CapturePipeline`.

    Note:
        The default ``backpressure_policy="block"`` guarantees lossless, bounded-memory
        capture and can stall live MCP forwarding if a downstream sink sustains low
        throughput. Configure ``"spill"`` to offload stalled writes to a local ``0o600``
        recovery spool without dropping events.
    """

    backpressure_policy: CaptureBackpressurePolicy = "block"
    redaction_mode: RedactionMode = "standard"
    extra_sensitive_keys: tuple[str, ...] = ()
    extra_secret_patterns: tuple[str, ...] = ()
    max_queue_events: int = _DEFAULT_MAX_QUEUE_EVENTS
    max_queue_bytes: int = _DEFAULT_MAX_QUEUE_BYTES
    spill_dir: Path | None = None
    spill_write_timeout_s: float = 0.5
    drain_timeout_s: float = 10.0

    def __post_init__(self) -> None:
        if self.backpressure_policy not in ("block", "spill", "mark_incomplete"):
            raise ValueError(f"Unsupported backpressure_policy: {self.backpressure_policy!r}")
        if self.redaction_mode not in ("standard", "strict_hash_only", "explicit_unredacted"):
            raise ValueError(f"Unsupported redaction_mode: {self.redaction_mode!r}")
        if self.max_queue_events <= 0:
            raise ValueError("max_queue_events must be a positive integer")
        if self.max_queue_bytes <= 0:
            raise ValueError("max_queue_bytes must be a positive integer")
        if self.spill_write_timeout_s <= 0:
            raise ValueError("spill_write_timeout_s must be positive")
        if self.drain_timeout_s <= 0:
            raise ValueError("drain_timeout_s must be positive")

    def to_redaction_config(self) -> RedactionConfig:
        """Build matching :class:`RedactionConfig` for normalizer and recovery spool."""
        return RedactionConfig(
            mode=self.redaction_mode,
            extra_sensitive_keys=self.extra_sensitive_keys,
            extra_secret_patterns=self.extra_secret_patterns,
        )


@dataclass(frozen=True, slots=True)
class _QueuedEntry:
    item: RawCaptureInput | None
    byte_cost: int


class CapturePipeline:
    """Async single-consumer capture pipeline connecting proxy events to sinks."""

    def __init__(
        self,
        sink: CaptureSink,
        *,
        command: Sequence[str],
        cwd: str | None = None,
        env_overrides: Mapping[str, str] | None = None,
        config: CaptureConfig | None = None,
        execution_id: str | None = None,
    ) -> None:
        self._config = config or CaptureConfig()
        self._sink = sink
        self._execution_id = new_execution_id() if execution_id is None else execution_id
        self._started_at = datetime.now(UTC)
        self._monotonic_start_ns = time.monotonic_ns()

        redaction_cfg = self._config.to_redaction_config()
        self._normalizer = EventNormalizer(
            execution_id=self._execution_id,
            started_at=self._started_at,
            monotonic_start_ns=self._monotonic_start_ns,
            command=command,
            cwd=cwd,
            env_overrides=env_overrides,
            redaction_config=redaction_cfg,
            backpressure_policy=self._config.backpressure_policy,
        )
        self._spool = RecoverySpool(
            default_spool_path(self._execution_id, self._config.spill_dir),
            redaction_config=redaction_cfg,
        )

        self._condition = asyncio.Condition()
        self._queue: deque[_QueuedEntry] = deque()
        self._queued_bytes = 0
        self._closed_for_input = False

        self._worker_task: asyncio.Task[None] | None = None
        self._spill_trigger = asyncio.Event()
        self._start_lock = asyncio.Lock()
        self._started = False
        self._finalized = False
        self._summary: ExecutionSummary | None = None

        self._spilled = False
        self._force_incomplete = False
        self._sink_error: str | None = None
        self._spool_error: str | None = None
        self._sink_delivered_header = False

        # Pending non-silent gap tracking when mark_incomplete overflows or sinks fail.
        self._pending_gap_count = 0
        self._pending_gap_first_ns: int | None = None
        self._pending_gap_last_ns: int | None = None
        self._pending_gap_reason: str = "capture_queue_full"
        self._gap_history_batches: list[tuple[int, str, int, int]] = []

    @property
    def execution_id(self) -> str:
        """Return unique UUIDv4 execution identifier."""
        return self._execution_id

    @property
    def config(self) -> CaptureConfig:
        """Return active capture pipeline configuration."""
        return self._config

    @property
    def spilled(self) -> bool:
        """Whether events spilled to local ``0o600`` recovery spool."""
        return self._spilled

    @property
    def spool_path(self) -> Path | None:
        """Return spool path if recovery spooling was activated."""
        return self._spool.path if self._spilled else None

    @property
    def sink_error(self) -> str | None:
        """First primary sink failure observed, if any."""
        return self._sink_error

    @property
    def summary(self) -> ExecutionSummary | None:
        """Return finalized :class:`ExecutionSummary` after ``finalize()``."""
        return self._summary

    def _has_capacity_for(self, item_bytes: int) -> bool:
        if not self._queue:
            return True
        if len(self._queue) >= self._config.max_queue_events:
            return False
        return (self._queued_bytes + item_bytes) <= self._config.max_queue_bytes

    def _record_gap_span(self, monotonic_ns: int, *, count: int = 1, reason: str) -> None:
        self._pending_gap_count += count
        if self._pending_gap_first_ns is None:
            self._pending_gap_first_ns = monotonic_ns
        self._pending_gap_last_ns = monotonic_ns
        self._pending_gap_reason = reason
        self._force_incomplete = True

    def _flush_pending_gap_events(self) -> list[ExecutionEvent]:
        events: list[ExecutionEvent] = []
        if self._gap_history_batches:
            for count, reason, first_ns, last_ns in self._gap_history_batches:
                events.append(
                    self._normalizer.build_gap_event(
                        timestamp=datetime.now(UTC),
                        monotonic_time_ns=last_ns,
                        dropped_count=count,
                        reason=reason,
                        first_gap_monotonic_ns=first_ns,
                        last_gap_monotonic_ns=last_ns,
                    )
                )
            self._gap_history_batches.clear()
        if self._pending_gap_count > 0:
            first_ns = (
                self._pending_gap_first_ns
                if self._pending_gap_first_ns is not None
                else time.monotonic_ns()
            )
            last_ns = (
                self._pending_gap_last_ns if self._pending_gap_last_ns is not None else first_ns
            )
            count = self._pending_gap_count
            reason = self._pending_gap_reason
            self._pending_gap_count = 0
            self._pending_gap_first_ns = None
            self._pending_gap_last_ns = None
            events.append(
                self._normalizer.build_gap_event(
                    timestamp=datetime.now(UTC),
                    monotonic_time_ns=last_ns,
                    dropped_count=count,
                    reason=reason,
                    first_gap_monotonic_ns=first_ns,
                    last_gap_monotonic_ns=last_ns,
                )
            )
        return events

    def _activate_spill(self, reason: str, detail: str | None = None) -> list[ExecutionEvent]:
        """Open the ``0o600`` spool file, write header if needed, and emit spill warning."""
        if self._spilled or self._spool_error is not None:
            return []
        try:
            header = self._normalizer.build_header()
            self._spool.write_header(header)
            warn_events = self._normalizer.normalize(
                RawCaptureWarningInput(
                    timestamp=datetime.now(UTC),
                    monotonic_time_ns=time.monotonic_ns(),
                    code="capture_spill_activated",
                    message=(f"Switched capture delivery to local 0o600 recovery spool ({reason})"),
                    details={
                        "reason": reason,
                        "spool_file": str(self._spool.path),
                        "detail": detail or "",
                    },
                )
            )
            self._spool.write_events(warn_events)
            self._spilled = True
            return warn_events
        except OSError as exc:
            self._spool_error = repr(exc)
            self._force_incomplete = True
            self._spilled = False
            return []

    async def _call_primary_sink_with_spill_guard(self, coro: Any) -> bool:
        """Run a primary sink coroutine, guarding stalls/failures under ``spill`` policy.

        Returns True if the primary sink succeeded cleanly, False if spilled/failed.
        """
        if self._spilled or self._sink_error is not None:
            close_coro = getattr(coro, "close", None)
            if callable(close_coro):
                close_coro()
            return False

        policy = self._config.backpressure_policy
        if policy != "spill":
            try:
                await coro
                return True
            except Exception as exc:
                self._sink_error = repr(exc)
                self._force_incomplete = True
                return False

        sink_task: asyncio.Task[Any] = asyncio.create_task(coro)
        spill_wait_task: asyncio.Task[bool] = asyncio.create_task(self._spill_trigger.wait())
        try:
            done, pending = await asyncio.wait(
                {sink_task, spill_wait_task},
                timeout=self._config.spill_write_timeout_s,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for p in pending:
                p.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

            if sink_task in done and not sink_task.cancelled():
                task_exc = sink_task.exception()
                if task_exc is None:
                    return True
                self._sink_error = repr(task_exc)
                self._activate_spill("primary_sink_error", repr(task_exc))
                return False

            reason = (
                "buffer_saturated_slow_sink"
                if self._spill_trigger.is_set()
                else "primary_sink_stalled"
            )
            self._activate_spill(
                reason,
                f"Primary sink exceeded {self._config.spill_write_timeout_s}s write budget",
            )
            return False
        except BaseException:
            sink_task.cancel()
            spill_wait_task.cancel()
            await asyncio.gather(sink_task, spill_wait_task, return_exceptions=True)
            raise

    async def _deliver_events(self, events: Sequence[ExecutionEvent]) -> None:
        """Deliver normalized events cleanly to primary sink or recovery spool."""
        if not events:
            return

        if self._spilled:
            try:
                self._spool.write_events(events)
            except OSError as exc:
                self._spool_error = repr(exc)
                self._record_gap_span(
                    events[-1].monotonic_time_ns,
                    count=len(events),
                    reason="recovery_spool_write_failed",
                )
            return

        if self._sink_error is not None:
            self._record_gap_span(
                events[-1].monotonic_time_ns,
                count=len(events),
                reason="primary_sink_failed",
            )
            return

        ok = await self._call_primary_sink_with_spill_guard(self._sink.emit_events(events))
        if ok:
            return

        if self._spilled:
            try:
                self._spool.write_events(events)
            except OSError as exc:
                self._spool_error = repr(exc)
                self._record_gap_span(
                    events[-1].monotonic_time_ns,
                    count=len(events),
                    reason="recovery_spool_write_failed",
                )
        else:
            self._record_gap_span(
                events[-1].monotonic_time_ns,
                count=len(events),
                reason="primary_sink_failed",
            )

    async def start(self) -> None:
        """Deliver header + startup events and launch the background consumer task."""
        if self._started:
            return
        async with self._start_lock:
            if self._started:
                return

            header = self._normalizer.build_header()
            ok = await self._call_primary_sink_with_spill_guard(self._sink.on_start(header))
            if ok:
                self._sink_delivered_header = True
            elif self._config.backpressure_policy == "spill" and self._spilled:
                # Header already written inside _activate_spill.
                pass

            startup_events = self._normalizer.start_execution()
            await self._deliver_events(startup_events)
            self._worker_task = asyncio.create_task(self._consumer_loop())
            self._started = True

    async def enqueue(self, raw_input: RawCaptureInput) -> None:
        """Enqueue a raw observation strictly honoring configured backpressure semantics."""
        if not self._started:
            await self.start()
        if self._closed_for_input:
            return

        byte_cost = estimate_raw_input_bytes(raw_input)
        policy = self._config.backpressure_policy

        async with self._condition:
            if self._closed_for_input:
                return

            if policy == "block":
                while not self._has_capacity_for(byte_cost):
                    if self._closed_for_input:
                        return
                    await self._condition.wait()
                self._queue.append(_QueuedEntry(item=raw_input, byte_cost=byte_cost))
                self._queued_bytes += byte_cost
                self._condition.notify_all()
                return

            if policy == "spill":
                if not self._has_capacity_for(byte_cost):
                    self._spill_trigger.set()
                    while not self._has_capacity_for(byte_cost):
                        if self._closed_for_input:
                            return
                        await self._condition.wait()
                self._queue.append(_QueuedEntry(item=raw_input, byte_cost=byte_cost))
                self._queued_bytes += byte_cost
                self._condition.notify_all()
                return

            # mark_incomplete policy: never stalls forwarding and never silently drops.
            if not self._has_capacity_for(byte_cost):
                self._record_gap_span(
                    raw_input.monotonic_time_ns,
                    count=1,
                    reason="capture_queue_full",
                )
                return

            if self._pending_gap_count > 0:
                first_ns = (
                    self._pending_gap_first_ns
                    if self._pending_gap_first_ns is not None
                    else raw_input.monotonic_time_ns
                )
                last_ns = (
                    self._pending_gap_last_ns
                    if self._pending_gap_last_ns is not None
                    else raw_input.monotonic_time_ns
                )
                self._gap_history_batches.append(
                    (self._pending_gap_count, self._pending_gap_reason, first_ns, last_ns)
                )
                self._pending_gap_count = 0
                self._pending_gap_first_ns = None
                self._pending_gap_last_ns = None

            self._queue.append(_QueuedEntry(item=raw_input, byte_cost=byte_cost))
            self._queued_bytes += byte_cost
            self._condition.notify_all()

    async def _consumer_loop(self) -> None:
        while True:
            async with self._condition:
                while not self._queue:
                    await self._condition.wait()
                entry = self._queue.popleft()
                self._queued_bytes = max(0, self._queued_bytes - entry.byte_cost)
                self._condition.notify_all()

            if entry.item is None:
                break

            gap_events = self._flush_pending_gap_events()
            if gap_events:
                await self._deliver_events(gap_events)

            normalized = self._normalizer.normalize(entry.item)
            await self._deliver_events(normalized)

    async def finalize(
        self,
        *,
        termination_reason: str,
        exit_code: int,
        returncode: int | None = None,
    ) -> ExecutionSummary:
        """Drain buffered inputs, emit ``execution_finished``, flush sinks, and return summary."""
        if self._finalized and self._summary is not None:
            return self._summary

        if not self._started:
            await self.start()

        async with self._condition:
            self._closed_for_input = True
            self._queue.append(_QueuedEntry(item=None, byte_cost=0))
            self._condition.notify_all()

        if self._worker_task is not None:
            try:
                await asyncio.wait_for(self._worker_task, timeout=self._config.drain_timeout_s)
            except TimeoutError:
                self._worker_task.cancel()
                with suppress(asyncio.CancelledError):
                    await self._worker_task
                async with self._condition:
                    remaining = [entry.item for entry in self._queue if entry.item is not None]
                    self._queue.clear()
                    self._queued_bytes = 0
                self._force_incomplete = True
                if remaining:
                    if self._config.backpressure_policy == "spill":
                        self._activate_spill("drain_timeout", "Worker drain timeout reached")
                        if not self._spilled:
                            self._record_gap_span(
                                remaining[-1].monotonic_time_ns,
                                count=len(remaining),
                                reason="drain_timeout_spill_failed",
                            )
                        else:
                            for raw_rem in remaining:
                                try:
                                    self._spool.write_events(self._normalizer.normalize(raw_rem))
                                except OSError as exc:
                                    self._spool_error = repr(exc)
                                    self._record_gap_span(
                                        raw_rem.monotonic_time_ns,
                                        count=1,
                                        reason="recovery_spool_write_failed",
                                    )
                    else:
                        self._record_gap_span(
                            remaining[-1].monotonic_time_ns,
                            count=len(remaining),
                            reason="drain_timeout",
                        )

        # Deliver any trailing gap markers before emitting execution_finished.
        trailing_gaps = self._flush_pending_gap_events()
        if trailing_gaps and (self._spilled or self._sink_error is None):
            await self._deliver_events(trailing_gaps)

        ended_at = datetime.now(UTC)
        monotonic_end_ns = time.monotonic_ns()

        def _build_final() -> tuple[ExecutionEvent, ExecutionSummary]:
            return self._normalizer.finalize_execution(
                ended_at=ended_at,
                monotonic_end_ns=monotonic_end_ns,
                termination_reason=termination_reason,
                exit_code=exit_code,
                returncode=returncode,
                spilled=self._spilled,
                force_incomplete=self._force_incomplete,
                spool_file=str(self._spool.path) if self._spilled else None,
            )

        finished_event, summary = _build_final()

        if self._spilled:
            try:
                self._spool.write_events([finished_event])
                self._spool.write_summary(summary)
                self._spool.flush()
            except OSError as exc:
                self._spool_error = repr(exc)
                self._force_incomplete = True
                summary = summary.model_copy(update={"capture_completeness": "incomplete"})
        elif self._sink_error is None:
            ok = await self._call_primary_sink_with_spill_guard(
                self._sink.emit_events([finished_event])
            )
            if not ok:
                if self._spilled:
                    finished_event, summary = _build_final()
                else:
                    self._force_incomplete = True
                    summary = summary.model_copy(update={"capture_completeness": "incomplete"})
            else:
                try:
                    await asyncio.wait_for(
                        self._sink.on_finish(summary),
                        timeout=self._config.drain_timeout_s,
                    )
                    await asyncio.wait_for(
                        self._sink.flush(),
                        timeout=self._config.drain_timeout_s,
                    )
                except Exception as exc:
                    self._sink_error = repr(exc)
                    if self._config.backpressure_policy == "spill":
                        self._activate_spill("finalize_sink_failed", repr(exc))
                        if not self._spilled:
                            self._force_incomplete = True
                    else:
                        self._force_incomplete = True
                    finished_event, summary = _build_final()

            if self._spilled:
                try:
                    self._spool.write_events([finished_event])
                    self._spool.write_summary(summary)
                    self._spool.flush()
                except OSError as exc:
                    self._spool_error = repr(exc)
                    self._force_incomplete = True
                    summary = summary.model_copy(update={"capture_completeness": "incomplete"})
        else:
            self._force_incomplete = True
            summary = summary.model_copy(update={"capture_completeness": "incomplete"})

        with suppress(Exception):
            await asyncio.wait_for(
                self._sink.close(), timeout=min(1.0, self._config.drain_timeout_s)
            )
        self._spool.close()

        self._finalized = True
        self._summary = summary
        return summary


def raw_process_exited_input(
    returncode: int | None, monotonic_time_ns: int
) -> RawProcessExitedInput:
    """Helper constructing a :class:`RawProcessExitedInput` with current UTC timestamp."""
    return RawProcessExitedInput(
        timestamp=datetime.now(UTC),
        monotonic_time_ns=monotonic_time_ns,
        returncode=returncode,
    )


__all__ = [
    "CaptureConfig",
    "CapturePipeline",
    "estimate_raw_input_bytes",
    "raw_process_exited_input",
]
