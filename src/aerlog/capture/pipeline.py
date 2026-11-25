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
import logging
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

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

if TYPE_CHECKING:
    from aerlog.storage.event_log import AppendFailureOutcome
    from aerlog.storage.ownership import ExecutionOwnership

_DEFAULT_MAX_QUEUE_EVENTS = 2048
_DEFAULT_MAX_QUEUE_BYTES = 64 * 1024 * 1024  # 64 MiB

_LOGGER = logging.getLogger(__name__)


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


@dataclass(slots=True)
class _GapSpan:
    reason: str
    count_unit: Literal["raw_input", "event"]
    count: int
    first_ns: int
    last_ns: int


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
        self._ownership: ExecutionOwnership | None = None
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
        self._finalize_lock = asyncio.Lock()
        self._started = False
        self._summary: ExecutionSummary | None = None
        self._capture_error: BaseException | None = None
        self._close_task: asyncio.Task[None] | None = None

        self._spilled = False
        self._force_incomplete = False
        self._sink_error: str | None = None
        self._primary_complete_prefix: int | None = None
        self._sink_timed_out = False
        self._spool_error: str | None = None
        self._sink_delivered_header = False

        # Pending non-silent gap tracking when mark_incomplete overflows or sinks fail.
        self._pending_gaps: list[_GapSpan] = []
        self._extend_pending_gap = False
        self._interrupted_events: Sequence[ExecutionEvent] = ()
        self._interruption_warnings: list[RawCaptureWarningInput] = []

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
    def sink_timed_out(self) -> bool:
        """Whether primary sink stalled past configured timeout budget."""
        return self._sink_timed_out

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

    def mark_incomplete(self, warning: RawCaptureWarningInput | None = None) -> None:
        """Record an interruption whose loss count cannot be established."""
        self._force_incomplete = True
        if warning is not None:
            self._interruption_warnings.append(warning)

    def _record_gap_span(
        self,
        monotonic_ns: int,
        *,
        end_ns: int | None = None,
        count: int = 1,
        reason: str,
        count_unit: Literal["raw_input", "event"] = "raw_input",
    ) -> None:
        last_ns = monotonic_ns if end_ns is None else end_ns
        prior = self._pending_gaps[-1] if self._extend_pending_gap else None
        if prior is not None and (prior.reason, prior.count_unit) == (reason, count_unit):
            prior.count += count
            prior.first_ns = min(prior.first_ns, monotonic_ns)
            prior.last_ns = max(prior.last_ns, last_ns)
            self._normalizer.record_gap(count, new_span=False)
        else:
            self._pending_gaps.append(_GapSpan(reason, count_unit, count, monotonic_ns, last_ns))
            self._normalizer.record_gap(count)
            self._extend_pending_gap = True
        self.mark_incomplete()

    def _record_event_losses(self, events: Sequence[ExecutionEvent], *, reason: str) -> None:
        self.mark_incomplete()
        times = [event.monotonic_time_ns for event in events if event.kind != "capture_gap"]
        if times:
            self._record_gap_span(
                min(times), end_ns=max(times), count=len(times), reason=reason, count_unit="event"
            )

    def _flush_pending_gap_events(self) -> list[ExecutionEvent]:
        spans, self._pending_gaps = self._pending_gaps, []
        self._extend_pending_gap = False
        return [
            self._normalizer.build_gap_event(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=span.last_ns,
                dropped_count=span.count,
                reason=span.reason,
                first_gap_monotonic_ns=span.first_ns,
                last_gap_monotonic_ns=span.last_ns,
                details={"count_unit": span.count_unit},
                account_loss=False,
            )
            for span in spans
        ]

    def _remember_primary_failure(self, error: BaseException) -> None:
        self._sink_error = repr(error)
        outcome: AppendFailureOutcome | None = getattr(error, "append_outcome", None)
        if outcome is not None:
            self._primary_complete_prefix = len(outcome.complete_slices)

    def _activate_spill(
        self, reason: str, detail: str | None = None, *, terminal: bool = False
    ) -> list[ExecutionEvent]:
        """Open the ``0o600`` spool file, write header if needed, and emit spill warning."""
        if self._spilled or self._spool_error is not None:
            return []
        try:
            header = self._normalizer.build_header()
            self._spool.write_header(header)
            if terminal:
                # The attempted terminal already occupies the final sequence.
                self._spilled = True
                return []
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

    async def _call_primary_sink_with_spill_guard(
        self, coro: Any, *, terminal: bool = False
    ) -> bool:
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
                self._remember_primary_failure(exc)
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
                self._remember_primary_failure(task_exc)
                self._activate_spill("primary_sink_error", repr(task_exc), terminal=terminal)
                return False

            reason = (
                "buffer_saturated_slow_sink"
                if self._spill_trigger.is_set()
                else "primary_sink_stalled"
            )
            if not self._spill_trigger.is_set():
                self._sink_timed_out = True
            self._activate_spill(
                reason,
                f"Primary sink exceeded {self._config.spill_write_timeout_s}s write budget",
                terminal=terminal,
            )
            return False
        except BaseException:
            sink_task.cancel()
            spill_wait_task.cancel()
            await asyncio.gather(sink_task, spill_wait_task, return_exceptions=True)
            raise

    def _write_spool_events(
        self, events: Sequence[ExecutionEvent], *, known_missing_from: int | None = 0
    ) -> None:
        if not events:
            return
        if self._spool_error is not None:
            if known_missing_from is not None:
                self._record_event_losses(
                    events[known_missing_from:], reason="recovery_spool_unavailable"
                )
            return

        before = self._spool.record_count
        try:
            self._spool.write_events(events)
        except OSError as exc:
            self._spool_error = repr(exc)
            self.mark_incomplete()
            if known_missing_from is not None:
                # The first failed record may have reached disk before flush failed.
                first_unattempted = self._spool.record_count - before + 1
                self._record_event_losses(
                    events[max(known_missing_from, first_unattempted) :],
                    reason="recovery_spool_write_failed",
                )

    async def _deliver_events(self, events: Sequence[ExecutionEvent]) -> None:
        """Deliver normalized events, tracking only losses established by either sink."""
        if not events:
            return
        if self._spilled:
            self._write_spool_events(events)
            return
        if self._sink_error is not None:
            self._record_event_losses(events, reason="primary_sink_unavailable")
            return

        try:
            ok = await self._call_primary_sink_with_spill_guard(self._sink.emit_events(events))
        except asyncio.CancelledError:
            self._interrupted_events = events
            raise
        if ok:
            return
        if self._spilled:
            # Exact records are safe to retry even when the primary write later finishes.
            self._write_spool_events(events, known_missing_from=self._primary_complete_prefix)
        else:
            self.mark_incomplete()
            if self._primary_complete_prefix is not None:
                self._record_event_losses(
                    events[self._primary_complete_prefix :], reason="primary_sink_write_failed"
                )

    def _reserve_capture(self) -> None:
        reserve = getattr(self._sink, "reserve_capture", None)
        if reserve is not None:
            self._ownership = reserve(self._execution_id, self._spool.path)
        elif self._config.backpressure_policy == "spill":
            # A custom sink has no storage root. The standard spool directory identifies
            # its data root; a custom spill directory is its own coordination namespace.
            from aerlog.storage.ownership import ExecutionOwnership

            directory = self._spool.path.parent
            root = directory.parent if directory.name == "spool" else directory
            self._ownership = ExecutionOwnership.acquire(root, self._execution_id)
            self._ownership.check_new_capture(self._spool.path)

    async def start(self) -> None:
        """Deliver header + startup events and launch the background consumer task."""
        if self._started:
            return
        async with self._start_lock:
            if self._started:
                return

            if self._capture_error is not None:
                raise self._capture_error
            try:
                self._reserve_capture()
            except BaseException as exc:
                # A contender has no claim on the sink already serving another pipeline.
                self._capture_error = exc
                if self._ownership is not None:
                    self._ownership.close()
                    self._ownership = None
                raise
            try:
                header = self._normalizer.build_header()
                ok = await self._call_primary_sink_with_spill_guard(self._sink.on_start(header))
                if ok:
                    self._sink_delivered_header = True

                startup_events = self._normalizer.start_execution()
                await self._deliver_events(startup_events)
                self._worker_task = asyncio.create_task(self._consumer_loop())
                self._started = True
            except BaseException as exc:
                await self._close_after_error(exc)
                raise

    async def enqueue(self, raw_input: RawCaptureInput) -> None:
        """Enqueue a raw observation strictly honoring configured backpressure semantics."""
        if self._closed_for_input:
            return
        if not self._started:
            await self.start()
        if self._closed_for_input:
            return

        byte_cost = estimate_raw_input_bytes(raw_input)
        policy = self._config.backpressure_policy

        async with self._condition:
            if self._closed_for_input:
                return

            if not self._has_capacity_for(byte_cost):
                if policy == "mark_incomplete":
                    self._record_gap_span(raw_input.monotonic_time_ns, reason="capture_queue_full")
                    return
                if policy == "spill":
                    self._spill_trigger.set()
                try:
                    await self._condition.wait_for(
                        lambda: self._closed_for_input or self._has_capacity_for(byte_cost)
                    )
                except asyncio.CancelledError:
                    if self._summary is None:
                        self._record_gap_span(
                            raw_input.monotonic_time_ns, reason="capture_enqueue_cancelled"
                        )
                    raise
                if self._closed_for_input:
                    if self._summary is None:
                        self._record_gap_span(
                            raw_input.monotonic_time_ns, reason="capture_input_closed"
                        )
                    return

            self._extend_pending_gap = False
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

            raw_pending = True
            try:
                gap_events = self._flush_pending_gap_events()
                if gap_events:
                    await self._deliver_events(gap_events)

                normalized = self._normalizer.normalize(entry.item)
                raw_pending = False
                await self._deliver_events(normalized)
            except asyncio.CancelledError:
                self.mark_incomplete()
                if raw_pending:
                    self._record_gap_span(
                        entry.item.monotonic_time_ns, reason="capture_consumer_cancelled"
                    )
                raise
            except Exception:
                self.mark_incomplete()
                if raw_pending:
                    self._record_gap_span(
                        entry.item.monotonic_time_ns, reason="capture_consumer_failed"
                    )
                async with self._condition:
                    self._closed_for_input = True
                    self._condition.notify_all()
                raise

    async def _drain_worker(self) -> None:
        worker = self._worker_task
        if worker is None:
            return

        done, _ = await asyncio.wait({worker}, timeout=self._config.drain_timeout_s)
        if done and not worker.cancelled():
            await worker
            return

        if not done:
            self._sink_timed_out = True
            worker.cancel()
            await asyncio.wait({worker})
        if not worker.cancelled():
            worker.result()
        async with self._condition:
            remaining = [entry.item for entry in self._queue if entry.item is not None]
            self._queue.clear()
            self._queued_bytes = 0
        self.mark_incomplete()
        reason = "drain_timeout" if self._sink_timed_out else "capture_consumer_cancelled"
        if self._config.backpressure_policy == "spill" and (remaining or self._interrupted_events):
            self._activate_spill(reason)
        if self._spilled:
            self._write_spool_events(self._interrupted_events, known_missing_from=None)
            for item in remaining:
                self._write_spool_events(self._normalizer.normalize(item))
        else:
            if self._interrupted_events:
                self._sink_error = self._sink_error or "Unconfirmed primary append during drain"
            for item in remaining:
                self._record_gap_span(item.monotonic_time_ns, reason=reason)
        self._interrupted_events = ()

    async def _finish_capture(
        self, *, termination_reason: str, exit_code: int, returncode: int | None
    ) -> ExecutionSummary:
        # Deliver any trailing gap markers before emitting execution_finished.
        if self._spool_error is None and (
            self._spilled or (self._sink_error is None and not self._sink_timed_out)
        ):
            controls = self._flush_pending_gap_events()
            for warning in self._interruption_warnings:
                controls.extend(self._normalizer.normalize(warning))
            if controls:
                try:
                    await asyncio.wait_for(
                        self._deliver_events(controls), timeout=self._config.drain_timeout_s
                    )
                except TimeoutError as exc:
                    self._sink_timed_out = True
                    self.mark_incomplete()
                    if self._config.backpressure_policy == "spill":
                        self._activate_spill("control_write_timeout", repr(exc))
                        self._write_spool_events(controls, known_missing_from=None)

        ended_at = datetime.now(UTC)
        monotonic_end_ns = time.monotonic_ns()

        spilled_before_terminal = self._spilled
        finished_event, summary = self._normalizer.finalize_execution(
            ended_at=ended_at,
            monotonic_end_ns=monotonic_end_ns,
            termination_reason=termination_reason,
            exit_code=exit_code,
            returncode=returncode,
            spilled=self._spilled,
            force_incomplete=self._force_incomplete,
            spool_file=str(self._spool.path) if self._spilled else None,
        )

        if not self._spilled and self._sink_error is None and not self._sink_timed_out:
            try:
                delivered = await asyncio.wait_for(
                    self._call_primary_sink_with_spill_guard(
                        self._sink.emit_events([finished_event]), terminal=True
                    ),
                    timeout=self._config.drain_timeout_s,
                )
                if delivered:
                    await asyncio.wait_for(
                        self._sink.on_finish(summary), timeout=self._config.drain_timeout_s
                    )
                    await asyncio.wait_for(self._sink.flush(), timeout=self._config.drain_timeout_s)
                    return summary
            except Exception as exc:
                self._sink_error = repr(exc)
                if isinstance(exc, TimeoutError):
                    self._sink_timed_out = True
                if self._config.backpressure_policy == "spill":
                    self._activate_spill("finalize_sink_failed", repr(exc), terminal=True)

        if self._spilled and self._spool_error is None:
            try:
                # A cancelled coroutine may have left an executor operation running.
                # Restart must see exactly the event and summary offered to that worker.
                self._spool.write_events([finished_event])
                self._spool.write_summary(summary)
                self._spool.flush()
            except OSError as exc:
                self._spool_error = repr(exc)
                self._force_incomplete = True
            else:
                if not spilled_before_terminal:
                    return summary.model_copy(
                        update={
                            "capture_completeness": "spilled"
                            if summary.capture_completeness == "complete"
                            else summary.capture_completeness,
                            "spool_file": str(self._spool.path),
                        }
                    )
                return summary
        self._force_incomplete = True
        summary = summary.model_copy(update={"capture_completeness": "incomplete"})
        return summary

    async def _close_resources(self) -> None:
        async with self._condition:
            self._closed_for_input = True
            self._queue.clear()
            self._queued_bytes = 0
            self._condition.notify_all()

        if self._worker_task is not None:
            if not self._worker_task.done():
                self._worker_task.cancel()
            await asyncio.gather(self._worker_task, return_exceptions=True)

        try:
            self._spool.close()
        except OSError as exc:
            if self._summary is None or self._capture_error is not None:
                raise
            _LOGGER.warning("Failed to close capture recovery spool %s: %s", self._spool.path, exc)
        finally:
            try:
                await asyncio.wait_for(
                    self._sink.close(), timeout=min(1.0, self._config.drain_timeout_s)
                )
            except Exception as exc:
                _LOGGER.warning("Failed to close capture sink %r: %s", self._sink, exc)
            finally:
                if self._ownership is not None:
                    self._ownership.close()
                    self._ownership = None

    async def _wait_for_close(self) -> None:
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close_resources())
        await asyncio.shield(self._close_task)

    async def _close_after_error(self, error: BaseException) -> None:
        self._capture_error = error
        try:
            await self._wait_for_close()
        except (Exception, asyncio.CancelledError) as close_error:
            if close_error is not error:
                error.add_note(f"Failed to close capture resources: {close_error}")

    async def finalize(
        self,
        *,
        termination_reason: str,
        exit_code: int,
        returncode: int | None = None,
    ) -> ExecutionSummary:
        """Drain buffered inputs, emit ``execution_finished``, flush sinks, and return summary."""
        async with self._finalize_lock:
            if self._capture_error is not None:
                raise self._capture_error
            if self._summary is not None:
                return self._summary

            # Startup handles its own cleanup once it has reserved the sink.
            if not self._started:
                await self.start()

            try:
                if termination_reason in {
                    "aborted",
                    "cancelled",
                    "diagnostic_write_failed",
                    "frame_too_large",
                    "signal",
                    "transport_error",
                }:
                    self.mark_incomplete()
                async with self._condition:
                    self._closed_for_input = True
                    self._queue.append(_QueuedEntry(item=None, byte_cost=0))
                    self._condition.notify_all()

                consumer_error: Exception | None = None
                try:
                    await self._drain_worker()
                except Exception as exc:
                    consumer_error = exc
                    self._force_incomplete = True
                    for entry in self._queue:
                        if entry.item is not None:
                            self._record_gap_span(
                                entry.item.monotonic_time_ns, reason="capture_consumer_failed"
                            )
                    self._queue.clear()
                    self._queued_bytes = 0

                try:
                    summary = await self._finish_capture(
                        termination_reason=termination_reason,
                        exit_code=exit_code,
                        returncode=returncode,
                    )
                except Exception as exc:
                    if consumer_error is None:
                        raise
                    consumer_error.add_note(f"Failed to finalize incomplete capture: {exc}")
                    raise consumer_error from None
                self._summary = summary
                if consumer_error is not None:
                    raise consumer_error

                await self._wait_for_close()
            except BaseException as exc:
                await self._close_after_error(exc)
                raise

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
