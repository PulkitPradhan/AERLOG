"""Bridge between Phase 3 StdioProxy hooks and Phase 4 CapturePipeline."""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from aerlog.capture.normalizer import (
    RawChildShutdownEscalateInput,
    RawFrameTooLargeInput,
    RawIncompleteFrameInput,
    RawProcessExitedInput,
    RawProxySignalInput,
    RawStderrLineInput,
    RawTransportErrorInput,
    RawWireFrameInput,
)
from aerlog.capture.pipeline import CaptureConfig, CapturePipeline
from aerlog.capture.sinks import CaptureSink
from aerlog.events.models import ExecutionSummary
from aerlog.events.types import WireDirection


class CaptureProxyObserver:
    """Implements Phase 3 ``ProxyObserver`` hooks to feed a :class:`CapturePipeline`."""

    def __init__(
        self,
        sink: CaptureSink,
        *,
        config: CaptureConfig | None = None,
        execution_id: str | None = None,
    ) -> None:
        self._sink = sink
        self._config = config or CaptureConfig()
        self._execution_id = execution_id
        self._pipeline: CapturePipeline | None = None
        self._last_summary: ExecutionSummary | None = None

    @property
    def pipeline(self) -> CapturePipeline | None:
        """Return underlying active :class:`CapturePipeline` once session starts."""
        return self._pipeline

    @property
    def last_summary(self) -> ExecutionSummary | None:
        """Return finalized :class:`ExecutionSummary` after proxy run finishes."""
        return self._last_summary

    async def on_execution_started(
        self,
        *,
        command: Sequence[str],
        cwd: Path | None,
        env_overrides: Mapping[str, str] | None,
        monotonic_time_ns: int,
    ) -> None:
        """Initialize and start the capture pipeline for one proxy session."""
        _ = monotonic_time_ns
        pipeline = CapturePipeline(
            self._sink,
            command=command,
            cwd=str(cwd) if cwd is not None else None,
            env_overrides=env_overrides,
            config=self._config,
            execution_id=self._execution_id,
        )
        self._pipeline = pipeline
        await pipeline.start()

    async def on_wire_frame(
        self,
        direction: WireDirection,
        raw_frame: bytes,
        monotonic_time_ns: int,
    ) -> None:
        """Queue an unmodified protocol frame observation."""
        if self._pipeline is None:
            return
        await self._pipeline.enqueue(
            RawWireFrameInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=monotonic_time_ns,
                direction=direction,
                raw_frame=raw_frame,
            )
        )

    async def on_incomplete_frame(
        self,
        direction: WireDirection,
        trailing_bytes: bytes,
        monotonic_time_ns: int,
    ) -> None:
        """Queue non-newline-terminated trailing bytes flushed at EOF."""
        if self._pipeline is None:
            return
        await self._pipeline.enqueue(
            RawIncompleteFrameInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=monotonic_time_ns,
                direction=direction,
                trailing_bytes=trailing_bytes,
            )
        )

    async def on_frame_too_large(
        self,
        direction: WireDirection,
        observed_bytes: int,
        max_frame_bytes: int,
        monotonic_time_ns: int,
    ) -> None:
        """Queue fail-closed oversized frame metadata."""
        if self._pipeline is None:
            return
        await self._pipeline.enqueue(
            RawFrameTooLargeInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=monotonic_time_ns,
                direction=direction,
                observed_bytes=observed_bytes,
                max_frame_bytes=max_frame_bytes,
            )
        )

    async def on_stderr_line(self, raw_line: bytes, monotonic_time_ns: int) -> None:
        """Queue one child stderr line."""
        if self._pipeline is None:
            return
        await self._pipeline.enqueue(
            RawStderrLineInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=monotonic_time_ns,
                raw_line=raw_line,
            )
        )

    async def on_transport_error(
        self,
        stream_direction: WireDirection | None,
        reason: str,
        error: str,
        monotonic_time_ns: int,
    ) -> None:
        """Queue transport closure or OS I/O error metadata."""
        if self._pipeline is None:
            return
        await self._pipeline.enqueue(
            RawTransportErrorInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=monotonic_time_ns,
                stream_direction=stream_direction,
                reason=reason,
                error=error,
            )
        )

    async def on_proxy_signal(self, signal_name: str, monotonic_time_ns: int) -> None:
        """Queue signal or proxy cancellation notification."""
        if self._pipeline is None:
            return
        await self._pipeline.enqueue(
            RawProxySignalInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=monotonic_time_ns,
                signal_name=signal_name,
            )
        )

    async def on_child_shutdown_escalate(
        self,
        signal_name: str,
        pgid: int,
        error: str | None,
        monotonic_time_ns: int,
    ) -> None:
        """Queue process-group termination signal escalation."""
        if self._pipeline is None:
            return
        await self._pipeline.enqueue(
            RawChildShutdownEscalateInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=monotonic_time_ns,
                signal_name=signal_name,
                pgid=pgid,
                error=error,
            )
        )

    async def on_process_exited(self, returncode: int | None, monotonic_time_ns: int) -> None:
        """Notify capture pipeline that the child server process exited."""
        if self._pipeline is None:
            return
        await self._pipeline.enqueue(
            RawProcessExitedInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=monotonic_time_ns,
                returncode=returncode,
            )
        )

    async def on_execution_finished(
        self,
        *,
        termination_reason: str,
        exit_code: int,
        returncode: int | None,
    ) -> None:
        """Finalize capture pipeline and store finalized summary."""
        if self._pipeline is None:
            return
        self._last_summary = await self._pipeline.finalize(
            termination_reason=termination_reason,
            exit_code=exit_code,
            returncode=returncode,
        )

    async def force_close(self) -> None:
        """Best-effort cleanup if startup aborted before normal finish."""
        if self._pipeline is not None and self._last_summary is None:
            self._last_summary = await self._pipeline.finalize(
                termination_reason="aborted",
                exit_code=1,
                returncode=None,
            )


def now_monotonic_ns() -> int:
    """Return current monotonic timestamp in nanoseconds."""
    return time.monotonic_ns()


__all__ = ["CaptureProxyObserver", "now_monotonic_ns"]
