"""Regression tests for reporting known losses and incomplete recordings."""

from __future__ import annotations

import asyncio
import io
import json
import subprocess
import sys
import time
from collections.abc import Sequence
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aerlog.analysis.timeline import reconstruct_execution_timeline
from aerlog.capture import (
    CaptureConfig,
    CapturePipeline,
    CaptureProxyObserver,
    InMemoryCaptureSink,
    RawProcessExitedInput,
    RawWireFrameInput,
)
from aerlog.capture.normalizer import EventNormalizer
from aerlog.events import CaptureGapPayload, CaptureWarningPayload, ExecutionEvent, new_execution_id
from aerlog.events.models import ExecutionFinishedPayload
from aerlog.proxy.stdio_proxy import ProxyConfig, StdioProxy
from aerlog.storage import JsonlEventLogWriter, RecordingRepository
from aerlog.storage.event_log import EXECUTION_FILE_NAME

_DRAIN_TIMEOUT_SERVER = """\
import subprocess
import sys

subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(20)"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
)
sys.stdout.buffer.write(b'{"jsonrpc":"2.0","method":"ready"}\\r\\n')
sys.exit(7)
"""


class _GapTestSink(InMemoryCaptureSink):
    def __init__(self, *, fail_gap: bool) -> None:
        super().__init__()
        self.fail_gap = fail_gap
        self.wire_write_started = asyncio.Event()
        self.release_wire_write = asyncio.Event()

    async def emit_events(self, events: Sequence[ExecutionEvent]) -> None:
        if any(event.kind == "jsonrpc_notification" for event in events):
            self.wire_write_started.set()
            await self.release_wire_write.wait()
        if self.fail_gap and any(event.kind == "capture_gap" for event in events):
            raise OSError("could not persist capture gap marker")
        await super().emit_events(events)


def _raw_frame(frame: bytes) -> RawWireFrameInput:
    return RawWireFrameInput(
        timestamp=datetime.now(UTC),
        monotonic_time_ns=time.monotonic_ns(),
        direction="client_to_server",
        raw_frame=frame,
    )


@pytest.mark.parametrize("fail_gap", [False, True], ids=["recorded-marker", "failed-marker"])
async def test_queue_drop_count_survives_gap_marker_failure(fail_gap: bool) -> None:
    sink = _GapTestSink(fail_gap=fail_gap)
    pipeline = CapturePipeline(
        sink,
        command=("test-server",),
        config=CaptureConfig(backpressure_policy="mark_incomplete", max_queue_events=1),
    )
    await pipeline.start()
    try:
        await pipeline.enqueue(_raw_frame(b'{"jsonrpc":"2.0","method":"ping"}\n'))
        await asyncio.wait_for(sink.wire_write_started.wait(), timeout=2)
        # Fill the queue with an input that normalizes to zero events. The two
        # malformed frames are dropped before normalization could expand them.
        await pipeline.enqueue(
            RawProcessExitedInput(
                timestamp=datetime.now(UTC), monotonic_time_ns=time.monotonic_ns(), returncode=7
            )
        )
        await pipeline.enqueue(_raw_frame(b"{malformed\n"))
        await pipeline.enqueue(_raw_frame(b"{also_malformed\n"))
    finally:
        sink.release_wire_write.set()
        summary = await pipeline.finalize(termination_reason="server_exited", exit_code=7)

    assert summary.exit_code == 7
    assert summary.capture_completeness == "incomplete"
    assert summary.dropped_events == 2
    assert summary.gap_count == 1
    if not fail_gap:
        (gap,) = [
            event.payload for event in sink.events if isinstance(event.payload, CaptureGapPayload)
        ]
        assert gap.dropped_count == 2
        assert gap.details.get("count_unit") == "raw_input"


async def test_cancelled_enqueue_counts_input_that_never_reached_queue() -> None:
    sink = _GapTestSink(fail_gap=False)
    pipeline = CapturePipeline(
        sink, command=("test-server",), config=CaptureConfig(max_queue_events=1)
    )
    await pipeline.start()
    producer_started = asyncio.Event()

    async def enqueue_while_full() -> None:
        producer_started.set()
        await pipeline.enqueue(_raw_frame(b"{never_queued\n"))

    try:
        await pipeline.enqueue(_raw_frame(b'{"jsonrpc":"2.0","method":"ping"}\n'))
        await asyncio.wait_for(sink.wire_write_started.wait(), timeout=2)
        await pipeline.enqueue(_raw_frame(b"{will_be_recorded\n"))
        producer = asyncio.create_task(enqueue_while_full())
        await asyncio.wait_for(producer_started.wait(), timeout=2)
        producer.cancel()
        with pytest.raises(asyncio.CancelledError):
            await producer
    finally:
        sink.release_wire_write.set()
        summary = await pipeline.finalize(termination_reason="server_exited", exit_code=7)

    assert summary.capture_completeness == "incomplete"
    assert summary.dropped_events == 1
    assert sum(event.kind == "malformed_json_frame" for event in sink.events) == 1


def test_timeline_requires_terminal_agreement_before_reported_complete(tmp_path: Path) -> None:
    execution_id = new_execution_id()
    started = datetime(2026, 11, 22, tzinfo=UTC)
    normalizer = EventNormalizer(
        execution_id=execution_id,
        started_at=started,
        monotonic_start_ns=10,
        command=("test-server",),
    )
    startup = normalizer.start_execution()
    terminal, summary = normalizer.finalize_execution(
        ended_at=started + timedelta(seconds=1),
        monotonic_end_ns=1_000_000_010,
        termination_reason="server_exited",
        exit_code=7,
        returncode=7,
    )
    writer = JsonlEventLogWriter(tmp_path, execution_id)
    writer.open(normalizer.build_header())
    try:
        writer.append_events([*startup, terminal])
        writer.finalize(summary)
    finally:
        writer.close()

    with closing(RecordingRepository(tmp_path)) as repository:
        healthy_timeline = reconstruct_execution_timeline(repository, execution_id)
        assert healthy_timeline.capture_completeness == "complete"
        execution_path = writer.execution_dir / EXECUTION_FILE_NAME
        execution_path.write_text(
            summary.model_copy(update={"exit_code": 0}).model_dump_json(), encoding="utf-8"
        )
        timeline = reconstruct_execution_timeline(repository, execution_id, strict_integrity=True)

    assert timeline.capture_completeness == "incomplete"


async def test_spool_append_failure_preserves_prefix_without_guessing_drop_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _UnavailablePrimary(InMemoryCaptureSink):
        async def emit_events(self, events: Sequence[ExecutionEvent]) -> None:
            raise OSError("primary capture unavailable")

    pipeline = CapturePipeline(
        _UnavailablePrimary(),
        command=("test-server",),
        config=CaptureConfig(backpressure_policy="spill", spill_dir=tmp_path / "spool"),
    )
    await pipeline.start()
    write_line = pipeline._spool._write_line

    def fail_first_of_two_events(record_type: str, data: dict[str, Any]) -> None:
        if record_type == "event" and data["kind"] == "malformed_json_frame":
            raise OSError("spool append outcome unconfirmed")
        write_line(record_type, data)

    monkeypatch.setattr(pipeline._spool, "_write_line", fail_first_of_two_events)
    await pipeline.enqueue(_raw_frame(b"{malformed\n"))
    summary = await pipeline.finalize(termination_reason="server_exited", exit_code=7)

    assert summary.capture_completeness == "incomplete"
    assert summary.dropped_events == 1  # The second event was never attempted.
    assert pipeline.spool_path is not None
    records = [json.loads(line) for line in pipeline.spool_path.read_text().splitlines()]
    assert [record["record_type"] for record in records] == ["header", "event", "event"]
    assert {record["data"]["kind"] for record in records[1:]} == {
        "execution_started",
        "capture_warning",
    }


class _BufferWriter:
    def __init__(self) -> None:
        self.output = bytearray()

    def write(self, data: bytes | bytearray | memoryview) -> None:
        self.output.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


async def test_proxy_drain_timeout_is_incomplete_without_guessing_drops() -> None:
    # The leader exits normally while its descendant keeps only stderr open.
    proxy = StdioProxy(
        ProxyConfig(
            command=(sys.executable, "-c", _DRAIN_TIMEOUT_SERVER),
            drain_timeout=0.05,
            grace_before_kill=0.05,
        )
    )
    reader = asyncio.StreamReader()
    reader.feed_eof()
    writer = _BufferWriter()
    diag = io.StringIO()
    sink = InMemoryCaptureSink()
    observer = CaptureProxyObserver(sink)

    result = await asyncio.wait_for(
        proxy.run(stdin_reader=reader, stdout_writer=writer, diag_stream=diag, observer=observer),
        timeout=5,
    )

    assert result.exit_code == 7
    assert bytes(writer.output) == b'{"jsonrpc":"2.0","method":"ready"}\r\n'
    assert observer.last_summary is not None
    assert observer.last_summary.capture_completeness == "incomplete"
    assert observer.last_summary.dropped_events == 0
    terminal = sink.events[-1].payload
    assert isinstance(terminal, ExecutionFinishedPayload)
    assert terminal.completeness == "incomplete"
    assert terminal.exit_code == 7
    assert terminal.dropped_events == 0
    warning_codes = [
        event.payload.code
        for event in sink.events
        if isinstance(event.payload, CaptureWarningPayload)
    ]
    assert "proxy_drain_timeout" in warning_codes
    diagnostic_events = [json.loads(line)["event"] for line in diag.getvalue().splitlines()]
    assert "proxy_drain_timeout" in diagnostic_events


def test_quiet_cli_reports_incomplete_capture_on_stderr(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aerlog",
            "run",
            "--quiet",
            "--data-dir",
            str(tmp_path),
            "--",
            sys.executable,
            "-c",
            _DRAIN_TIMEOUT_SERVER,
        ],
        input=b"",
        capture_output=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 7
    assert result.stdout == b'{"jsonrpc":"2.0","method":"ready"}\r\n'
    assert b"capture incomplete" in result.stderr.lower()
