"""Unit tests for durability-first CapturePipeline, RecoverySpool, and backpressure policies."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aerlog.capture import (
    REDACTED_MARKER,
    CaptureConfig,
    CapturePipeline,
    InMemoryCaptureSink,
    RawWireFrameInput,
    RecoverySpool,
)
from aerlog.config import ConfigValidationError, load_config
from aerlog.events import (
    CaptureGapPayload,
    ExecutionEvent,
    ExecutionHeader,
    ExecutionStartedPayload,
    ExecutionSummary,
    JsonRpcRequestPayload,
    RedactionSummary,
    new_execution_id,
)


class _SlowSink:
    def __init__(self, delay_s: float) -> None:
        self.delay_s = delay_s
        self.header: ExecutionHeader | None = None
        self.events: list[ExecutionEvent] = []
        self.summary: ExecutionSummary | None = None
        self.closed = False

    async def on_start(self, header: ExecutionHeader) -> None:
        self.header = header

    async def emit_events(self, events: Sequence[ExecutionEvent]) -> None:
        await asyncio.sleep(self.delay_s)
        self.events.extend(events)

    async def on_finish(self, summary: ExecutionSummary) -> None:
        self.summary = summary

    async def flush(self) -> None:
        return None

    async def close(self) -> None:
        self.closed = True


class _FailingSink:
    def __init__(self, *, fail_on_emit: bool = True) -> None:
        self.fail_on_emit = fail_on_emit
        self.header: ExecutionHeader | None = None
        self.closed = False

    async def on_start(self, header: ExecutionHeader) -> None:
        self.header = header
        if not self.fail_on_emit:
            raise OSError("disk unavailable at start")

    async def emit_events(self, events: Sequence[ExecutionEvent]) -> None:
        _ = events
        raise OSError("primary sink write failure")

    async def on_finish(self, summary: ExecutionSummary) -> None:
        _ = summary

    async def flush(self) -> None:
        return None

    async def close(self) -> None:
        self.closed = True


def _wire_frame(seq_id: int, secret: str | None = None, pad: str = "") -> RawWireFrameInput:
    params: dict[str, object] = {"n": seq_id}
    if secret is not None:
        params["api_key"] = secret
    if pad:
        params["pad"] = pad
    raw = (
        json.dumps({"jsonrpc": "2.0", "id": seq_id, "method": "tools/call", "params": params})
        + "\n"
    ).encode("utf-8")
    return RawWireFrameInput(
        timestamp=datetime.now(UTC),
        monotonic_time_ns=seq_id * 1_000,
        direction="client_to_server",
        raw_frame=raw,
    )


def test_capture_config_defaults_and_toml_validation(tmp_path: Path) -> None:
    """Default CaptureConfig uses block + standard redaction; invalid values fail validation."""
    cfg = CaptureConfig()
    assert cfg.backpressure_policy == "block"
    assert cfg.redaction_mode == "standard"

    with pytest.raises(ValueError, match="Unsupported redaction_mode"):
        CaptureConfig(redaction_mode="off")  # type: ignore[arg-type]

    bad_toml = tmp_path / "bad_capture.toml"
    bad_toml.write_text('[capture]\nredaction_mode = "off"\n', encoding="utf-8")
    with pytest.raises(ConfigValidationError):
        load_config(bad_toml)

    good_toml = tmp_path / "good_capture.toml"
    good_toml.write_text(
        '[capture]\nbackpressure_policy = "spill"\nmax_queue_events = 64\n',
        encoding="utf-8",
    )
    loaded = load_config(good_toml)
    assert loaded.capture.backpressure_policy == "spill"
    assert loaded.capture.max_queue_events == 64
    assert loaded.capture.redaction_mode == "standard"


async def test_block_policy_slow_sink_stalls_without_silent_drops() -> None:
    """block policy stays lossless under slow sink backpressure and maintains exact sequences."""
    sink = _SlowSink(delay_s=0.025)
    pipeline = CapturePipeline(
        sink,
        command=("python", "server.py"),
        config=CaptureConfig(
            backpressure_policy="block",
            max_queue_events=2,
            drain_timeout_s=5.0,
        ),
    )
    await pipeline.start()

    for idx in range(1, 9):
        await pipeline.enqueue(_wire_frame(idx, secret="sk-secret-block-123456"))

    summary = await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)

    assert summary.capture_completeness == "complete"
    assert summary.dropped_events == 0
    assert summary.gap_count == 0
    assert sink.closed is True
    assert sink.summary == summary

    wire_events = [evt for evt in sink.events if evt.kind == "jsonrpc_request"]
    assert len(wire_events) == 8
    assert [evt.sequence for evt in sink.events] == list(range(1, len(sink.events) + 1))
    for evt in wire_events:
        assert isinstance(evt.payload, JsonRpcRequestPayload)
        assert evt.payload.params["api_key"] == REDACTED_MARKER


async def test_block_policy_enforces_queue_byte_budget() -> None:
    """max_queue_bytes triggers lossless backpressure before max_queue_events is exceeded."""
    sink = _SlowSink(delay_s=0.02)
    pipeline = CapturePipeline(
        sink,
        command=("python", "server.py"),
        config=CaptureConfig(
            backpressure_policy="block",
            max_queue_events=100,
            max_queue_bytes=1_500,
            drain_timeout_s=5.0,
        ),
    )
    await pipeline.start()

    for idx in range(1, 7):
        await pipeline.enqueue(_wire_frame(idx, pad="X" * 600))

    summary = await pipeline.finalize(termination_reason="completed", exit_code=0)
    assert summary.capture_completeness == "complete"
    wire_events = [evt for evt in sink.events if evt.kind == "jsonrpc_request"]
    assert len(wire_events) == 6


async def test_spill_policy_writes_redacted_0o600_recovery_spool_when_sink_stalls_or_fails(
    tmp_path: Path,
) -> None:
    """Slow or failing primary sink spills redacted records cleanly to a 0o600 local spool."""
    slow_sink = _SlowSink(delay_s=0.4)
    spill_dir = tmp_path / "spool"
    pipeline = CapturePipeline(
        slow_sink,
        command=("python", "server.py", "--token", "secret_cli_token"),
        config=CaptureConfig(
            backpressure_policy="spill",
            max_queue_events=2,
            spill_dir=spill_dir,
            spill_write_timeout_s=0.04,
            drain_timeout_s=5.0,
        ),
    )
    await pipeline.start()
    for idx in range(1, 7):
        await pipeline.enqueue(_wire_frame(idx, secret="sk-spill-supersecret-9999"))

    summary = await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)

    assert pipeline.spilled is True
    assert summary.capture_completeness == "spilled"
    assert summary.dropped_events == 0
    assert pipeline.spool_path is not None
    spool_file = pipeline.spool_path
    assert spool_file.exists()
    if os.name == "posix":
        assert stat.S_IMODE(spool_file.stat().st_mode) == 0o600

    raw_spool_text = spool_file.read_text(encoding="utf-8")
    assert "sk-spill-supersecret-9999" not in raw_spool_text
    assert "secret_cli_token" not in raw_spool_text
    assert REDACTED_MARKER in raw_spool_text

    records = [json.loads(line) for line in raw_spool_text.splitlines() if line.strip()]
    event_kinds = [r["data"]["kind"] for r in records if r["record_type"] == "event"]
    assert "capture_warning" in event_kinds
    assert event_kinds.count("jsonrpc_request") == 6
    assert records[-1]["record_type"] == "summary"

    # Also test failing sink recovery under spill policy
    fail_sink = _FailingSink(fail_on_emit=True)
    fail_pipeline = CapturePipeline(
        fail_sink,
        command=("python", "server.py"),
        config=CaptureConfig(
            backpressure_policy="spill",
            spill_dir=tmp_path / "spool_fail",
            spill_write_timeout_s=0.2,
        ),
    )
    await fail_pipeline.start()
    await fail_pipeline.enqueue(_wire_frame(1, secret="Bearer secret_fail_bearer_tok"))
    fail_summary = await fail_pipeline.finalize(termination_reason="completed", exit_code=0)
    assert fail_summary.capture_completeness == "spilled"
    assert fail_summary.dropped_events == 0
    assert fail_pipeline.spool_path is not None
    fail_text = fail_pipeline.spool_path.read_text(encoding="utf-8")
    assert "secret_fail_bearer_tok" not in fail_text


async def test_mark_incomplete_policy_records_explicit_capture_gaps() -> None:
    """mark_incomplete never silently drops; overflows emit capture_gap and mark incomplete."""
    sink = _SlowSink(delay_s=0.05)
    pipeline = CapturePipeline(
        sink,
        command=("python", "server.py"),
        config=CaptureConfig(
            backpressure_policy="mark_incomplete",
            max_queue_events=1,
            drain_timeout_s=5.0,
        ),
    )
    await pipeline.start()

    for idx in range(1, 15):
        await pipeline.enqueue(_wire_frame(idx))

    summary = await pipeline.finalize(termination_reason="completed", exit_code=0)
    assert summary.capture_completeness == "incomplete"
    assert summary.dropped_events > 0
    assert summary.gap_count > 0

    gap_events = [evt for evt in sink.events if evt.kind == "capture_gap"]
    assert len(gap_events) >= 1
    assert isinstance(gap_events[0].payload, CaptureGapPayload)
    assert gap_events[0].payload.dropped_count >= 1


async def test_failing_sink_under_block_policy_marks_incomplete_explicitly() -> None:
    """A failing primary sink under block never falsely claims complete capture."""
    sink = _FailingSink(fail_on_emit=True)
    pipeline = CapturePipeline(
        sink,
        command=("python", "server.py"),
        config=CaptureConfig(backpressure_policy="block"),
    )
    await pipeline.start()
    await pipeline.enqueue(_wire_frame(1))
    summary = await pipeline.finalize(termination_reason="completed", exit_code=0)

    assert pipeline.sink_error is not None
    assert summary.capture_completeness == "incomplete"
    assert summary.dropped_events >= 1


def test_recovery_spool_refuses_unredacted_event_under_standard_mode(tmp_path: Path) -> None:
    """RecoverySpool refuses events whose redaction summary violates active policy."""
    spool = RecoverySpool(tmp_path / "test.ndjson.spool")
    unredacted_evt = ExecutionEvent(
        execution_id=new_execution_id(),
        sequence=1,
        timestamp=datetime.now(UTC),
        monotonic_time_ns=100,
        direction="proxy",
        kind="execution_started",
        redaction=RedactionSummary(
            mode="explicit_unredacted",
            payload_mode="full_unredacted",
            applied=False,
        ),
        payload=ExecutionStartedPayload(
            command=("server.py",),
            redaction_mode="standard",
            backpressure_policy="spill",
        ),
    )
    with pytest.raises(ValueError, match="Refusing to write unredacted event"):
        spool.write_events([unredacted_evt])
    spool.close()
    assert isinstance(InMemoryCaptureSink().events, list)
