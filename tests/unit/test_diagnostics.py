"""Unit tests for Phase 7 deterministic, evidence-linked diagnostics."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aerlog.analysis.diagnostics import (
    DiagnosticOptions,
    DiagnosticReport,
    diagnose_events,
    diagnose_jsonl_result,
    diagnostic_timeline_context_check,
)
from aerlog.capture.normalizer import (
    EventNormalizer,
    RawCaptureWarningInput,
    RawChildShutdownEscalateInput,
    RawFrameTooLargeInput,
    RawIncompleteFrameInput,
    RawProcessExitedInput,
    RawProxySignalInput,
    RawStderrLineInput,
    RawTransportErrorInput,
    RawWireFrameInput,
)
from aerlog.capture.redaction import RedactionConfig
from aerlog.config import AerlogConfig, load_config
from aerlog.events.ids import new_execution_id
from aerlog.events.models import ExecutionEvent
from aerlog.events.types import WireDirection
from aerlog.storage.event_log import CorruptRecordReport, IndexedLogEvent, JsonlReadResult

_FORBIDDEN_DEFERRED_CODES = frozenset(
    {
        "REPEATED_SIMILAR_CALLS",
        "NO_PROGRESS_LOOP",
        "CANCEL_LATE_RESPONSE",
    }
)


def _wire_bytes(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def _wire_events(
    norm: EventNormalizer,
    *,
    ts: datetime,
    mono_ns: int,
    direction: WireDirection,
    obj: dict[str, Any],
) -> list[ExecutionEvent]:
    return norm.normalize(
        RawWireFrameInput(
            timestamp=ts,
            monotonic_time_ns=mono_ns,
            direction=direction,
            raw_frame=_wire_bytes(obj),
        )
    )


def _assert_report_invariants(report: DiagnosticReport, events: list[ExecutionEvent]) -> None:
    """Verify every finding cites valid evidence and separates inference from root cause."""
    tl_report_timeline = None
    if events:
        from aerlog.analysis.timeline import reconstruct_timeline_from_events

        tl_report_timeline = reconstruct_timeline_from_events(
            events, execution_id=report.execution_id
        )

    for item in report.diagnostics:
        assert item.code not in _FORBIDDEN_DEFERRED_CODES
        assert len(item.evidence) >= 1
        assert len(item.cannot_be_concluded) >= 1
        assert len(item.additional_evidence_needed) >= 1
        assert len(item.reasonable_conclusions) >= 1
        assert len(item.next_steps) >= 1
        if tl_report_timeline is not None and not report.has_corruptions:
            assert diagnostic_timeline_context_check(item, tl_report_timeline)


def test_diagnostics_healthy_execution_zero_findings_and_config_defaults(tmp_path: Path) -> None:
    """Healthy varied/paginated calls, slow clean tool, benign stderr, old TOML -> 0 findings."""
    cfg_default = AerlogConfig()
    assert cfg_default.diagnostics.request_timeout_ms is None
    assert cfg_default.diagnostics.repeated_call_threshold == 3

    legacy_toml = tmp_path / "legacy.toml"
    legacy_toml.write_text('log_level = "INFO"\n', encoding="utf-8")
    loaded_legacy = load_config(legacy_toml)
    assert loaded_legacy.diagnostics.request_timeout_ms is None

    diag_toml = tmp_path / "diag.toml"
    diag_toml.write_text(
        "[diagnostics]\nrequest_timeout_ms = 1500\nrepeated_call_threshold = 4\n",
        encoding="utf-8",
    )
    loaded_diag = load_config(diag_toml)
    assert loaded_diag.diagnostics.request_timeout_ms == 1500
    assert loaded_diag.diagnostics.repeated_call_threshold == 4

    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 21, 0, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000_000,
        command=("python", "healthy_srv.py"),
    )
    events: list[ExecutionEvent] = list(norm.start_execution())
    events.extend(
        norm.normalize(
            RawStderrLineInput(
                timestamp=t0 + timedelta(milliseconds=1),
                monotonic_time_ns=1_100_000,
                raw_line=b"INFO: server ready on stdio\n",
            )
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=2),
            mono_ns=2_000_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=3),
            mono_ns=3_000_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=4),
            mono_ns=4_000_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
    )
    # Paginated tools/list across distinct cursors + slow (2.5s) legitimate tool call.
    for req_id, cursor in ((2, "p1"), (3, "p2"), (4, "p3")):
        events.extend(
            _wire_events(
                norm,
                ts=t0 + timedelta(milliseconds=req_id * 5),
                mono_ns=req_id * 10_000_000,
                direction="client_to_server",
                obj={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/list",
                    "params": {"cursor": cursor},
                },
            )
        )
        events.extend(
            _wire_events(
                norm,
                ts=t0 + timedelta(milliseconds=req_id * 5 + 1),
                mono_ns=req_id * 10_000_000 + 200_000,
                direction="server_to_client",
                obj={"jsonrpc": "2.0", "id": req_id, "result": {"tools": []}},
            )
        )

    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=30),
            mono_ns=50_000_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "slow_report", "arguments": {"day": "2026-11-11"}},
            },
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(seconds=2, milliseconds=530),
            mono_ns=2_550_000_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 5, "result": {"content": [], "isError": False}},
        )
    )
    events.extend(
        norm.normalize(
            RawProcessExitedInput(
                timestamp=t0 + timedelta(seconds=2, milliseconds=540),
                monotonic_time_ns=2_560_000_000,
                returncode=0,
            )
        )
    )
    fin_ev, summary = norm.finalize_execution(
        ended_at=t0 + timedelta(seconds=2, milliseconds=550),
        monotonic_end_ns=2_570_000_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin_ev)

    report = diagnose_events(events, execution_id=exec_id, summary=summary)
    assert report.total_diagnostics == 0
    assert report.request_timeout_ms is None
    assert all(count == 0 for count in report.counts_by_severity.values())


def test_diagnostics_protocol_tool_errors_and_invalid_params() -> None:
    """Detect JSON-RPC errors, -32602 invalid params, isError=True; defer Variant B schema check."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 21, 5, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    events: list[ExecutionEvent] = list(norm.start_execution())

    # Publish tools/list with required schema key, then send a tools/call omitting it (ok reply):
    # Variant B client-side schema check is DEFERRED and must NOT fire.
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=2_500,
            direction="server_to_client",
            obj={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": "strict_tool",
                            "inputSchema": {
                                "type": "object",
                                "required": ["must_have"],
                                "properties": {"must_have": {"type": "string"}},
                            },
                        }
                    ]
                },
            },
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=3_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "strict_tool", "arguments": {}},
            },
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=3_500,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 2, "result": {"content": []}},
        )
    )

    # Explicit -32602 invalid params error
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=4_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "strict_tool", "arguments": {"bad": 1}},
            },
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=4_500,
            direction="server_to_client",
            obj={
                "jsonrpc": "2.0",
                "id": 3,
                "error": {"code": -32602, "message": "Missing required parameter 'must_have'"},
            },
        )
    )

    # Explicit JSON-RPC server error (-32603)
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=5_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "x://y"}},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=5_500,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 4, "error": {"code": -32603, "message": "Internal err"}},
        )
    )

    # MCP tool execution error (isError=True)
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=6_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "db_query", "arguments": {"sql": "SELECT 1"}},
            },
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=6_500,
            direction="server_to_client",
            obj={
                "jsonrpc": "2.0",
                "id": 5,
                "result": {"isError": True, "content": [{"type": "text", "text": "Query denied"}]},
            },
        )
    )

    # JSON-RPC 2.0 valid null ID on -32600 error should NOT fire INVALID_JSONRPC_ID.
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=7_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid req"}},
        )
    )

    fin_ev, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=8_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin_ev)

    report = diagnose_events(events, execution_id=exec_id, summary=summary)
    _assert_report_invariants(report, events)

    codes = [item.code for item in report.diagnostics]
    assert "INVALID_ARGUMENTS_OBSERVED" in codes
    assert "JSONRPC_ERROR_RESPONSE" in codes
    assert "MCP_TOOL_EXECUTION_ERROR" in codes
    assert "INVALID_JSONRPC_ID" not in codes
    # Exact count: 1 invalid -32602 + 2 JSONRPC errors (-32603, -32600) + 1 MCP tool error = 4.
    assert codes.count("INVALID_ARGUMENTS_OBSERVED") == 1
    assert codes.count("JSONRPC_ERROR_RESPONSE") == 2
    assert codes.count("MCP_TOOL_EXECUTION_ERROR") == 1


def test_diagnostics_missing_responses_timeouts_and_cancellations() -> None:
    """Missing responses, wire timeouts, configured threshold, capture timeout, and cancels."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 21, 10, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000_000, command=("srv.py",)
    )
    events: list[ExecutionEvent] = list(norm.start_execution())

    # 1. Slow completed span (80ms) to test configured timeout vs None default.
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=10_000_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "slow"}},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=80),
            mono_ns=90_000_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
        )
    )

    # 2. Wire -32001 timeout error.
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=90),
            mono_ns=100_000_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "hang"}},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=95),
            mono_ns=105_000_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 2, "error": {"code": -32001, "message": "Timed out"}},
        )
    )

    # 3. Cooperative cancellation before response -> info diagnostic only.
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=100),
            mono_ns=110_000_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "long"}},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=105),
            mono_ns=115_000_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 3, "reason": "User cancelled"},
            },
        )
    )

    # 4. Cancellation targeting unknown ID + timeout cancellation reason.
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=110),
            mono_ns=120_000_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 999, "reason": "Timed out waiting"},
            },
        )
    )

    # 5. Cancellation with late response (timeline preserves, NO CANCEL_LATE_RESPONSE diagnostic).
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=115),
            mono_ns=125_000_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "race"}},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=116),
            mono_ns=126_000_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 4},
            },
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=117),
            mono_ns=127_000_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 4, "result": {"late": True}},
        )
    )

    # 6. True missing response (never answered, never cancelled).
    events.extend(
        _wire_events(
            norm,
            ts=t0 + timedelta(milliseconds=120),
            mono_ns=130_000_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "lost"}},
        )
    )

    # 7. Capture timeout warning (drain / spill stalled timeout).
    events.extend(
        norm.normalize(
            RawCaptureWarningInput(
                timestamp=t0 + timedelta(milliseconds=220),
                monotonic_time_ns=230_000_000,
                code="capture_spill_activated",
                message="Primary sink exceeded 0.5s write budget",
                details={"reason": "primary_sink_stalled"},
            )
        )
    )

    fin_ev, summary = norm.finalize_execution(
        ended_at=t0 + timedelta(milliseconds=250),
        monotonic_end_ns=260_000_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
        spilled=True,
    )
    events.append(fin_ev)

    # Without configured request_timeout_ms: zero CONFIGURED_REQUEST_TIMEOUT_EXCEEDED.
    no_cfg = diagnose_events(events, execution_id=exec_id, summary=summary)
    _assert_report_invariants(no_cfg, events)
    no_cfg_codes = [d.code for d in no_cfg.diagnostics]
    assert "CONFIGURED_REQUEST_TIMEOUT_EXCEEDED" not in no_cfg_codes
    assert "REQUEST_WITHOUT_RESPONSE" in no_cfg_codes
    assert no_cfg_codes.count("OBSERVED_REQUEST_TIMEOUT") == 2  # -32001 + cancel timeout reason
    assert "CAPTURE_TIMEOUT_OBSERVED" in no_cfg_codes
    assert "CANCEL_TARGET_MISSING" in no_cfg_codes
    cancel_items = [d for d in no_cfg.diagnostics if d.code == "CANCEL_REQUESTED_NO_RESPONSE"]
    assert len(cancel_items) == 1
    assert cancel_items[0].severity == "info"

    # With explicit request_timeout_ms=50: slow (80ms) + unanswered (150ms+) trigger threshold rule.
    with_cfg = diagnose_events(
        events,
        execution_id=exec_id,
        summary=summary,
        options=DiagnosticOptions(request_timeout_ms=50),
    )
    _assert_report_invariants(with_cfg, events)
    cfg_items = [d for d in with_cfg.diagnostics if d.code == "CONFIGURED_REQUEST_TIMEOUT_EXCEEDED"]
    assert len(cfg_items) >= 2
    assert all(d.certainty == "configured_threshold" for d in cfg_items)


def test_diagnostics_correlation_anomalies() -> None:
    """Detect duplicate in-flight IDs, orphaned responses, duplicate responses, and invalid IDs."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 21, 15, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    events: list[ExecutionEvent] = list(norm.start_execution())

    # Normal req/resp followed by duplicate response
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 10, "method": "tools/list"},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=2_500,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 10, "result": {"tools": []}},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=2_700,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 10, "result": {"tools": []}},
        )
    )
    # Duplicate in-flight ID 20
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=3_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 20, "method": "ping"},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=3_200,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 20, "method": "ping"},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=3_500,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 20, "result": {}},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=3_600,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 20, "result": {}},
        )
    )
    # Orphan response (no request 777) & invalid response ID (bool true)
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=4_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 777, "result": {}},
        )
    )
    events.extend(
        _wire_events(
            norm,
            ts=t0,
            mono_ns=4_200,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": True, "result": {}},
        )
    )

    fin_ev, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=5_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin_ev)

    report = diagnose_events(events, execution_id=exec_id, summary=summary)
    _assert_report_invariants(report, events)
    codes = {d.code for d in report.diagnostics}
    assert {
        "DUPLICATE_RESPONSE",
        "AMBIGUOUS_CORRELATION_ID",
        "ORPHANED_RESPONSE",
        "INVALID_JSONRPC_ID",
    }.issubset(codes)


def test_diagnostics_process_exits_signals_transport_and_wire_anomalies() -> None:
    """Cover non-zero exit, signals, escalation, transport errors, malformed/oversized/EOF."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 21, 20, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    events: list[ExecutionEvent] = list(norm.start_execution())

    events.extend(
        norm.normalize(
            RawStderrLineInput(
                timestamp=t0,
                monotonic_time_ns=2_000,
                raw_line=b"FATAL: password=raw-stderr-secret crash stack\n",
            )
        )
    )
    events.extend(
        norm.normalize(
            RawWireFrameInput(
                timestamp=t0,
                monotonic_time_ns=2_200,
                direction="server_to_client",
                raw_frame=b"{not-valid-json\n",
            )
        )
    )
    events.extend(
        norm.normalize(
            RawFrameTooLargeInput(
                timestamp=t0,
                monotonic_time_ns=2_400,
                direction="server_to_client",
                observed_bytes=20_000_000,
                max_frame_bytes=16_777_216,
            )
        )
    )
    events.extend(
        norm.normalize(
            RawIncompleteFrameInput(
                timestamp=t0,
                monotonic_time_ns=2_600,
                direction="server_to_client",
                trailing_bytes=b'{"partial":',
            )
        )
    )
    events.extend(
        norm.normalize(
            RawTransportErrorInput(
                timestamp=t0,
                monotonic_time_ns=2_800,
                stream_direction="server_to_client",
                reason="broken_pipe",
                error="BrokenPipeError: pipe closed",
            )
        )
    )
    events.extend(
        norm.normalize(
            RawProxySignalInput(
                timestamp=t0,
                monotonic_time_ns=3_000,
                signal_name="SIGTERM",
            )
        )
    )
    events.extend(
        norm.normalize(
            RawChildShutdownEscalateInput(
                timestamp=t0,
                monotonic_time_ns=3_200,
                signal_name="SIGKILL",
                pgid=43210,
            )
        )
    )
    events.extend(
        norm.normalize(
            RawProcessExitedInput(
                timestamp=t0,
                monotonic_time_ns=3_400,
                returncode=-9,
            )
        )
    )
    fin_ev, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=3_600,
        termination_reason="signal",
        exit_code=143,
        returncode=-9,
    )
    events.append(fin_ev)

    report = diagnose_events(events, execution_id=exec_id, summary=summary)
    _assert_report_invariants(report, events)
    codes = {d.code for d in report.diagnostics}
    assert {
        "MALFORMED_WIRE_FRAME",
        "OVERSIZED_WIRE_FRAME",
        "INCOMPLETE_TRAILING_FRAME",
        "TRANSPORT_FAILURE_OBSERVED",
        "SIGNAL_INTERRUPTED_EXECUTION",
        "CHILD_SHUTDOWN_ESCALATED",
        "UNEXPECTED_PROCESS_EXIT",
    }.issubset(codes)
    # Secrets in stderr must NEVER leak into diagnostic report JSON!
    assert "raw-stderr-secret" not in report.model_dump_json()

    # Check negative returncode without separate ProxySignalPayload also emits signal warning.
    exec_sig = new_execution_id()
    norm_sig = EventNormalizer(
        execution_id=exec_sig, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    sig_events = list(norm_sig.start_execution())
    sig_events.extend(
        norm_sig.normalize(
            RawProcessExitedInput(timestamp=t0, monotonic_time_ns=2_000, returncode=-11)
        )
    )
    sig_fin, sig_sum = norm_sig.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=3_000,
        termination_reason="server_exited",
        exit_code=1,
        returncode=-11,
    )
    sig_events.append(sig_fin)
    sig_rep = diagnose_events(sig_events, execution_id=exec_sig, summary=sig_sum)
    assert {d.code for d in sig_rep.diagnostics} >= {
        "UNEXPECTED_PROCESS_EXIT",
        "SIGNAL_INTERRUPTED_EXECUTION",
    }

    # Graceful SIGINT with clean returncode=0 and no unanswered requests -> info only.
    exec_int = new_execution_id()
    norm_int = EventNormalizer(
        execution_id=exec_int, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    int_events = list(norm_int.start_execution())
    int_events.extend(
        norm_int.normalize(
            RawProxySignalInput(timestamp=t0, monotonic_time_ns=2_000, signal_name="SIGINT")
        )
    )
    int_fin, int_sum = norm_int.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=3_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    int_events.append(int_fin)
    int_rep = diagnose_events(int_events, execution_id=exec_int, summary=int_sum)
    assert len(int_rep.diagnostics) == 1
    assert int_rep.diagnostics[0].code == "SIGNAL_INTERRUPTED_EXECUTION"
    assert int_rep.diagnostics[0].severity == "info"


def test_diagnostics_repeated_identical_calls_and_exclusions() -> None:
    """Identical calls trigger only at configured threshold; strict_hash_only/varied excluded."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 21, 25, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    events: list[ExecutionEvent] = list(norm.start_execution())

    # 3 identical calls (even with rotating _meta.progressToken) -> triggers at threshold=3.
    for idx in (1, 2, 3):
        events.extend(
            _wire_events(
                norm,
                ts=t0,
                mono_ns=1_000 + idx * 500,
                direction="client_to_server",
                obj={
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "tools/call",
                    "params": {
                        "name": "lookup",
                        "arguments": {"id": "same-secret-key-token-123"},
                        "_meta": {"progressToken": f"tok-{idx}"},
                    },
                },
            )
        )
        events.extend(
            _wire_events(
                norm,
                ts=t0,
                mono_ns=1_000 + idx * 500 + 200,
                direction="server_to_client",
                obj={"jsonrpc": "2.0", "id": idx, "result": {"ok": True}},
            )
        )

    # 3 near-duplicate varied calls -> must NOT trigger REPEATED_IDENTICAL_CALLS or deferred.
    for idx, q in ((4, "alpha"), (5, "beta"), (6, "gamma")):
        events.extend(
            _wire_events(
                norm,
                ts=t0,
                mono_ns=1_000 + idx * 500,
                direction="client_to_server",
                obj={
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "tools/call",
                    "params": {"name": "search", "arguments": {"query": q}},
                },
            )
        )
        events.extend(
            _wire_events(
                norm,
                ts=t0,
                mono_ns=1_000 + idx * 500 + 200,
                direction="server_to_client",
                obj={"jsonrpc": "2.0", "id": idx, "result": {"hits": [q]}},
            )
        )

    fin_ev, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=20_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin_ev)

    rep3 = diagnose_events(
        events,
        execution_id=exec_id,
        summary=summary,
        options=DiagnosticOptions(repeated_call_threshold=3),
    )
    _assert_report_invariants(rep3, events)
    rep_items = [d for d in rep3.diagnostics if d.code == "REPEATED_IDENTICAL_CALLS"]
    assert len(rep_items) == 1
    assert rep_items[0].observed_values["repeat_count"] == 3
    assert "same-secret-key-token-123" not in rep3.model_dump_json()

    # Raising threshold to 4 suppresses the 3x identical calls.
    rep4 = diagnose_events(
        events,
        execution_id=exec_id,
        summary=summary,
        options=DiagnosticOptions(repeated_call_threshold=4),
    )
    assert rep4.total_diagnostics == 0

    # Two identical calls do NOT trigger at default threshold=3.
    exec_two = new_execution_id()
    norm_two = EventNormalizer(
        execution_id=exec_two, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    two_evs: list[ExecutionEvent] = list(norm_two.start_execution())
    for idx in (1, 2):
        two_evs.extend(
            _wire_events(
                norm_two,
                ts=t0,
                mono_ns=2_000 + idx * 100,
                direction="client_to_server",
                obj={"jsonrpc": "2.0", "id": idx, "method": "tools/list"},
            )
        )
        two_evs.extend(
            _wire_events(
                norm_two,
                ts=t0,
                mono_ns=2_000 + idx * 100 + 50,
                direction="server_to_client",
                obj={"jsonrpc": "2.0", "id": idx, "result": {"tools": []}},
            )
        )
    two_fin, two_sum = norm_two.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=5_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    two_evs.append(two_fin)
    two_rep = diagnose_events(two_evs, execution_id=exec_two, summary=two_sum)
    assert two_rep.total_diagnostics == 0

    # strict_hash_only with masked params must NOT falsely trigger REPEATED_IDENTICAL_CALLS.
    exec_strict = new_execution_id()
    norm_strict = EventNormalizer(
        execution_id=exec_strict,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("srv.py",),
        redaction_config=RedactionConfig(mode="strict_hash_only"),
    )
    s_evs: list[ExecutionEvent] = list(norm_strict.start_execution())
    for idx, val in ((1, "a"), (2, "b"), (3, "c")):
        s_evs.extend(
            _wire_events(
                norm_strict,
                ts=t0,
                mono_ns=2_000 + idx * 100,
                direction="client_to_server",
                obj={
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "tools/call",
                    "params": {"name": "lookup", "arguments": {"secret": val}},
                },
            )
        )
        s_evs.extend(
            _wire_events(
                norm_strict,
                ts=t0,
                mono_ns=2_000 + idx * 100 + 50,
                direction="server_to_client",
                obj={"jsonrpc": "2.0", "id": idx, "result": {"ok": True}},
            )
        )
    s_fin, s_sum = norm_strict.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=5_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    s_evs.append(s_fin)
    strict_rep = diagnose_events(s_evs, execution_id=exec_strict, summary=s_sum)
    assert all(d.code != "REPEATED_IDENTICAL_CALLS" for d in strict_rep.diagnostics)


def test_diagnostics_integrity_determinism_and_evidence_invariants() -> None:
    """Cover corrupt JSONL markers, capture gaps, incomplete shutdown, and byte determinism."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 21, 30, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    evs: list[ExecutionEvent] = list(norm.start_execution())
    evs.append(
        norm.build_gap_event(
            timestamp=t0,
            monotonic_time_ns=2_000,
            dropped_count=4,
            reason="capture_queue_full",
            first_gap_monotonic_ns=1_500,
            last_gap_monotonic_ns=2_000,
        )
    )
    indexed = tuple(
        IndexedLogEvent(event=ev, line_number=idx + 1, byte_offset=idx * 200, byte_length=180)
        for idx, ev in enumerate(evs)
    )
    read_res = JsonlReadResult(
        execution_id=exec_id,
        header=norm.build_header(),
        summary=None,
        manifest=None,
        events=indexed,
        corruptions=(
            CorruptRecordReport(
                execution_id=exec_id,
                line_number=len(evs) + 1,
                byte_offset=400,
                byte_length=28,
                issue_kind="invalid_json",
                excerpt_sha256="deadbeef" * 8,
                details="Unterminated JSON record at EOF",
            ),
        ),
        byte_size=428,
        line_count=len(evs) + 1,
        last_valid_sequence=len(evs),
        events_file_sha256="abcd" * 16,
        unclean_shutdown=True,
    )

    rep1 = diagnose_jsonl_result(read_res, diverged_index=True)
    rep2 = diagnose_jsonl_result(read_res, diverged_index=True)
    assert rep1.model_dump_json() == rep2.model_dump_json()

    _assert_report_invariants(rep1, evs)
    codes = {d.code for d in rep1.diagnostics}
    assert {
        "CORRUPT_RECORDING_DETECTED",
        "CAPTURE_GAP_DETECTED",
        "INCOMPLETE_CAPTURE_RECORDING",
    }.issubset(codes)
    corrupt_item = next(d for d in rep1.diagnostics if d.code == "CORRUPT_RECORDING_DETECTED")
    assert corrupt_item.evidence[0].source_kind == "timeline_corruption_marker"
    assert corrupt_item.evidence[0].line_number == len(evs) + 1
