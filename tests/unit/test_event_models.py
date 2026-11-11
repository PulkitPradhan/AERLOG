"""Unit tests for AERLOG event models, IDs, trace parsing, and schema versioning."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aerlog.events import (
    EVENT_SCHEMA_VERSION,
    CaptureGapPayload,
    CaptureWarningPayload,
    CorrelationInfo,
    DerivedMetadata,
    ExecutionEvent,
    ExecutionFinishedPayload,
    ExecutionHeader,
    ExecutionStartedPayload,
    ExecutionSummary,
    JsonRpcErrorPayload,
    JsonRpcNotificationPayload,
    JsonRpcRequestPayload,
    JsonRpcResponsePayload,
    JsonRpcUnknownObjectPayload,
    MalformedJsonFramePayload,
    MalformedUtf8FramePayload,
    RedactionSummary,
    TraceContext,
    WireFrameInfo,
    classify_jsonrpc_id,
    extract_observed_trace_from_params,
    new_event_id,
    new_execution_id,
    parse_w3c_traceparent,
)


def test_uuidv4_ids_are_unique_standard_uuid4() -> None:
    """execution_id and event_id use standard uuid.uuid4() and are unique."""
    exec_ids = [new_execution_id() for _ in range(25)]
    event_ids = [new_event_id() for _ in range(100)]

    assert len(set(exec_ids)) == 25
    assert len(set(event_ids)) == 100
    assert all(uuid.UUID(val).version == 4 for val in exec_ids)
    assert all(uuid.UUID(val).version == 4 for val in event_ids)


def test_classify_jsonrpc_id_preserves_exact_types() -> None:
    """1, '1', True, 1.5, None, list, dict, and missing are strictly distinct."""
    assert classify_jsonrpc_id({}) == ("missing", None)
    assert classify_jsonrpc_id({"id": None}) == ("null", None)
    assert classify_jsonrpc_id({"id": True}) == ("bool", True)
    assert classify_jsonrpc_id({"id": False}) == ("bool", False)
    assert classify_jsonrpc_id({"id": 1}) == ("int", 1)
    assert classify_jsonrpc_id({"id": "1"}) == ("str", "1")
    assert classify_jsonrpc_id({"id": 1.5}) == ("float", 1.5)
    assert classify_jsonrpc_id({"id": [1, 2]}) == ("array", [1, 2])
    assert classify_jsonrpc_id({"id": {"k": "v"}}) == ("object", {"k": "v"})


def test_event_schema_json_round_trip_preserves_unknown_methods_and_fields() -> None:
    """ExecutionEvent round-trips via JSON and retains arbitrary unknown fields."""
    exec_id = new_execution_id()
    now = datetime(2026, 11, 11, 16, 30, 0, tzinfo=UTC)

    events = [
        ExecutionEvent(
            execution_id=exec_id,
            sequence=1,
            timestamp=now,
            monotonic_time_ns=1_000,
            direction="proxy",
            kind="execution_started",
            payload=ExecutionStartedPayload(
                command=("python", "server.py"),
                redaction_mode="standard",
                backpressure_policy="block",
            ),
        ),
        ExecutionEvent(
            execution_id=exec_id,
            sequence=2,
            timestamp=now,
            monotonic_time_ns=2_000,
            direction="client_to_server",
            kind="jsonrpc_request",
            wire=WireFrameInfo(
                byte_length=142,
                line_ending="lf",
                sha256="a" * 64,
                jsonrpc_version="2.0",
                raw_id_present=True,
                raw_id_type="str",
                is_valid_jsonrpc_id=True,
                keys=("id", "jsonrpc", "method", "params", "x_custom"),
            ),
            trace=TraceContext(
                trace_source="w3c_meta",
                observed_trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
                observed_parent_span_id="00f067aa0ba902b7",
                observed_trace_flags="01",
                observed_traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            ),
            derived=DerivedMetadata(otel_attributes={"mcp.method.name": "vendor.x/run"}),
            redaction=RedactionSummary(mode="standard", payload_mode="redacted", applied=True),
            payload=JsonRpcRequestPayload(
                method="vendor.x/run",
                id="req-42",
                id_type="str",
                has_params=True,
                params={"customArg": [1, 2], "_meta": {"traceparent": "00-..."}},
                extra_fields={"x_custom": {"nested": True}},
            ),
        ),
        ExecutionEvent(
            execution_id=exec_id,
            sequence=3,
            timestamp=now,
            monotonic_time_ns=3_500,
            direction="server_to_client",
            kind="jsonrpc_response",
            correlation=CorrelationInfo(
                status="matched",
                confidence="exact",
                basis="exact_opposite_direction_id",
                matched_request_event_id="placeholder",
                matched_request_sequence=2,
                matched_request_method="vendor.x/run",
                origin_direction="client_to_server",
                latency_ns=1_500,
            ),
            payload=JsonRpcResponsePayload(
                id="req-42",
                id_type="str",
                result={"ok": True, "vendorExtension": 99},
                extra_fields={"x_response_meta": "keep-me"},
            ),
        ),
        ExecutionEvent(
            execution_id=exec_id,
            sequence=4,
            timestamp=now,
            monotonic_time_ns=4_000,
            direction="server_to_client",
            kind="jsonrpc_error",
            payload=JsonRpcErrorPayload(
                id=None,
                id_type="null",
                error={"code": -32020, "message": "URL elicitation required", "data": {"x": 1}},
                error_code=-32020,
                error_message="URL elicitation required",
                error_data={"x": 1},
            ),
        ),
        ExecutionEvent(
            execution_id=exec_id,
            sequence=5,
            timestamp=now,
            monotonic_time_ns=5_000,
            direction="server_to_client",
            kind="jsonrpc_notification",
            payload=JsonRpcNotificationPayload(
                method="notifications/custom",
                has_params=True,
                params={"flag": True},
                extra_fields={"extraKey": 123},
            ),
        ),
        ExecutionEvent(
            execution_id=exec_id,
            sequence=6,
            timestamp=now,
            monotonic_time_ns=6_000,
            direction="client_to_server",
            kind="jsonrpc_unknown_object",
            payload=JsonRpcUnknownObjectPayload(body={"foo": "bar", "nested": [1, 2]}),
        ),
        ExecutionEvent(
            execution_id=exec_id,
            sequence=7,
            timestamp=now,
            monotonic_time_ns=7_000,
            direction="client_to_server",
            kind="malformed_json_frame",
            payload=MalformedJsonFramePayload(error="Expecting value", text="{bad"),
        ),
        ExecutionEvent(
            execution_id=exec_id,
            sequence=8,
            timestamp=now,
            monotonic_time_ns=8_000,
            direction="server_to_client",
            kind="malformed_utf8_frame",
            payload=MalformedUtf8FramePayload(error="invalid start byte", redacted_lossy_text=""),
        ),
        ExecutionEvent(
            execution_id=exec_id,
            sequence=9,
            timestamp=now,
            monotonic_time_ns=9_000,
            direction="system",
            kind="capture_warning",
            payload=CaptureWarningPayload(code="test", message="warn", details={"k": 1}),
        ),
        ExecutionEvent(
            execution_id=exec_id,
            sequence=10,
            timestamp=now,
            monotonic_time_ns=10_000,
            direction="system",
            kind="capture_gap",
            payload=CaptureGapPayload(
                dropped_count=3,
                reason="queue_overflow",
                first_gap_monotonic_ns=9_100,
                last_gap_monotonic_ns=9_900,
            ),
        ),
        ExecutionEvent(
            execution_id=exec_id,
            sequence=11,
            timestamp=now,
            monotonic_time_ns=11_000,
            direction="proxy",
            kind="execution_finished",
            payload=ExecutionFinishedPayload(
                termination_reason="completed",
                exit_code=0,
                returncode=0,
                completeness="complete",
                total_events=11,
            ),
        ),
    ]

    for original in events:
        assert original.schema_version == EVENT_SCHEMA_VERSION == "1.0.0"
        encoded = original.model_dump_json()
        decoded = ExecutionEvent.model_validate_json(encoded)
        assert decoded == original

    req_decoded = ExecutionEvent.model_validate_json(events[1].model_dump_json())
    assert isinstance(req_decoded.payload, JsonRpcRequestPayload)
    assert req_decoded.payload.method == "vendor.x/run"
    assert req_decoded.payload.extra_fields == {"x_custom": {"nested": True}}


def test_execution_header_and_summary_round_trip() -> None:
    """ExecutionHeader and ExecutionSummary preserve schema_version and metadata."""
    exec_id = new_execution_id()
    started = datetime(2026, 11, 11, 16, 0, 0, tzinfo=UTC)
    ended = datetime(2026, 11, 11, 16, 0, 5, tzinfo=UTC)

    header = ExecutionHeader(
        execution_id=exec_id,
        started_at=started,
        monotonic_start_ns=100,
        command=("python", "-m", "my_server"),
    )
    summary = ExecutionSummary(
        execution_id=exec_id,
        started_at=started,
        ended_at=ended,
        duration_ns=5_000_000_000,
        command=("python", "-m", "my_server"),
        capture_completeness="complete",
        termination_reason="completed",
        exit_code=0,
        returncode=0,
        total_events=4,
        observed_mcp_protocol_versions=("2026-07-28",),
    )

    assert header.schema_version == EVENT_SCHEMA_VERSION
    assert ExecutionHeader.model_validate_json(header.model_dump_json()) == header
    assert ExecutionSummary.model_validate_json(summary.model_dump_json()) == summary


def test_envelope_validation_rejects_mismatched_kind_or_extra_envelope_fields() -> None:
    """Envelope forbids mismatched payload kind, sequence < 1, or unknown outer fields."""
    exec_id = new_execution_id()
    now = datetime(2026, 11, 11, 16, 30, 0, tzinfo=UTC)

    with pytest.raises(ValidationError):
        ExecutionEvent(
            execution_id=exec_id,
            sequence=1,
            timestamp=now,
            monotonic_time_ns=1,
            direction="client_to_server",
            kind="jsonrpc_notification",
            payload=JsonRpcRequestPayload(id=1, id_type="int", method="tools/list"),
        )

    with pytest.raises(ValidationError):
        ExecutionEvent(
            execution_id=exec_id,
            sequence=0,
            timestamp=now,
            monotonic_time_ns=1,
            direction="system",
            kind="capture_warning",
            payload=CaptureWarningPayload(code="x", message="y"),
        )

    with pytest.raises(ValidationError):
        ExecutionEvent.model_validate(
            {
                "execution_id": exec_id,
                "sequence": 1,
                "timestamp": now.isoformat(),
                "monotonic_time_ns": 1,
                "direction": "system",
                "kind": "capture_warning",
                "unknown_envelope_key": True,
                "payload": {"kind": "capture_warning", "code": "x", "message": "y"},
            }
        )


def test_w3c_traceparent_extraction_is_read_only_and_never_fabricates() -> None:
    """Valid W3C traceparent is extracted; invalid or absent headers stay separated."""
    exec_id = new_execution_id()
    valid_tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    params = {"name": "echo", "_meta": {"traceparent": valid_tp, "tracestate": "rojo=00f067"}}
    snapshot = dict(params)

    extracted = extract_observed_trace_from_params(params, execution_id=exec_id)
    assert params == snapshot
    assert extracted.trace_source == "w3c_meta"
    assert extracted.observed_traceparent is not None
    assert extracted.observed_traceparent.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert extracted.observed_traceparent.parent_span_id == "00f067aa0ba902b7"
    assert extracted.observed_tracestate == "rojo=00f067"
    assert extracted.invalid_traceparent_present is False
    assert extracted.synthetic_execution_trace_id == uuid.UUID(exec_id).hex

    invalid_params = {"_meta": {"traceparent": "00-" + ("0" * 32) + "-00f067aa0ba902b7-01"}}
    invalid = extract_observed_trace_from_params(invalid_params, execution_id=exec_id)
    assert invalid.trace_source == "synthetic_execution"
    assert invalid.observed_traceparent is None
    assert invalid.invalid_traceparent_present is True
    assert invalid.synthetic_execution_trace_id == uuid.UUID(exec_id).hex

    assert parse_w3c_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") is None
    assert parse_w3c_traceparent(12345) is None
