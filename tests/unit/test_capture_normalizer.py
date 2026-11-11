"""Unit tests for AERLOG EventNormalizer across valid, unknown, and malformed inputs."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from aerlog.capture.normalizer import (
    EventNormalizer,
    RawFrameTooLargeInput,
    RawIncompleteFrameInput,
    RawProcessExitedInput,
    RawStderrLineInput,
    RawWireFrameInput,
)
from aerlog.capture.redaction import REDACTED_MARKER, RedactionConfig
from aerlog.events import (
    CaptureWarningPayload,
    FrameTooLargePayload,
    IncompleteTrailingFramePayload,
    JsonRpcNotificationPayload,
    JsonRpcRequestPayload,
    JsonRpcResponsePayload,
    JsonRpcUnknownObjectPayload,
    MalformedJsonFramePayload,
    MalformedUtf8FramePayload,
    NonObjectJsonFramePayload,
    ProcessStderrPayload,
    new_execution_id,
)


def test_normalizer_handles_mcp_versions_unknown_methods_extra_fields_and_redaction() -> None:
    """Normalizer preserves unknown methods/fields while redacting secrets pre-persistence."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 16, 40, 0, tzinfo=UTC)
    normalizer = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("server.py", "--api-key", "supersecret"),
        env_overrides={"API_KEY": "sk-1234567890abcd", "MODE": "test"},
    )

    events = normalizer.start_execution()
    assert len(events) == 1
    assert events[0].kind == "execution_started"

    req_obj = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "vendor.custom/exec",
        "params": {
            "token": "Bearer secret_bearer_token_value",
            "_meta": {
                "progressToken": "prog-1",
                "mcpProtocolVersion": "2026-07-28",
                "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            },
        },
        "customHeader": "preserve-me",
    }
    req_frame = (json.dumps(req_obj) + "\r\n").encode("utf-8")
    req_events = normalizer.normalize(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=2_000,
            direction="client_to_server",
            raw_frame=req_frame,
        )
    )
    assert len(req_events) == 1
    req_evt = req_events[0]
    assert req_evt.sequence == 2
    assert req_evt.wire is not None
    assert req_evt.wire.line_ending == "crlf"
    assert isinstance(req_evt.payload, JsonRpcRequestPayload)
    assert req_evt.payload.method == "vendor.custom/exec"
    assert req_evt.payload.extra_fields == {"customHeader": "preserve-me"}
    assert req_evt.payload.params["token"] == REDACTED_MARKER
    assert req_evt.payload.params["_meta"]["progressToken"] == "prog-1"
    assert req_evt.derived is not None
    assert req_evt.derived.otel_attributes["mcp.protocol.version"] == "2026-07-28"

    resp_frame = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"access_token": "secret999", "data": "ok"},
                "xRespField": 42,
            }
        )
        + "\n"
    ).encode("utf-8")
    resp_events = normalizer.normalize(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=3_500,
            direction="server_to_client",
            raw_frame=resp_frame,
        )
    )
    assert len(resp_events) == 1
    resp_evt = resp_events[0]
    assert isinstance(resp_evt.payload, JsonRpcResponsePayload)
    assert resp_evt.payload.result["access_token"] == REDACTED_MARKER
    assert resp_evt.payload.result["data"] == "ok"
    assert resp_evt.payload.extra_fields == {"xRespField": 42}
    assert resp_evt.correlation is not None
    assert resp_evt.correlation.status == "matched"
    assert resp_evt.correlation.latency_ns == 1_500

    # Unknown JSON object without method/result/error and notification
    unknown_obj_events = normalizer.normalize(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=4_000,
            direction="server_to_client",
            raw_frame=b'{"custom": "val", "password": "pw"}\n',
        )
    )
    assert isinstance(unknown_obj_events[0].payload, JsonRpcUnknownObjectPayload)
    assert unknown_obj_events[0].payload.body == {"custom": "val", "password": REDACTED_MARKER}

    notif_events = normalizer.normalize(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=4_500,
            direction="server_to_client",
            raw_frame=b'{"jsonrpc":"2.0","method":"notifications/custom"}\n',
        )
    )
    assert isinstance(notif_events[0].payload, JsonRpcNotificationPayload)

    finished_evt, summary = normalizer.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=5_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    assert finished_evt.sequence == summary.total_events
    assert summary.capture_completeness == "complete"
    assert summary.observed_mcp_protocol_versions == ("2026-07-28",)
    assert summary.observed_trace_ids == ("4bf92f3577b34da6a3ce929d0e0e4736",)


def test_normalizer_handles_malformed_non_object_incomplete_oversized_and_late_frames() -> None:
    """Malformed UTF-8, bad JSON, batch arrays, incomplete EOF, oversized, and stderr serialize."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 16, 45, 0, tzinfo=UTC)
    normalizer = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=100,
        command=("server.py",),
    )
    normalizer.start_execution()

    # 1. Malformed UTF-8 with embedded secret must not leak secret in lossy preview
    bad_utf8 = normalizer.normalize(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=200,
            direction="client_to_server",
            raw_frame=b"\xffAuthorization: Bearer supersecret_utf8_tok\n",
        )
    )
    assert isinstance(bad_utf8[0].payload, MalformedUtf8FramePayload)
    assert bad_utf8[0].payload.raw_bytes_b64 is None
    assert "supersecret_utf8_tok" not in (bad_utf8[0].payload.redacted_lossy_text or "")
    assert isinstance(bad_utf8[1].payload, CaptureWarningPayload)
    assert bad_utf8[1].payload.code == "malformed_utf8_frame"

    # 2. Malformed JSON with API key redacted
    bad_json = normalizer.normalize(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=300,
            direction="client_to_server",
            raw_frame=b'{broken "api_key": "sk-secret1234567890"\n',
        )
    )
    assert isinstance(bad_json[0].payload, MalformedJsonFramePayload)
    assert "sk-secret1234567890" not in (bad_json[0].payload.text or "")
    assert isinstance(bad_json[1].payload, CaptureWarningPayload)
    assert bad_json[1].payload.code == "malformed_json_frame"

    # 3. Non-object JSON batch array redacts inner secrets
    batch_arr = normalizer.normalize(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=400,
            direction="client_to_server",
            raw_frame=b'[{"jsonrpc":"2.0","id":1,"method":"m","params":{"secret":"top"}}]\n',
        )
    )
    assert isinstance(batch_arr[0].payload, NonObjectJsonFramePayload)
    assert batch_arr[0].payload.is_jsonrpc_batch_candidate is True
    assert batch_arr[0].payload.value[0]["params"]["secret"] == REDACTED_MARKER

    # 4. Incomplete EOF frame
    incomplete = normalizer.normalize(
        RawIncompleteFrameInput(
            timestamp=t0,
            monotonic_time_ns=500,
            direction="server_to_client",
            trailing_bytes=b'{"partial": "Bearer secret_trailing_tok"',
        )
    )
    assert isinstance(incomplete[0].payload, IncompleteTrailingFramePayload)
    assert "secret_trailing_tok" not in (incomplete[0].payload.text or "")
    assert isinstance(incomplete[1].payload, CaptureWarningPayload)
    assert incomplete[1].payload.code == "incomplete_trailing_frame"

    # 5. Oversized frame metadata only
    oversized = normalizer.normalize(
        RawFrameTooLargeInput(
            timestamp=t0,
            monotonic_time_ns=600,
            direction="client_to_server",
            observed_bytes=20_000_000,
            max_frame_bytes=16 * 1024 * 1024,
        )
    )
    assert isinstance(oversized[0].payload, FrameTooLargePayload)
    assert oversized[0].payload.observed_bytes == 20_000_000

    # 6. Stderr line redaction
    stderr_evts = normalizer.normalize(
        RawStderrLineInput(
            timestamp=t0,
            monotonic_time_ns=700,
            raw_line=b"stderr token=ghp_1234567890abcdef",
        )
    )
    assert isinstance(stderr_evts[0].payload, ProcessStderrPayload)
    assert "ghp_1234567890abcdef" not in (stderr_evts[0].payload.text or "")

    # 7. Process exited then late post-exit frame
    assert (
        normalizer.normalize(
            RawProcessExitedInput(timestamp=t0, monotonic_time_ns=800, returncode=0)
        )
        == []
    )
    late = normalizer.normalize(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=900,
            direction="server_to_client",
            raw_frame=b'{"jsonrpc":"2.0","method":"notifications/late"}\n',
        )
    )
    assert late[0].derived is not None
    assert "post_exit_frame" in late[0].derived.anomaly_flags
    assert isinstance(late[1].payload, CaptureWarningPayload)
    assert late[1].payload.code == "post_exit_frame"


def test_normalizer_degrades_safely_when_redactor_fails_and_warns_unredacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Redaction error degrades the event & execution without raising; explicit_unredacted warns."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 16, 50, 0, tzinfo=UTC)
    normalizer = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=100,
        command=("server.py",),
    )
    normalizer.start_execution()

    def _fail(_self: object, _value: object) -> tuple[str, int]:
        raise RuntimeError("boom")

    monkeypatch.setattr(normalizer.redactor, "_redact_string_impl", lambda _x: _fail(None, _x))

    evts = normalizer.normalize(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=200,
            direction="client_to_server",
            raw_frame=b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"secret"}}\n',
        )
    )
    assert evts[0].degraded is True
    assert evts[0].redaction.degraded is True
    assert isinstance(evts[0].payload, JsonRpcRequestPayload)
    assert evts[0].payload.params is None
    assert isinstance(evts[1].payload, CaptureWarningPayload)
    assert evts[1].payload.code == "redaction_failed"

    _, summary = normalizer.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=300,
        termination_reason="completed",
        exit_code=0,
    )
    assert summary.capture_completeness == "degraded"
    assert summary.degraded_events >= 1

    with pytest.warns(UserWarning, match="explicit_unredacted"):
        unredacted_norm = EventNormalizer(
            execution_id=new_execution_id(),
            started_at=t0,
            monotonic_start_ns=100,
            command=("server.py",),
            redaction_config=RedactionConfig(mode="explicit_unredacted"),
        )
    started = unredacted_norm.start_execution()
    assert len(started) == 2
    assert isinstance(started[1].payload, CaptureWarningPayload)
    assert started[1].payload.code == "unredacted_capture_enabled"
