"""Unit tests for request/response, cancellation, progress, and trace correlation."""

from __future__ import annotations

from aerlog.events import RequestCorrelator, new_execution_id


def test_bidirectional_same_id_and_int_vs_string_id_isolation() -> None:
    """Client/server requests and int '1' vs str '1' never collide."""
    correlator = RequestCorrelator(new_execution_id())

    correlator.process_request(
        event_id="req-c-int",
        sequence=1,
        monotonic_time_ns=1_000,
        direction="client_to_server",
        method="tools/call",
        id_type="int",
        request_id=1,
        params={
            "name": "echo",
            "_meta": {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
        },
    )
    correlator.process_request(
        event_id="req-c-str",
        sequence=2,
        monotonic_time_ns=1_200,
        direction="client_to_server",
        method="tools/list",
        id_type="str",
        request_id="1",
        params={},
    )
    correlator.process_request(
        event_id="req-s-int",
        sequence=3,
        monotonic_time_ns=1_300,
        direction="server_to_client",
        method="roots/list",
        id_type="int",
        request_id=1,
        params={},
    )

    resp_s = correlator.process_response(
        event_id="resp-s",
        sequence=4,
        monotonic_time_ns=2_300,
        direction="client_to_server",
        id_type="int",
        request_id=1,
        is_error=False,
        result_or_error={"roots": []},
    )
    assert resp_s.correlation is not None
    assert resp_s.correlation.status == "matched"
    assert resp_s.correlation.matched_request_event_id == "req-s-int"
    assert resp_s.correlation.latency_ns == 1_000

    resp_c_str = correlator.process_response(
        event_id="resp-c-str",
        sequence=5,
        monotonic_time_ns=2_500,
        direction="server_to_client",
        id_type="str",
        request_id="1",
        is_error=False,
        result_or_error={"tools": []},
    )
    assert resp_c_str.correlation is not None
    assert resp_c_str.correlation.matched_request_event_id == "req-c-str"
    assert resp_c_str.correlation.latency_ns == 1_300

    resp_c_int = correlator.process_response(
        event_id="resp-c-int",
        sequence=6,
        monotonic_time_ns=3_000,
        direction="server_to_client",
        id_type="int",
        request_id=1,
        is_error=False,
        result_or_error={"isError": True, "content": []},
    )
    assert resp_c_int.correlation is not None
    assert resp_c_int.correlation.matched_request_event_id == "req-c-int"
    assert resp_c_int.correlation.latency_ns == 2_000
    assert resp_c_int.derived is not None
    assert resp_c_int.derived.tool_is_error is True
    assert resp_c_int.derived.otel_attributes["mcp.method.name"] == "tools/call"
    assert resp_c_int.trace is not None
    assert resp_c_int.trace.trace_source == "w3c_meta"


def test_duplicate_in_flight_ids_and_orphaned_and_duplicate_responses() -> None:
    """Duplicate in-flight IDs, orphaned responses, and duplicates are explicitly flagged."""
    correlator = RequestCorrelator(new_execution_id())

    first = correlator.process_request(
        event_id="req-1",
        sequence=1,
        monotonic_time_ns=100,
        direction="client_to_server",
        method="tools/list",
        id_type="int",
        request_id=7,
        params={},
    )
    assert first.warnings == ()

    second = correlator.process_request(
        event_id="req-2",
        sequence=2,
        monotonic_time_ns=200,
        direction="client_to_server",
        method="prompts/list",
        id_type="int",
        request_id=7,
        params={},
    )
    assert second.correlation is not None
    assert second.correlation.status == "ambiguous_duplicate_id"
    assert second.correlation.confidence == "none"
    assert second.correlation.candidate_request_event_ids == ("req-1",)
    assert second.warnings[0].code == "duplicate_in_flight_request_id"

    r1 = correlator.process_response(
        event_id="resp-1",
        sequence=3,
        monotonic_time_ns=300,
        direction="server_to_client",
        id_type="int",
        request_id=7,
        is_error=False,
        result_or_error={},
    )
    assert r1.correlation is not None
    assert r1.correlation.status == "ambiguous_duplicate_id"
    assert r1.correlation.confidence == "heuristic"
    assert r1.correlation.latency_ns is None
    assert r1.correlation.matched_request_event_id == "req-1"
    assert r1.correlation.candidate_request_event_ids == ("req-1", "req-2")

    r2 = correlator.process_response(
        event_id="resp-2",
        sequence=4,
        monotonic_time_ns=400,
        direction="server_to_client",
        id_type="int",
        request_id=7,
        is_error=False,
        result_or_error={},
    )
    assert r2.correlation is not None
    assert r2.correlation.status == "ambiguous_duplicate_id"
    assert r2.correlation.matched_request_event_id == "req-2"

    extra = correlator.process_response(
        event_id="resp-3",
        sequence=5,
        monotonic_time_ns=500,
        direction="server_to_client",
        id_type="int",
        request_id=7,
        is_error=False,
        result_or_error={},
    )
    assert extra.correlation is not None
    assert extra.correlation.status == "duplicate_response"
    assert extra.warnings[0].code == "duplicate_response"

    orphan = correlator.process_response(
        event_id="resp-orphan",
        sequence=6,
        monotonic_time_ns=600,
        direction="server_to_client",
        id_type="str",
        request_id="unknown-999",
        is_error=True,
        result_or_error={"code": -32000, "message": "oops"},
    )
    assert orphan.correlation is not None
    assert orphan.correlation.status == "orphaned_response"
    assert orphan.warnings[0].code == "orphaned_response"


def test_cancellation_progress_tokens_invalid_ids_and_late_post_exit_frames() -> None:
    """Cancelled requests, progress tokens, invalid IDs, and late/post-exit frames are tracked."""
    correlator = RequestCorrelator(new_execution_id())

    correlator.process_request(
        event_id="req-slow",
        sequence=1,
        monotonic_time_ns=1_000,
        direction="client_to_server",
        method="tools/call",
        id_type="int",
        request_id=10,
        params={"name": "slow_echo", "_meta": {"progressToken": "tok-10"}},
    )

    prog = correlator.process_notification(
        event_id="notif-prog",
        direction="server_to_client",
        method="notifications/progress",
        params={"progressToken": "tok-10", "progress": 1, "total": 2},
    )
    assert prog.correlation is not None
    assert prog.correlation.status == "progress_target_matched"
    assert prog.correlation.matched_request_event_id == "req-slow"

    cancel = correlator.process_notification(
        event_id="notif-cancel",
        direction="client_to_server",
        method="notifications/cancelled",
        params={"requestId": 10, "reason": "user abort"},
    )
    assert cancel.correlation is not None
    assert cancel.correlation.status == "cancel_target_matched"
    assert cancel.correlation.matched_request_event_id == "req-slow"

    # Boolean / float / null request IDs are invalid and never match int 1.
    bool_req = correlator.process_request(
        event_id="req-bool",
        sequence=2,
        monotonic_time_ns=1_500,
        direction="client_to_server",
        method="ping",
        id_type="bool",
        request_id=True,
        params={},
    )
    assert bool_req.correlation is not None
    assert bool_req.correlation.status == "invalid_id"
    assert bool_req.warnings[0].code == "invalid_jsonrpc_request_id"

    float_req = correlator.process_request(
        event_id="req-float",
        sequence=3,
        monotonic_time_ns=1_600,
        direction="client_to_server",
        method="ping",
        id_type="float",
        request_id=1.5,
        params={},
    )
    assert float_req.correlation is not None
    assert float_req.correlation.status == "invalid_id"

    null_err = correlator.process_response(
        event_id="err-parse",
        sequence=4,
        monotonic_time_ns=1_700,
        direction="server_to_client",
        id_type="null",
        request_id=None,
        is_error=True,
        result_or_error={"code": -32700, "message": "Parse error"},
    )
    assert null_err.correlation is not None
    assert null_err.correlation.status == "invalid_id"
    assert null_err.warnings == ()

    correlator.mark_process_exited()
    late_resp = correlator.process_response(
        event_id="resp-late",
        sequence=5,
        monotonic_time_ns=2_500,
        direction="server_to_client",
        id_type="int",
        request_id=10,
        is_error=False,
        result_or_error={"content": []},
    )
    assert late_resp.correlation is not None
    assert late_resp.correlation.status == "matched"
    assert late_resp.correlation.late_after_cancel is True
    assert late_resp.correlation.post_exit_frame is True
    assert late_resp.derived is not None
    assert "late_after_cancel" in late_resp.derived.anomaly_flags
    assert "post_exit_frame" in late_resp.derived.anomaly_flags
    assert late_resp.warnings[0].code == "post_exit_frame"

    # Unanswered request tracking
    correlator.process_request(
        event_id="req-hanging",
        sequence=6,
        monotonic_time_ns=3_000,
        direction="client_to_server",
        method="tools/call",
        id_type="str",
        request_id="hang-1",
        params={"name": "forever"},
    )
    assert correlator.unanswered_request_labels() == ("client_to_server:str:'hang-1'",)
