"""Unit tests for Phase 6 timeline reconstruction across complete, incomplete, and corrupt runs."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from aerlog.analysis import (
    DEFAULT_TIMELINE_LIMIT,
    TIMELINE_SCHEMA_VERSION,
    reconstruct_timeline,
    reconstruct_timeline_from_events,
    slice_timeline,
)
from aerlog.capture import EventNormalizer, RawProxySignalInput, RawWireFrameInput
from aerlog.events import (
    ExecutionEvent,
    ExecutionFinishedPayload,
    ExecutionHeader,
    ExecutionStartedPayload,
    ExecutionSummary,
    JsonRpcNotificationPayload,
    JsonRpcRequestPayload,
    JsonRpcResponsePayload,
    new_execution_id,
)
from aerlog.storage import CorruptRecordReport, IndexedLogEvent, JsonlReadResult


def _wire_ev(
    normalizer: EventNormalizer,
    *,
    ts: datetime,
    mono_ns: int,
    direction: str,
    obj: dict[str, object],
) -> list[ExecutionEvent]:
    raw = (json.dumps(obj) + "\n").encode("utf-8")
    return normalizer.normalize(
        RawWireFrameInput(
            timestamp=ts,
            monotonic_time_ns=mono_ns,
            direction=direction,  # type: ignore[arg-type]
            raw_frame=raw,
        )
    )


def test_timeline_reconstructs_complete_legacy_and_modern_runs_and_unknown_methods() -> None:
    """Both legacy initialize and modern server/discover + unknown methods reconstruct cleanly."""
    for is_legacy in (False, True):
        exec_id = new_execution_id()
        t0 = datetime(2026, 11, 11, 19, 0, 0, tzinfo=UTC)
        norm = EventNormalizer(
            execution_id=exec_id,
            started_at=t0,
            monotonic_start_ns=1_000,
            command=("python", "server.py"),
        )
        events: list[ExecutionEvent] = list(norm.start_execution())
        if is_legacy:
            events.extend(
                _wire_ev(
                    norm,
                    ts=t0,
                    mono_ns=2_000,
                    direction="client_to_server",
                    obj={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-11-25"},
                    },
                )
            )
            events.extend(
                _wire_ev(
                    norm,
                    ts=t0,
                    mono_ns=3_000,
                    direction="server_to_client",
                    obj={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-11-25"}},
                )
            )
            events.extend(
                _wire_ev(
                    norm,
                    ts=t0,
                    mono_ns=3_500,
                    direction="client_to_server",
                    obj={"jsonrpc": "2.0", "method": "notifications/initialized"},
                )
            )
        else:
            events.extend(
                _wire_ev(
                    norm,
                    ts=t0,
                    mono_ns=2_000,
                    direction="client_to_server",
                    obj={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}},
                )
            )
            events.extend(
                _wire_ev(
                    norm,
                    ts=t0,
                    mono_ns=3_000,
                    direction="server_to_client",
                    obj={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {"supportedVersions": ["2026-07-28"]},
                    },
                )
            )

        # Custom unknown method + extra top-level fields + W3C traceparent
        events.extend(
            _wire_ev(
                norm,
                ts=t0,
                mono_ns=4_000,
                direction="client_to_server",
                obj={
                    "jsonrpc": "2.0",
                    "id": "custom-1",
                    "method": "vendor.x/customOp",
                    "params": {
                        "_meta": {
                            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                        }
                    },
                    "xExtra": True,
                },
            )
        )
        events.extend(
            _wire_ev(
                norm,
                ts=t0,
                mono_ns=6_500,
                direction="server_to_client",
                obj={"jsonrpc": "2.0", "id": "custom-1", "result": {"ok": True}},
            )
        )
        fin_evt, summary = norm.finalize_execution(
            ended_at=t0,
            monotonic_end_ns=7_000,
            termination_reason="completed",
            exit_code=0,
            returncode=0,
        )
        events.append(fin_evt)

        timeline = reconstruct_timeline_from_events(
            events,
            execution_id=exec_id,
            header=norm.build_header(),
            summary=summary,
        )
        assert timeline.timeline_version == TIMELINE_SCHEMA_VERSION
        assert timeline.capture_completeness == "complete"
        assert timeline.execution_duration_ns == 6_000
        assert timeline.missing_response_count == 0
        assert timeline.request_count == 2
        assert timeline.response_count == 2

        custom_spans = [sp for sp in timeline.spans if sp.method == "vendor.x/customOp"]
        assert len(custom_spans) == 1
        assert custom_spans[0].is_unknown_method is True
        assert custom_spans[0].duration_ns == 2_500
        assert custom_spans[0].duration_basis == "exact_monotonic_delta"
        assert custom_spans[0].trace.trace_source == "w3c_meta"
        assert custom_spans[0].trace.is_synthetic is False

        # Separate observed vs synthetic trace groups cleanly
        assert any(g.is_synthetic is False for g in timeline.trace_groups)
        assert any(g.is_synthetic is True for g in timeline.trace_groups)


def test_timeline_interleaved_bidirectional_id_types_and_duplicate_ids_no_fake_latency() -> None:
    """Interleaved C->S and S->C requests, typed IDs, invalid IDs, and duplicates work safely."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 19, 5, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("server.py",),
    )
    events: list[ExecutionEvent] = list(norm.start_execution())

    # Interleaved int 1, str "1", server->client int 1, bool True, null, float 1.5, array [1]
    events.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "a"}},
        )
    )
    events.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=2_200,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": "1", "method": "tools/call", "params": {"name": "b"}},
        )
    )
    events.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=2_400,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 1, "method": "roots/list", "params": {}},
        )
    )
    for bad_id in (True, None, 1.5, [1]):
        events.extend(
            _wire_ev(
                norm,
                ts=t0,
                mono_ns=2_500,
                direction="client_to_server",
                obj={"jsonrpc": "2.0", "id": bad_id, "method": "ping"},
            )
        )

    # Duplicate in-flight id=99 (two requests open concurrently before responses arrive)
    events.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=3_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 99, "method": "tools/list"},
        )
    )
    events.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=3_100,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 99, "method": "prompts/list"},
        )
    )

    # Reply to server->client int 1, client str "1", client int 1 (isError=True), and duplicate 99
    events.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=3_400,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 1, "result": {"roots": []}},
        )
    )
    events.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=3_800,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": "1", "result": {"content": []}},
        )
    )
    events.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=4_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": []}},
        )
    )
    events.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=5_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 99, "result": {}},
        )
    )

    fin_evt, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=6_000,
        termination_reason="completed",
        exit_code=0,
    )
    events.append(fin_evt)

    timeline = reconstruct_timeline_from_events(events, execution_id=exec_id, summary=summary)
    assert timeline.tool_error_count == 1

    # Exact distinct ID checks
    s_req = next(s for s in timeline.spans if s.method == "roots/list")
    assert s_req.origin_direction == "server_to_client"
    assert s_req.duration_ns == 1_000
    assert s_req.outcome == "ok"

    c_str = next(s for s in timeline.spans if s.request_id_display == 'str:"1"')
    assert c_str.duration_ns == 1_600

    c_int = next(
        s
        for s in timeline.spans
        if s.origin_direction == "client_to_server" and s.request_id_display == "int:1"
    )
    assert c_int.duration_ns == 2_000
    assert c_int.outcome == "tool_error"

    # Invalid IDs stay isolated with invalid_id outcome & no duration
    invalid_spans = [s for s in timeline.spans if s.outcome == "invalid_id"]
    assert len(invalid_spans) == 4
    assert all(s.duration_ns is None for s in invalid_spans)

    # Duplicate in-flight id=99 MUST NOT fabricate exact latency!
    dup_spans = [s for s in timeline.spans if s.request_id_display == "int:99"]
    assert len(dup_spans) == 2
    matched_dup = next(s for s in dup_spans if s.response_event_id is not None)
    assert matched_dup.duration_ns is None
    assert matched_dup.duration_basis == "unavailable_ambiguous_correlation"
    assert matched_dup.outcome == "ambiguous_correlation"
    assert any(s.outcome == "missing_response" for s in dup_spans)


def test_timeline_missing_response_cancellations_signals_and_notification_only() -> None:
    """Missing responses, cancel before/after response, signal exit, and notification-only work."""
    # 1. Notification-only execution
    notif_exec = new_execution_id()
    t0 = datetime(2026, 11, 11, 19, 10, 0, tzinfo=UTC)
    n_norm = EventNormalizer(
        execution_id=notif_exec,
        started_at=t0,
        monotonic_start_ns=100,
        command=("srv.py",),
    )
    n_events = list(n_norm.start_execution())
    n_events.extend(
        _wire_ev(
            n_norm,
            ts=t0,
            mono_ns=200,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "method": "notifications/tools/list_changed"},
        )
    )
    n_fin, n_sum = n_norm.finalize_execution(
        ended_at=t0, monotonic_end_ns=300, termination_reason="completed", exit_code=0
    )
    n_events.append(n_fin)
    n_tl = reconstruct_timeline_from_events(n_events, execution_id=notif_exec, summary=n_sum)
    assert n_tl.request_count == 0
    assert n_tl.notification_count == 1
    assert n_tl.missing_response_count == 0

    # 2. Cancel without reply, cancel with late reply, missing reply, signal exit
    exec_id = new_execution_id()
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    evs: list[ExecutionEvent] = list(norm.start_execution())
    # Cancel -> no response
    evs.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "slow1"}},
        )
    )
    evs.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=2_500,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 10},
            },
        )
    )
    # Cancel -> late response still arrives
    evs.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=3_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "slow2"}},
        )
    )
    evs.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=3_200,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 11},
            },
        )
    )
    evs.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=4_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 11, "result": {"content": []}},
        )
    )
    # Unanswered request + SIGTERM signal exit
    evs.extend(
        _wire_ev(
            norm,
            ts=t0,
            mono_ns=4_500,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "hang"}},
        )
    )
    evs.extend(
        norm.normalize(
            RawProxySignalInput(timestamp=t0, monotonic_time_ns=5_000, signal_name="SIGTERM")
        )
    )
    fin, smry = norm.finalize_execution(
        ended_at=t0, monotonic_end_ns=5_500, termination_reason="signal", exit_code=143
    )
    evs.append(fin)

    tl = reconstruct_timeline_from_events(evs, execution_id=exec_id, summary=smry)
    by_id = {sp.request_id_display: sp for sp in tl.spans if sp.request_id_display}

    assert by_id["int:10"].outcome == "cancelled_no_response"
    assert by_id["int:10"].duration_ns is None
    assert by_id["int:11"].outcome == "cancelled_late_response"
    assert by_id["int:11"].duration_ns == 1_000
    assert by_id["int:12"].outcome == "missing_response"
    assert len(tl.missing_response_spans) == 2
    assert any(e.kind == "proxy_signal" for e in tl.entries)


def test_timeline_fallback_correlation_corrupt_markers_and_large_slicing() -> None:
    """Fallback correlation handles un-correlated events, corrupt markers, and 500+ slicing."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 19, 15, 0, tzinfo=UTC)

    # Manually built raw events with correlation=None to exercise fallback deterministic correlator.
    raw_events: list[ExecutionEvent] = [
        ExecutionEvent(
            execution_id=exec_id,
            sequence=1,
            timestamp=t0,
            monotonic_time_ns=1_000,
            direction="proxy",
            kind="execution_started",
            payload=ExecutionStartedPayload(
                command=("srv.py",),
                redaction_mode="standard",
                backpressure_policy="block",
            ),
        ),
    ]
    seq = 2
    # 260 request+response pairs = 520 wire events + start = 521 events
    for idx in range(1, 261):
        base_ns = seq * 1_000
        raw_events.append(
            ExecutionEvent(
                execution_id=exec_id,
                sequence=seq,
                timestamp=t0,
                monotonic_time_ns=base_ns,
                direction="client_to_server",
                kind="jsonrpc_request",
                payload=JsonRpcRequestPayload(id=idx, id_type="int", method="ping"),
            )
        )
        seq += 1
        raw_events.append(
            ExecutionEvent(
                execution_id=exec_id,
                sequence=seq,
                timestamp=t0,
                monotonic_time_ns=base_ns + 500,
                direction="server_to_client",
                kind="jsonrpc_response",
                payload=JsonRpcResponsePayload(id=idx, id_type="int", result={}),
            )
        )
        seq += 1

    # Add notification & corrupt report via JsonlReadResult
    raw_events.append(
        ExecutionEvent(
            execution_id=exec_id,
            sequence=seq,
            timestamp=t0,
            monotonic_time_ns=seq * 1_000,
            direction="server_to_client",
            kind="jsonrpc_notification",
            payload=JsonRpcNotificationPayload(method="notifications/message"),
        )
    )
    seq += 1
    raw_events.append(
        ExecutionEvent(
            execution_id=exec_id,
            sequence=seq,
            timestamp=t0,
            monotonic_time_ns=seq * 1_000,
            direction="proxy",
            kind="execution_finished",
            payload=ExecutionFinishedPayload(
                termination_reason="completed",
                exit_code=0,
                completeness="complete",
                total_events=seq,
            ),
        )
    )

    read_res = JsonlReadResult(
        execution_id=exec_id,
        header=ExecutionHeader(
            execution_id=exec_id,
            started_at=t0,
            monotonic_start_ns=1_000,
            command=("srv.py",),
        ),
        summary=ExecutionSummary(
            execution_id=exec_id,
            started_at=t0,
            ended_at=t0,
            duration_ns=seq * 1_000,
            command=("srv.py",),
            capture_completeness="complete",
            termination_reason="completed",
            exit_code=0,
            total_events=seq,
        ),
        manifest=None,
        events=tuple(
            IndexedLogEvent(event=ev, line_number=i, byte_offset=i * 100, byte_length=100)
            for i, ev in enumerate(raw_events, start=1)
        ),
        corruptions=(
            CorruptRecordReport(
                execution_id=exec_id,
                line_number=999,
                byte_offset=99_900,
                byte_length=25,
                issue_kind="missing_newline",
                excerpt_sha256="0" * 64,
                details="Trailing truncated line",
            ),
        ),
        byte_size=100_000,
        line_count=seq + 1,
        last_valid_sequence=seq,
        events_file_sha256="a" * 64,
        unclean_shutdown=False,
    )

    tl = reconstruct_timeline(read_res, diverged_index=True)
    assert tl.total_events == 523
    assert tl.has_corruptions is True
    assert tl.capture_completeness == "corrupted"
    assert tl.corrupt_record_count == 1
    assert tl.diverged_index is True
    assert all(sp.duration_ns == 500 for sp in tl.spans if sp.span_kind == "request_exchange")

    page1 = slice_timeline(tl)
    assert page1.limit == DEFAULT_TIMELINE_LIMIT == 200
    assert page1.returned_entries == 200
    assert page1.truncated is True
    assert page1.remaining_entries == 323
    assert [e.sequence for e in page1.entries] == list(range(1, 201))

    page3 = slice_timeline(tl, offset=400, limit=200)
    assert page3.returned_entries == 123
    assert page3.truncated is False
    assert page3.remaining_entries == 0
