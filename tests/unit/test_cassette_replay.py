"""Unit tests for Phase 8 cassette creation, integrity, matching, safety gating, and replay."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aerlog.capture.normalizer import EventNormalizer, RawWireFrameInput
from aerlog.config import AerlogConfig, load_config
from aerlog.events.ids import new_execution_id
from aerlog.events.models import ExecutionEvent
from aerlog.events.types import WireDirection
from aerlog.replay import (
    ERR_CASSETTE_MISSING_RESPONSE,
    ERR_CASSETTE_UNMATCHED,
    ERR_CASSETTE_UNSAFE_BLOCKED,
    CassetteIntegrityError,
    CassetteMatcher,
    CassetteSchemaVersionError,
    CassetteValidationError,
    LiveReplayBlockedError,
    UnredactedCassetteRefusedError,
    build_cassette_from_read_result,
    classify_interaction_safety,
    load_cassette,
    parse_untrusted_cassette_dict,
    replay_cassette,
    save_cassette,
    save_replay_report,
    serve_cassette_stdio,
)
from aerlog.storage.event_log import IndexedLogEvent, JsonlReadResult


def _wire_bytes(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def _build_read_result(
    events: list[ExecutionEvent],
    *,
    norm: EventNormalizer,
    summary: Any,
    exec_id: str,
) -> JsonlReadResult:
    indexed = tuple(
        IndexedLogEvent(event=ev, line_number=idx + 1, byte_offset=idx * 100, byte_length=90)
        for idx, ev in enumerate(events)
    )
    return JsonlReadResult(
        execution_id=exec_id,
        header=norm.build_header(),
        summary=summary,
        manifest=None,
        events=indexed,
        corruptions=(),
        byte_size=len(events) * 100,
        line_count=len(events),
        last_valid_sequence=events[-1].sequence if events else 0,
        events_file_sha256="ab" * 32,
        unclean_shutdown=summary is None,
    )


def _wire(
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


def test_cassette_build_integrity_schema_and_untrusted_isolation(tmp_path: Path) -> None:
    """Sealed cassettes check SHA-256, 0o600 mode, schema version, and untrusted JSON."""
    default_cfg = AerlogConfig()
    assert default_cfg.replay.default_replay_mode == "cassette"
    assert default_cfg.replay.default_match_mode == "strict"
    assert default_cfg.replay.unsafe_tool_policy == "block"
    assert default_cfg.replay.missing_response_policy == "error"

    legacy_toml = tmp_path / "legacy.toml"
    legacy_toml.write_text('log_level = "WARNING"\n', encoding="utf-8")
    assert load_config(legacy_toml).replay.unsafe_tool_policy == "block"

    replay_toml = tmp_path / "replay.toml"
    replay_toml.write_text(
        '[replay]\ndefault_match_mode = "tolerant"\nmissing_response_policy = "omit"\n',
        encoding="utf-8",
    )
    loaded = load_config(replay_toml)
    assert loaded.replay.default_match_mode == "tolerant"
    assert loaded.replay.missing_response_policy == "omit"

    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 23, 0, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("python", "srv.py", "--token=raw-secret-cli"),
    )
    events: list[ExecutionEvent] = list(norm.start_execution())
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_500,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2026-07-28"}},
        )
    )
    fin, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=3_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin)

    read_res = _build_read_result(events, norm=norm, summary=summary, exec_id=exec_id)
    cassette = build_cassette_from_read_result(read_res)
    assert cassette.cassette_sha256 is not None
    assert cassette.contains_raw_secrets is False
    assert "raw-secret-cli" not in json.dumps(cassette.model_dump(mode="json"))

    data_dir = tmp_path / "aerlog-data"
    saved_path = save_cassette(cassette, data_dir=data_dir)
    assert stat.S_IMODE(saved_path.stat().st_mode) == 0o600

    loaded_cassette, _ = load_cassette(cassette.cassette_id, data_dir=data_dir)
    assert loaded_cassette == cassette

    # Verify replay NEVER spawns subprocesses even if command_summary contains shell tricks.
    def _forbid_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Subprocess execution must never happen during cassette replay")

    mp = pytest.MonkeyPatch()
    try:
        mp.setattr("subprocess.Popen", _forbid_spawn)
        mp.setattr("os.system", _forbid_spawn)
        rep = replay_cassette(loaded_cassette)
        assert rep.overall_status == "clean_match"
    finally:
        mp.undo()

    # Tampered payload fails integrity check.
    raw = json.loads(saved_path.read_text(encoding="utf-8"))
    raw["interactions"][0]["method"] = "evil/exec"
    tampered_path = tmp_path / "tampered.cassette.json"
    tampered_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(CassetteIntegrityError):
        load_cassette(tampered_path)

    # Unsupported future major version rejected cleanly.
    newer = json.loads(saved_path.read_text(encoding="utf-8"))
    newer["cassette_schema_version"] = "2.0.0"
    with pytest.raises(CassetteSchemaVersionError):
        parse_untrusted_cassette_dict(newer)

    # Extra unknown field in untrusted cassette rejected cleanly (extra="forbid").
    extra = json.loads(saved_path.read_text(encoding="utf-8"))
    extra["malicious_hook"] = "rm -rf /"
    with pytest.raises(CassetteValidationError):
        parse_untrusted_cassette_dict(extra)


def test_safety_classification_mutating_gating_and_live_block() -> None:
    """Unknown tools default unknown_unsafe; unsafe gated unless opted in; live blocked."""
    assert classify_interaction_safety("initialize").side_effect_class == "protocol_control"
    assert classify_interaction_safety("tools/list").side_effect_class == "read_only_hint"
    assert (
        classify_interaction_safety(
            "tools/call",
            tool_name="get_docs",
            tool_annotations={"readOnlyHint": True},
        ).side_effect_class
        == "read_only_hint"
    )
    assert (
        classify_interaction_safety("tools/call", tool_name="mystery_tool").side_effect_class
        == "unknown_unsafe"
    )
    assert (
        classify_interaction_safety("tools/call", tool_name="delete_record").side_effect_class
        == "potentially_mutating"
    )
    # Verb check must not falsely flag "compute" as containing "put".
    assert (
        classify_interaction_safety("tools/call", tool_name="compute_sum").side_effect_class
        == "unknown_unsafe"
    )
    assert (
        classify_interaction_safety(
            "tools/call",
            tool_name="send_email",
            tool_annotations={"readOnlyHint": True},
        ).side_effect_class
        == "potentially_mutating"
    )

    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 23, 5, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    events: list[ExecutionEvent] = list(norm.start_execution())
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_500,
            direction="server_to_client",
            obj={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {"name": "safe_lookup", "annotations": {"readOnlyHint": True}},
                        {"name": "delete_user", "annotations": {"destructiveHint": True}},
                    ]
                },
            },
        )
    )
    for req_id, tool in ((2, "safe_lookup"), (3, "delete_user"), (4, "mystery_tool")):
        events.extend(
            _wire(
                norm,
                ts=t0,
                mono_ns=2_000 + req_id * 500,
                direction="client_to_server",
                obj={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": {}},
                },
            )
        )
        events.extend(
            _wire(
                norm,
                ts=t0,
                mono_ns=2_000 + req_id * 500 + 200,
                direction="server_to_client",
                obj={"jsonrpc": "2.0", "id": req_id, "result": {"tool": tool}},
            )
        )
    fin, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=10_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin)
    cassette = build_cassette_from_read_result(
        _build_read_result(events, norm=norm, summary=summary, exec_id=exec_id)
    )

    with pytest.raises(LiveReplayBlockedError):
        replay_cassette(cassette, mode="live")

    blocked_report = replay_cassette(cassette, unsafe_tool_policy="block")
    assert blocked_report.is_replay is True
    assert blocked_report.overall_status == "diverged"
    assert blocked_report.matched_count == 2  # tools/list + safe_lookup
    assert blocked_report.blocked_count == 2  # delete_user + mystery_tool

    warn_report = replay_cassette(cassette, unsafe_tool_policy="warn")
    assert warn_report.overall_status == "matched_with_warnings"
    assert warn_report.matched_count == 4
    assert warn_report.blocked_count == 0
    assert warn_report.safety_warning_count == 2


def test_matcher_strict_vs_tolerant_out_of_order_unmatched_and_repeated_slots() -> None:
    """Test exact strict replay, tolerant _meta matching, out-of-order, unmatched, and repeats."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 23, 10, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    events: list[ExecutionEvent] = list(norm.start_execution())

    # Build cassette: initialize (id=1), progress-enabled read_tool x2 (ids=2,3)
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_500,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=3_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=3_200,
            direction="server_to_client",
            obj={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "tools": [{"name": "inspect_item", "annotations": {"readOnlyHint": True}}]
                },
            },
        )
    )
    for req_id, val in ((3, "first"), (4, "first")):  # two identical repeated slots
        events.extend(
            _wire(
                norm,
                ts=t0,
                mono_ns=3_500 + req_id * 500,
                direction="client_to_server",
                obj={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/call",
                    "params": {
                        "name": "inspect_item",
                        "arguments": {"key": val},
                        "_meta": {"progressToken": f"rec-{req_id}"},
                    },
                },
            )
        )
        events.extend(
            _wire(
                norm,
                ts=t0,
                mono_ns=3_500 + req_id * 500 + 100,
                direction="server_to_client",
                obj={
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {"progressToken": f"rec-{req_id}", "progress": 1, "total": 1},
                },
            )
        )
        events.extend(
            _wire(
                norm,
                ts=t0,
                mono_ns=3_500 + req_id * 500 + 200,
                direction="server_to_client",
                obj={"jsonrpc": "2.0", "id": req_id, "result": {"step": req_id}},
            )
        )

    fin, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=15_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin)
    cassette = build_cassette_from_read_result(
        _build_read_result(events, norm=norm, summary=summary, exec_id=exec_id)
    )

    # 1. Clean self-replay
    clean = replay_cassette(cassette, match_mode="strict")
    assert clean.overall_status == "clean_match"
    assert clean.matched_count == 4
    assert clean.diverged_count == 0

    # 2. Strict rejects out-of-order, unmatched, and 3rd repeat calls.
    strict_matcher = CassetteMatcher(cassette, match_mode="strict")
    ooo = strict_matcher.match_request(
        method="tools/list", params=None, has_params=False, request_id=10, id_type="int"
    )
    assert not ooo.matched
    assert ooo.outcome_kind == "out_of_order_request"
    assert ooo.response_frame_obj is not None
    assert ooo.response_frame_obj["error"]["code"] == ERR_CASSETTE_UNMATCHED

    unmatched = strict_matcher.match_request(
        method="unknown/op", params=None, has_params=False, request_id=11, id_type="int"
    )
    assert not unmatched.matched
    assert unmatched.outcome_kind == "unmatched_request"
    assert unmatched.response_frame_obj is not None
    assert unmatched.response_frame_obj["error"]["code"] == ERR_CASSETTE_UNMATCHED

    # 3. Tolerant matches normalized _meta + renumbered IDs and detects 3rd repeat.
    tol_matcher = CassetteMatcher(cassette, match_mode="tolerant")
    assert (
        tol_matcher.match_request(
            method="initialize",
            params={
                "capabilities": {},
                "_meta": {"traceparent": "00-11111111111111111111111111111111-1111111111111111-01"},
            },
            has_params=True,
            request_id="new-id-1",
            id_type="str",
        ).outcome_kind
        == "normalized_match"
    )
    assert (
        tol_matcher.match_request(
            method="tools/list", params=None, has_params=False, request_id=200, id_type="int"
        ).outcome_kind
        == "matched_ok"
    )

    slot1 = tol_matcher.match_request(
        method="tools/call",
        params={
            "name": "inspect_item",
            "arguments": {"key": "first"},
            "_meta": {"progressToken": "live-tok-1"},
        },
        has_params=True,
        request_id=300,
        id_type="int",
    )
    assert slot1.matched and slot1.outcome_kind == "normalized_match"
    assert slot1.response_frame_obj is not None
    assert slot1.response_frame_obj["id"] == 300
    assert slot1.response_frame_obj["result"] == {"step": 3}
    assert slot1.emitted_notifications[0]["params"]["progressToken"] == "live-tok-1"

    slot2 = tol_matcher.match_request(
        method="tools/call",
        params={
            "name": "inspect_item",
            "arguments": {"key": "first"},
            "_meta": {"progressToken": "live-tok-2"},
        },
        has_params=True,
        request_id=301,
        id_type="int",
    )
    assert slot2.matched and slot2.response_frame_obj is not None
    assert slot2.response_frame_obj["result"] == {"step": 4}

    exhausted = tol_matcher.match_request(
        method="tools/call",
        params={"name": "inspect_item", "arguments": {"key": "first"}},
        has_params=True,
        request_id=302,
        id_type="int",
    )
    assert not exhausted.matched
    assert exhausted.outcome_kind == "repeated_request_exhausted"
    assert exhausted.response_frame_obj is not None
    assert exhausted.response_frame_obj["error"]["code"] == ERR_CASSETTE_UNMATCHED


def test_replay_missing_recorded_responses_and_cancellations() -> None:
    """Missing response triggers -32005 or omit under policy; cancellations match target request."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 23, 15, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000, command=("srv.py",)
    )
    events: list[ExecutionEvent] = list(norm.start_execution())
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_200,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_500,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
    )
    fin, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=5_000,
        termination_reason="server_exited",
        exit_code=1,
        returncode=1,
    )
    events.append(fin)
    cassette = build_cassette_from_read_result(
        _build_read_result(events, norm=norm, summary=summary, exec_id=exec_id)
    )

    err_report = replay_cassette(cassette, missing_response_policy="error")
    assert err_report.missing_response_count == 2
    assert err_report.diverged_count == 2
    assert any(
        s.kind == "notification" and s.outcome_kind == "cancellation_matched"
        for s in err_report.steps
    )

    matcher_err = CassetteMatcher(cassette, missing_response_policy="error")
    d1 = matcher_err.match_request(
        method="ping", params=None, has_params=False, request_id=1, id_type="int"
    )
    assert d1.outcome_kind == "missing_recorded_response"
    assert d1.response_frame_obj is not None
    assert d1.response_frame_obj["error"]["code"] == ERR_CASSETTE_MISSING_RESPONSE

    matcher_omit = CassetteMatcher(cassette, missing_response_policy="omit")
    d2 = matcher_omit.match_request(
        method="ping", params=None, has_params=False, request_id=1, id_type="int"
    )
    assert d2.outcome_kind == "missing_recorded_response"
    assert d2.response_frame_obj is None


def test_unredacted_cassette_requires_explicit_opt_in() -> None:
    """explicit_unredacted recordings refuse cassette build without explicit opt-in flag."""
    from aerlog.capture.redaction import RedactionConfig

    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 23, 20, 0, tzinfo=UTC)
    with pytest.warns(UserWarning, match="explicit_unredacted"):
        norm = EventNormalizer(
            execution_id=exec_id,
            started_at=t0,
            monotonic_start_ns=1_000,
            command=("srv.py",),
            redaction_config=RedactionConfig(mode="explicit_unredacted"),
        )
    events: list[ExecutionEvent] = list(norm.start_execution())
    fin, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=2_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin)
    read_res = _build_read_result(events, norm=norm, summary=summary, exec_id=exec_id)

    with pytest.raises(UnredactedCassetteRefusedError):
        build_cassette_from_read_result(read_res, allow_unredacted_cassette=False)

    allowed = build_cassette_from_read_result(read_res, allow_unredacted_cassette=True)
    assert allowed.contains_raw_secrets is True


async def test_serve_cassette_stdio_offline_roundtrip_and_report_permissions(
    tmp_path: Path,
) -> None:
    """serve_cassette_stdio handles chunked frames purely offline and saves 0o600 replay report."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 23, 25, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id, started_at=t0, monotonic_start_ns=1_000, command=("nonexistent.py",)
    )
    events = list(norm.start_execution())
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_500,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 1, "result": {"pong": True}},
        )
    )
    fin, summary = norm.finalize_execution(
        ended_at=t0,
        monotonic_end_ns=3_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin)
    cassette = build_cassette_from_read_result(
        _build_read_result(events, norm=norm, summary=summary, exec_id=exec_id)
    )

    incoming = [b'{"jsonrpc":"2.0",', b'"id":99,"method":"ping"}\n', b"{broken_json\n", b""]
    idx = 0
    written: list[bytes] = []

    def _read_chunk() -> bytes:
        nonlocal idx
        chunk = incoming[idx]
        idx += 1
        return chunk

    report = await serve_cassette_stdio(
        cassette,
        match_mode="tolerant",
        read_chunk=_read_chunk,
        write_frame=written.append,
    )
    assert report.driver_mode == "stdio_mock_server"
    assert report.matched_count == 1
    assert json.loads(written[0].decode("utf-8")) == {
        "jsonrpc": "2.0",
        "id": 99,
        "result": {"pong": True},
    }
    assert json.loads(written[1].decode("utf-8"))["error"]["code"] == -32700

    # Save replay report cleanly outside original execution directory with 0o600 permissions.
    data_dir = tmp_path / "aerlog-data"
    rep_path = save_replay_report(report, data_dir=data_dir)
    assert "replays" in rep_path.parts
    assert stat.S_IMODE(rep_path.stat().st_mode) == 0o600
    assert (data_dir / "replays" / report.replay_id / "report.json") == rep_path
    assert not (data_dir / "executions" / exec_id).exists()
    assert ERR_CASSETTE_UNSAFE_BLOCKED == -32010
    assert (t0 + timedelta(seconds=1)) > t0
