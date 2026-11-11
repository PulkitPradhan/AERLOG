"""Unit regression tests for Phase 12 security, durability, and edge-case hardening."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from aerlog.analysis import diagnose_events
from aerlog.capture import (
    CaptureConfig,
    CapturePipeline,
    CaptureProxyObserver,
    EventNormalizer,
    InMemoryCaptureSink,
    RawWireFrameInput,
    RecoverySpool,
    default_spool_path,
)
from aerlog.capture.redaction import EventRedactor, RedactionConfig
from aerlog.events import (
    ExecutionEvent,
    ExecutionHeader,
    ExecutionSummary,
    JsonRpcRequestPayload,
    RedactionSummary,
    WireDirection,
    new_event_id,
    new_execution_id,
    synthetic_trace_id_for_execution,
)
from aerlog.proxy.diagnostics import DiagnosticConfig, DiagnosticSink
from aerlog.proxy.forwarding import forward_stderr_stream
from aerlog.proxy.subprocess import SpawnError, spawn_mcp_server
from aerlog.replay import (
    CassetteMatcher,
    CassetteValidationError,
    build_cassette_from_read_result,
    classify_interaction_safety,
    load_cassette,
    replay_cassette,
    seal_cassette_digest,
)
from aerlog.storage.event_log import (
    EVENTS_FILE_NAME,
    EXECUTIONS_DIR_NAME,
    IndexedLogEvent,
    JsonlReadResult,
)
from aerlog.storage.exceptions import StorageCorruptionError
from aerlog.storage.repositories import RecordingRepository


def _wire_bytes(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def test_spool_recovery_and_writer_fail_closed_on_redactor_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failing redaction during spool write or import never leaves raw secrets unredacted."""
    exec_id = new_execution_id()
    secret = "sk-spool-fail-closed-99999"
    t0 = datetime(2026, 11, 12, 0, 0, 0, tzinfo=UTC)

    evt = ExecutionEvent(
        event_id=new_event_id(),
        execution_id=exec_id,
        sequence=1,
        timestamp=t0,
        monotonic_time_ns=1_000,
        direction="client_to_server",
        kind="jsonrpc_request",
        redaction=RedactionSummary(mode="standard", payload_mode="redacted", applied=True),
        payload=JsonRpcRequestPayload(
            method="tools/call",
            id=1,
            id_type="int",
            has_params=True,
            params={"name": "op", "secret": secret, "token": "Bearer tok_should_vanish"},
        ),
    )

    def _boom_redact_value(self: EventRedactor, value: Any, *, root_path: str = "") -> Any:
        _ = (self, value, root_path)
        from aerlog.capture.redaction import RedactedValueOutcome

        return RedactedValueOutcome(
            value=None,
            summary=RedactionSummary(
                mode="standard",
                payload_mode="redaction_failed",
                applied=False,
                degraded=True,
                error="boom",
            ),
        )

    spool_path = tmp_path / "fail.ndjson.spool"
    spool = RecoverySpool(spool_path)
    monkeypatch.setattr(EventRedactor, "redact_value", _boom_redact_value)
    spool.write_header(
        ExecutionHeader(
            execution_id=exec_id,
            started_at=t0,
            monotonic_start_ns=500,
            command=("srv.py",),
            redaction_mode="standard",
            backpressure_policy="spill",
        )
    )
    spool.write_events([evt])
    spool.close()
    monkeypatch.undo()

    assert secret not in spool_path.read_text(encoding="utf-8")

    # Also simulate an untrusted/existing spool event imported under a failing redactor.
    raw_spool = tmp_path / "import_fail.ndjson.spool"
    raw_spool.write_text(
        json.dumps({"record_type": "event", "data": evt.model_dump(mode="json")}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(EventRedactor, "redact_value", _boom_redact_value)
    repo = RecordingRepository(tmp_path / "data")
    try:
        report = repo.import_recovery_spool(raw_spool, redaction_mode="standard")
        assert report.imported_events == 1
        events_file = (
            tmp_path / "data" / EXECUTIONS_DIR_NAME / exec_id / EVENTS_FILE_NAME
        ).read_text(encoding="utf-8")
        assert secret not in events_file
        assert "Bearer tok_should_vanish" not in events_file
        loaded = repo.get_execution_events(exec_id, strict_integrity=False)
        req_ev = loaded.events[0].event
        assert req_ev.degraded is True
        assert req_ev.redaction.payload_mode == "redaction_failed"
        assert req_ev.redaction.applied is False
        assert isinstance(req_ev.payload, JsonRpcRequestPayload)
        assert req_ev.payload.params is None
    finally:
        repo.close()


def test_default_spool_path_and_symlink_guards(tmp_path: Path) -> None:
    """Path traversal IDs and symlinked storage/cassette files are rejected fail-closed."""
    for bad in ("../escape", "a/b", "..", "id\x00x"):
        with pytest.raises(ValueError, match="execution_id"):
            default_spool_path(bad, tmp_path)

    real_file = tmp_path / "real.cassette.json"
    real_file.write_text("{}", encoding="utf-8")
    link_file = tmp_path / "link.cassette.json"
    link_file.symlink_to(real_file)
    with pytest.raises(CassetteValidationError, match="symlink"):
        load_cassette(link_file)

    data_dir = tmp_path / "sym_data"
    bad_exec_id = new_execution_id()
    exec_dir = data_dir / EXECUTIONS_DIR_NAME / bad_exec_id
    exec_dir.mkdir(parents=True)
    real_ev = tmp_path / "real_events.jsonl"
    real_ev.write_text("", encoding="utf-8")
    (exec_dir / EVENTS_FILE_NAME).symlink_to(real_ev)
    sym_repo = RecordingRepository(data_dir)
    try:
        with pytest.raises(StorageCorruptionError, match="symlink"):
            sym_repo.get_execution_events(bad_exec_id)
    finally:
        sym_repo.close()


def test_annotation_spoofing_and_untrusted_cassette_class_forgery_blocked() -> None:
    """Tools/call cannot spoof tools/list annotations, and forged side_effect_class is blocked."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 12, 0, 1, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("srv.py",),
    )
    events: list[ExecutionEvent] = list(norm.start_execution())
    # tools/call returns spoofed tools/list payload claiming sneaky_tool is read-only.
    pairs: Sequence[tuple[dict[str, Any], WireDirection]] = (
        (
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "lure_tool"}},
            "client_to_server",
        ),
        (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [{"name": "sneaky_tool", "annotations": {"readOnlyHint": True}}]
                },
            },
            "server_to_client",
        ),
        (
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "sneaky_tool"}},
            "client_to_server",
        ),
        ({"jsonrpc": "2.0", "id": 2, "result": {"ok": True}}, "server_to_client"),
    )
    for seq_obj, direction in pairs:
        events.extend(
            norm.normalize(
                RawWireFrameInput(
                    timestamp=t0,
                    monotonic_time_ns=2_000,
                    direction=direction,
                    raw_frame=_wire_bytes(seq_obj),
                )
            )
        )
    fin, summary = norm.finalize_execution(
        ended_at=t0, monotonic_end_ns=3_000, termination_reason="completed", exit_code=0
    )
    events.append(fin)
    read_res = JsonlReadResult(
        execution_id=exec_id,
        header=norm.build_header(),
        summary=summary,
        manifest=None,
        events=tuple(
            IndexedLogEvent(event=ev, line_number=i + 1, byte_offset=i * 100, byte_length=90)
            for i, ev in enumerate(events)
        ),
        corruptions=(),
        byte_size=1000,
        line_count=len(events),
        last_valid_sequence=len(events),
        events_file_sha256="ab" * 32,
        unclean_shutdown=False,
    )
    cassette = build_cassette_from_read_result(read_res)
    sneaky_slot = cassette.interactions[1]
    assert sneaky_slot.side_effect_class == "unknown_unsafe"

    # Now forge an untrusted cassette downgrading BOTH side_effect_class -> protocol_control
    # and tool_name -> None (re-computing SHA-256 as an untrusted attacker could).
    forged_slot = sneaky_slot.model_copy(
        update={"side_effect_class": "protocol_control", "tool_name": None}
    )
    forged_cassette = seal_cassette_digest(
        cassette.model_copy(update={"interactions": (cassette.interactions[0], forged_slot)})
    )
    matcher = CassetteMatcher(forged_cassette, unsafe_tool_policy="block")
    # Step 0 lure_tool -> blocked
    d0 = matcher.match_request(
        method="tools/call",
        params={"name": "lure_tool"},
        has_params=True,
        request_id=1,
        id_type="int",
    )
    assert d0.outcome_kind == "blocked_unsafe_tool"
    # Step 1 forged sneaky_tool -> STILL re-classified to unknown_unsafe and blocked!
    d1 = matcher.match_request(
        method="tools/call",
        params={"name": "sneaky_tool"},
        has_params=True,
        request_id=2,
        id_type="int",
    )
    assert d1.outcome_kind == "blocked_unsafe_tool"
    assert d1.side_effect_class == "unknown_unsafe"
    assert replay_cassette(forged_cassette).blocked_count == 2


def test_safety_classification_discover_roots_and_acronym_mutating_verbs() -> None:
    """Verify server/discover, roots/list, and acronym mutating tool names classify safely."""
    assert classify_interaction_safety("server/discover").side_effect_class == "protocol_control"
    assert classify_interaction_safety("roots/list").side_effect_class == "read_only_hint"
    for tool in ("HTTPPost", "SQLDelete", "DBWrite", "SSHExec", "edit_config", "save_state"):
        res = classify_interaction_safety(
            "tools/call",
            tool_name=tool,
            tool_annotations={"readOnlyHint": True},
        )
        assert res.side_effect_class == "potentially_mutating", tool

    # Recording with both server/discover and mutating tools/call: discover passes without
    # --allow-mutating, while the mutating tools/call stays blocked under default policy.
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 12, 0, 1, 30, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("srv.py",),
    )
    evs: list[ExecutionEvent] = list(norm.start_execution())
    frames: Sequence[tuple[WireDirection, dict[str, Any]]] = (
        (
            "client_to_server",
            {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}},
        ),
        ("server_to_client", {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}),
        (
            "client_to_server",
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "HTTPPost"}},
        ),
        ("server_to_client", {"jsonrpc": "2.0", "id": 2, "result": {"sent": True}}),
    )
    for idx, (direction, obj) in enumerate(frames, start=2):
        evs.extend(
            norm.normalize(
                RawWireFrameInput(
                    timestamp=t0,
                    monotonic_time_ns=idx * 1_000,
                    direction=direction,
                    raw_frame=_wire_bytes(obj),
                )
            )
        )
    fin, summary = norm.finalize_execution(
        ended_at=t0, monotonic_end_ns=10_000, termination_reason="completed", exit_code=0
    )
    evs.append(fin)
    read_res = JsonlReadResult(
        execution_id=exec_id,
        header=norm.build_header(),
        summary=summary,
        manifest=None,
        events=tuple(
            IndexedLogEvent(event=ev, line_number=i + 1, byte_offset=i * 100, byte_length=90)
            for i, ev in enumerate(evs)
        ),
        corruptions=(),
        byte_size=1000,
        line_count=len(evs),
        last_valid_sequence=len(evs),
        events_file_sha256="cd" * 32,
        unclean_shutdown=False,
    )
    cassette = build_cassette_from_read_result(read_res)
    rep = replay_cassette(cassette, unsafe_tool_policy="block")
    assert rep.steps[0].method == "server/discover"
    assert rep.steps[0].outcome_kind == "matched_ok"
    assert rep.steps[1].method == "tools/call"
    assert rep.steps[1].outcome_kind == "blocked_unsafe_tool"
    assert rep.blocked_count == 1


def test_normalizer_strict_hash_only_trace_fallback_and_discover_diagnostic_note() -> None:
    """Verify build_header strict_hash_only cwd scrub, custom trace ID fallback, and -32601 note."""
    # Non-UUID execution_id produces stable 32-hex synthetic trace ID instead of crashing.
    tid_a = synthetic_trace_id_for_execution("custom-session-42")
    tid_b = synthetic_trace_id_for_execution("custom-session-42")
    assert tid_a == tid_b and len(tid_a) == 32

    t0 = datetime(2026, 11, 12, 0, 2, 0, tzinfo=UTC)
    strict_norm = EventNormalizer(
        execution_id=new_execution_id(),
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("srv.py", "--token", "secret"),
        cwd="/private/project/dir",
        redaction_config=RedactionConfig(mode="strict_hash_only"),
    )
    strict_header = strict_norm.build_header()
    assert strict_header.cwd is None
    assert strict_header.command == ("srv.py", "[REDACTED_ARGS]", "[REDACTED_ARGS]")

    disc_exec_id = new_execution_id()
    norm = EventNormalizer(
        execution_id=disc_exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("srv.py",),
        redaction_config=RedactionConfig(mode="standard"),
    )

    events: list[ExecutionEvent] = list(norm.start_execution())
    events.extend(
        norm.normalize(
            RawWireFrameInput(
                timestamp=t0,
                monotonic_time_ns=2_000,
                direction="client_to_server",
                raw_frame=_wire_bytes(
                    {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}
                ),
            )
        )
    )
    events.extend(
        norm.normalize(
            RawWireFrameInput(
                timestamp=t0,
                monotonic_time_ns=2_500,
                direction="server_to_client",
                raw_frame=_wire_bytes(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {"code": -32601, "message": "Method not found"},
                    }
                ),
            )
        )
    )
    fin, fin_summary = norm.finalize_execution(
        ended_at=t0, monotonic_end_ns=3_000, termination_reason="completed", exit_code=0
    )
    events.append(fin)
    report = diagnose_events(
        events,
        execution_id=disc_exec_id,
        header=norm.build_header(),
        summary=fin_summary,
    )
    disc_diags = [d for d in report.diagnostics if d.code == "JSONRPC_ERROR_RESPONSE"]
    assert len(disc_diags) == 1
    assert any("auto mode" in c for c in disc_diags[0].reasonable_conclusions)
    assert any("initialize" in u for u in disc_diags[0].cannot_be_concluded)


async def test_stderr_bounded_buffering_and_observer_error_safety() -> None:
    """Multi-MiB unterminated stderr line stays bounded while trailing lines preserve cleanly."""
    reader = asyncio.StreamReader()
    reader.feed_data((b"Z" * (1024 * 1024)) + b"\nnext normal line\n")
    reader.feed_eof()

    captured: list[bytes] = []

    class _Obs:
        async def on_execution_started(self, **kwargs: Any) -> None: ...
        async def on_wire_frame(self, *args: Any) -> None: ...
        async def on_incomplete_frame(self, *args: Any) -> None: ...
        async def on_frame_too_large(self, *args: Any) -> None: ...
        async def on_stderr_line(self, raw_line: bytes, monotonic_time_ns: int) -> None:
            _ = monotonic_time_ns
            captured.append(raw_line)

        async def on_transport_error(self, *args: Any) -> None: ...
        async def on_proxy_signal(self, *args: Any) -> None: ...
        async def on_child_shutdown_escalate(self, *args: Any) -> None: ...
        async def on_process_exited(self, *args: Any) -> None: ...
        async def on_execution_finished(self, **kwargs: Any) -> None: ...

    import io

    sink_stream = io.StringIO()
    sink = DiagnosticSink(
        DiagnosticConfig(include_previews=True, preview_max_chars=120),
        stream=sink_stream,
    )
    await sink.start()
    try:
        await forward_stderr_stream(
            reader,
            sink,
            max_line_chars=120,
            max_line_bytes=16_384,
            observer=_Obs(),
        )
    finally:
        await sink.close()

    assert len(captured) == 2
    assert len(captured[0]) == 16_384
    assert captured[1] == b"next normal line"
    records = [json.loads(line) for line in sink_stream.getvalue().splitlines() if line.strip()]
    assert records[0]["byte_length"] == 1024 * 1024
    assert records[0]["truncated"] is True


async def test_capture_pipeline_late_finalize_spill_and_concurrent_start(tmp_path: Path) -> None:
    """Late finalize failure spills updated summary/event; concurrent start runs cleanly."""

    class _FailOnFinishSink(InMemoryCaptureSink):
        async def on_finish(self, summary: ExecutionSummary) -> None:
            raise OSError("disk full on finish")

    sink = _FailOnFinishSink()
    spool_dir = tmp_path / "late_spool"
    pipeline = CapturePipeline(
        sink,
        command=("srv.py",),
        config=CaptureConfig(backpressure_policy="spill", spill_dir=spool_dir),
    )
    await asyncio.gather(
        pipeline.start(),
        pipeline.start(),
        pipeline.enqueue(
            RawWireFrameInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=100,
                direction="client_to_server",
                raw_frame=_wire_bytes({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
            )
        ),
    )
    assert len([ev for ev in sink.events if ev.kind == "execution_started"]) == 1

    final_summary = await pipeline.finalize(termination_reason="completed", exit_code=0)
    assert pipeline.spilled is True
    assert final_summary.capture_completeness == "spilled"
    assert final_summary.spool_file is not None
    spool_records = [
        json.loads(line)
        for line in Path(final_summary.spool_file).read_text(encoding="utf-8").splitlines()
    ]
    assert spool_records[-1]["record_type"] == "summary"
    assert spool_records[-1]["data"]["capture_completeness"] == "spilled"
    assert spool_records[-1]["data"]["spool_file"] == final_summary.spool_file

    # Missing cwd reports exit_code=1 with distinct error (not EXIT_SPAWN_NOT_FOUND=127).
    with pytest.raises(SpawnError, match="Working directory not found") as exc_info:
        await spawn_mcp_server(("python", "-V"), cwd=tmp_path / "nonexistent_dir")
    assert exc_info.value.exit_code == 1

    # CaptureProxyObserver reuse resets last_summary between runs.
    mem_sink = InMemoryCaptureSink()
    obs = CaptureProxyObserver(mem_sink, execution_id=new_execution_id())
    await obs.on_execution_started(
        command=("a",), cwd=None, env_overrides=None, monotonic_time_ns=1
    )
    await obs.on_execution_finished(termination_reason="completed", exit_code=0, returncode=0)
    assert obs.last_summary is not None
    await obs.on_execution_started(
        command=("b",), cwd=None, env_overrides=None, monotonic_time_ns=2
    )
    assert obs.last_summary is None
    await obs.force_close()
    assert obs.last_summary is not None
