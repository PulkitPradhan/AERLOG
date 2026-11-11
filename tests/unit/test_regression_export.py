"""Unit tests for Phase 9 deterministic regression test export, sanitization, and verification."""

from __future__ import annotations

import ast
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aerlog.capture.normalizer import EventNormalizer, RawWireFrameInput
from aerlog.capture.pipeline import CaptureConfig, CapturePipeline
from aerlog.config import AerlogConfig, load_config
from aerlog.events.ids import new_execution_id
from aerlog.events.models import ExecutionEvent
from aerlog.events.types import WireDirection
from aerlog.export import (
    EPOCH_ANCHOR_TIMESTAMP,
    HOME_PATH_PLACEHOLDER,
    REGRESSION_FIXTURE_SCHEMA_VERSION,
    TIMESTAMP_PLACEHOLDER,
    TMP_PATH_PLACEHOLDER,
    TRACEPARENT_PLACEHOLDER,
    UUID_PLACEHOLDER,
    RegressionFixture,
    RegressionFixtureIntegrityError,
    RegressionFixtureSchemaError,
    RegressionFixtureValidationError,
    UnredactedExportRefusedError,
    build_regression_fixture_from_read_result,
    export_execution_regression_test,
    format_regression_failure,
    load_regression_fixture,
    parse_regression_fixture_dict,
    resolve_export_paths,
    run_regression_fixture,
    seal_regression_fixture,
    validate_export_slug,
)
from aerlog.replay import ERR_CASSETTE_MISSING_RESPONSE, build_cassette_from_read_result
from aerlog.storage.event_log import IndexedLogEvent, JsonlReadResult
from aerlog.storage.repositories import RecordingRepository
from aerlog.storage.sink import PersistentCaptureSink


def _wire_bytes(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


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


def _make_read_result(
    events: list[ExecutionEvent],
    *,
    norm: EventNormalizer | None,
    summary: Any,
    exec_id: str,
) -> JsonlReadResult:
    indexed = tuple(
        IndexedLogEvent(event=ev, line_number=idx + 1, byte_offset=idx * 100, byte_length=90)
        for idx, ev in enumerate(events)
    )
    return JsonlReadResult(
        execution_id=exec_id,
        header=norm.build_header() if norm is not None else None,
        summary=summary,
        manifest=None,
        events=indexed,
        corruptions=(),
        byte_size=len(events) * 100,
        line_count=len(events),
        last_valid_sequence=events[-1].sequence if events else 0,
        events_file_sha256="12" * 32,
        unclean_shutdown=summary is None,
    )


def test_export_config_defaults_and_backward_compatibility(tmp_path: Path) -> None:
    """AerlogConfig loads default ExportSettings cleanly and remains TOML backward compatible."""
    default_cfg = AerlogConfig()
    assert default_cfg.export.default_format == "both"
    assert default_cfg.export.normalize_volatile is True
    assert default_cfg.export.sanitize_by_default is True

    legacy_toml = tmp_path / "legacy.toml"
    legacy_toml.write_text('[replay]\ndefault_match_mode = "tolerant"\n', encoding="utf-8")
    loaded_legacy = load_config(legacy_toml)
    assert loaded_legacy.export.default_format == "both"
    assert loaded_legacy.export.normalize_volatile is True
    assert loaded_legacy.export.sanitize_by_default is True

    custom_toml = tmp_path / "custom.toml"
    custom_toml.write_text(
        '[export]\ndefault_format = "json"\nnormalize_volatile = false\n'
        "sanitize_by_default = false\n",
        encoding="utf-8",
    )
    loaded_custom = load_config(custom_toml)
    assert loaded_custom.export.default_format == "json"
    assert loaded_custom.export.normalize_volatile is False
    assert loaded_custom.export.sanitize_by_default is False


def test_export_successful_session_and_offline_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful session exports fixture + static pytest file and verifies strictly offline."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 12, 0, 0, 0, tzinfo=UTC)
    t_end = t0 + timedelta(seconds=2)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("python", "server.py"),
    )
    events: list[ExecutionEvent] = list(norm.start_execution())
    events.extend(
        _wire(
            norm,
            ts=t0 + timedelta(milliseconds=10),
            mono_ns=2_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "id": 10,
                "method": "initialize",
                "params": {"capabilities": {}},
            },
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0 + timedelta(milliseconds=20),
            mono_ns=3_000,
            direction="server_to_client",
            obj={"jsonrpc": "2.0", "id": 10, "result": {"protocolVersion": "2026-07-28"}},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0 + timedelta(milliseconds=30),
            mono_ns=4_000,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0 + timedelta(milliseconds=35),
            mono_ns=4_500,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 11, "method": "tools/list"},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0 + timedelta(milliseconds=38),
            mono_ns=4_800,
            direction="server_to_client",
            obj={
                "jsonrpc": "2.0",
                "id": 11,
                "result": {
                    "tools": [{"name": "search_docs", "annotations": {"readOnlyHint": True}}]
                },
            },
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0 + timedelta(milliseconds=40),
            mono_ns=5_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "id": "req-read-1",
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {"query": "aerlog"}},
            },
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0 + timedelta(milliseconds=50),
            mono_ns=6_000,
            direction="server_to_client",
            obj={
                "jsonrpc": "2.0",
                "id": "req-read-1",
                "result": {
                    "content": [{"type": "text", "text": "matched document"}],
                    "isError": False,
                },
            },
        )
    )
    fin, summary = norm.finalize_execution(
        ended_at=t_end,
        monotonic_end_ns=10_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin)

    read_res = _make_read_result(events, norm=norm, summary=summary, exec_id=exec_id)
    fixture, sanitized_unredacted = build_regression_fixture_from_read_result(read_res)

    assert sanitized_unredacted is False
    assert fixture.fixture_schema_version == REGRESSION_FIXTURE_SCHEMA_VERSION
    assert fixture.fixture_sha256 is not None
    assert fixture.timestamp_anchor_basis == "ended_at"
    assert fixture.anchored_at == t_end
    assert fixture.sanitized_for_export is True
    assert fixture.contains_raw_secrets is False
    assert fixture.expected_overall_status == "clean_match"
    assert fixture.expected_matched_count == 3
    assert len(fixture.steps) == 4

    def _forbid_network_or_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Regression verification must never spawn subprocesses or use network")

    monkeypatch.setattr("subprocess.Popen", _forbid_network_or_spawn)
    monkeypatch.setattr("os.system", _forbid_network_or_spawn)
    monkeypatch.setattr("socket.create_connection", _forbid_network_or_spawn)

    run_res = run_regression_fixture(fixture)
    assert run_res.passed is True
    assert run_res.passed_steps == 4
    assert run_res.failed_steps == 0
    assert run_res.matched_count == 3


def test_export_failure_outcomes_and_diagnostic_linkage() -> None:
    """Exported fixtures pin -32602 error codes, isError=True tool errors, and diagnostics."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 12, 0, 5, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("python", "failing_srv.py"),
    )
    events: list[ExecutionEvent] = list(norm.start_execution())
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=1_500,
            direction="client_to_server",
            obj={"jsonrpc": "2.0", "id": 0, "method": "tools/list"},
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=1_800,
            direction="server_to_client",
            obj={
                "jsonrpc": "2.0",
                "id": 0,
                "result": {
                    "tools": [
                        {"name": "search_docs", "annotations": {"readOnlyHint": True}},
                        {"name": "read_config", "annotations": {"readOnlyHint": True}},
                    ]
                },
            },
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
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
                "error": {"code": -32602, "message": "Invalid params"},
            },
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=3_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_config", "arguments": {"path": "bad"}},
            },
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=3_500,
            direction="server_to_client",
            obj={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"isError": True, "content": [{"type": "text", "text": "missing file"}]},
            },
        )
    )
    fin, summary = norm.finalize_execution(
        ended_at=t0 + timedelta(seconds=1),
        monotonic_end_ns=5_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin)

    read_res = _make_read_result(events, norm=norm, summary=summary, exec_id=exec_id)
    fixture, _ = build_regression_fixture_from_read_result(read_res)

    assert "INVALID_ARGUMENTS_OBSERVED" in fixture.source_diagnostic_codes
    assert "MCP_TOOL_EXECUTION_ERROR" in fixture.source_diagnostic_codes
    assert fixture.steps[1].expected.expected_outcome_kind == "matched_error"
    assert fixture.steps[1].expected.expected_response_kind == "jsonrpc_error"
    assert fixture.steps[1].expected.expected_error_code == -32602
    assert fixture.steps[2].expected.expected_outcome_kind == "matched_tool_error"
    assert fixture.steps[2].expected.expected_response_kind == "jsonrpc_response"
    assert fixture.steps[2].expected.expected_tool_is_error is True

    result = run_regression_fixture(fixture)
    assert result.passed is True


def test_export_missing_response_policies_and_timestamp_anchors() -> None:
    """Missing recorded responses pin -32005/omit and fallback timestamps deterministically."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 12, 0, 10, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("python", "hanging_srv.py"),
    )
    events: list[ExecutionEvent] = list(norm.start_execution())
    events.extend(
        _wire(
            norm,
            ts=t0 + timedelta(seconds=1),
            mono_ns=2_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {"q": "slow"}},
            },
        )
    )

    unclean_res = _make_read_result(events, norm=norm, summary=None, exec_id=exec_id)
    err_fixture, _ = build_regression_fixture_from_read_result(
        unclean_res, unsafe_tool_policy="warn", missing_response_policy="error"
    )
    assert err_fixture.timestamp_anchor_basis == "started_at"
    assert err_fixture.anchored_at == t0
    assert "REQUEST_WITHOUT_RESPONSE" in err_fixture.source_diagnostic_codes
    assert err_fixture.steps[0].expected.expected_outcome_kind == "missing_recorded_response"
    assert err_fixture.steps[0].expected.expected_response_kind == "jsonrpc_error"
    assert err_fixture.steps[0].expected.expected_error_code == ERR_CASSETTE_MISSING_RESPONSE
    assert run_regression_fixture(err_fixture).passed is True

    omit_fixture, _ = build_regression_fixture_from_read_result(
        unclean_res, unsafe_tool_policy="warn", missing_response_policy="omit"
    )
    assert omit_fixture.steps[0].expected.expected_outcome_kind == "missing_recorded_response"
    assert omit_fixture.steps[0].expected.expected_response_kind is None
    assert omit_fixture.steps[0].expected.expected_error_code is None
    assert run_regression_fixture(omit_fixture).passed is True

    empty_res = _make_read_result([], norm=None, summary=None, exec_id=exec_id)
    epoch_fixture, _ = build_regression_fixture_from_read_result(empty_res)
    assert epoch_fixture.timestamp_anchor_basis == "epoch_fallback"
    assert epoch_fixture.anchored_at == EPOCH_ANCHOR_TIMESTAMP


def test_default_sanitization_strips_secrets_and_normalizes_volatiles() -> None:
    """Default export scrubs API keys, Bearer tokens, passwords, paths, timestamps, and UUIDs."""
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 12, 0, 15, 0, tzinfo=UTC)
    norm = EventNormalizer(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=1_000,
        command=("python", "srv.py", "--api-key=raw-cli-secret-888"),
    )
    events: list[ExecutionEvent] = list(norm.start_execution())
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=2_000,
            direction="client_to_server",
            obj={
                "jsonrpc": "2.0",
                "id": "client-uuid-999",
                "method": "tools/call",
                "params": {
                    "name": "search_docs",
                    "_meta": {
                        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                        "tracestate": "rojo=00f067aa0ba902b7",
                    },
                    "arguments": {
                        "api_key": "sk-live-secret-token-777777",
                        "authorization": "Bearer secret-bearer-123456",
                        "password": "my-secret-password",
                        "scratch_path": "/tmp/aerlog-run-xyz/work/input.txt",
                        "home_path": "/home/alice/repos/private/doc.md",
                        "created_at": "2026-11-11T23:55:12.123456Z",
                        "request_uuid": "123e4567-e89b-12d3-a456-426614174000",
                    },
                },
            },
        )
    )
    events.extend(
        _wire(
            norm,
            ts=t0,
            mono_ns=3_000,
            direction="server_to_client",
            obj={
                "jsonrpc": "2.0",
                "id": "client-uuid-999",
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                "Saved under /tmp/run-42/out.json at "
                                "2026-11-11T23:55:13Z id=123e4567-e89b-12d3-a456-426614174000"
                            ),
                        }
                    ],
                    "isError": False,
                },
            },
        )
    )
    fin, summary = norm.finalize_execution(
        ended_at=t0 + timedelta(seconds=1),
        monotonic_end_ns=4_000,
        termination_reason="completed",
        exit_code=0,
        returncode=0,
    )
    events.append(fin)

    read_res = _make_read_result(events, norm=norm, summary=summary, exec_id=exec_id)
    fixture, _ = build_regression_fixture_from_read_result(read_res)
    serialized = fixture.model_dump_json()

    for forbidden in (
        "raw-cli-secret-888",
        "sk-live-secret-token-777777",
        "secret-bearer-123456",
        "my-secret-password",
        "/tmp/aerlog-run-xyz",
        "/home/alice/repos",
        "2026-11-11T23:55:12.123456Z",
        "123e4567-e89b-12d3-a456-426614174000",
        "4bf92f3577b34da6a3ce929d0e0e4736",
    ):
        assert forbidden not in serialized

    for placeholder in (
        TMP_PATH_PLACEHOLDER,
        HOME_PATH_PLACEHOLDER,
        TIMESTAMP_PLACEHOLDER,
        UUID_PLACEHOLDER,
        TRACEPARENT_PLACEHOLDER,
        "[REDACTED",
    ):
        assert placeholder in serialized

    assert fixture.contains_redacted_placeholders is True
    assert fixture.redaction_findings_count >= 1
    assert fixture.normalization.variable_fields
    assert fixture.normalization.constant_fields
    assert run_regression_fixture(fixture).passed is True


async def test_explicit_unredacted_sanitizes_by_default_and_gates_raw_opt_in(
    tmp_path: Path,
) -> None:
    """explicit_unredacted source sanitizes on default export and gates --raw behind opt-in."""
    data_dir = tmp_path / "data"
    exec_id = new_execution_id()
    sink = PersistentCaptureSink(
        data_dir,
        fsync_policy="lifecycle",
        redaction_mode="explicit_unredacted",
    )
    pipeline = CapturePipeline(
        sink,
        command=("python", "raw_srv.py", "--token=cli-raw-secret"),
        config=CaptureConfig(redaction_mode="explicit_unredacted"),
        execution_id=exec_id,
    )
    await pipeline.start()
    t0 = datetime(2026, 11, 12, 0, 20, 0, tzinfo=UTC)
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=1_000,
            direction="client_to_server",
            raw_frame=_wire_bytes(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "search_docs",
                        "arguments": {"api_key": "sk-unredacted-super-secret-5555"},
                    },
                }
            ),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=10),
            monotonic_time_ns=2_000,
            direction="server_to_client",
            raw_frame=_wire_bytes(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
                }
            ),
        )
    )
    await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)

    repo = RecordingRepository(data_dir)
    try:
        out_clean = tmp_path / "out_clean"
        bundle = export_execution_regression_test(
            repo,
            exec_id,
            output_dir=out_clean,
            slug="clean_from_unredacted",
        )
        assert bundle.sanitized_from_unredacted_source is True
        assert bundle.fixture.sanitized_for_export is True
        assert bundle.fixture.contains_raw_secrets is False
        assert "sk-unredacted-super-secret-5555" not in bundle.fixture_path.read_text("utf-8")
        assert "cli-raw-secret" not in bundle.fixture_path.read_text("utf-8")

        with pytest.raises(UnredactedExportRefusedError):
            export_execution_regression_test(
                repo,
                exec_id,
                output_dir=tmp_path / "out_refused",
                slug="refused",
                raw=True,
                allow_unredacted_export=False,
            )

        raw_bundle = export_execution_regression_test(
            repo,
            exec_id,
            output_dir=tmp_path / "out_raw",
            slug="raw_allowed",
            raw=True,
            allow_unredacted_export=True,
        )
        assert raw_bundle.fixture.sanitized_for_export is False
        assert raw_bundle.fixture.contains_raw_secrets is True
        assert stat.S_IMODE(raw_bundle.fixture_path.stat().st_mode) == 0o600
        assert "sk-unredacted-super-secret-5555" in raw_bundle.fixture_path.read_text("utf-8")
        verify_raw = run_regression_fixture(raw_bundle.fixture)
        assert verify_raw.passed is True
        assert verify_raw.contains_raw_secrets is True
    finally:
        repo.close()


async def test_deterministic_reexport_and_static_pytest_ast(tmp_path: Path) -> None:
    """Two exports from identical recording yield byte-for-byte identical fixture and test files."""
    data_dir = tmp_path / "data"
    exec_id = new_execution_id()
    sink = PersistentCaptureSink(data_dir, fsync_policy="lifecycle")
    pipeline = CapturePipeline(
        sink,
        command=("python", "det_srv.py"),
        config=CaptureConfig(redaction_mode="standard"),
        execution_id=exec_id,
    )
    await pipeline.start()
    t0 = datetime(2026, 11, 12, 0, 25, 0, tzinfo=UTC)
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=1_000,
            direction="client_to_server",
            raw_frame=_wire_bytes({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=5),
            monotonic_time_ns=2_000,
            direction="server_to_client",
            raw_frame=_wire_bytes(
                {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2026-07-28"}}
            ),
        )
    )
    await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)

    repo = RecordingRepository(data_dir)
    try:
        out1 = tmp_path / "exp1"
        out2 = tmp_path / "exp2"
        b1 = export_execution_regression_test(repo, exec_id, output_dir=out1, slug="det_case")
        b2 = export_execution_regression_test(repo, exec_id, output_dir=out2, slug="det_case")
        assert b1.overwritten_files == ()
        assert b1.pytest_path is not None and b2.pytest_path is not None
        assert b1.fixture_path.read_bytes() == b2.fixture_path.read_bytes()
        assert b1.pytest_path.read_bytes() == b2.pytest_path.read_bytes()

        # Overwrite on out1 writes byte-identically and tracks overwritten paths.
        b_over = export_execution_regression_test(repo, exec_id, output_dir=out1, slug="det_case")
        assert set(b_over.overwritten_files) == {b1.fixture_path, b1.pytest_path}
        assert b_over.fixture_path.read_bytes() == b1.fixture_path.read_bytes()

        src = b1.pytest_path.read_text("utf-8")
        tree = ast.parse(src)
        assert any(isinstance(node, ast.FunctionDef) for node in tree.body)
        for banned in ("eval(", "exec(", "subprocess", "os.system", "Popen("):
            assert banned not in src
    finally:
        repo.close()


def test_changed_server_drift_detection_and_diff_output() -> None:
    """Override cassettes catch result drift, isError flips, and missing steps safely."""
    base_exec = new_execution_id()
    t0 = datetime(2026, 11, 12, 0, 30, 0, tzinfo=UTC)

    def _build_res(response_obj: dict[str, Any], *, drop_call: bool = False) -> JsonlReadResult:
        norm = EventNormalizer(
            execution_id=base_exec,
            started_at=t0,
            monotonic_start_ns=1_000,
            command=("python", "srv.py"),
        )
        evs: list[ExecutionEvent] = list(norm.start_execution())
        evs.extend(
            _wire(
                norm,
                ts=t0,
                mono_ns=2_000,
                direction="client_to_server",
                obj={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            )
        )
        evs.extend(
            _wire(
                norm,
                ts=t0,
                mono_ns=2_500,
                direction="server_to_client",
                obj={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2026-07-28"}},
            )
        )
        if not drop_call:
            evs.extend(
                _wire(
                    norm,
                    ts=t0,
                    mono_ns=3_000,
                    direction="client_to_server",
                    obj={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "search_docs", "arguments": {"q": "hello"}},
                    },
                )
            )
            resp = {"jsonrpc": "2.0", "id": 2, **response_obj}
            evs.extend(
                _wire(
                    norm,
                    ts=t0,
                    mono_ns=3_500,
                    direction="server_to_client",
                    obj=resp,
                )
            )
        fin, summary = norm.finalize_execution(
            ended_at=t0 + timedelta(seconds=1),
            monotonic_end_ns=5_000,
            termination_reason="completed",
            exit_code=0,
            returncode=0,
        )
        evs.append(fin)
        return _make_read_result(evs, norm=norm, summary=summary, exec_id=base_exec)

    baseline_read = _build_res(
        {
            "result": {
                "isError": False,
                "content": [{"type": "text", "text": "report saved /tmp/run-100/out.txt"}],
            }
        }
    )
    fixture, _ = build_regression_fixture_from_read_result(baseline_read, unsafe_tool_policy="warn")

    # Volatile path change inside result still passes normalized regression checks.
    volatile_only = build_cassette_from_read_result(
        _build_res(
            {
                "result": {
                    "isError": False,
                    "content": [{"type": "text", "text": "report saved /tmp/run-999/out.txt"}],
                }
            }
        )
    )
    assert run_regression_fixture(fixture, override_cassette=volatile_only).passed is True

    # Structural result drift fails with actionable hash/keys diff.
    drifted_content = build_cassette_from_read_result(
        _build_res(
            {
                "result": {
                    "isError": False,
                    "content": [{"type": "text", "text": "COMPLETELY DIFFERENT"}],
                    "extraKey": 123,
                }
            }
        )
    )
    fail_res = run_regression_fixture(fixture, override_cassette=drifted_content)
    assert fail_res.passed is False
    assert any(f.field == "normalized_result_sha256" for f in fail_res.failures)
    diff_txt = format_regression_failure(fail_res)
    assert "step #1" in diff_txt
    assert "search_docs" in diff_txt
    assert "normalized_result_sha256" in diff_txt

    # Flipped isError fails cleanly.
    flipped_error = build_cassette_from_read_result(
        _build_res({"result": {"isError": True, "content": [{"type": "text", "text": "err"}]}})
    )
    err_res = run_regression_fixture(fixture, override_cassette=flipped_error)
    assert err_res.passed is False
    assert any(f.field == "tool_is_error" for f in err_res.failures)

    # Missing step on override cassette reports unmatched_request divergence cleanly.
    dropped_cassette = build_cassette_from_read_result(_build_res({}, drop_call=True))
    dropped_res = run_regression_fixture(fixture, override_cassette=dropped_cassette)
    assert dropped_res.passed is False
    assert dropped_res.unmatched_count == 1


def test_fixture_integrity_schema_extra_fields_and_slug_validation(tmp_path: Path) -> None:
    """Tampered digests, unknown schema versions, extra keys, and unsafe slugs fail closed."""
    exec_id = new_execution_id()
    empty_res = _make_read_result([], norm=None, summary=None, exec_id=exec_id)
    fixture, _ = build_regression_fixture_from_read_result(empty_res)

    payload = json.loads(fixture.model_dump_json())
    tampered = dict(payload)
    tampered["source_capture_completeness"] = "tampered"
    tampered_path = tmp_path / "tampered.fixture.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(RegressionFixtureIntegrityError):
        load_regression_fixture(tampered_path)

    newer_schema = dict(payload)
    newer_schema["fixture_schema_version"] = "2.0.0"
    with pytest.raises(RegressionFixtureSchemaError):
        parse_regression_fixture_dict(newer_schema)

    extra_field = dict(payload)
    extra_field["unexpected"] = True
    with pytest.raises(RegressionFixtureValidationError):
        parse_regression_fixture_dict(extra_field)

    assert validate_export_slug("valid_slug_123") == "valid_slug_123"
    for bad_slug in ("", "../evil", "/etc/passwd", "sub/dir", "win\\path", "BadSlug", "bad-slug"):
        with pytest.raises(ValueError):
            validate_export_slug(bad_slug)
        with pytest.raises(ValueError):
            resolve_export_paths(tmp_path, bad_slug)

    assert isinstance(
        seal_regression_fixture(RegressionFixture.model_validate(payload)), RegressionFixture
    )
