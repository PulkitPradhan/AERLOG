"""CLI and offline portability integration tests for Phase 9 regression export and verify."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aerlog.capture.normalizer import RawWireFrameInput
from aerlog.capture.pipeline import CaptureConfig, CapturePipeline
from aerlog.events.ids import new_execution_id
from aerlog.events.types import RedactionMode
from aerlog.storage.database import DB_FILE_NAME
from aerlog.storage.event_log import EVENTS_FILE_NAME, EXECUTIONS_DIR_NAME
from aerlog.storage.sink import PersistentCaptureSink
from tests.conftest import IsolatedXdgPaths

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PYTHON = sys.executable


def _run_aerlog_cli(
    *args: str,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        [_PYTHON, "-m", "aerlog", *args],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _wire_frame(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _xdg_env(isolated_xdg: IsolatedXdgPaths) -> dict[str, str]:
    return {
        "HOME": str(isolated_xdg.home),
        "XDG_CONFIG_HOME": str(isolated_xdg.config_home),
        "XDG_DATA_HOME": str(isolated_xdg.data_home),
    }


async def _record_sample_execution(
    data_dir: Path,
    *,
    redaction_mode: RedactionMode = "standard",
    tool_text: str = "search result v1 at /tmp/run-11/data.txt",
    is_error: bool = False,
) -> str:
    exec_id = new_execution_id()
    sink = PersistentCaptureSink(data_dir, fsync_policy="lifecycle", redaction_mode=redaction_mode)
    pipeline = CapturePipeline(
        sink,
        command=("python", "srv.py", "--api-key=cli-raw-secret-123"),
        config=CaptureConfig(redaction_mode=redaction_mode),
        execution_id=exec_id,
    )
    await pipeline.start()
    t0 = datetime(2026, 11, 12, 0, 40, 0, tzinfo=UTC)
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=1_000,
            direction="client_to_server",
            raw_frame=_wire_frame({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=5),
            monotonic_time_ns=2_000,
            direction="server_to_client",
            raw_frame=_wire_frame(
                {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2026-07-28"}}
            ),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=6),
            monotonic_time_ns=2_200,
            direction="client_to_server",
            raw_frame=_wire_frame({"jsonrpc": "2.0", "id": 10, "method": "tools/list"}),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=8),
            monotonic_time_ns=2_500,
            direction="server_to_client",
            raw_frame=_wire_frame(
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "result": {
                        "tools": [{"name": "search_docs", "annotations": {"readOnlyHint": True}}]
                    },
                }
            ),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=10),
            monotonic_time_ns=3_000,
            direction="client_to_server",
            raw_frame=_wire_frame(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "search_docs",
                        "arguments": {
                            "query": "status",
                            "api_key": "sk-cli-raw-secret-98765",
                        },
                    },
                }
            ),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=20),
            monotonic_time_ns=4_000,
            direction="server_to_client",
            raw_frame=_wire_frame(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "isError": is_error,
                        "content": [{"type": "text", "text": tool_text}],
                    },
                }
            ),
        )
    )
    await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)
    return exec_id


def test_export_missing_xdg_storage_creates_nothing(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """Missing storage exits 1 cleanly without creating XDG dirs, aerlog.db, or outputs."""
    out_dir = tmp_path / "never_created"
    env = _xdg_env(isolated_xdg)
    res = _run_aerlog_cli(
        "export",
        "test",
        new_execution_id(),
        "--output",
        str(out_dir),
        "--name",
        "missing_case",
        env_overrides=env,
    )
    assert res.returncode == 1
    assert "No AERLOG storage found" in res.stderr
    assert not (isolated_xdg.data_home / "aerlog").exists()
    assert not (isolated_xdg.data_home / "aerlog" / DB_FILE_NAME).exists()
    assert not out_dir.exists()


async def test_cli_export_pytest_portability_and_overwrite_notices(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """Exported fixture + pytest run offline via subprocess pytest cleanly and overwrite cleanly."""
    data_dir = isolated_xdg.data_home / "aerlog"
    exec_id = await _record_sample_execution(data_dir, redaction_mode="standard")
    events_path = data_dir / EXECUTIONS_DIR_NAME / exec_id / EVENTS_FILE_NAME
    events_digest_before = _file_sha256(events_path)

    env = _xdg_env(isolated_xdg)
    out_dir = tmp_path / "generated"

    first = _run_aerlog_cli(
        "export",
        "test",
        exec_id,
        "--output",
        str(out_dir),
        "--name",
        "my_reg_case",
        env_overrides=env,
    )
    assert first.returncode == 0, first.stderr
    assert "AERLOG REGRESSION EXPORT" in first.stdout
    assert "NOTICE: Overwrote" not in first.stderr

    fixture_file = out_dir / "my_reg_case.fixture.json"
    pytest_file = out_dir / "test_my_reg_case.py"
    assert fixture_file.is_file()
    assert pytest_file.is_file()
    assert _file_sha256(events_path) == events_digest_before

    # Run exported test strictly standalone in a portable copy directory with storage removed!
    portable_dir = tmp_path / "portable_copy"
    portable_dir.mkdir()
    shutil.copy2(fixture_file, portable_dir / fixture_file.name)
    shutil.copy2(pytest_file, portable_dir / pytest_file.name)
    shutil.rmtree(data_dir)

    portable_env = _xdg_env(isolated_xdg)
    pytest_proc = subprocess.run(
        [_PYTHON, "-m", "pytest", str(portable_dir / pytest_file.name), "-q"],
        cwd=_REPO_ROOT,
        env=portable_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert pytest_proc.returncode == 0, pytest_proc.stdout + pytest_proc.stderr
    assert not data_dir.exists()

    # Recreate data for deterministic overwrite verification.
    data_dir2 = tmp_path / "data2"
    exec_id2 = await _record_sample_execution(data_dir2, redaction_mode="standard")
    overwrite_dir = tmp_path / "overwrite_target"
    run1 = _run_aerlog_cli(
        "export",
        "test",
        exec_id2,
        "--output",
        str(overwrite_dir),
        "--name",
        "det_overwrite",
        "--data-dir",
        str(data_dir2),
        env_overrides=env,
    )
    assert run1.returncode == 0, run1.stderr
    b_fix_1 = (overwrite_dir / "det_overwrite.fixture.json").read_bytes()
    b_py_1 = (overwrite_dir / "test_det_overwrite.py").read_bytes()

    run2 = _run_aerlog_cli(
        "export",
        "test",
        exec_id2,
        "--output",
        str(overwrite_dir),
        "--name",
        "det_overwrite",
        "--data-dir",
        str(data_dir2),
        env_overrides=env,
    )
    assert run2.returncode == 0, run2.stderr
    assert "NOTICE: Overwrote existing export artifact" in run2.stderr
    assert (overwrite_dir / "det_overwrite.fixture.json").read_bytes() == b_fix_1
    assert (overwrite_dir / "test_det_overwrite.py").read_bytes() == b_py_1


async def test_cli_export_format_json_config_unredacted_and_slug_validation(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """Test --format json, TOML [export], explicit_unredacted sanitization, --raw, and bad slugs."""
    data_dir = tmp_path / "data"
    exec_id = await _record_sample_execution(data_dir, redaction_mode="explicit_unredacted")
    env = _xdg_env(isolated_xdg)

    # Default export on explicit_unredacted sanitizes silently to stdout JSON + WARNING on stderr.
    out_sanitized = tmp_path / "sanitized"
    san_proc = _run_aerlog_cli(
        "export",
        "test",
        exec_id,
        "--output",
        str(out_sanitized),
        "--name",
        "sanitized_json_only",
        "--format",
        "json",
        "--json",
        "--data-dir",
        str(data_dir),
        env_overrides=env,
    )
    assert san_proc.returncode == 0, san_proc.stderr
    assert "WARNING:" in san_proc.stderr
    payload = json.loads(san_proc.stdout)
    assert payload["sanitized_for_export"] is True
    assert payload["sanitized_from_unredacted_source"] is True
    assert payload["contains_raw_secrets"] is False
    assert payload["pytest_path"] is None
    assert not (out_sanitized / "test_sanitized_json_only.py").exists()
    assert "sk-cli-raw-secret-98765" not in (
        out_sanitized / "sanitized_json_only.fixture.json"
    ).read_text("utf-8")

    # --raw without --allow-unredacted-export fails closed with code 1.
    out_refused = tmp_path / "refused"
    refused = _run_aerlog_cli(
        "export",
        "test",
        exec_id,
        "--output",
        str(out_refused),
        "--name",
        "refused_raw",
        "--raw",
        "--data-dir",
        str(data_dir),
        env_overrides=env,
    )
    assert refused.returncode == 1
    assert "--allow-unredacted-export" in refused.stderr
    assert not out_refused.exists()

    # --raw + --allow-unredacted-export writes 0o600 fixture & warns on stderr without raw echoes.
    out_raw = tmp_path / "raw_allowed"
    raw_proc = _run_aerlog_cli(
        "export",
        "test",
        exec_id,
        "--output",
        str(out_raw),
        "--name",
        "raw_allowed",
        "--raw",
        "--allow-unredacted-export",
        "--json",
        "--data-dir",
        str(data_dir),
        env_overrides=env,
    )
    assert raw_proc.returncode == 0, raw_proc.stderr
    assert "WARNING:" in raw_proc.stderr
    raw_json = json.loads(raw_proc.stdout)
    assert raw_json["contains_raw_secrets"] is True
    assert "sk-cli-raw-secret-98765" not in raw_proc.stdout
    raw_fix = out_raw / "raw_allowed.fixture.json"
    assert stat.S_IMODE(raw_fix.stat().st_mode) == 0o600
    assert "sk-cli-raw-secret-98765" in raw_fix.read_text("utf-8")

    # Config [export].default_format = "json" applies when --format is omitted.
    cfg_path = tmp_path / "aerlog.toml"
    cfg_path.write_text('[export]\ndefault_format = "json"\n', encoding="utf-8")
    out_cfg = tmp_path / "cfg_out"
    cfg_proc = _run_aerlog_cli(
        "export",
        "test",
        exec_id,
        "--output",
        str(out_cfg),
        "--name",
        "from_cfg",
        "--config",
        str(cfg_path),
        "--data-dir",
        str(data_dir),
        env_overrides=env,
    )
    assert cfg_proc.returncode == 0, cfg_proc.stderr
    assert (out_cfg / "from_cfg.fixture.json").is_file()
    assert not (out_cfg / "test_from_cfg.py").exists()

    # Bad slugs exit 1 before touching disk.
    for bad_slug in ("../escape", "Bad-Name"):
        bad_res = _run_aerlog_cli(
            "export",
            "test",
            exec_id,
            "--output",
            str(tmp_path / "bad_out"),
            "--name",
            bad_slug,
            "--data-dir",
            str(data_dir),
            env_overrides=env,
        )
        assert bad_res.returncode == 1
        assert "Export option error" in bad_res.stderr


async def test_cli_export_verify_pass_drift_and_tamper(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """aerlog export verify exits 0 on pass, 2 on changed-server cassette drift, and 1 on tamper."""
    data_dir = tmp_path / "data"
    env = _xdg_env(isolated_xdg)
    base_exec = await _record_sample_execution(
        data_dir,
        redaction_mode="standard",
        tool_text="stable response v1",
        is_error=False,
    )
    drifted_exec = await _record_sample_execution(
        data_dir,
        redaction_mode="standard",
        tool_text="CHANGED RESPONSE V2",
        is_error=True,
    )

    out_dir = tmp_path / "exported"
    exp_proc = _run_aerlog_cli(
        "export",
        "test",
        base_exec,
        "--output",
        str(out_dir),
        "--name",
        "drift_check",
        "--data-dir",
        str(data_dir),
        env_overrides=env,
    )
    assert exp_proc.returncode == 0, exp_proc.stderr
    fixture_path = out_dir / "drift_check.fixture.json"

    pass_proc = _run_aerlog_cli(
        "export",
        "verify",
        str(fixture_path),
        "--json",
        env_overrides=env,
    )
    assert pass_proc.returncode == 0, pass_proc.stderr
    pass_json = json.loads(pass_proc.stdout)
    assert pass_json["passed"] is True

    drifted_cassette_path = tmp_path / "drifted.cassette.json"
    cas_proc = _run_aerlog_cli(
        "cassette",
        "create",
        drifted_exec,
        "--output",
        str(drifted_cassette_path),
        "--data-dir",
        str(data_dir),
        env_overrides=env,
    )
    assert cas_proc.returncode == 0, cas_proc.stderr

    drift_text = _run_aerlog_cli(
        "export",
        "verify",
        str(fixture_path),
        "--cassette",
        str(drifted_cassette_path),
        env_overrides=env,
    )
    assert drift_text.returncode == 2
    assert "FAILED" in drift_text.stdout
    assert "REGRESSION FAILURES" in drift_text.stdout
    assert "search_docs" in drift_text.stdout

    drift_json_proc = _run_aerlog_cli(
        "export",
        "verify",
        str(fixture_path),
        "--cassette",
        str(drifted_cassette_path),
        "--json",
        env_overrides=env,
    )
    assert drift_json_proc.returncode == 2
    drift_json = json.loads(drift_json_proc.stdout)
    assert drift_json["passed"] is False
    assert drift_json["failed_steps"] >= 1
    assert any(f["field"] == "tool_is_error" for f in drift_json["failures"])

    tampered = json.loads(fixture_path.read_text("utf-8"))
    tampered["source_capture_completeness"] = "tampered"
    tampered_path = tmp_path / "tampered.fixture.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    tamper_proc = _run_aerlog_cli(
        "export",
        "verify",
        str(tampered_path),
        env_overrides=env,
    )
    assert tamper_proc.returncode == 1
    assert "Verification error" in tamper_proc.stderr
