"""CLI integration tests for Phase 7 read-only ``aerlog diagnose`` command."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aerlog.capture.normalizer import (
    RawProcessExitedInput,
    RawStderrLineInput,
    RawWireFrameInput,
)
from aerlog.capture.pipeline import CaptureConfig, CapturePipeline
from aerlog.events.ids import new_execution_id
from aerlog.events.types import RedactionMode
from aerlog.storage.event_log import EVENTS_FILE_NAME, EXECUTIONS_DIR_NAME
from aerlog.storage.sink import PersistentCaptureSink
from tests.conftest import IsolatedXdgPaths

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_aerlog_cli(
    *args: str,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Invoke ``python -m aerlog`` via subprocess for OS-level stdout/stderr verification."""
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-m", "aerlog", *args],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _wire_frame(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


async def _record_healthy_execution(data_dir: Path) -> str:
    exec_id = new_execution_id()
    sink = PersistentCaptureSink(data_dir, fsync_policy="lifecycle")
    pipeline = CapturePipeline(
        sink,
        command=("python", "healthy_srv.py"),
        config=CaptureConfig(redaction_mode="standard"),
        execution_id=exec_id,
    )
    await pipeline.start()
    t0 = datetime(2026, 11, 11, 22, 0, 0, tzinfo=UTC)
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=1_000_000,
            direction="client_to_server",
            raw_frame=_wire_frame({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=1),
            monotonic_time_ns=2_000_000,
            direction="server_to_client",
            raw_frame=_wire_frame({"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}}),
        )
    )
    await pipeline.enqueue(
        RawStderrLineInput(
            timestamp=t0 + timedelta(milliseconds=2),
            monotonic_time_ns=3_000_000,
            raw_line=b"INFO: server running cleanly\n",
        )
    )
    await pipeline.enqueue(
        RawProcessExitedInput(
            timestamp=t0 + timedelta(milliseconds=5),
            monotonic_time_ns=5_000_000,
            returncode=0,
        )
    )
    await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)
    return exec_id


async def _record_failing_execution(
    data_dir: Path,
    *,
    redaction_mode: RedactionMode = "standard",
) -> str:
    exec_id = new_execution_id()
    sink = PersistentCaptureSink(
        data_dir,
        fsync_policy="lifecycle",
        redaction_mode=redaction_mode,
        persist_cwd=False,
    )
    pipeline = CapturePipeline(
        sink,
        command=("python", "bad_srv.py", "--api-key=cli-cmd-secret-abc"),
        cwd="/home/bob/private-repo-secret",
        env_overrides={"API_TOKEN": "cli-env-secret-xyz"},
        config=CaptureConfig(redaction_mode=redaction_mode),
        execution_id=exec_id,
    )
    await pipeline.start()
    t0 = datetime(2026, 11, 11, 22, 5, 0, tzinfo=UTC)

    # Slow/errored tool call + unanswered call + non-zero exit + secret-bearing stderr.
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0,
            monotonic_time_ns=10_000_000,
            direction="client_to_server",
            raw_frame=_wire_frame(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "query_db",
                        "arguments": {"token": "param-secret-999"},
                    },
                }
            ),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=30),
            monotonic_time_ns=40_000_000,  # 30ms duration
            direction="server_to_client",
            raw_frame=_wire_frame(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {
                        "code": -32603,
                        "message": "Upstream rejected Authorization: Bearer err-secret-456",
                    },
                }
            ),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=35),
            monotonic_time_ns=45_000_000,
            direction="client_to_server",
            raw_frame=_wire_frame({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        )
    )
    await pipeline.enqueue(
        RawStderrLineInput(
            timestamp=t0 + timedelta(milliseconds=40),
            monotonic_time_ns=50_000_000,
            raw_line=b"FATAL: password=stderr-secret-777 crash\n",
        )
    )
    await pipeline.enqueue(
        RawProcessExitedInput(
            timestamp=t0 + timedelta(milliseconds=45),
            monotonic_time_ns=55_000_000,
            returncode=2,
        )
    )
    await pipeline.finalize(termination_reason="server_exited", exit_code=2, returncode=2)
    return exec_id


def test_cli_diagnose_read_only_on_nonexistent_xdg_storage(
    isolated_xdg: IsolatedXdgPaths,
) -> None:
    """aerlog diagnose on missing XDG storage exits 1 cleanly without creating XDG dirs or DB."""
    xdg_env = {
        "HOME": str(isolated_xdg.home),
        "XDG_CONFIG_HOME": str(isolated_xdg.config_home),
        "XDG_DATA_HOME": str(isolated_xdg.data_home),
    }
    res = _run_aerlog_cli("diagnose", new_execution_id(), env_overrides=xdg_env)
    assert res.returncode == 1
    assert res.stdout == ""
    assert "Diagnostics error:" in res.stderr
    assert not isolated_xdg.config_home.exists()
    assert not isolated_xdg.data_home.exists()


async def test_cli_diagnose_healthy_and_error_executions_with_strict_privacy(
    tmp_path: Path,
) -> None:
    """Healthy runs emit zero findings; failing runs link evidence without leaking secrets."""
    data_dir = tmp_path / "aerlog-data"
    healthy_id = await _record_healthy_execution(data_dir)
    fail_id = await _record_failing_execution(data_dir, redaction_mode="standard")

    # Healthy CLI output
    healthy_txt = _run_aerlog_cli("diagnose", healthy_id, "--data-dir", str(data_dir))
    assert healthy_txt.returncode == 0
    assert healthy_txt.stderr == ""
    assert "No observable diagnostic issues detected." in healthy_txt.stdout

    healthy_json_res = _run_aerlog_cli(
        "diagnose", healthy_id, "--json", "--data-dir", str(data_dir)
    )
    assert healthy_json_res.returncode == 0
    assert healthy_json_res.stderr == ""
    healthy_json = json.loads(healthy_json_res.stdout)
    assert healthy_json["total_diagnostics"] == 0
    assert healthy_json["diagnostics"] == []

    # Failing run text + JSON privacy check
    forbidden_secrets = (
        "cli-cmd-secret-abc",
        "private-repo-secret",
        "cli-env-secret-xyz",
        "param-secret-999",
        "err-secret-456",
        "stderr-secret-777",
    )
    for args in (
        ("diagnose", fail_id, "--data-dir", str(data_dir)),
        ("diagnose", fail_id, "--json", "--data-dir", str(data_dir)),
    ):
        res = _run_aerlog_cli(*args)
        assert res.returncode == 0
        assert res.stderr == ""
        for secret in forbidden_secrets:
            assert secret not in res.stdout

    fail_json = json.loads(
        _run_aerlog_cli("diagnose", fail_id, "--json", "--data-dir", str(data_dir)).stdout
    )
    codes = {d["code"] for d in fail_json["diagnostics"]}
    assert {
        "JSONRPC_ERROR_RESPONSE",
        "REQUEST_WITHOUT_RESPONSE",
        "UNEXPECTED_PROCESS_EXIT",
    }.issubset(codes)
    for diag in fail_json["diagnostics"]:
        assert diag["evidence"]
        assert diag["event_ids"]
        assert diag["sequence_numbers"]
        assert diag["cannot_be_concluded"]
        assert diag["additional_evidence_needed"]


async def test_cli_diagnose_timeout_filters_config_and_fail_on_exit_codes(
    tmp_path: Path,
) -> None:
    """Verify --request-timeout-ms, --min-severity, --fail-on exit code 2, and --config."""
    data_dir = tmp_path / "aerlog-data"
    healthy_id = await _record_healthy_execution(data_dir)
    fail_id = await _record_failing_execution(data_dir)

    # Healthy execution passes even with --fail-on info.
    ok_gate = _run_aerlog_cli(
        "diagnose", healthy_id, "--fail-on", "info", "--data-dir", str(data_dir)
    )
    assert ok_gate.returncode == 0

    # Configured timeout triggers CONFIGURED_REQUEST_TIMEOUT_EXCEEDED cleanly via CLI or TOML.
    timeout_res = _run_aerlog_cli(
        "diagnose",
        fail_id,
        "--request-timeout-ms",
        "10",
        "--json",
        "--data-dir",
        str(data_dir),
    )
    assert timeout_res.returncode == 0
    assert timeout_res.stderr == ""
    t_json = json.loads(timeout_res.stdout)
    assert any(d["code"] == "CONFIGURED_REQUEST_TIMEOUT_EXCEEDED" for d in t_json["diagnostics"])

    cfg_toml = tmp_path / "aerlog.toml"
    cfg_toml.write_text("[diagnostics]\nrequest_timeout_ms = 10\n", encoding="utf-8")
    cfg_res = _run_aerlog_cli(
        "diagnose",
        fail_id,
        "--config",
        str(cfg_toml),
        "--data-dir",
        str(data_dir),
        "--json",
    )
    assert cfg_res.returncode == 0
    c_json = json.loads(cfg_res.stdout)
    assert any(d["code"] == "CONFIGURED_REQUEST_TIMEOUT_EXCEEDED" for d in c_json["diagnostics"])

    # --min-severity error filters out warning while preserving unfiltered count.
    filtered_res = _run_aerlog_cli(
        "diagnose",
        fail_id,
        "--request-timeout-ms",
        "10",
        "--min-severity",
        "error",
        "--json",
        "--data-dir",
        str(data_dir),
    )
    assert filtered_res.returncode == 0
    f_json = json.loads(filtered_res.stdout)
    assert f_json["total_diagnostics"] < f_json["unfiltered_total_diagnostics"]
    assert all(d["severity"] in {"error", "critical"} for d in f_json["diagnostics"])

    # --fail-on error exits 2 and STILL writes pure JSON to stdout.
    fail_gate = _run_aerlog_cli(
        "diagnose",
        fail_id,
        "--fail-on",
        "error",
        "--json",
        "--data-dir",
        str(data_dir),
    )
    assert fail_gate.returncode == 2
    assert fail_gate.stderr == ""
    gated_json = json.loads(fail_gate.stdout)
    assert gated_json["total_diagnostics"] >= 1

    # Invalid severity or UUID exits 1 with stderr error.
    bad_sev = _run_aerlog_cli(
        "diagnose", fail_id, "--fail-on", "bogus", "--data-dir", str(data_dir)
    )
    assert bad_sev.returncode == 1
    assert "Diagnostics option error:" in bad_sev.stderr

    bad_uuid = _run_aerlog_cli("diagnose", "not-a-uuid", "--data-dir", str(data_dir))
    assert bad_uuid.returncode == 1
    assert "Diagnostics error:" in bad_uuid.stderr


async def test_cli_diagnose_corruption_tolerant_vs_strict_and_unredacted_warning(
    tmp_path: Path,
) -> None:
    """Handle corrupt JSONL without creating aerlog.db; stderr warnings stay off --json stdout."""
    data_dir = tmp_path / "aerlog-data"
    corrupt_id = await _record_healthy_execution(data_dir)
    unredacted_id = await _record_failing_execution(data_dir, redaction_mode="explicit_unredacted")

    events_path = data_dir / EXECUTIONS_DIR_NAME / corrupt_id / EVENTS_FILE_NAME
    with events_path.open("ab") as fh:
        fh.write(b'{"record_schema_version":1,"broken')

    db_path = data_dir / "aerlog.db"
    for suffix in ("", "-wal", "-shm"):
        candidate = data_dir / f"aerlog.db{suffix}"
        if candidate.exists():
            candidate.unlink()

    tolerant = _run_aerlog_cli("diagnose", corrupt_id, "--json", "--data-dir", str(data_dir))
    assert tolerant.returncode == 0
    assert "WARNING:" in tolerant.stderr
    t_json = json.loads(tolerant.stdout)
    assert t_json["has_corruptions"] is True
    assert any(d["code"] == "CORRUPT_RECORDING_DETECTED" for d in t_json["diagnostics"])
    assert not db_path.exists()

    strict_err = _run_aerlog_cli("diagnose", corrupt_id, "--strict", "--data-dir", str(data_dir))
    assert strict_err.returncode == 1
    assert "Diagnostics error:" in strict_err.stderr

    unred_res = _run_aerlog_cli("diagnose", unredacted_id, "--json", "--data-dir", str(data_dir))
    assert unred_res.returncode == 0
    assert "WARNING:" in unred_res.stderr
    assert "explicit_unredacted" in unred_res.stderr
    u_json = json.loads(unred_res.stdout)
    assert u_json["redaction_mode"] == "explicit_unredacted"
    assert "stderr-secret-777" not in unred_res.stdout
    assert "param-secret-999" not in unred_res.stdout
