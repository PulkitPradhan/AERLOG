"""CLI integration tests for Phase 6 read-only inspection and timeline reconstruction."""

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
    """Invoke ``python -m aerlog`` in a subprocess for strict stdout/stderr separation."""
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


async def _record_sample_execution(
    data_dir: Path,
    *,
    command: tuple[str, ...],
    redaction_mode: RedactionMode = "standard",
    cwd: str | None = None,
    env_overrides: dict[str, str] | None = None,
    pair_count: int = 1,
    include_secrets: bool = True,
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
        command=command,
        cwd=cwd,
        env_overrides=env_overrides,
        config=CaptureConfig(redaction_mode=redaction_mode),
        execution_id=exec_id,
    )
    await pipeline.start()

    base_ts = datetime(2026, 11, 11, 20, 0, 0, tzinfo=UTC)
    mono_ns = 10_000_000

    for idx in range(1, pair_count + 1):
        method = "initialize" if idx == 1 else "tools/call"
        params: dict[str, Any]
        if idx == 1 and include_secrets:
            params = {
                "protocolVersion": "2025-11-25",
                "clientInfo": {"name": "cli-test"},
                "_meta": {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
            }
        elif include_secrets:
            params = {
                "name": "fetch_data",
                "arguments": {
                    "api_key": "raw-param-secret-1234",
                    "query": "SELECT 1",
                },
                "_meta": {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
            }
        else:
            params = {"name": "ping_tool", "arguments": {"n": idx}}

        await pipeline.enqueue(
            RawWireFrameInput(
                timestamp=base_ts + timedelta(milliseconds=idx * 2),
                monotonic_time_ns=mono_ns + idx * 2_000_000,
                direction="client_to_server",
                raw_frame=_wire_frame(
                    {
                        "jsonrpc": "2.0",
                        "id": idx,
                        "method": method,
                        "params": params,
                    }
                ),
            )
        )

        result_payload: dict[str, Any]
        if include_secrets and idx > 1:
            result_payload = {
                "content": [
                    {
                        "type": "text",
                        "text": "Authorization: Bearer super-secret-result-token",
                    }
                ]
            }
        else:
            result_payload = {"ok": True, "step": idx}

        await pipeline.enqueue(
            RawWireFrameInput(
                timestamp=base_ts + timedelta(milliseconds=idx * 2 + 1),
                monotonic_time_ns=mono_ns + idx * 2_000_000 + 500_000,
                direction="server_to_client",
                raw_frame=_wire_frame({"jsonrpc": "2.0", "id": idx, "result": result_payload}),
            )
        )

    if include_secrets:
        await pipeline.enqueue(
            RawStderrLineInput(
                timestamp=base_ts + timedelta(seconds=1),
                monotonic_time_ns=mono_ns + 999_000_000,
                raw_line=b"ERROR: password=stderr-secret-xyz failed to connect\n",
            )
        )

    await pipeline.enqueue(
        RawProcessExitedInput(
            timestamp=base_ts + timedelta(seconds=1, milliseconds=10),
            monotonic_time_ns=mono_ns + 1_010_000_000,
            returncode=0,
        )
    )
    await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)
    return exec_id


def test_cli_read_only_commands_on_nonexistent_xdg_storage(
    isolated_xdg: IsolatedXdgPaths,
) -> None:
    """Read-only commands work safely and never create XDG dirs or aerlog.db."""
    xdg_env = {
        "HOME": str(isolated_xdg.home),
        "XDG_CONFIG_HOME": str(isolated_xdg.config_home),
        "XDG_DATA_HOME": str(isolated_xdg.data_home),
    }
    missing_id = new_execution_id()

    list_res = _run_aerlog_cli("executions", "list", env_overrides=xdg_env)
    assert list_res.returncode == 0
    assert "No recorded executions found." in list_res.stdout
    assert list_res.stderr == ""

    list_json = _run_aerlog_cli("executions", "list", "--json", env_overrides=xdg_env)
    assert list_json.returncode == 0
    assert list_json.stderr == ""
    parsed_list = json.loads(list_json.stdout)
    assert parsed_list["executions"] == []
    assert parsed_list["returned_count"] == 0

    inspect_missing = _run_aerlog_cli("inspect", missing_id, env_overrides=xdg_env)
    assert inspect_missing.returncode == 1
    assert inspect_missing.stdout == ""
    assert "Inspection error:" in inspect_missing.stderr

    timeline_missing = _run_aerlog_cli("timeline", missing_id, env_overrides=xdg_env)
    assert timeline_missing.returncode == 1
    assert timeline_missing.stdout == ""
    assert "Timeline error:" in timeline_missing.stderr

    assert not isolated_xdg.config_home.exists()
    assert not isolated_xdg.data_home.exists()


async def test_cli_end_to_end_persisted_redaction_and_default_view_privacy(
    tmp_path: Path,
) -> None:
    """CLI overview and timeline omit secrets, private cwd, env vars, and raw payloads."""
    data_dir = tmp_path / "aerlog-data"
    exec_id = await _record_sample_execution(
        data_dir,
        command=("python", "server.py", "--api-key=super-secret-cmd-value"),
        cwd="/home/alice/private-repo-secret",
        env_overrides={"MY_SECRET_TOKEN": "topsecret-env-token"},
        pair_count=2,
        include_secrets=True,
    )

    list_res = _run_aerlog_cli("executions", "list", "--data-dir", str(data_dir))
    assert list_res.returncode == 0
    assert list_res.stderr == ""
    assert exec_id in list_res.stdout
    assert "super-secret-cmd-value" not in list_res.stdout

    list_json_res = _run_aerlog_cli(
        "executions", "list", "--status", "complete", "--json", "--data-dir", str(data_dir)
    )
    assert list_json_res.returncode == 0
    assert list_json_res.stderr == ""
    list_payload = json.loads(list_json_res.stdout)
    assert list_payload["returned_count"] == 1
    assert list_payload["executions"][0]["execution_id"] == exec_id
    assert "super-secret-cmd-value" not in list_json_res.stdout

    bad_status = _run_aerlog_cli(
        "executions", "list", "--status", "bogus", "--data-dir", str(data_dir)
    )
    assert bad_status.returncode == 1
    assert "Invalid --status" in bad_status.stderr

    forbidden_secrets = (
        "raw-param-secret-1234",
        "super-secret-result-token",
        "stderr-secret-xyz",
        "private-repo-secret",
        "topsecret-env-token",
        "super-secret-cmd-value",
    )

    for cmd_args in (
        ("inspect", exec_id, "--data-dir", str(data_dir)),
        ("inspect", exec_id, "--json", "--data-dir", str(data_dir)),
        ("timeline", exec_id, "--data-dir", str(data_dir)),
        ("timeline", exec_id, "--json", "--data-dir", str(data_dir)),
    ):
        res = _run_aerlog_cli(*cmd_args)
        assert res.returncode == 0
        assert res.stderr == ""
        for secret in forbidden_secrets:
            assert secret not in res.stdout

    inspect_json = json.loads(
        _run_aerlog_cli("inspect", exec_id, "--json", "--data-dir", str(data_dir)).stdout
    )
    assert inspect_json["execution_id"] == exec_id
    assert inspect_json["counts"]["request_count"] == 2
    assert inspect_json["counts"]["response_count"] == 2
    assert any(not grp["is_synthetic"] for grp in inspect_json["trace_groups"])

    # Single-event lookup by --sequence exposes redacted stored event and rejects bad sequence.
    ev_res = _run_aerlog_cli(
        "inspect", exec_id, "--sequence", "3", "--json", "--data-dir", str(data_dir)
    )
    assert ev_res.returncode == 0
    assert ev_res.stderr == ""
    ev_json = json.loads(ev_res.stdout)
    assert ev_json["sequence"] == 3
    assert "raw-param-secret-1234" not in ev_res.stdout

    bad_seq = _run_aerlog_cli("inspect", exec_id, "--sequence", "9999", "--data-dir", str(data_dir))
    assert bad_seq.returncode == 1
    assert "Inspection error:" in bad_seq.stderr


async def test_cli_timeline_pagination_limit_200_and_filters(tmp_path: Path) -> None:
    """Timeline defaults to 200 entries with explicit truncation and filter support."""
    data_dir = tmp_path / "aerlog-data"
    exec_id = await _record_sample_execution(
        data_dir,
        command=("python", "bulk_server.py"),
        pair_count=110,  # 220 wire frames + startup/process_exit/finished > 200
        include_secrets=False,
    )

    default_text = _run_aerlog_cli("timeline", exec_id, "--data-dir", str(data_dir))
    assert default_text.returncode == 0
    assert "[TRUNCATED]" in default_text.stdout
    assert "Pass --offset 200 --limit 200 to inspect more." in default_text.stdout

    page1_res = _run_aerlog_cli("timeline", exec_id, "--json", "--data-dir", str(data_dir))
    assert page1_res.returncode == 0
    assert page1_res.stderr == ""
    page1 = json.loads(page1_res.stdout)
    assert page1["limit"] == 200
    assert page1["offset"] == 0
    assert page1["returned_entries"] == 200
    assert page1["truncated"] is True
    assert page1["remaining_entries"] == page1["filtered_entries"] - 200

    page2_res = _run_aerlog_cli(
        "timeline", exec_id, "--offset", "200", "--json", "--data-dir", str(data_dir)
    )
    assert page2_res.returncode == 0
    page2 = json.loads(page2_res.stdout)
    assert page2["truncated"] is False
    assert page2["remaining_entries"] == 0
    assert page2["returned_entries"] == page1["remaining_entries"]

    filtered_res = _run_aerlog_cli(
        "timeline",
        exec_id,
        "--method",
        "tools/call",
        "--direction",
        "client_to_server",
        "--json",
        "--data-dir",
        str(data_dir),
    )
    assert filtered_res.returncode == 0
    filtered = json.loads(filtered_res.stdout)
    assert filtered["filtered_entries"] == 109
    assert all(
        e["method"] == "tools/call" and e["direction"] == "client_to_server"
        for e in filtered["entries"]
    )


async def test_cli_unredacted_warning_stderr_only_and_json_stdout_purity(
    tmp_path: Path,
) -> None:
    """explicit_unredacted emits WARNING to stderr only without breaking --json stdout."""
    data_dir = tmp_path / "aerlog-data"
    exec_id = await _record_sample_execution(
        data_dir,
        command=("python", "server.py", "--token=visible-only-in-unredacted"),
        redaction_mode="explicit_unredacted",
        pair_count=1,
        include_secrets=False,
    )

    for subcmd in (
        ("inspect", exec_id, "--json", "--data-dir", str(data_dir)),
        ("inspect", exec_id, "--sequence", "2", "--json", "--data-dir", str(data_dir)),
        ("timeline", exec_id, "--json", "--data-dir", str(data_dir)),
    ):
        res = _run_aerlog_cli(*subcmd)
        assert res.returncode == 0
        assert "WARNING:" in res.stderr
        assert "explicit_unredacted" in res.stderr
        parsed = json.loads(res.stdout)
        assert parsed["redaction_mode"] == "explicit_unredacted"


async def test_cli_corruption_tolerant_vs_strict_and_unindexed_disk_fallback(
    tmp_path: Path,
) -> None:
    """Commands fall back read-only without aerlog.db and respect --strict on corrupt JSONL."""
    data_dir = tmp_path / "aerlog-data"
    exec_corrupt = await _record_sample_execution(
        data_dir,
        command=("python", "srv_corrupt.py"),
        pair_count=1,
        include_secrets=False,
    )
    exec_clean = await _record_sample_execution(
        data_dir,
        command=("python", "srv_clean.py"),
        pair_count=1,
        include_secrets=False,
    )

    events_path = data_dir / EXECUTIONS_DIR_NAME / exec_corrupt / EVENTS_FILE_NAME
    with events_path.open("ab") as fh:
        fh.write(b'{"record_schema_version":1,"truncated')

    db_path = data_dir / "aerlog.db"
    for suffix in ("", "-wal", "-shm"):
        candidate = data_dir / f"aerlog.db{suffix}"
        if candidate.exists():
            candidate.unlink()

    # Listing works purely from JSONL directories without creating aerlog.db.
    list_res = _run_aerlog_cli("executions", "list", "--json", "--data-dir", str(data_dir))
    assert list_res.returncode == 0
    listed = json.loads(list_res.stdout)
    statuses = {row["execution_id"]: row["capture_completeness"] for row in listed["executions"]}
    assert statuses[exec_corrupt] == "corrupted"
    assert statuses[exec_clean] == "complete"
    assert not db_path.exists()

    # Tolerant timeline reconstructs valid prefix and surfaces explicit corruption marker.
    tolerant = _run_aerlog_cli("timeline", exec_corrupt, "--json", "--data-dir", str(data_dir))
    assert tolerant.returncode == 0
    assert "WARNING:" in tolerant.stderr
    tl_json = json.loads(tolerant.stdout)
    assert tl_json["has_corruptions"] is True
    assert len(tl_json["corruption_markers"]) == 1
    assert not db_path.exists()

    # --strict fails non-zero on both inspect and timeline.
    strict_tl = _run_aerlog_cli("timeline", exec_corrupt, "--strict", "--data-dir", str(data_dir))
    assert strict_tl.returncode == 1
    assert "Timeline error:" in strict_tl.stderr

    strict_insp = _run_aerlog_cli("inspect", exec_corrupt, "--strict", "--data-dir", str(data_dir))
    assert strict_insp.returncode == 1
    assert "Inspection error:" in strict_insp.stderr

    bad_id = _run_aerlog_cli("inspect", "not-a-uuid", "--data-dir", str(data_dir))
    assert bad_id.returncode == 1
    assert "Inspection error:" in bad_id.stderr
