"""CLI and real MCP SDK client integration tests for Phase 8 offline cassette replay."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from mcp import Client, StdioServerParameters
from mcp.types import TextContent

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
_PYTHON = sys.executable

_REAL_SDK_SERVER_CODE = """
import sys
import anyio
from mcp.server.mcpserver import Context, MCPServer

mcp = MCPServer("aerlog-phase8-source-server")

@mcp.tool()
async def echo_progress(text: str, ctx: Context) -> str:
    await ctx.report_progress(1, 2, "step1")
    await anyio.sleep(0.01)
    await ctx.report_progress(2, 2, "step2")
    return f"echo:{text}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
"""


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


async def _record_mixed_safety_execution(
    data_dir: Path,
    *,
    redaction_mode: RedactionMode = "standard",
) -> str:
    exec_id = new_execution_id()
    sink = PersistentCaptureSink(data_dir, fsync_policy="lifecycle", redaction_mode=redaction_mode)
    pipeline = CapturePipeline(
        sink,
        command=("python", "orig_srv.py", "--api-key=secret-orig-cmd"),
        config=CaptureConfig(redaction_mode=redaction_mode),
        execution_id=exec_id,
    )
    await pipeline.start()
    t0 = datetime(2026, 11, 11, 23, 30, 0, tzinfo=UTC)

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
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=2),
            monotonic_time_ns=3_000_000,
            direction="client_to_server",
            raw_frame=_wire_frame({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        )
    )
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=t0 + timedelta(milliseconds=3),
            monotonic_time_ns=4_000_000,
            direction="server_to_client",
            raw_frame=_wire_frame(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "tools": [
                            {"name": "read_profile", "annotations": {"readOnlyHint": True}},
                            {"name": "delete_user", "annotations": {"destructiveHint": True}},
                        ]
                    },
                }
            ),
        )
    )
    for req_id, tool_name in ((3, "read_profile"), (4, "delete_user"), (5, "mystery_tool")):
        await pipeline.enqueue(
            RawWireFrameInput(
                timestamp=t0 + timedelta(milliseconds=req_id * 2),
                monotonic_time_ns=req_id * 2_000_000,
                direction="client_to_server",
                raw_frame=_wire_frame(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "method": "tools/call",
                        "params": {
                            "name": tool_name,
                            "arguments": {"api_key": "param-secret-leak-check"},
                        },
                    }
                ),
            )
        )
        await pipeline.enqueue(
            RawWireFrameInput(
                timestamp=t0 + timedelta(milliseconds=req_id * 2 + 1),
                monotonic_time_ns=req_id * 2_000_000 + 500_000,
                direction="server_to_client",
                raw_frame=_wire_frame(
                    {"jsonrpc": "2.0", "id": req_id, "result": {"called": tool_name}}
                ),
            )
        )
    await pipeline.enqueue(
        RawStderrLineInput(
            timestamp=t0 + timedelta(milliseconds=12),
            monotonic_time_ns=15_000_000,
            raw_line=b"INFO: secret=stderr-secret-should-not-leak\n",
        )
    )
    await pipeline.enqueue(
        RawProcessExitedInput(
            timestamp=t0 + timedelta(milliseconds=15),
            monotonic_time_ns=20_000_000,
            returncode=0,
        )
    )
    await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)
    return exec_id


def test_cli_replay_and_cassette_read_only_on_empty_xdg(
    isolated_xdg: IsolatedXdgPaths,
) -> None:
    """Missing storage and --mode live fail cleanly without creating XDG directories or DBs."""
    xdg_env = {
        "HOME": str(isolated_xdg.home),
        "XDG_CONFIG_HOME": str(isolated_xdg.config_home),
        "XDG_DATA_HOME": str(isolated_xdg.data_home),
    }
    missing_id = new_execution_id()

    for cmd in (
        ("cassette", "create", missing_id),
        ("cassette", "inspect", missing_id),
        ("replay", missing_id),
        ("replay", "--mode", "live", missing_id),
    ):
        res = _run_aerlog_cli(*cmd, env_overrides=xdg_env)
        assert res.returncode == 1
        assert res.stdout == ""
        assert res.stderr.strip() != ""

    assert not isolated_xdg.config_home.exists()
    assert not isolated_xdg.data_home.exists()


async def test_cli_cassette_create_inspect_replay_isolation_and_mutating_gate(
    tmp_path: Path,
) -> None:
    """Full cassette create -> inspect -> replay workflow keeping originals immutable."""
    data_dir = tmp_path / "aerlog-data"
    exec_id = await _record_mixed_safety_execution(data_dir, redaction_mode="standard")
    events_file = data_dir / EXECUTIONS_DIR_NAME / exec_id / EVENTS_FILE_NAME
    orig_events_hash = _file_sha256(events_file)

    # 1. Create cassette and verify saved path under <data_dir>/cassettes/
    create_res = _run_aerlog_cli(
        "cassette", "create", exec_id, "--json", "--data-dir", str(data_dir)
    )
    assert create_res.returncode == 0
    assert create_res.stderr == ""
    created = json.loads(create_res.stdout)
    cassette_id = created["cassette_id"]
    cassette_path = Path(created["cassette_path"])
    assert cassette_path.is_file()
    assert cassette_path.parent == (data_dir / "cassettes").resolve()
    assert "param-secret-leak-check" not in create_res.stdout
    assert "secret-orig-cmd" not in create_res.stdout

    # 2. Inspect cassette by UUID read-only
    insp_res = _run_aerlog_cli(
        "cassette", "inspect", cassette_id, "--json", "--data-dir", str(data_dir)
    )
    assert insp_res.returncode == 0
    assert insp_res.stderr == ""
    assert json.loads(insp_res.stdout)["cassette_id"] == cassette_id

    # 3. Default replay blocks delete_user (potentially_mutating) & mystery_tool (unknown_unsafe)
    blocked_res = _run_aerlog_cli("replay", exec_id, "--json", "--data-dir", str(data_dir))
    assert blocked_res.returncode == 0
    assert blocked_res.stderr == ""
    blocked = json.loads(blocked_res.stdout)
    assert blocked["is_replay"] is True
    assert blocked["blocked_count"] == 2
    assert blocked["overall_status"] == "diverged"
    report_path = Path(blocked["report_path"])
    assert report_path.is_file()
    assert report_path == data_dir / "replays" / blocked["replay_id"] / "report.json"

    # --fail-on-divergence returns exit code 2
    gated = _run_aerlog_cli("replay", exec_id, "--fail-on-divergence", "--data-dir", str(data_dir))
    assert gated.returncode == 2

    # 4. Replay from --cassette without execution_id + --allow-mutating opts in cleanly.
    allowed_res = _run_aerlog_cli(
        "replay",
        "--cassette",
        str(cassette_path),
        "--allow-mutating",
        "--fail-on-divergence",
        "--json",
        "--data-dir",
        str(data_dir),
    )
    assert allowed_res.returncode == 0
    allowed = json.loads(allowed_res.stdout)
    assert allowed["overall_status"] == "matched_with_warnings"
    assert allowed["matched_count"] == 5
    assert allowed["safety_warning_count"] == 2

    # 5. Original execution files and catalog stay completely untouched.
    assert _file_sha256(events_file) == orig_events_hash
    exec_list = json.loads(
        _run_aerlog_cli("executions", "list", "--json", "--data-dir", str(data_dir)).stdout
    )
    assert exec_list["returned_count"] == 1
    assert exec_list["executions"][0]["execution_id"] == exec_id


async def test_cli_unredacted_cassette_gate_warnings_and_live_mode_blocked(
    tmp_path: Path,
) -> None:
    """explicit_unredacted refuses cassette build without opt-in and warns on stderr on load."""
    data_dir = tmp_path / "aerlog-data"
    unred_id = await _record_mixed_safety_execution(data_dir, redaction_mode="explicit_unredacted")

    refused_create = _run_aerlog_cli("cassette", "create", unred_id, "--data-dir", str(data_dir))
    assert refused_create.returncode == 1
    assert "--allow-unredacted-cassette" in refused_create.stderr

    refused_replay = _run_aerlog_cli("replay", unred_id, "--data-dir", str(data_dir))
    assert refused_replay.returncode == 1
    assert "--allow-unredacted-cassette" in refused_replay.stderr

    ok_create = _run_aerlog_cli(
        "cassette",
        "create",
        unred_id,
        "--allow-unredacted-cassette",
        "--json",
        "--data-dir",
        str(data_dir),
    )
    assert ok_create.returncode == 0
    assert "WARNING:" in ok_create.stderr
    c_meta = json.loads(ok_create.stdout)
    assert c_meta["contains_raw_secrets"] is True
    c_path = c_meta["cassette_path"]

    load_replay = _run_aerlog_cli(
        "replay", "--cassette", c_path, "--allow-mutating", "--json", "--data-dir", str(data_dir)
    )
    assert load_replay.returncode == 0
    assert "WARNING:" in load_replay.stderr
    assert "contains_raw_secrets=True" in load_replay.stderr
    assert json.loads(load_replay.stdout)["contains_raw_secrets"] is True

    live_refused = _run_aerlog_cli(
        "replay", unred_id, "--mode", "live", "--data-dir", str(data_dir)
    )
    assert live_refused.returncode == 1
    assert "Live replay mode is blocked" in live_refused.stderr


async def test_cli_replay_serve_with_real_mcp_sdk_client(tmp_path: Path) -> None:
    """Real mcp.Client works offline against ``aerlog replay --serve`` after server deletion."""
    data_dir = tmp_path / "aerlog-data"
    server_script = tmp_path / "ephemeral_sdk_server.py"
    server_script.write_text(_REAL_SDK_SERVER_CODE, encoding="utf-8")

    wrapper_script = tmp_path / "capture_wrapper.py"
    wrapper_script.write_text(
        (
            "import asyncio, sys\n"
            "from pathlib import Path\n"
            "from aerlog.capture.observer import CaptureProxyObserver\n"
            "from aerlog.capture.pipeline import CaptureConfig\n"
            "from aerlog.proxy.stdio_proxy import ProxyConfig, StdioProxy\n"
            "from aerlog.storage.sink import PersistentCaptureSink\n"
            "data_dir = Path(sys.argv[1])\n"
            "exec_id = sys.argv[2]\n"
            "cmd = tuple(sys.argv[3:])\n"
            "sink = PersistentCaptureSink(data_dir, fsync_policy='lifecycle')\n"
            "obs = CaptureProxyObserver(sink, config=CaptureConfig(), execution_id=exec_id)\n"
            "res = asyncio.run(StdioProxy(ProxyConfig(command=cmd)).run(observer=obs))\n"
            "raise SystemExit(res.exit_code)\n"
        ),
        encoding="utf-8",
    )

    exec_id = new_execution_id()
    proxy_params = StdioServerParameters(
        command=_PYTHON,
        args=[str(wrapper_script), str(data_dir), exec_id, _PYTHON, str(server_script)],
    )

    orig_progress: list[tuple[float, float | None, str | None]] = []

    async def on_orig_progress(progress: float, total: float | None, message: str | None) -> None:
        orig_progress.append((progress, total, message))

    async with Client(proxy_params) as client:
        tools_res = await client.list_tools()
        assert [t.name for t in tools_res.tools] == ["echo_progress"]
        call_res = await client.call_tool(
            "echo_progress",
            {"text": "offline-replay"},
            progress_callback=on_orig_progress,
        )
        assert isinstance(call_res.content[0], TextContent)
        assert call_res.content[0].text == "echo:offline-replay"

    # Delete original server script completely to guarantee zero live server contact!
    server_script.unlink()
    assert not server_script.exists()

    # 2. Connect a fresh mcp.Client directly to offline `aerlog replay <exec_id> --serve`.
    replay_server_params = StdioServerParameters(
        command=_PYTHON,
        args=[
            "-m",
            "aerlog",
            "replay",
            exec_id,
            "--serve",
            "--match",
            "tolerant",
            "--allow-mutating",
            "--data-dir",
            str(data_dir),
        ],
    )
    replayed_progress: list[tuple[float, float | None, str | None]] = []

    async def on_replay_progress(progress: float, total: float | None, message: str | None) -> None:
        replayed_progress.append((progress, total, message))

    async with Client(replay_server_params) as replay_client:
        rep_tools = await replay_client.list_tools()
        assert [t.name for t in rep_tools.tools] == ["echo_progress"]
        rep_call = await replay_client.call_tool(
            "echo_progress",
            {"text": "offline-replay"},
            progress_callback=on_replay_progress,
        )
        assert isinstance(rep_call.content[0], TextContent)
        assert rep_call.content[0].text == "echo:offline-replay"

    assert replayed_progress == orig_progress
