"""End-to-end Phase 10 integration tests covering the full AERLOG CLI lifecycle."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcp import Client, StdioServerParameters
from mcp.types import TextContent

from aerlog import __version__
from aerlog.events.ids import new_execution_id
from tests.conftest import IsolatedXdgPaths

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PYTHON = sys.executable

_WORKFLOW_MCP_SERVER_CODE = """
import sys
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

tag = "v1"
for arg in sys.argv[1:]:
    if arg.startswith("--server-tag="):
        tag = arg.split("=", 1)[1]

mcp = MCPServer("aerlog-phase10-workflow-server")

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def lookup_status(item: str, api_key: str) -> str:
    sys.stderr.write("stderr authorization: Bearer leaked-stderr-token-999\\n")
    sys.stderr.flush()
    return f"{tag}:{item}"

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def intentional_fail() -> str:
    raise RuntimeError("simulated server tool failure")

if __name__ == "__main__":
    mcp.run(transport="stdio")
"""


def _xdg_env(isolated_xdg: IsolatedXdgPaths) -> dict[str, str]:
    env = os.environ.copy()
    env["HOME"] = str(isolated_xdg.home)
    env["XDG_CONFIG_HOME"] = str(isolated_xdg.config_home)
    env["XDG_DATA_HOME"] = str(isolated_xdg.data_home)
    env.pop("AERLOG_CONFIG", None)
    return env


def _run_aerlog_cli(
    *args: str,
    env: dict[str, str],
    stdin_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_PYTHON, "-m", "aerlog", *args],
        cwd=_REPO_ROOT,
        env=env,
        input=stdin_text,
        capture_output=True,
        text=True,
        check=False,
    )


def _ndjson(*objs: dict[str, Any]) -> str:
    return "".join(json.dumps(obj, separators=(",", ":")) + "\n" for obj in objs)


async def test_full_cli_lifecycle_run_list_inspect_timeline_diagnose_replay_export_verify(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """Exercise run -> list -> inspect -> timeline -> diagnose -> replay -> export -> verify."""
    env = _xdg_env(isolated_xdg)
    server_script = tmp_path / "workflow_server.py"
    server_script.write_text(_WORKFLOW_MCP_SERVER_CODE, encoding="utf-8")

    # 1. Verify --version and shell completion never create XDG files.
    ver_res = _run_aerlog_cli("--version", env=env)
    assert ver_res.returncode == 0
    assert ver_res.stdout.strip() == f"aerlog {__version__}"
    assert ver_res.stderr == ""

    comp_res = subprocess.run(
        ["bash", "-c", f'"{_PYTHON}" -m aerlog --show-completion; exit $?'],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert comp_res.returncode == 0
    assert "_COMPLETE" in comp_res.stdout
    assert not (isolated_xdg.config_home / "aerlog").exists()
    assert not (isolated_xdg.data_home / "aerlog").exists()

    # 2. Prove stdout protocol purity and --quiet behavior via deterministic NDJSON stdio piping.
    echo_ndjson_srv = tmp_path / "echo_ndjson.py"
    echo_ndjson_srv.write_text(
        "import json, sys\n"
        "for raw in sys.stdin:\n"
        "    msg = json.loads(raw)\n"
        "    if 'id' in msg:\n"
        "        sys.stderr.write('stderr authorization: Bearer leaked-direct-999\\n')\n"
        "        sys.stderr.flush()\n"
        "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], "
        "'result': {'ok': True}}) + '\\n')\n"
        "        sys.stdout.flush()\n",
        encoding="utf-8",
    )
    ndjson_input = _ndjson(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
    )
    direct_run = _run_aerlog_cli(
        "run",
        "--",
        _PYTHON,
        str(echo_ndjson_srv),
        "--api-key=cli-raw-secret-111",
        env=env,
        stdin_text=ndjson_input,
    )
    assert direct_run.returncode == 0, direct_run.stderr
    stdout_lines = [line for line in direct_run.stdout.splitlines() if line.strip()]
    assert len(stdout_lines) == 2
    for line in stdout_lines:
        parsed_frame = json.loads(line)
        assert parsed_frame["jsonrpc"] == "2.0"
        assert parsed_frame["result"] == {"ok": True}
    assert "[aerlog] Recording MCP execution" in direct_run.stderr
    assert "cli-raw-secret-111" not in direct_run.stderr
    assert "leaked-direct-999" not in direct_run.stdout

    quiet_run = _run_aerlog_cli(
        "run",
        "--quiet",
        "--",
        _PYTHON,
        str(echo_ndjson_srv),
        env=env,
        stdin_text=_ndjson({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
    )
    assert quiet_run.returncode == 0, quiet_run.stderr
    assert quiet_run.stderr == ""
    assert json.loads(quiet_run.stdout.strip())["id"] == 1

    # 3. Record full real MCP SDK client workflow via `aerlog run --quiet`.
    v1_exec_id = new_execution_id()
    v1_params = StdioServerParameters(
        command=_PYTHON,
        args=[
            "-m",
            "aerlog",
            "run",
            "--quiet",
            "--execution-id",
            v1_exec_id,
            "--",
            _PYTHON,
            str(server_script),
            "--server-tag=v1",
            "--api-key=sk-cmd-secret-abc",
        ],
        env=env,
    )
    async with Client(v1_params, mode="legacy") as client:
        listed_tools = await client.list_tools()
        assert [t.name for t in listed_tools.tools] == ["lookup_status", "intentional_fail"]

        ok_res = await client.call_tool(
            "lookup_status",
            {"item": "alpha", "api_key": "sk-sdk-live-secret-999"},
        )
        assert isinstance(ok_res.content[0], TextContent)
        assert ok_res.content[0].text == "v1:alpha"

        err_res = await client.call_tool("intentional_fail", {})
        assert err_res.is_error is True

    # 4. List alias parity (`aerlog list` == `aerlog executions list`).
    list_text = _run_aerlog_cli("list", env=env)
    exec_list_text = _run_aerlog_cli("executions", "list", env=env)
    assert list_text.returncode == 0
    assert exec_list_text.returncode == 0
    assert list_text.stdout == exec_list_text.stdout
    assert list_text.stderr == ""

    list_json = _run_aerlog_cli("list", "--json", env=env)
    exec_list_json = _run_aerlog_cli("executions", "list", "--json", env=env)
    assert list_json.returncode == 0
    assert list_json.stdout == exec_list_json.stdout
    executions_payload = json.loads(list_json.stdout)
    recorded_ids = [row["execution_id"] for row in executions_payload["executions"]]
    assert v1_exec_id in recorded_ids

    # 5. Inspect summary, single sequence, and timeline filters + secret redaction checks.
    insp_res = _run_aerlog_cli("inspect", v1_exec_id, env=env)
    assert insp_res.returncode == 0, insp_res.stderr
    assert "sk-sdk-live-secret-999" not in insp_res.stdout
    assert "sk-cmd-secret-abc" not in insp_res.stdout
    assert "leaked-stderr-token-999" not in insp_res.stdout

    seq2_res = _run_aerlog_cli("inspect", v1_exec_id, "--sequence", "2", "--json", env=env)
    assert seq2_res.returncode == 0, seq2_res.stderr
    assert json.loads(seq2_res.stdout)["sequence"] == 2

    tl_filtered = _run_aerlog_cli(
        "timeline",
        v1_exec_id,
        "--direction",
        "client_to_server",
        "--method",
        "tools/call",
        "--json",
        env=env,
    )
    assert tl_filtered.returncode == 0, tl_filtered.stderr
    tl_payload = json.loads(tl_filtered.stdout)
    assert len(tl_payload["entries"]) == 2

    # 6. Diagnose catches the failing MCP tool execution error and triggers --fail-on gate (code 2).
    diag_ok = _run_aerlog_cli("diagnose", v1_exec_id, "--json", env=env)
    assert diag_ok.returncode == 0, diag_ok.stderr
    diag_codes = {item["code"] for item in json.loads(diag_ok.stdout)["diagnostics"]}
    assert "MCP_TOOL_EXECUTION_ERROR" in diag_codes

    diag_gate = _run_aerlog_cli("diagnose", v1_exec_id, "--fail-on", "error", env=env)
    assert diag_gate.returncode == 2

    # 7. Cassette create/inspect & offline replay pass; live replay remains blocked.
    cas_res = _run_aerlog_cli("cassette", "create", v1_exec_id, "--json", env=env)
    assert cas_res.returncode == 0, cas_res.stderr
    cassette_v1_id = json.loads(cas_res.stdout)["cassette_id"]

    cas_insp = _run_aerlog_cli("cassette", "inspect", cassette_v1_id, "--json", env=env)
    assert cas_insp.returncode == 0, cas_insp.stderr
    assert json.loads(cas_insp.stdout)["cassette_id"] == cassette_v1_id

    replay_res = _run_aerlog_cli(
        "replay",
        v1_exec_id,
        "--mode",
        "cassette",
        "--fail-on-divergence",
        "--json",
        env=env,
    )
    assert replay_res.returncode == 0, replay_res.stderr
    assert json.loads(replay_res.stdout)["overall_status"] == "clean_match"

    live_blocked = _run_aerlog_cli("replay", v1_exec_id, "--mode", "live", env=env)
    assert live_blocked.returncode == 1
    assert "Hint:" in live_blocked.stderr

    # 8. Export regression fixture + pytest file, verify standalone, and detect drifted v2 cassette.
    export_dir = tmp_path / "exported_tests"
    exp_res = _run_aerlog_cli(
        "export",
        "test",
        v1_exec_id,
        "--output",
        str(export_dir),
        "--name",
        "workflow_case",
        "--json",
        env=env,
    )
    assert exp_res.returncode == 0, exp_res.stderr
    exp_json = json.loads(exp_res.stdout)
    fixture_path = Path(exp_json["fixture_path"])
    pytest_path = Path(exp_json["pytest_path"])
    assert fixture_path.is_file()
    assert pytest_path.is_file()

    verify_ok = _run_aerlog_cli("export", "verify", str(fixture_path), "--json", env=env)
    assert verify_ok.returncode == 0, verify_ok.stderr
    assert json.loads(verify_ok.stdout)["passed"] is True

    # Verify UUID resolution via `--cassette <uuid>` works cleanly.
    verify_uuid_ok = _run_aerlog_cli(
        "export",
        "verify",
        str(fixture_path),
        "--cassette",
        cassette_v1_id,
        "--json",
        env=env,
    )
    assert verify_uuid_ok.returncode == 0, verify_uuid_ok.stderr
    assert json.loads(verify_uuid_ok.stdout)["passed"] is True

    pytest_run = subprocess.run(
        [_PYTHON, "-m", "pytest", str(pytest_path), "-q"],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert pytest_run.returncode == 0, pytest_run.stdout + pytest_run.stderr

    # Record v2 drifted execution via `aerlog run`, create cassette v2, and trigger verify exit 2.
    v2_exec_id = new_execution_id()
    v2_params = StdioServerParameters(
        command=_PYTHON,
        args=[
            "-m",
            "aerlog",
            "run",
            "--quiet",
            "--execution-id",
            v2_exec_id,
            "--",
            _PYTHON,
            str(server_script),
            "--server-tag=v2-DRIFTED",
        ],
        env=env,
    )
    async with Client(v2_params, mode="legacy") as client_v2:
        await client_v2.list_tools()
        await client_v2.call_tool("lookup_status", {"item": "alpha", "api_key": "sk-v2"})
        await client_v2.call_tool("intentional_fail", {})

    cas_v2 = _run_aerlog_cli("cassette", "create", v2_exec_id, "--json", env=env)
    assert cas_v2.returncode == 0, cas_v2.stderr
    cassette_v2_id = json.loads(cas_v2.stdout)["cassette_id"]

    verify_drift = _run_aerlog_cli(
        "export",
        "verify",
        str(fixture_path),
        "--cassette",
        cassette_v2_id,
        "--json",
        env=env,
    )
    assert verify_drift.returncode == 2
    drift_json = json.loads(verify_drift.stdout)
    assert drift_json["passed"] is False
    assert any(f["field"] == "normalized_result_sha256" for f in drift_json["failures"])


def test_cli_run_exit_codes_quiet_errors_and_actionable_failures(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """Verify run pass-through exit codes (127, 42), quiet critical errors, and failure hints."""
    env = _xdg_env(isolated_xdg)

    missing_bin = _run_aerlog_cli(
        "run",
        "--quiet",
        "--",
        str(tmp_path / "nonexistent_mcp_binary_xyz"),
        env=env,
    )
    assert missing_bin.returncode == 127
    assert missing_bin.stdout == ""
    assert "Run error:" in missing_bin.stderr

    failing_script = tmp_path / "exit42.py"
    failing_script.write_text("import sys\nsys.exit(42)\n", encoding="utf-8")
    child_fail = _run_aerlog_cli("run", "--", _PYTHON, str(failing_script), env=env)
    assert child_fail.returncode == 42
    assert child_fail.stdout == ""
    assert "exit_code=42" in child_fail.stderr

    refused_raw = _run_aerlog_cli(
        "run",
        "--redaction-mode",
        "explicit_unredacted",
        "--",
        _PYTHON,
        "-c",
        "pass",
        env=env,
    )
    assert refused_raw.returncode == 1
    assert "--allow-unredacted" in refused_raw.stderr
    assert "Hint:" in refused_raw.stderr

    missing_exec = _run_aerlog_cli("inspect", new_execution_id(), env=env)
    assert missing_exec.returncode == 1
    assert "Inspection error:" in missing_exec.stderr
    assert "Hint:" in missing_exec.stderr

    bad_syntax = _run_aerlog_cli("list", "--unknown-flag-xyz", env=env)
    assert bad_syntax.returncode == 2
