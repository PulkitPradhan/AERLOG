"""Phase 11 compatibility, adverse protocol, large-payload, and end-to-end scale tests."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

import pytest
from mcp import Client, StdioServerParameters
from mcp.types import TextContent

from aerlog.analysis import diagnose_execution, reconstruct_execution_timeline
from aerlog.capture import CaptureConfig, CaptureProxyObserver
from aerlog.events.ids import new_execution_id
from aerlog.events.models import JsonRpcRequestPayload, JsonRpcResponsePayload
from aerlog.export import (
    export_execution_regression_test,
    load_regression_fixture,
    run_regression_fixture,
)
from aerlog.proxy.stdio_proxy import EXIT_FRAME_TOO_LARGE, ProxyConfig, StdioProxy
from aerlog.replay import build_cassette_from_execution, replay_cassette
from aerlog.storage.repositories import RecordingRepository
from aerlog.storage.sink import PersistentCaptureSink
from tests.conftest import IsolatedXdgPaths

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PYTHON = sys.executable


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


async def test_adverse_wire_crlf_utf8_malformed_typed_ids_and_unknown_methods_e2e(
    tmp_path: Path,
) -> None:
    """Malformed JSON, invalid/split UTF-8, CRLF, duplicate/typed IDs, and unknowns stay clean."""
    data_dir = tmp_path / "adverse_data"
    exec_id = new_execution_id()

    # Custom stdio server speaking CRLF/LF, out-of-order responses, unknown fields & methods.
    srv_script = tmp_path / "adverse_srv.py"
    srv_script.write_text(
        "import json, sys\n"
        "pending = []\n"
        "while True:\n"
        "    raw = sys.stdin.buffer.readline()\n"
        "    if not raw:\n"
        "        break\n"
        "    crlf = raw.endswith(b'\\r\\n')\n"
        "    eol = b'\\r\\n' if crlf else b'\\n'\n"
        "    try:\n"
        "        msg = json.loads(raw.decode('utf-8'))\n"
        "    except Exception:\n"
        "        continue\n"
        "    if not isinstance(msg, dict) or 'id' not in msg:\n"
        "        continue\n"
        "    if msg.get('method') == 'custom/defer_one':\n"
        "        pending.append((msg['id'], eol))\n"
        "        continue\n"
        "    resp = {\n"
        "        'jsonrpc': '2.0',\n"
        "        'id': msg['id'],\n"
        "        'result': {'method': msg.get('method'), 'echo': msg.get('params')},\n"
        "        'x_server_ext': 'kept',\n"
        "    }\n"
        "    sys.stdout.buffer.write(json.dumps(resp, ensure_ascii=False).encode('utf-8') + eol)\n"
        "    sys.stdout.buffer.flush()\n"
        "    if msg.get('method') == 'custom/flush_deferred' and pending:\n"
        "        for pid, peol in reversed(pending):\n"
        "            dresp = {'jsonrpc': '2.0', 'id': pid, 'result': {'deferred': True}}\n"
        "            sys.stdout.buffer.write(json.dumps(dresp).encode('utf-8') + peol)\n"
        "            sys.stdout.buffer.flush()\n"
        "        pending.clear()\n",
        encoding="utf-8",
    )

    client_sock, proxy_sock = socket.socketpair()
    client_sock.setblocking(False)
    proxy_sock.setblocking(False)
    cli_reader, cli_writer = await asyncio.open_connection(sock=client_sock)
    proxy_reader, proxy_writer = await asyncio.open_connection(sock=proxy_sock)

    sink = PersistentCaptureSink(data_dir, fsync_policy="lifecycle")
    observer = CaptureProxyObserver(sink, config=CaptureConfig(), execution_id=exec_id)
    proxy = StdioProxy(ProxyConfig(command=(_PYTHON, str(srv_script))))

    with open(os.devnull, "w", encoding="utf-8") as devnull:
        proxy_task = asyncio.create_task(
            proxy.run(
                stdin_reader=proxy_reader,
                stdout_writer=proxy_writer,
                diag_stream=devnull,
                observer=observer,
            )
        )

        # 1. Valid CRLF frame.
        crlf_init = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\r\n'
        cli_writer.write(crlf_init)
        await cli_writer.drain()
        init_reply = await asyncio.wait_for(cli_reader.readline(), timeout=5.0)
        assert init_reply.endswith(b"\r\n")
        assert json.loads(init_reply.decode("utf-8"))["id"] == 1

        # 2. Invalid UTF-8 bytes + malformed JSON must NOT poison later traffic.
        cli_writer.write(b'{"bad_utf8":\xff\xfe}\n')
        cli_writer.write(b"{not_valid_json_at_all\n")
        await cli_writer.drain()

        # 3. Multi-byte UTF-8 frame split cleanly across tiny socket writes + typed string ID "1".
        utf8_frame = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "1",
                    "method": "custom/vendor_ping",
                    "params": {"text": "café 日本語 🚀", "control_nul": "a\x00b"},
                    "x_client_ext": True,
                },
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
        for idx in range(0, len(utf8_frame), 3):
            cli_writer.write(utf8_frame[idx : idx + 3])
            await cli_writer.drain()
            await asyncio.sleep(0.001)

        utf8_reply = await asyncio.wait_for(cli_reader.readline(), timeout=5.0)
        parsed_utf8 = json.loads(utf8_reply.decode("utf-8"))
        assert parsed_utf8["id"] == "1"
        assert parsed_utf8["result"]["echo"]["text"] == "café 日本語 🚀"
        assert parsed_utf8["x_server_ext"] == "kept"

        # 4. Duplicate in-flight int ID + out-of-order response resolution.
        for msg in (
            {"jsonrpc": "2.0", "id": 7, "method": "custom/defer_one", "params": {"n": 1}},
            {"jsonrpc": "2.0", "id": 7, "method": "custom/defer_one", "params": {"n": 2}},
            {"jsonrpc": "2.0", "id": 8, "method": "custom/flush_deferred", "params": {}},
        ):
            cli_writer.write((json.dumps(msg) + "\n").encode("utf-8"))
        await cli_writer.drain()

        received_ids: list[Any] = []
        for _ in range(3):
            line = await asyncio.wait_for(cli_reader.readline(), timeout=5.0)
            received_ids.append(json.loads(line.decode("utf-8"))["id"])
        assert received_ids == [8, 7, 7]

        cli_writer.close()
        await asyncio.wait_for(cli_writer.wait_closed(), timeout=5.0)
        proxy_res = await asyncio.wait_for(proxy_task, timeout=10.0)
        assert proxy_res.exit_code == 0

    # Walk full storage -> timeline -> diagnostics -> cassette/replay -> export -> verify pipeline.
    repo = RecordingRepository(data_dir)
    try:
        read_res = repo.get_execution_events(exec_id, strict_integrity=True)
        assert not read_res.has_corruptions
        kinds = {item.event.kind for item in read_res.events}
        assert "malformed_utf8_frame" in kinds
        assert "malformed_json_frame" in kinds
        req_events = [
            item.event
            for item in read_res.events
            if isinstance(item.event.payload, JsonRpcRequestPayload)
        ]
        assert any(
            isinstance(ev.payload, JsonRpcRequestPayload)
            and ev.payload.id_type == "str"
            and ev.payload.id == "1"
            for ev in req_events
        )
        assert any(
            isinstance(ev.payload, JsonRpcResponsePayload) and ev.payload.id_type == "str"
            for ev in (item.event for item in read_res.events)
        )

        tl = reconstruct_execution_timeline(repo, exec_id, strict_integrity=True)
        assert tl.total_events >= 10
        assert any(sp.method == "custom/vendor_ping" for sp in tl.spans)

        diag = diagnose_execution(repo, exec_id, strict_integrity=True)
        diag_codes = {d.code for d in diag.diagnostics}
        assert "MALFORMED_WIRE_FRAME" in diag_codes

        cassette = build_cassette_from_execution(repo, exec_id, strict_integrity=True)
        rep = replay_cassette(cassette)
        assert rep.total_steps >= 4

        bundle = export_execution_regression_test(
            repo,
            exec_id,
            output_dir=tmp_path / "adverse_exp",
            slug="adverse_wire_case",
        )
        loaded = load_regression_fixture(bundle.fixture_path)
        assert run_regression_fixture(loaded).passed is True
    finally:
        repo.close()


def test_large_multi_mib_unicode_and_oversized_frame_boundary_end_to_end(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """Multi-MiB Unicode JSON with secrets passes safely; >limit frames fail closed cleanly."""
    env = _xdg_env(isolated_xdg)
    data_dir = tmp_path / "scale_data"

    echo_srv = tmp_path / "large_echo_srv.py"
    echo_srv.write_text(
        "import json, sys\n"
        "for raw in sys.stdin:\n"
        "    msg = json.loads(raw)\n"
        "    if 'id' in msg:\n"
        "        resp = {\n"
        "            'jsonrpc': '2.0', 'id': msg['id'], 'result': {'payload': msg.get('params')}\n"
        "        }\n"
        "        sys.stdout.write(json.dumps(resp, ensure_ascii=False) + '\\n')\n"
        "        sys.stdout.flush()\n",
        encoding="utf-8",
    )

    # 1. Valid ~2.5 MiB multi-byte Unicode + embedded secret through CLI `aerlog run`.
    exec_big = new_execution_id()
    big_chunk = "αβγ🚀" * 150_000  # ~1.05M chars / > 2.2 MiB UTF-8
    big_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "custom/big_blob",
        "params": {
            "blob": big_chunk,
            "nested": {"api_key": "sk-huge-payload-secret-9999", "nul_safe": "prefix\x00suffix"},
        },
    }
    big_proc = _run_aerlog_cli(
        "run",
        "--quiet",
        "--execution-id",
        exec_big,
        "--data-dir",
        str(data_dir),
        "--",
        _PYTHON,
        str(echo_srv),
        env=env,
        stdin_text=json.dumps(big_req, ensure_ascii=False) + "\n",
    )
    assert big_proc.returncode == 0, big_proc.stderr
    wire_reply = json.loads(big_proc.stdout.strip())
    assert wire_reply["result"]["payload"]["blob"] == big_chunk
    assert wire_reply["result"]["payload"]["nested"]["api_key"] == "sk-huge-payload-secret-9999"

    # Stored recording + exported fixture redact the embedded secret cleanly and verify pass.
    repo = RecordingRepository(data_dir)
    try:
        ev_res = repo.get_execution_events(exec_big, strict_integrity=True)
        assert ev_res.summary is not None
        assert ev_res.summary.capture_completeness == "complete"
        bundle = export_execution_regression_test(
            repo,
            exec_big,
            output_dir=tmp_path / "big_exp",
            slug="large_unicode_case",
        )
        raw_fixture_txt = bundle.fixture_path.read_text(encoding="utf-8")
        assert "sk-huge-payload-secret-9999" not in raw_fixture_txt
        assert bundle.fixture.contains_raw_secrets is False
        assert run_regression_fixture(load_regression_fixture(bundle.fixture_path)).passed is True
    finally:
        repo.close()

    # 2. Oversized single frame (> 64 KiB custom limit) fails closed with exit code 65 cleanly.
    exec_over = new_execution_id()
    over_frame = (
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "A" * 70_000}})
        + "\n"
    )
    over_proc = _run_aerlog_cli(
        "run",
        "--max-frame-bytes",
        "65536",
        "--execution-id",
        exec_over,
        "--data-dir",
        str(data_dir),
        "--",
        _PYTHON,
        str(echo_srv),
        env=env,
        stdin_text=over_frame,
    )
    assert over_proc.returncode == EXIT_FRAME_TOO_LARGE
    assert over_proc.stdout == ""
    assert "frame_too_large" in over_proc.stderr

    diag_over = _run_aerlog_cli(
        "diagnose", exec_over, "--data-dir", str(data_dir), "--json", env=env
    )
    assert diag_over.returncode == 0, diag_over.stderr
    diag_codes = {d["code"] for d in json.loads(diag_over.stdout)["diagnostics"]}
    assert "OVERSIZED_WIRE_FRAME" in diag_codes


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_mcp_sdk_auto_and_legacy_modes_record_replay_serve_and_export(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
    mode: Literal["auto", "legacy"],
) -> None:
    """Real ``mcp.Client`` in ``auto`` and ``legacy`` modes records, serves, and exports."""
    env = _xdg_env(isolated_xdg)
    data_dir = tmp_path / f"sdk_{mode}"
    srv_script = tmp_path / f"sdk_{mode}_srv.py"
    srv_script.write_text(
        "from mcp.server.mcpserver import MCPServer\n"
        "from mcp.types import ToolAnnotations\n"
        "mcp = MCPServer('aerlog-compat-srv')\n"
        "@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))\n"
        "def echo_compat(msg: str) -> str:\n"
        "    return f'compat:{msg}'\n"
        "if __name__ == '__main__':\n"
        "    mcp.run(transport='stdio')\n",
        encoding="utf-8",
    )

    exec_id = new_execution_id()
    run_params = StdioServerParameters(
        command=_PYTHON,
        args=[
            "-m",
            "aerlog",
            "run",
            "--quiet",
            "--execution-id",
            exec_id,
            "--data-dir",
            str(data_dir),
            "--",
            _PYTHON,
            str(srv_script),
        ],
        env=env,
    )
    async with Client(run_params, mode=mode) as client:
        tools = await client.list_tools()
        assert [t.name for t in tools.tools] == ["echo_compat"]
        call_res = await client.call_tool("echo_compat", {"msg": mode})
        assert isinstance(call_res.content[0], TextContent)
        assert call_res.content[0].text == f"compat:{mode}"

    # Remove server script completely to guarantee replay serve runs strictly offline.
    srv_script.unlink()

    # MCP 2026-07-28 `server/discover` is classified as protocol_control, so strict
    # auto-mode offline replay, --serve, and regression export pass without --allow-mutating.
    serve_args = [
        "-m",
        "aerlog",
        "replay",
        exec_id,
        "--serve",
        "--no-save-report",
        "--data-dir",
        str(data_dir),
    ]
    if mode == "auto":
        clean_auto = _run_aerlog_cli(
            "replay",
            exec_id,
            "--fail-on-divergence",
            "--no-save-report",
            "--data-dir",
            str(data_dir),
            "--json",
            env=env,
        )
        assert clean_auto.returncode == 0, clean_auto.stderr
        rep_json = json.loads(clean_auto.stdout)
        assert rep_json["overall_status"] == "clean_match"
        assert any(
            step["method"] == "server/discover"
            and step["side_effect_class"] == "protocol_control"
            and step["outcome_kind"] == "matched_ok"
            for step in rep_json["steps"]
        )
        cass_res = _run_aerlog_cli(
            "cassette", "create", exec_id, "--data-dir", str(data_dir), "--json", env=env
        )
        assert cass_res.returncode == 0, cass_res.stderr
        assert "2026-07-28" in json.loads(cass_res.stdout).get("observed_mcp_protocol_versions", [])

    serve_params = StdioServerParameters(
        command=_PYTHON,
        args=serve_args,
        env=env,
    )
    async with Client(serve_params, mode=mode) as replay_client:
        rep_tools = await replay_client.list_tools()
        assert [t.name for t in rep_tools.tools] == ["echo_compat"]
        rep_res = await replay_client.call_tool("echo_compat", {"msg": mode})
        assert isinstance(rep_res.content[0], TextContent)
        assert rep_res.content[0].text == f"compat:{mode}"

    exp_args = [
        "export",
        "test",
        exec_id,
        "--output",
        str(tmp_path / f"exp_{mode}"),
        "--name",
        f"sdk_{mode}_case",
        "--data-dir",
        str(data_dir),
        "--json",
    ]
    exp_proc = _run_aerlog_cli(*exp_args, env=env)
    assert exp_proc.returncode == 0, exp_proc.stderr
    ver_proc = _run_aerlog_cli(
        "export",
        "verify",
        json.loads(exp_proc.stdout)["fixture_path"],
        "--json",
        env=env,
    )
    assert ver_proc.returncode == 0, ver_proc.stderr
    assert json.loads(ver_proc.stdout)["passed"] is True
