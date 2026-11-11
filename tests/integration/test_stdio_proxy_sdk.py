"""End-to-end integration tests using the installed MCP SDK through StdioProxy."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from mcp import Client, MCPError, StdioServerParameters
from mcp.types import TextContent

PYTHON = sys.executable

_SDK_SERVER_SCRIPT = """
import sys
import anyio
from mcp.server.mcpserver import Context, MCPServer

mcp = MCPServer("aerlog-phase3-test-server")

@mcp.tool()
def echo(text: str) -> str:
    msg = (
        f"[test-server] echo bytes={len(text.encode('utf-8'))} "
        "Authorization: Bearer leaked_token_999\\n"
    )
    sys.stderr.write(msg)
    sys.stderr.flush()
    return text

@mcp.tool()
async def slow_echo(text: str, delay_s: float, ctx: Context) -> str:
    sys.stderr.write(f"[test-server] slow_echo delay_s={delay_s}\\n")
    sys.stderr.flush()
    await ctx.report_progress(1, 2, "started")
    await anyio.sleep(delay_s)
    await ctx.report_progress(2, 2, "completed")
    return text

if __name__ == "__main__":
    mcp.run(transport="stdio")
"""


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_mcp_sdk_end_to_end_both_protocol_modes(tmp_path: Path, mode: str) -> None:
    server_path = tmp_path / "mcp_server.py"
    server_path.write_text(_SDK_SERVER_SCRIPT, encoding="utf-8")
    log_path = tmp_path / f"sdk_{mode}.jsonl"

    server_params = StdioServerParameters(
        command=PYTHON,
        args=[
            "-m",
            "aerlog.proxy.stdio_proxy",
            "--log-file",
            str(log_path),
            "--",
            PYTHON,
            str(server_path),
        ],
    )

    progress_events: list[tuple[float, float | None, str | None]] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        progress_events.append((progress, total, message))

    large_text = "M" * 100_000  # > 64 KiB

    async with Client(server_params, mode=mode) as client:
        expected_version = "2026-07-28" if mode == "auto" else "2025-11-25"
        assert client.protocol_version == expected_version

        tools_res = await client.list_tools()
        assert [tool.name for tool in tools_res.tools] == ["echo", "slow_echo"]

        echo_res = await client.call_tool("echo", {"text": large_text})
        assert isinstance(echo_res.content[0], TextContent)
        assert echo_res.content[0].text == large_text

        slow_res = await client.call_tool(
            "slow_echo",
            {"text": "done", "delay_s": 0.05},
            progress_callback=on_progress,
        )
        assert isinstance(slow_res.content[0], TextContent)
        assert slow_res.content[0].text == "done"

    assert progress_events == [(1.0, 2.0, "started"), (2.0, 2.0, "completed")]

    records = _read_jsonl(log_path)
    methods = [
        r.get("method") for r in records if r.get("event") == "protocol_frame" and r.get("method")
    ]
    if mode == "auto":
        assert "server/discover" in methods
        assert "initialize" not in methods
    else:
        assert "initialize" in methods
        assert "notifications/initialized" in methods
    assert "notifications/progress" in methods

    # Server stderr is captured off-stdout and secrets inside stderr are redacted.
    stderr_records = [r for r in records if r.get("event") == "server_stderr"]
    assert any("[test-server] echo" in str(r.get("text")) for r in stderr_records)
    raw_log = log_path.read_text(encoding="utf-8")
    assert "leaked_token_999" not in raw_log
    assert "Authorization: [REDACTED]" in raw_log


async def test_mcp_sdk_protocol_cancellation_and_recovery(tmp_path: Path) -> None:
    server_path = tmp_path / "mcp_server.py"
    server_path.write_text(_SDK_SERVER_SCRIPT, encoding="utf-8")
    log_path = tmp_path / "sdk_cancel.jsonl"

    server_params = StdioServerParameters(
        command=PYTHON,
        args=[
            "-m",
            "aerlog.proxy.stdio_proxy",
            "--log-file",
            str(log_path),
            "--",
            PYTHON,
            str(server_path),
        ],
    )

    async with Client(server_params, mode="auto") as client:
        with pytest.raises(MCPError):
            await client.call_tool(
                "slow_echo",
                {"text": "never", "delay_s": 5.0},
                read_timeout_seconds=0.25,
            )

        follow_up = await client.call_tool("echo", {"text": "still-healthy"})
        assert isinstance(follow_up.content[0], TextContent)
        assert follow_up.content[0].text == "still-healthy"

    records = _read_jsonl(log_path)
    assert any(
        r.get("event") == "protocol_frame" and r.get("method") == "notifications/cancelled"
        for r in records
    )
