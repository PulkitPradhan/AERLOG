"""End-to-end integration tests wiring StdioProxy, CapturePipeline, and real MCP SDK sessions."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import stat
import sys
from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Literal, cast

import anyio
import mcp_types as types
import pytest
from mcp import Client
from mcp.client._transport import TransportStreams
from mcp.shared.message import SessionMessage
from mcp.types import TextContent

from aerlog.capture import (
    REDACTED_MARKER,
    CaptureConfig,
    CaptureProxyObserver,
    InMemoryCaptureSink,
)
from aerlog.events import (
    CaptureWarningPayload,
    ExecutionEvent,
    ExecutionHeader,
    ExecutionSummary,
    FrameTooLargePayload,
    IncompleteTrailingFramePayload,
    JsonRpcRequestPayload,
    JsonRpcResponsePayload,
    MalformedJsonFramePayload,
    ProcessStderrPayload,
)
from aerlog.proxy.stdio_proxy import ProxyConfig, StdioProxy

PYTHON = sys.executable

_SDK_CAPTURE_SERVER = """
import sys
import anyio
from mcp.server.mcpserver import Context, MCPServer

mcp = MCPServer("aerlog-phase4-e2e-server")

@mcp.tool()
def echo_with_secret(text: str, api_key: str) -> str:
    sys.stderr.write(
        "stderr auth=Bearer leaked_token_999 github=ghp_sdk_stderr_secret_1234\\n"
    )
    sys.stderr.flush()
    return f"{text}:{api_key}"

@mcp.tool()
async def slow_progress(text: str, delay_s: float, ctx: Context) -> str:
    await ctx.report_progress(1, 2, "step1")
    await anyio.sleep(delay_s)
    await ctx.report_progress(2, 2, "step2")
    return text

@mcp.tool()
def intentional_tool_error() -> str:
    raise RuntimeError("boom tool error")

if __name__ == "__main__":
    mcp.run(transport="stdio")
"""


class _SlowCaptureSink:
    def __init__(self, delay_s: float) -> None:
        self.delay_s = delay_s
        self.header: ExecutionHeader | None = None
        self.events: list[ExecutionEvent] = []
        self.summary: ExecutionSummary | None = None

    async def on_start(self, header: ExecutionHeader) -> None:
        self.header = header

    async def emit_events(self, events: Sequence[ExecutionEvent]) -> None:
        await asyncio.sleep(self.delay_s)
        self.events.extend(events)

    async def on_finish(self, summary: ExecutionSummary) -> None:
        self.summary = summary

    async def flush(self) -> None:
        return None

    async def close(self) -> None:
        return None


@asynccontextmanager
async def _proxy_sdk_transport(
    proxy_config: ProxyConfig,
    observer: CaptureProxyObserver,
    tmp_path: Path,
) -> AsyncGenerator[TransportStreams, None]:
    """Bridge an MCP SDK client cleanly over an OS socketpair into in-process StdioProxy."""
    client_sock, proxy_sock = socket.socketpair()
    client_sock.setblocking(False)
    proxy_sock.setblocking(False)

    cli_reader, cli_writer = await asyncio.open_connection(sock=client_sock)
    proxy_reader, proxy_writer = await asyncio.open_connection(sock=proxy_sock)

    proxy = StdioProxy(proxy_config)
    diag_log = tmp_path / "proxy_diag.jsonl"
    diag_file = diag_log.open("w", encoding="utf-8")
    proxy_task = asyncio.create_task(
        proxy.run(
            stdin_reader=proxy_reader,
            stdout_writer=proxy_writer,
            diag_stream=diag_file,
            observer=observer,
        )
    )

    read_stream_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](
        0
    )
    write_stream, write_stream_reader = anyio.create_memory_object_stream[SessionMessage](0)

    async def reader_pump() -> None:
        buffer = b""
        try:
            async with read_stream_writer:
                while True:
                    chunk = await cli_reader.read(65536)
                    if not chunk:
                        break
                    buffer += chunk
                    while (nl := buffer.find(b"\n")) != -1:
                        line = buffer[:nl].decode("utf-8").rstrip("\r")
                        buffer = buffer[nl + 1 :]
                        if not line:
                            continue
                        try:
                            msg = types.jsonrpc_message_adapter.validate_json(line, by_name=False)
                            await read_stream_writer.send(SessionMessage(msg))
                        except ValueError as exc:
                            await read_stream_writer.send(exc)
        except (anyio.ClosedResourceError, anyio.BrokenResourceError, OSError):
            pass

    async def writer_pump() -> None:
        try:
            async with write_stream_reader:
                async for session_msg in write_stream_reader:
                    line = (
                        session_msg.message.model_dump_json(by_alias=True, exclude_unset=True)
                        + "\n"
                    ).encode("utf-8")
                    cli_writer.write(line)
                    await cli_writer.drain()
        except (anyio.ClosedResourceError, anyio.BrokenResourceError, OSError):
            pass
        finally:
            if cli_writer.can_write_eof():
                with suppress(OSError, RuntimeError):
                    cli_writer.write_eof()
            with suppress(OSError):
                cli_writer.close()

    r_task = asyncio.create_task(reader_pump())
    w_task = asyncio.create_task(writer_pump())

    try:
        yield read_stream, write_stream
    finally:
        await write_stream.aclose()
        await read_stream.aclose()
        await asyncio.gather(w_task, return_exceptions=True)
        await asyncio.wait_for(proxy_task, timeout=10.0)
        if not r_task.done():
            r_task.cancel()
        await asyncio.gather(r_task, return_exceptions=True)
        with suppress(OSError):
            cli_writer.close()
        diag_file.close()


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_mcp_sdk_e2e_capture_correlation_redaction_and_trace(
    tmp_path: Path,
    mode: Literal["auto", "legacy"],
) -> None:
    """Real MCP SDK client + server via StdioProxy + CapturePipeline in auto and legacy modes."""
    server_path = tmp_path / "server.py"
    server_path.write_text(_SDK_CAPTURE_SERVER, encoding="utf-8")

    sink = InMemoryCaptureSink()
    observer = CaptureProxyObserver(sink, config=CaptureConfig())
    proxy_cfg = ProxyConfig(command=(PYTHON, str(server_path)))

    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    progress_updates: list[tuple[float, float | None, str | None]] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        progress_updates.append((progress, total, message))

    secret_val = "sk-live-sdk-secret-9999"

    async with Client(_proxy_sdk_transport(proxy_cfg, observer, tmp_path), mode=mode) as client:
        expected_ver = "2026-07-28" if mode == "auto" else "2025-11-25"
        assert client.protocol_version == expected_ver

        listed = await client.list_tools()
        assert [t.name for t in listed.tools] == [
            "echo_with_secret",
            "slow_progress",
            "intentional_tool_error",
        ]

        # Wire transparency proof: real server sees and echoes back the raw secret intact.
        echo_res = await client.call_tool(
            "echo_with_secret",
            {"text": "hello", "api_key": secret_val},
            meta=cast(types.RequestParamsMeta, {"traceparent": traceparent}),
        )
        assert isinstance(echo_res.content[0], TextContent)
        assert echo_res.content[0].text == f"hello:{secret_val}"

        slow_res = await client.call_tool(
            "slow_progress",
            {"text": "ok", "delay_s": 0.03},
            progress_callback=on_progress,
        )
        assert isinstance(slow_res.content[0], TextContent)
        assert slow_res.content[0].text == "ok"

        err_res = await client.call_tool("intentional_tool_error", {})
        assert err_res.is_error is True

    assert progress_updates == [(1.0, 2.0, "step1"), (2.0, 2.0, "step2")]

    summary = observer.last_summary
    assert summary is not None
    assert sink.summary == summary
    assert summary.capture_completeness == "complete"
    assert summary.dropped_events == 0
    assert summary.unanswered_request_ids == ()
    assert "4bf92f3577b34da6a3ce929d0e0e4736" in summary.observed_trace_ids

    events = sink.events
    assert events[0].kind == "execution_started"
    assert events[-1].kind == "execution_finished"
    assert [e.sequence for e in events] == list(range(1, len(events) + 1))

    # Pre-persistence redaction check across ALL captured JSON events (requests, responses, stderr).
    dumped_all = "\n".join(e.model_dump_json() for e in events)
    assert secret_val not in dumped_all
    assert "leaked_token_999" not in dumped_all
    assert "ghp_sdk_stderr_secret_1234" not in dumped_all
    assert REDACTED_MARKER in dumped_all

    # Check stderr capture
    stderr_payloads = [e.payload for e in events if isinstance(e.payload, ProcessStderrPayload)]
    assert stderr_payloads
    assert "leaked_token_999" not in (stderr_payloads[0].text or "")

    # Check request/response correlation and derived OTel metadata
    requests = [e for e in events if isinstance(e.payload, JsonRpcRequestPayload)]
    responses = [e for e in events if isinstance(e.payload, JsonRpcResponsePayload)]
    req_methods = [
        e.payload.method for e in requests if isinstance(e.payload, JsonRpcRequestPayload)
    ]
    if mode == "legacy":
        assert "initialize" in req_methods
    else:
        assert "server/discover" in req_methods
    assert "tools/list" in req_methods
    assert req_methods.count("tools/call") == 3

    matched_resps = [
        r for r in responses if r.correlation is not None and r.correlation.status == "matched"
    ]
    assert len(matched_resps) == len(requests)
    assert all(
        r.correlation is not None and r.correlation.latency_ns is not None for r in matched_resps
    )

    tool_err_resps = [
        r for r in responses if r.derived is not None and r.derived.tool_is_error is True
    ]
    assert len(tool_err_resps) == 1

    traced_reqs = [
        req
        for req in requests
        if req.trace is not None
        and req.trace.trace_source == "w3c_meta"
        and req.trace.observed_trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    ]
    assert len(traced_reqs) == 1

    progress_notifs = [
        e
        for e in events
        if e.kind == "jsonrpc_notification"
        and e.correlation is not None
        and e.correlation.status == "progress_target_matched"
    ]
    assert len(progress_notifs) == 2


@pytest.mark.parametrize("policy", ["block", "spill"])
async def test_mcp_sdk_e2e_slow_sink_durability_block_and_spill(
    tmp_path: Path,
    policy: Literal["block", "spill"],
) -> None:
    """MCP SDK traffic stays lossless under block and spills redacted to 0o600 under spill."""
    server_path = tmp_path / "server_durability.py"
    server_path.write_text(_SDK_CAPTURE_SERVER, encoding="utf-8")

    slow_sink = _SlowCaptureSink(delay_s=0.02 if policy == "block" else 0.4)
    spill_dir = tmp_path / "e2e_spool"
    observer = CaptureProxyObserver(
        slow_sink,
        config=CaptureConfig(
            backpressure_policy=policy,
            max_queue_events=2,
            spill_dir=spill_dir,
            spill_write_timeout_s=0.04,
            drain_timeout_s=10.0,
        ),
    )
    proxy_cfg = ProxyConfig(command=(PYTHON, str(server_path)))

    async with Client(_proxy_sdk_transport(proxy_cfg, observer, tmp_path), mode="auto") as client:
        for idx in range(3):
            res = await client.call_tool(
                "echo_with_secret",
                {"text": f"msg-{idx}", "api_key": "sk-durability-secret-1111"},
            )
            assert isinstance(res.content[0], TextContent)
            assert res.content[0].text == f"msg-{idx}:sk-durability-secret-1111"

    summary = observer.last_summary
    assert summary is not None
    assert summary.dropped_events == 0

    if policy == "block":
        assert summary.capture_completeness == "complete"
        assert slow_sink.summary == summary
        req_count = sum(1 for e in slow_sink.events if e.kind == "jsonrpc_request")
        resp_count = sum(1 for e in slow_sink.events if e.kind == "jsonrpc_response")
        assert req_count == resp_count >= 5
    else:
        assert summary.capture_completeness == "spilled"
        assert summary.spool_file is not None
        spool_path = Path(summary.spool_file)
        assert spool_path.exists()
        if os.name == "posix":
            assert stat.S_IMODE(spool_path.stat().st_mode) == 0o600
        raw_spool = spool_path.read_text(encoding="utf-8")
        assert "sk-durability-secret-1111" not in raw_spool
        assert "ghp_sdk_stderr_secret_1234" not in raw_spool
        assert REDACTED_MARKER in raw_spool
        records = [json.loads(line) for line in raw_spool.splitlines() if line.strip()]
        assert records[-1]["record_type"] == "summary"


async def test_proxy_capture_preserves_malformed_crlf_incomplete_and_oversized_frames(
    tmp_path: Path,
) -> None:
    """Raw malformed JSON, CRLF frames, incomplete EOF, and oversized frames capture cleanly."""
    echo_server = (
        "import sys\n"
        "for line in sys.stdin.buffer:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n"
    )
    input_bytes = (
        b'{"jsonrpc":"2.0","id":1,"method":"x/crlf","extra":true}\r\n'
        b'{broken "secret": "Bearer badjson_secret_tok"\n'
        b'{"trailing_incomplete": true'
    )

    stdin_reader = asyncio.StreamReader()
    stdin_reader.feed_data(input_bytes)
    stdin_reader.feed_eof()

    captured_stdout = bytearray()

    class _MemWriter:
        def write(self, data: bytes) -> None:
            captured_stdout.extend(data)

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    sink = InMemoryCaptureSink()
    observer = CaptureProxyObserver(sink)
    proxy = StdioProxy(ProxyConfig(command=(PYTHON, "-u", "-c", echo_server)))
    diag_path = tmp_path / "diag.jsonl"
    with diag_path.open("w", encoding="utf-8") as diag_f:
        result = await proxy.run(
            stdin_reader=stdin_reader,
            stdout_writer=_MemWriter(),  # type: ignore[arg-type]
            diag_stream=diag_f,
            observer=observer,
        )

    assert result.exit_code == 0
    assert bytes(captured_stdout) == input_bytes
    assert observer.last_summary is not None
    assert observer.last_summary.capture_completeness == "complete"

    kinds = [e.kind for e in sink.events]
    assert "malformed_json_frame" in kinds
    assert "incomplete_trailing_frame" in kinds

    crlf_reqs = [
        e
        for e in sink.events
        if isinstance(e.payload, JsonRpcRequestPayload) and e.payload.method == "x/crlf"
    ]
    assert len(crlf_reqs) == 2  # client_to_server and echoed server_to_client
    assert isinstance(crlf_reqs[0].payload, JsonRpcRequestPayload)
    assert crlf_reqs[0].payload.extra_fields == {"extra": True}
    assert crlf_reqs[0].wire is not None
    assert crlf_reqs[0].wire.line_ending == "crlf"

    malformed_payloads = [
        e.payload for e in sink.events if isinstance(e.payload, MalformedJsonFramePayload)
    ]
    assert malformed_payloads
    assert "badjson_secret_tok" not in (malformed_payloads[0].text or "")

    incomplete = [e for e in sink.events if isinstance(e.payload, IncompleteTrailingFramePayload)]
    assert len(incomplete) == 2  # client_to_server and echoed server_to_client

    # Also verify fail-closed oversized frame capture cleanly via StdioProxy
    oversized_reader = asyncio.StreamReader()
    oversized_reader.feed_data(b"A" * 512 + b"\n")
    oversized_reader.feed_eof()

    oversized_sink = InMemoryCaptureSink()
    oversized_observer = CaptureProxyObserver(oversized_sink)
    oversized_proxy = StdioProxy(
        ProxyConfig(command=(PYTHON, "-u", "-c", echo_server), max_frame_bytes=128)
    )
    with diag_path.open("w", encoding="utf-8") as diag_f:
        oversized_res = await oversized_proxy.run(
            stdin_reader=oversized_reader,
            stdout_writer=_MemWriter(),  # type: ignore[arg-type]
            diag_stream=diag_f,
            observer=oversized_observer,
        )

    assert oversized_res.termination_reason == "frame_too_large"
    too_large_payloads = [
        e.payload for e in oversized_sink.events if isinstance(e.payload, FrameTooLargePayload)
    ]
    assert len(too_large_payloads) == 1
    assert too_large_payloads[0].observed_bytes == 513
    assert any(
        isinstance(e.payload, CaptureWarningPayload) or e.kind == "execution_finished"
        for e in oversized_sink.events
    )
