"""Integration tests for AERLOG storage recovery, divergence reconciliation, and E2E capture."""

from __future__ import annotations

import asyncio
import errno
import json
import os
import shutil
import socket
import sqlite3
import stat
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

import anyio
import mcp_types as types
import pytest
from mcp import Client
from mcp.client._transport import TransportStreams
from mcp.shared.message import SessionMessage
from mcp.types import TextContent

from aerlog.capture import CaptureConfig, CapturePipeline, CaptureProxyObserver, RawWireFrameInput
from aerlog.capture.redaction import REDACTED_MARKER
from aerlog.events import (
    ExecutionEvent,
    ExecutionFinishedPayload,
    ExecutionHeader,
    ExecutionStartedPayload,
    ExecutionSummary,
    JsonRpcRequestPayload,
    RedactionSummary,
    new_event_id,
    new_execution_id,
)
from aerlog.proxy.stdio_proxy import ProxyConfig, StdioProxy
from aerlog.storage import (
    EVENTS_FILE_NAME,
    EXECUTION_FILE_NAME,
    MANIFEST_FILE_NAME,
    JsonlEventLogWriter,
    PersistentCaptureSink,
    RecordingRepository,
    SQLiteMetadataStore,
)

PYTHON = sys.executable

_E2E_STORAGE_SERVER = """
import sys
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("aerlog-phase5-storage-server")

@mcp.tool()
def echo_payload(text: str, secret_key: str) -> str:
    sys.stderr.write("server stderr secret=Bearer leaked_storage_bearer_tok\\n")
    sys.stderr.flush()
    return f"{text}:{secret_key}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
"""


@asynccontextmanager
async def _sdk_proxy_transport(
    proxy_config: ProxyConfig,
    observer: CaptureProxyObserver,
    tmp_path: Path,
) -> AsyncGenerator[TransportStreams, None]:
    client_sock, proxy_sock = socket.socketpair()
    client_sock.setblocking(False)
    proxy_sock.setblocking(False)

    cli_reader, cli_writer = await asyncio.open_connection(sock=client_sock)
    proxy_reader, proxy_writer = await asyncio.open_connection(sock=proxy_sock)

    proxy = StdioProxy(proxy_config)
    diag_f = (tmp_path / "diag.jsonl").open("w", encoding="utf-8")
    proxy_task = asyncio.create_task(
        proxy.run(
            stdin_reader=proxy_reader,
            stdout_writer=proxy_writer,
            diag_stream=diag_f,
            observer=observer,
        )
    )

    read_w, read_r = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write_w, write_r = anyio.create_memory_object_stream[SessionMessage](0)

    async def r_pump() -> None:
        buf = b""
        try:
            async with read_w:
                while chunk := await cli_reader.read(65536):
                    buf += chunk
                    while (nl := buf.find(b"\n")) != -1:
                        line = buf[:nl].decode("utf-8").rstrip("\r")
                        buf = buf[nl + 1 :]
                        if line:
                            msg = types.jsonrpc_message_adapter.validate_json(line, by_name=False)
                            await read_w.send(SessionMessage(msg))
        except (anyio.ClosedResourceError, anyio.BrokenResourceError, OSError):
            pass

    async def w_pump() -> None:
        try:
            async with write_r:
                async for s_msg in write_r:
                    out = (
                        s_msg.message.model_dump_json(by_alias=True, exclude_unset=True) + "\n"
                    ).encode("utf-8")
                    cli_writer.write(out)
                    await cli_writer.drain()
        except (anyio.ClosedResourceError, anyio.BrokenResourceError, OSError):
            pass
        finally:
            if cli_writer.can_write_eof():
                with suppress(OSError, RuntimeError):
                    cli_writer.write_eof()
            with suppress(OSError):
                cli_writer.close()

    rt = asyncio.create_task(r_pump())
    wt = asyncio.create_task(w_pump())
    try:
        yield read_r, write_w
    finally:
        await write_w.aclose()
        await read_r.aclose()
        await asyncio.gather(wt, return_exceptions=True)
        await asyncio.wait_for(proxy_task, timeout=10.0)
        if not rt.done():
            rt.cancel()
        await asyncio.gather(rt, return_exceptions=True)
        with suppress(OSError):
            cli_writer.close()
        diag_f.close()


def test_crash_interrupted_write_corruption_and_sqlite_divergence_reconciliation(
    tmp_path: Path,
) -> None:
    """Reconcile interrupted runs, DB-vs-JSONL divergence, and missing JSONL directories."""
    data_dir = tmp_path / "data"
    t0 = datetime(2026, 11, 11, 18, 0, 0, tzinfo=UTC)

    # Execution A: complete run on disk, deleted aerlog.db later to force full rebuild.
    exec_a = new_execution_id()
    hdr_a = ExecutionHeader(
        execution_id=exec_a,
        started_at=t0,
        monotonic_start_ns=100,
        command=("python", "srv.py"),
    )
    ev_a1 = ExecutionEvent(
        execution_id=exec_a,
        sequence=1,
        timestamp=t0,
        monotonic_time_ns=100,
        direction="proxy",
        kind="execution_started",
        payload=ExecutionStartedPayload(
            command=("python", "srv.py"),
            redaction_mode="standard",
            backpressure_policy="block",
        ),
    )
    ev_a2 = ExecutionEvent(
        execution_id=exec_a,
        sequence=2,
        timestamp=t0,
        monotonic_time_ns=200,
        direction="client_to_server",
        kind="jsonrpc_request",
        payload=JsonRpcRequestPayload(id=1, id_type="int", method="tools/list"),
    )
    ev_a3 = ExecutionEvent(
        execution_id=exec_a,
        sequence=3,
        timestamp=t0,
        monotonic_time_ns=300,
        direction="proxy",
        kind="execution_finished",
        payload=ExecutionFinishedPayload(
            termination_reason="completed",
            exit_code=0,
            returncode=0,
            completeness="complete",
            total_events=3,
        ),
    )
    sum_a = ExecutionSummary(
        execution_id=exec_a,
        started_at=t0,
        ended_at=t0,
        duration_ns=200,
        command=("python", "srv.py"),
        capture_completeness="complete",
        termination_reason="completed",
        exit_code=0,
        returncode=0,
        total_events=3,
    )
    w_a = JsonlEventLogWriter(data_dir, exec_a)
    w_a.open(hdr_a)
    w_a.append_events([ev_a1, ev_a2, ev_a3])
    w_a.finalize(sum_a)
    w_a.close()

    # Execution B: interrupted mid-crash (no finalize, truncated partial final line in JSONL).
    exec_b = new_execution_id()
    hdr_b = ExecutionHeader(
        execution_id=exec_b,
        started_at=t0,
        monotonic_start_ns=400,
        command=("python", "srv.py"),
    )
    ev_b1 = ev_a1.model_copy(update={"execution_id": exec_b, "event_id": new_event_id()})
    w_b = JsonlEventLogWriter(data_dir, exec_b)
    w_b.open(hdr_b)
    w_b.append_events([ev_b1])
    w_b.close()
    events_b_path = data_dir / "executions" / exec_b / EVENTS_FILE_NAME
    with events_b_path.open("ab") as f:
        f.write(b'{"record_schema_version": "1.0.0", "partial_crash":')

    # Execution C: indexed in SQLite, then JSONL dir removed on disk.
    exec_c = new_execution_id()
    hdr_c = ExecutionHeader(
        execution_id=exec_c,
        started_at=t0,
        monotonic_start_ns=500,
        command=("python", "srv.py"),
    )
    w_c = JsonlEventLogWriter(data_dir, exec_c)
    w_c.open(hdr_c)
    w_c.close()

    store = SQLiteMetadataStore(data_dir)
    store.initialize()
    store.insert_execution_start(hdr_c)
    store.close()

    # Delete aerlog.db completely? First test full rebuild without exec_c deletion,
    # then test missing JSONL marking!
    shutil.rmtree(data_dir / "executions" / exec_c)

    repo = RecordingRepository(data_dir)
    report = repo.reconcile_all_executions()

    assert exec_a in report.discovered_execution_ids
    assert exec_b in report.discovered_execution_ids
    assert exec_c in report.missing_jsonl_execution_ids
    assert exec_b in report.unclean_shutdown_ids
    assert report.corruptions_found >= 1

    rec_a = repo.get_execution(exec_a)
    assert rec_a.index_row is not None
    assert rec_a.index_row.capture_completeness == "complete"
    assert rec_a.diverged is False

    rec_b = repo.get_execution(exec_b)
    assert rec_b.index_row is not None
    assert rec_b.index_row.capture_completeness == "corrupted"
    assert len(rec_b.corruptions) >= 1
    # Corrupt trailing line preserved in file (not truncated/repaired away)
    assert b'"partial_crash":' in events_b_path.read_bytes()
    b_events = repo.get_execution_events(exec_b)
    assert [e.event.sequence for e in b_events.events] == [1]

    rec_c = repo.get_execution(exec_c)
    assert rec_c.index_row is not None
    assert rec_c.index_row.capture_completeness == "corrupted"
    assert rec_c.index_row.index_status == "missing_jsonl"
    assert rec_c.diverged is True

    repo.close()


def test_import_recovery_spool_validates_redacts_deduplicates_and_reports_corrupt_lines(
    tmp_path: Path,
) -> None:
    """Spool importer applies redaction, skips duplicates, and preserves corrupt reports."""
    data_dir = tmp_path / "data"
    exec_id = new_execution_id()
    t0 = datetime(2026, 11, 11, 18, 10, 0, tzinfo=UTC)

    hdr = ExecutionHeader(
        execution_id=exec_id,
        started_at=t0,
        monotonic_start_ns=100,
        command=("python", "server.py"),
    )
    e1 = ExecutionEvent(
        execution_id=exec_id,
        sequence=1,
        timestamp=t0,
        monotonic_time_ns=100,
        direction="proxy",
        kind="execution_started",
        payload=ExecutionStartedPayload(
            command=("python", "server.py"),
            redaction_mode="standard",
            backpressure_policy="spill",
        ),
    )
    e2 = ExecutionEvent(
        execution_id=exec_id,
        sequence=2,
        timestamp=t0,
        monotonic_time_ns=200,
        direction="client_to_server",
        kind="jsonrpc_request",
        redaction=RedactionSummary(
            mode="explicit_unredacted",
            payload_mode="full_unredacted",
            applied=False,
        ),
        payload=JsonRpcRequestPayload(
            id=1,
            id_type="int",
            method="tools/call",
            has_params=True,
            params={"api_key": "sk-unredacted-in-spool-9999"},
        ),
    )

    # Event 1 already persisted before primary sink failed.
    writer = JsonlEventLogWriter(data_dir, exec_id)
    writer.open(hdr)
    writer.append_events([e1])
    writer.close()

    spool_path = tmp_path / f"{exec_id}.ndjson.spool"
    spool_lines = [
        json.dumps({"record_type": "header", "data": hdr.model_dump(mode="json")}),
        json.dumps({"record_type": "event", "data": e1.model_dump(mode="json")}),  # duplicate
        "{bad_spool_line",
        json.dumps({"record_type": "event", "data": e2.model_dump(mode="json")}),
    ]
    spool_path.write_text("\n".join(spool_lines) + "\n{trailing_partial", encoding="utf-8")

    repo = RecordingRepository(data_dir)
    report = repo.import_recovery_spool(spool_path, redaction_mode="standard")

    assert report.execution_id == exec_id
    assert report.imported_events == 1
    assert report.skipped_duplicates == 1
    assert len(report.corrupt_lines) == 2

    read_res = repo.get_execution_events(exec_id)
    assert [item.event.sequence for item in read_res.events] == [1, 2]
    jsonl_text = (data_dir / "executions" / exec_id / EVENTS_FILE_NAME).read_text(encoding="utf-8")
    assert "sk-unredacted-in-spool-9999" not in jsonl_text
    assert REDACTED_MARKER in jsonl_text
    if os.name == "posix":
        assert stat.S_IMODE((data_dir / "aerlog.db").stat().st_mode) == 0o600
    repo.close()


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_e2e_mcp_sdk_proxy_capture_to_persistent_storage_and_queries(
    tmp_path: Path,
    mode: Literal["auto", "legacy"],
) -> None:
    """Real MCP SDK + StdioProxy + CapturePipeline persists redacted logs queryable via Repo."""
    server_path = tmp_path / "srv.py"
    server_path.write_text(_E2E_STORAGE_SERVER, encoding="utf-8")
    data_dir = tmp_path / "aerlog_data"

    sink = PersistentCaptureSink(data_dir)
    observer = CaptureProxyObserver(sink, config=CaptureConfig())
    proxy_cfg = ProxyConfig(command=(PYTHON, str(server_path)), env={"HOST_SECRET": "do_not_save"})
    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    secret = "sk-e2e-persist-secret-8888"

    async with Client(_sdk_proxy_transport(proxy_cfg, observer, tmp_path), mode=mode) as client:
        res = await client.call_tool(
            "echo_payload",
            {"text": "hello", "secret_key": secret},
            meta=cast(types.RequestParamsMeta, {"traceparent": traceparent}),
        )
        assert isinstance(res.content[0], TextContent)
        assert res.content[0].text == f"hello:{secret}"

    summary = observer.last_summary
    assert summary is not None
    assert summary.capture_completeness == "complete"

    repo = RecordingRepository(data_dir)
    rec = repo.get_execution(summary.execution_id)
    assert not rec.diverged
    assert rec.summary is not None
    assert rec.manifest is not None
    assert rec.manifest.status == "finalized"

    # Zero secrets or env overrides persisted anywhere in JSONL, companions, or SQLite DB bytes.
    exec_dir = data_dir / "executions" / summary.execution_id
    for fpath in (
        exec_dir / EVENTS_FILE_NAME,
        exec_dir / EXECUTION_FILE_NAME,
        exec_dir / MANIFEST_FILE_NAME,
    ):
        txt = fpath.read_text(encoding="utf-8")
        assert secret not in txt
        assert "leaked_storage_bearer_tok" not in txt
        assert "HOST_SECRET" not in txt
        assert "do_not_save" not in txt
    db_bytes = (data_dir / "aerlog.db").read_bytes()
    assert secret.encode("utf-8") not in db_bytes
    assert b"leaked_storage_bearer_tok" not in db_bytes
    assert b"do_not_save" not in db_bytes

    # Query across trace, span, method, and time range
    traced = repo.query_events(trace_id="4bf92f3577b34da6a3ce929d0e0e4736")
    assert len(traced.events) >= 2
    by_span = repo.query_events(span_id="00f067aa0ba902b7")
    assert len(by_span.events) >= 2
    by_method = repo.query_events(execution_id=summary.execution_id, method="tools/call")
    assert len(by_method.events) == 1
    repo.close()


async def test_many_and_large_events_concurrent_reader_and_enospc_failure_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Handles large payloads, 260+ events, concurrent WAL readers, and ENOSPC honestly."""
    data_dir = tmp_path / "bulk_data"
    sink = PersistentCaptureSink(data_dir)
    pipeline = CapturePipeline(
        sink,
        command=("python", "srv.py"),
        config=CaptureConfig(max_queue_events=128),
    )
    await pipeline.start()

    large_pad = "Z" * 150_000
    large_frame = (
        json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"big": large_pad}}
        )
        + "\n"
    ).encode("utf-8")
    await pipeline.enqueue(
        RawWireFrameInput(
            timestamp=datetime.now(UTC),
            monotonic_time_ns=1_000,
            direction="client_to_server",
            raw_frame=large_frame,
        )
    )

    for idx in range(2, 262):
        small = (json.dumps({"jsonrpc": "2.0", "id": idx, "method": "ping"}) + "\n").encode("utf-8")
        await pipeline.enqueue(
            RawWireFrameInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=idx * 1_000,
                direction="client_to_server",
                raw_frame=small,
            )
        )

    # Concurrent reader queries SQLite in WAL mode WHILE the recording is still open!
    await asyncio.sleep(0.05)
    reader_conn = sqlite3.connect(str(data_dir / "aerlog.db"))
    in_flight_row = reader_conn.execute(
        "SELECT capture_completeness FROM executions WHERE execution_id = ?",
        (pipeline.execution_id,),
    ).fetchone()
    reader_conn.close()
    assert in_flight_row is not None
    if os.name == "posix":
        for suffix in ("", "-wal", "-shm"):
            p = Path(f"{data_dir / 'aerlog.db'}{suffix}")
            if p.exists():
                assert stat.S_IMODE(p.stat().st_mode) == 0o600

    summary = await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)
    assert summary.capture_completeness == "complete"
    assert summary.total_events == 263  # started + 261 wire + finished

    reader_conn2 = sqlite3.connect(str(data_dir / "aerlog.db"))
    cnt_row = reader_conn2.execute(
        "SELECT COUNT(*) FROM events_index WHERE execution_id = ?",
        (summary.execution_id,),
    ).fetchone()
    reader_conn2.close()
    assert cnt_row is not None and int(cnt_row[0]) == 263

    repo = RecordingRepository(data_dir)
    read_res = repo.get_execution_events(summary.execution_id, strict_integrity=True)
    assert len(read_res.events) == 263
    assert isinstance(read_res.events[1].event.payload, JsonRpcRequestPayload)
    assert len(read_res.events[1].event.payload.params["big"]) == 150_000
    repo.close()

    # Simulated ENOSPC in os.write: block policy marks incomplete & surfaces StorageDiskFullError.
    full_data_dir = tmp_path / "enospc_block"
    full_sink = PersistentCaptureSink(full_data_dir)
    full_pipe = CapturePipeline(
        full_sink,
        command=("python", "srv.py"),
        config=CaptureConfig(backpressure_policy="block"),
    )
    await full_pipe.start()

    assert full_sink._writer is not None
    blocked_fd = full_sink._writer._fd
    real_os_write = os.write

    def _enospc_on_target_fd(fd: int, data: object) -> int:
        if fd == blocked_fd:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_os_write(fd, data)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "write", _enospc_on_target_fd)

    await full_pipe.enqueue(
        RawWireFrameInput(
            timestamp=datetime.now(UTC),
            monotonic_time_ns=1_000,
            direction="client_to_server",
            raw_frame=b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
        )
    )
    fail_summary = await full_pipe.finalize(termination_reason="completed", exit_code=0)
    assert full_pipe.sink_error is not None
    assert "StorageDiskFullError" in full_pipe.sink_error
    assert fail_summary.capture_completeness == "incomplete"

    # Simulated ENOSPC under spill policy falls back cleanly to 0o600 redacted recovery spool!
    spill_dir = tmp_path / "enospc_spool"
    spill_sink = PersistentCaptureSink(tmp_path / "enospc_spill_data")
    spill_pipe = CapturePipeline(
        spill_sink,
        command=("python", "srv.py"),
        config=CaptureConfig(backpressure_policy="spill", spill_dir=spill_dir),
    )
    await spill_pipe.start()
    assert spill_sink._writer is not None
    spill_blocked_fd = spill_sink._writer._fd

    def _enospc_on_spill_primary(fd: int, data: object) -> int:
        if fd == spill_blocked_fd:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_os_write(fd, data)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "write", _enospc_on_spill_primary)

    spill_payload = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"token": "secret_diskfull_tok"},
    }
    await spill_pipe.enqueue(
        RawWireFrameInput(
            timestamp=datetime.now(UTC),
            monotonic_time_ns=2_000,
            direction="client_to_server",
            raw_frame=(json.dumps(spill_payload) + "\n").encode("utf-8"),
        )
    )
    spill_summary = await spill_pipe.finalize(termination_reason="completed", exit_code=0)
    assert spill_summary.capture_completeness == "spilled"
    assert spill_summary.spool_file is not None
    spool_txt = Path(spill_summary.spool_file).read_text(encoding="utf-8")
    assert "secret_diskfull_tok" not in spool_txt
    assert REDACTED_MARKER in spool_txt
