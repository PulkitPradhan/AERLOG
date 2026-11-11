"""Phase 11 reproducible performance, memory, latency, and disk-growth baseline tests."""

from __future__ import annotations

import asyncio
import json
import os
import statistics
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path

from aerlog.capture import CaptureConfig, CaptureProxyObserver
from aerlog.events.ids import new_execution_id
from aerlog.protocol.framing import DEFAULT_MAX_FRAME_BYTES
from aerlog.proxy.stdio_proxy import ProxyConfig, StdioProxy
from aerlog.storage.database import DB_FILE_NAME
from aerlog.storage.event_log import EVENTS_FILE_NAME, EXECUTIONS_DIR_NAME
from aerlog.storage.repositories import RecordingRepository
from aerlog.storage.sink import PersistentCaptureSink

_PYTHON = sys.executable

_ECHO_SERVER_CODE = """
import json
import sys

for raw in sys.stdin:
    msg = json.loads(raw)
    if "id" in msg:
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"echo": msg.get("params")}}
        sys.stdout.write(json.dumps(resp, separators=(",", ":")) + "\\n")
        sys.stdout.flush()
"""


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, round((pct / 100.0) * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


def _measure_direct_rtt_ms(server_path: Path, count: int) -> list[float]:
    proc = subprocess.Popen(
        [_PYTHON, str(server_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    rtts_ms: list[float] = []
    try:
        assert proc.stdin is not None and proc.stdout is not None
        for idx in range(1, count + 1):
            frame = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": idx,
                        "method": "ping",
                        "params": {"seq": idx},
                    },
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            t0 = time.perf_counter_ns()
            proc.stdin.write(frame)
            proc.stdin.flush()
            reply = proc.stdout.readline()
            t1 = time.perf_counter_ns()
            assert json.loads(reply.decode("utf-8"))["id"] == idx
            rtts_ms.append((t1 - t0) / 1_000_000.0)
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        proc.wait(timeout=10)
    assert proc.returncode == 0
    return rtts_ms


async def _run_proxy_workload(
    *,
    server_path: Path,
    data_dir: Path,
    count: int,
    payload_text: str,
    measure_sequential_rtt: bool,
) -> tuple[str, float, list[float]]:
    import socket

    exec_id = new_execution_id()
    client_sock, proxy_sock = socket.socketpair()
    client_sock.setblocking(False)
    proxy_sock.setblocking(False)
    cli_reader, cli_writer = await asyncio.open_connection(
        sock=client_sock,
        limit=DEFAULT_MAX_FRAME_BYTES,
    )
    proxy_reader, proxy_writer = await asyncio.open_connection(
        sock=proxy_sock,
        limit=DEFAULT_MAX_FRAME_BYTES,
    )

    sink = PersistentCaptureSink(data_dir, fsync_policy="lifecycle", redaction_mode="standard")
    observer = CaptureProxyObserver(sink, config=CaptureConfig(), execution_id=exec_id)
    proxy = StdioProxy(ProxyConfig(command=(_PYTHON, str(server_path))))

    rtts_ms: list[float] = []
    t_start = time.perf_counter()
    with open(os.devnull, "w", encoding="utf-8") as devnull:
        proxy_task = asyncio.create_task(
            proxy.run(
                stdin_reader=proxy_reader,
                stdout_writer=proxy_writer,
                diag_stream=devnull,
                observer=observer,
            )
        )
        if measure_sequential_rtt:
            for idx in range(1, count + 1):
                frame = (
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": idx,
                            "method": "ping",
                            "params": {"seq": idx, "data": payload_text},
                        },
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
                req_t0 = time.perf_counter_ns()
                cli_writer.write(frame)
                await cli_writer.drain()
                reply = await asyncio.wait_for(cli_reader.readline(), timeout=10.0)
                req_t1 = time.perf_counter_ns()
                assert json.loads(reply.decode("utf-8"))["id"] == idx
                rtts_ms.append((req_t1 - req_t0) / 1_000_000.0)
        else:
            batch = bytearray()
            for idx in range(1, count + 1):
                batch.extend(
                    (
                        json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": idx,
                                "method": "tools/call",
                                "params": {"seq": idx, "data": payload_text},
                            },
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode("utf-8")
                )
            cli_writer.write(bytes(batch))
            await cli_writer.drain()
            for idx in range(1, count + 1):
                reply = await asyncio.wait_for(cli_reader.readline(), timeout=20.0)
                assert json.loads(reply.decode("utf-8"))["id"] == idx

        cli_writer.close()
        await asyncio.wait_for(cli_writer.wait_closed(), timeout=10.0)
        proxy_res = await asyncio.wait_for(proxy_task, timeout=20.0)
        assert proxy_res.exit_code == 0

    elapsed_s = max(1e-9, time.perf_counter() - t_start)
    return exec_id, elapsed_s, rtts_ms


async def test_performance_baseline_throughput_latency_memory_and_disk_growth(
    tmp_path: Path,
) -> None:
    """Measure throughput, latency overhead, peak heap, and disk growth cleanly.

    Guardrails:
    - Latency and throughput are measured in Pass 1 WITHOUT ``tracemalloc`` enabled.
    - Memory allocation is measured separately in Pass 2 WITH ``tracemalloc``.
    - Assertions check correctness and a generous memory ceiling (< 500 MiB), never flaky speeds.
    """
    srv_path = tmp_path / "perf_echo_srv.py"
    srv_path.write_text(_ECHO_SERVER_CODE, encoding="utf-8")

    # Pass 1A: Latency comparison (300 sequential pings direct vs proxy, tracemalloc OFF).
    rtt_count = 300
    direct_rtts = sorted(_measure_direct_rtt_ms(srv_path, rtt_count))
    lat_dir = tmp_path / "lat_data"
    lat_exec_id, _, proxy_rtts_raw = await _run_proxy_workload(
        server_path=srv_path,
        data_dir=lat_dir,
        count=rtt_count,
        payload_text="latency-probe",
        measure_sequential_rtt=True,
    )
    proxy_rtts = sorted(proxy_rtts_raw)

    # Pass 1B: Sustained throughput + disk growth (1,000 request/response exchanges = 2,000 frames).
    bulk_count = 1000
    bulk_dir = tmp_path / "bulk_perf_data"
    bulk_exec_id, bulk_elapsed_s, _ = await _run_proxy_workload(
        server_path=srv_path,
        data_dir=bulk_dir,
        count=bulk_count,
        payload_text="x" * 64,
        measure_sequential_rtt=False,
    )
    frames_total = bulk_count * 2
    throughput_msg_s = frames_total / bulk_elapsed_s

    # Correctness + disk accounting on Pass 1B.
    repo = RecordingRepository(bulk_dir)
    try:
        read_res = repo.get_execution_events(bulk_exec_id, strict_integrity=True)
        assert not read_res.has_corruptions
        assert read_res.summary is not None
        assert read_res.summary.capture_completeness == "complete"
        assert read_res.summary.dropped_events == 0
        expected_events = frames_total + 2  # execution_started + 2000 wire + execution_finished
        assert len(read_res.events) == expected_events
    finally:
        repo.close()

    lat_repo = RecordingRepository(lat_dir)
    try:
        lat_res = lat_repo.get_execution_events(lat_exec_id, strict_integrity=True)
        assert lat_res.summary is not None
        assert lat_res.summary.capture_completeness == "complete"
    finally:
        lat_repo.close()

    exec_dir = bulk_dir / EXECUTIONS_DIR_NAME / bulk_exec_id
    jsonl_bytes = (exec_dir / EVENTS_FILE_NAME).stat().st_size
    db_bytes = sum(
        p.stat().st_size
        for suffix in ("", "-wal", "-shm")
        if (p := Path(f"{bulk_dir / DB_FILE_NAME}{suffix}")).exists()
    )
    total_disk_bytes = jsonl_bytes + db_bytes

    # Pass 2: Separate tracemalloc pass (250 exchanges + 2 MiB burst) measuring peak Python heap.
    mem_dir = tmp_path / "mem_data"
    tracemalloc.start()
    try:
        mem_exec_1, _, _ = await _run_proxy_workload(
            server_path=srv_path,
            data_dir=mem_dir,
            count=250,
            payload_text="m" * 128,
            measure_sequential_rtt=False,
        )
        mem_exec_2, _, _ = await _run_proxy_workload(
            server_path=srv_path,
            data_dir=mem_dir,
            count=1,
            payload_text="B" * (2 * 1024 * 1024),
            measure_sequential_rtt=False,
        )
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    peak_mib = peak_bytes / (1024.0 * 1024.0)
    assert peak_mib < 500.0

    # Verify Pass 2 integrity as well.
    mem_repo = RecordingRepository(mem_dir)
    try:
        r1 = mem_repo.get_execution_events(mem_exec_1, strict_integrity=True)
        r2 = mem_repo.get_execution_events(mem_exec_2, strict_integrity=True)
        assert len(r1.events) == 502
        assert len(r2.events) == 4
    finally:
        mem_repo.close()

    metrics = {
        "throughput_frames_per_sec": round(throughput_msg_s, 2),
        "bulk_frames": frames_total,
        "bulk_elapsed_s": round(bulk_elapsed_s, 4),
        "direct_rtt_p50_ms": round(_percentile(direct_rtts, 50.0), 3),
        "direct_rtt_p95_ms": round(_percentile(direct_rtts, 95.0), 3),
        "proxy_rtt_p50_ms": round(_percentile(proxy_rtts, 50.0), 3),
        "proxy_rtt_p95_ms": round(_percentile(proxy_rtts, 95.0), 3),
        "proxy_rtt_mean_ms": round(statistics.mean(proxy_rtts), 3),
        "latency_overhead_p50_ms": round(
            _percentile(proxy_rtts, 50.0) - _percentile(direct_rtts, 50.0), 3
        ),
        "jsonl_bytes_for_2002_events": jsonl_bytes,
        "sqlite_bytes_for_2002_events": db_bytes,
        "total_disk_bytes_per_event": round(total_disk_bytes / expected_events, 1),
        "tracemalloc_peak_mib": round(peak_mib, 2),
    }
    report_path = tmp_path / "baseline_metrics.json"
    report_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"AERLOG_PERF_BASELINE={json.dumps(metrics)}")
