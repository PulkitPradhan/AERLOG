"""Phase 11 cross-subsystem fault-injection, concurrency, signal, and recovery tests."""

from __future__ import annotations

import asyncio
import errno
import json
import os
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp.client._transport import TransportStreams
from mcp.shared.message import SessionMessage
from mcp.types import TextContent

from aerlog.analysis import diagnose_execution, reconstruct_execution_timeline
from aerlog.capture import (
    CaptureConfig,
    CaptureProxyObserver,
)
from aerlog.events.ids import new_execution_id
from aerlog.export import (
    export_execution_regression_test,
    load_regression_fixture,
    run_regression_fixture,
)
from aerlog.proxy.stdio_proxy import ProxyConfig, StdioProxy
from aerlog.replay import build_cassette_from_execution, replay_cassette
from aerlog.storage.database import DB_FILE_NAME
from aerlog.storage.event_log import EVENTS_FILE_NAME, EXECUTIONS_DIR_NAME
from aerlog.storage.exceptions import StorageCorruptionError
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


def _ndjson(*objs: dict[str, Any]) -> str:
    return "".join(json.dumps(obj, separators=(",", ":")) + "\n" for obj in objs)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_concurrent_aerlog_run_migration_race_and_shared_db_wal(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """Multiple concurrent ``aerlog run`` workers racing a fresh DB never hit SQLite errors."""
    env = _xdg_env(isolated_xdg)
    shared_dir = tmp_path / "shared_race_data"
    assert not shared_dir.exists()

    echo_srv = tmp_path / "race_srv.py"
    echo_srv.write_text(
        "import json, sys\n"
        "for raw in sys.stdin:\n"
        "    msg = json.loads(raw)\n"
        "    if 'id' in msg:\n"
        "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], "
        "'result': {'ok': True}}) + '\\n')\n"
        "        sys.stdout.flush()\n",
        encoding="utf-8",
    )

    payload = _ndjson(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
    )
    exec_ids = [new_execution_id() for _ in range(4)]

    procs: list[subprocess.Popen[str]] = [
        subprocess.Popen(
            [
                _PYTHON,
                "-m",
                "aerlog",
                "run",
                "--quiet",
                "--execution-id",
                eid,
                "--data-dir",
                str(shared_dir),
                "--",
                _PYTHON,
                str(echo_srv),
            ],
            cwd=_REPO_ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for eid in exec_ids
    ]

    # Trigger parallel list readers while writers race DB creation and migrations.
    list_proc = subprocess.Popen(
        [_PYTHON, "-m", "aerlog", "list", "--data-dir", str(shared_dir), "--json"],
        cwd=_REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    for idx, proc in enumerate(procs):
        out, err = proc.communicate(input=payload, timeout=15)
        assert proc.returncode == 0, f"worker {idx} failed rc={proc.returncode}: {err}"
        assert err == ""
        lines = [line for line in out.splitlines() if line.strip()]
        assert len(lines) == 2

    list_out, list_err = list_proc.communicate(timeout=15)
    assert list_proc.returncode == 0, list_err
    json.loads(list_out)

    db_path = shared_dir / DB_FILE_NAME
    assert db_path.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(db_path.stat().st_mode) == 0o600

    conn = sqlite3.connect(str(db_path))
    try:
        mig_rows = conn.execute("SELECT version, name FROM schema_migrations").fetchall()
        assert mig_rows == [(1, "0001_initial")]
    finally:
        conn.close()

    final_list = _run_aerlog_cli("list", "--data-dir", str(shared_dir), "--json", env=env)
    assert final_list.returncode == 0
    listed_ids = {row["execution_id"] for row in json.loads(final_list.stdout)["executions"]}
    assert set(exec_ids).issubset(listed_ids)

    repo = RecordingRepository(shared_dir)
    try:
        for eid in exec_ids:
            tl = reconstruct_execution_timeline(repo, eid, strict_integrity=True)
            assert tl.total_events >= 4
            rep = diagnose_execution(repo, eid, strict_integrity=True)
            assert not rep.has_corruptions
    finally:
        repo.close()


def test_aerlog_run_spill_dir_isolation_and_full_spool_recovery_chain(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """``aerlog run --data-dir`` isolates recovery spools under ``<custom>/spool`` end-to-end."""
    env = _xdg_env(isolated_xdg)
    custom_dir = tmp_path / "custom_data_dir"
    exec_id = new_execution_id()

    echo_srv = tmp_path / "spill_echo_srv.py"
    echo_srv.write_text(
        "import json, sys\n"
        "for raw in sys.stdin:\n"
        "    msg = json.loads(raw)\n"
        "    if 'id' in msg:\n"
        "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], "
        "'result': {'status': 'ok'}}) + '\\n')\n"
        "        sys.stdout.flush()\n",
        encoding="utf-8",
    )

    cfg_path = tmp_path / "spill_cfg.toml"
    cfg_path.write_text(
        '[capture]\nbackpressure_policy = "spill"\nspill_write_timeout_s = 0.03\n',
        encoding="utf-8",
    )

    # Drive real CLI `run` in a child python process with a stalled PersistentCaptureSink write
    # so CapturePipeline triggers spill activation over live OS stdio pipes.
    driver_code = (
        "import sys, time\n"
        "from aerlog.cli.app import main\n"
        "from aerlog.storage.sink import PersistentCaptureSink\n"
        "orig = PersistentCaptureSink._emit_events_sync\n"
        "def slow_emit(self, events):\n"
        "    time.sleep(0.25)\n"
        "    return orig(self, events)\n"
        "PersistentCaptureSink._emit_events_sync = slow_emit\n"
        "sys.argv = sys.argv[1:]\n"
        "main()\n"
    )
    ndjson_in = _ndjson(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    run_proc = subprocess.run(
        [
            _PYTHON,
            "-c",
            driver_code,
            "aerlog",
            "run",
            "--quiet",
            "--execution-id",
            exec_id,
            "--data-dir",
            str(custom_dir),
            "--config",
            str(cfg_path),
            "--",
            _PYTHON,
            str(echo_srv),
        ],
        cwd=_REPO_ROOT,
        env=env,
        input=ndjson_in,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run_proc.returncode == 0, run_proc.stderr
    assert len([line for line in run_proc.stdout.splitlines() if line.strip()]) == 2

    # Critical isolation assertion: spool MUST land in custom_dir/spool, NEVER default XDG spool.
    default_spool_dir = isolated_xdg.data_home / "aerlog" / "spool"
    assert not default_spool_dir.exists()

    custom_spool_file = custom_dir / "spool" / f"{exec_id}.ndjson.spool"
    assert custom_spool_file.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(custom_spool_file.stat().st_mode) == 0o600

    # Import spool -> reconcile -> timeline -> diagnose -> replay -> export -> verify.
    repo = RecordingRepository(custom_dir)
    try:
        imp = repo.import_recovery_spool(custom_spool_file)
        assert imp.execution_id == exec_id
        assert imp.imported_events >= 1
        repo.reconcile_execution(exec_id)

        tl = reconstruct_execution_timeline(repo, exec_id, strict_integrity=True)
        assert any(sp.method == "tools/list" for sp in tl.spans)

        diag = diagnose_execution(repo, exec_id, strict_integrity=True)
        assert diag.execution_id == exec_id

        cassette = build_cassette_from_execution(repo, exec_id, strict_integrity=True)
        rep = replay_cassette(cassette)
        assert rep.overall_status == "clean_match"

        bundle = export_execution_regression_test(
            repo,
            exec_id,
            output_dir=tmp_path / "exported_spill",
            slug="spill_recovered",
        )
        loaded = load_regression_fixture(bundle.fixture_path)
        assert run_regression_fixture(loaded).passed is True
    finally:
        repo.close()


def test_live_aerlog_run_signal_termination_orphan_cleanup_and_recovery(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """``SIGTERM`` mid-RPC reaps child + grandchild processes and keeps recording inspectable."""
    env = _xdg_env(isolated_xdg)
    data_dir = tmp_path / "sig_data"
    exec_id = new_execution_id()
    pid_file = tmp_path / "pids.json"

    slow_srv = tmp_path / "slow_grandchild_srv.py"
    slow_srv.write_text(
        "import json, os, subprocess, sys, time\n"
        f"pid_file = {str(pid_file)!r}\n"
        "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "with open(pid_file, 'w', encoding='utf-8') as f:\n"
        "    json.dump({'child': os.getpid(), 'grandchild': gc.pid}, f)\n"
        "for raw in sys.stdin:\n"
        "    msg = json.loads(raw)\n"
        "    if msg.get('method') == 'initialize':\n"
        "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], "
        "'result': {'protocolVersion': '2025-11-25'}}) + '\\n')\n"
        "        sys.stdout.flush()\n"
        "    elif msg.get('method') == 'tools/call':\n"
        "        time.sleep(60)\n",
        encoding="utf-8",
    )

    proc = subprocess.Popen(
        [
            _PYTHON,
            "-m",
            "aerlog",
            "run",
            "--execution-id",
            exec_id,
            "--data-dir",
            str(data_dir),
            "--",
            _PYTHON,
            str(slow_srv),
        ],
        cwd=_REPO_ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
        proc.stdin.flush()

        init_line = proc.stdout.readline()
        assert json.loads(init_line)["id"] == 1

        # Wait briefly until grandchild PID file exists, then send an unanswered tools/call.
        deadline = time.monotonic() + 5.0
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert pid_file.exists()
        pids = json.loads(pid_file.read_text(encoding="utf-8"))

        proc.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "hang_tool", "arguments": {}},
                }
            )
            + "\n"
        )
        proc.stdin.flush()
        time.sleep(0.08)

        proc.terminate()
        _, err_out = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

    assert proc.returncode == 143
    assert "[aerlog]" in err_out

    # Both server process and spawned grandchild must be cleanly reaped.
    reap_deadline = time.monotonic() + 3.0
    while (_pid_alive(pids["child"]) or _pid_alive(pids["grandchild"])) and (
        time.monotonic() < reap_deadline
    ):
        time.sleep(0.05)
    assert not _pid_alive(pids["child"])
    assert not _pid_alive(pids["grandchild"])

    diag_res = _run_aerlog_cli("diagnose", exec_id, "--data-dir", str(data_dir), "--json", env=env)
    assert diag_res.returncode == 0, diag_res.stderr
    codes = {d["code"] for d in json.loads(diag_res.stdout)["diagnostics"]}
    assert "SIGNAL_INTERRUPTED_EXECUTION" in codes
    assert "REQUEST_WITHOUT_RESPONSE" in codes

    exp_res = _run_aerlog_cli(
        "export",
        "test",
        exec_id,
        "--allow-mutating",
        "--missing-policy",
        "error",
        "--output",
        str(tmp_path / "sig_export"),
        "--name",
        "sig_case",
        "--data-dir",
        str(data_dir),
        "--json",
        env=env,
    )
    assert exp_res.returncode == 0, exp_res.stderr
    ver_res = _run_aerlog_cli(
        "export",
        "verify",
        json.loads(exp_res.stdout)["fixture_path"],
        "--json",
        env=env,
    )
    assert ver_res.returncode == 0, ver_res.stderr
    assert json.loads(ver_res.stdout)["passed"] is True


def test_server_crash_and_corrupted_jsonl_tail_across_all_subsystems(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """Abrupt server crash + truncated trailing JSONL record degrades safely across CLI stages."""
    env = _xdg_env(isolated_xdg)
    data_dir = tmp_path / "crash_data"
    exec_id = new_execution_id()

    crash_srv = tmp_path / "crash_srv.py"
    crash_srv.write_text(
        "import json, os, sys\n"
        "for raw in sys.stdin:\n"
        "    msg = json.loads(raw)\n"
        "    if msg.get('id') == 1:\n"
        "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': 1, "
        "'result': {'protocolVersion': '2025-11-25'}}) + '\\n')\n"
        "        sys.stdout.flush()\n"
        "    elif msg.get('id') == 2:\n"
        "        sys.stderr.write('fatal server panic before reply\\n')\n"
        "        sys.stderr.flush()\n"
        "        os._exit(9)\n",
        encoding="utf-8",
    )

    in_frames = _ndjson(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
    )
    run_res = _run_aerlog_cli(
        "run",
        "--execution-id",
        exec_id,
        "--data-dir",
        str(data_dir),
        "--",
        _PYTHON,
        str(crash_srv),
        env=env,
        stdin_text=in_frames,
    )
    assert run_res.returncode == 9

    # Inject a simulated power-loss truncated partial UTF-8 JSONL line at the tail of events.jsonl.
    events_path = data_dir / EXECUTIONS_DIR_NAME / exec_id / EVENTS_FILE_NAME
    with events_path.open("ab") as fh:
        fh.write(b'{"partial_corrupt_tail": \xff\xfe')

    # Default tolerant CLI inspection/timeline/diagnostics/export warn cleanly and preserve prefix.
    for cmd in (
        ("inspect", exec_id),
        ("timeline", exec_id),
        ("diagnose", exec_id, "--json"),
    ):
        res = _run_aerlog_cli(*cmd, "--data-dir", str(data_dir), env=env)
        assert res.returncode == 0, f"{cmd}: {res.stderr}"
        assert "WARNING:" in res.stderr

    diag_json = json.loads(
        _run_aerlog_cli("diagnose", exec_id, "--data-dir", str(data_dir), "--json", env=env).stdout
    )
    diag_codes = {item["code"] for item in diag_json["diagnostics"]}
    assert "CORRUPT_RECORDING_DETECTED" in diag_codes
    assert "REQUEST_WITHOUT_RESPONSE" in diag_codes
    assert "UNEXPECTED_PROCESS_EXIT" in diag_codes

    # Export & verify succeed cleanly over the verified prefix, while --strict rejects corruption.
    exp_ok = _run_aerlog_cli(
        "export",
        "test",
        exec_id,
        "--output",
        str(tmp_path / "crash_exp"),
        "--name",
        "crash_prefix",
        "--data-dir",
        str(data_dir),
        "--json",
        env=env,
    )
    assert exp_ok.returncode == 0, exp_ok.stderr
    assert "WARNING:" in exp_ok.stderr

    ver_ok = _run_aerlog_cli(
        "export",
        "verify",
        json.loads(exp_ok.stdout)["fixture_path"],
        "--json",
        env=env,
    )
    assert ver_ok.returncode == 0, ver_ok.stderr

    for strict_cmd in (
        ("inspect", exec_id, "--strict"),
        ("diagnose", exec_id, "--strict"),
        ("export", "test", exec_id, "--strict", "--output", str(tmp_path / "strict_out")),
    ):
        strict_res = _run_aerlog_cli(*strict_cmd, "--data-dir", str(data_dir), env=env)
        assert strict_res.returncode == 1

    repo = RecordingRepository(data_dir)
    try:
        with pytest.raises(StorageCorruptionError):
            repo.get_execution_events(exec_id, strict_integrity=True)
    finally:
        repo.close()


@asynccontextmanager
async def _proxy_sdk_socketpair(
    proxy_cfg: ProxyConfig,
    observer: CaptureProxyObserver,
) -> AsyncGenerator[TransportStreams, None]:
    client_sock, proxy_sock = socket.socketpair()
    client_sock.setblocking(False)
    proxy_sock.setblocking(False)
    cli_reader, cli_writer = await asyncio.open_connection(sock=client_sock)
    proxy_reader, proxy_writer = await asyncio.open_connection(sock=proxy_sock)

    async def _c2s(send_stream: Any) -> None:
        async with send_stream:
            async for item in send_stream:
                payload = item.message.model_dump_json(by_alias=True, exclude_none=True)
                cli_writer.write((payload + "\n").encode("utf-8"))
                await cli_writer.drain()

    async def _s2c(recv_stream: Any) -> None:
        import mcp_types as types

        async with recv_stream:
            while raw := await cli_reader.readline():
                msg = types.jsonrpc_message_adapter.validate_json(
                    raw.decode("utf-8"), by_name=False
                )
                await recv_stream.send(SessionMessage(msg))

    import anyio

    send_w, recv_r = anyio.create_memory_object_stream[SessionMessage](32)
    send_c, recv_w = anyio.create_memory_object_stream[SessionMessage](32)
    proxy = StdioProxy(proxy_cfg)
    with open(os.devnull, "w", encoding="utf-8") as devnull:
        proxy_task = asyncio.create_task(
            proxy.run(
                stdin_reader=proxy_reader,
                stdout_writer=proxy_writer,
                diag_stream=devnull,
                observer=observer,
            )
        )
        t1 = asyncio.create_task(_c2s(recv_w))
        t2 = asyncio.create_task(_s2c(send_w))
        try:
            yield recv_r, send_c
        finally:
            await send_c.aclose()
            await recv_r.aclose()
            for task in (t1, t2):
                if not task.done():
                    task.cancel()
            await asyncio.gather(t1, t2, return_exceptions=True)
            cli_writer.close()
            await asyncio.wait_for(proxy_task, timeout=10.0)


async def test_enospc_disk_full_preserves_prior_recordings_and_marks_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mid-session ENOSPC keeps live MCP proxy working and leaves earlier runs uncorrupted."""
    data_dir = tmp_path / "enospc_data"
    srv_script = tmp_path / "enospc_srv.py"
    srv_script.write_text(
        "from mcp.server.mcpserver import MCPServer\n"
        "mcp = MCPServer('enospc-srv')\n"
        "@mcp.tool()\n"
        "def echo(text: str) -> str:\n"
        "    return f'ok:{text}'\n"
        "if __name__ == '__main__':\n"
        "    mcp.run(transport='stdio')\n",
        encoding="utf-8",
    )

    # 1. Persist one healthy execution first.
    healthy_id = new_execution_id()
    healthy_sink = PersistentCaptureSink(data_dir)
    healthy_obs = CaptureProxyObserver(
        healthy_sink, config=CaptureConfig(), execution_id=healthy_id
    )
    async with Client(
        _proxy_sdk_socketpair(ProxyConfig(command=(_PYTHON, str(srv_script))), healthy_obs),
        mode="legacy",
    ) as client_ok:
        r_ok = await client_ok.call_tool("echo", {"text": "first"})
        assert isinstance(r_ok.content[0], TextContent)
        assert r_ok.content[0].text == "ok:first"

    # 2. Second live proxy session suffers ENOSPC on its events.jsonl fd mid-session.
    fail_id = new_execution_id()
    fail_sink = PersistentCaptureSink(data_dir)
    fail_obs = CaptureProxyObserver(fail_sink, config=CaptureConfig(), execution_id=fail_id)
    target_fd: int | None = None
    real_os_write = os.write

    def _fail_enospc_on_second_exec(fd: int, data: object) -> int:
        if target_fd is not None and fd == target_fd:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_os_write(fd, data)  # type: ignore[arg-type]

    monkeypatch.setattr("os.write", _fail_enospc_on_target := _fail_enospc_on_second_exec)
    _ = _fail_enospc_on_target

    async with Client(
        _proxy_sdk_socketpair(ProxyConfig(command=(_PYTHON, str(srv_script))), fail_obs),
        mode="legacy",
    ) as client_fail:
        assert fail_sink._writer is not None
        target_fd = fail_sink._writer._fd
        # MCP protocol forwarding stays alive and succeeds despite capture disk failure!
        r_fail = await client_fail.call_tool("echo", {"text": "during-enospc"})
        assert isinstance(r_fail.content[0], TextContent)
        assert r_fail.content[0].text == "ok:during-enospc"

    assert fail_obs.pipeline is not None
    assert fail_obs.pipeline.sink_error is not None
    assert fail_obs.last_summary is not None
    assert fail_obs.last_summary.capture_completeness == "incomplete"

    # Earlier healthy execution stays completely intact with strict integrity verification.
    monkeypatch.undo()
    repo = RecordingRepository(data_dir)
    try:
        res_ok = repo.get_execution_events(healthy_id, strict_integrity=True)
        assert res_ok.summary is not None
        assert res_ok.summary.capture_completeness == "complete"
        assert res_ok.events[0].event.kind == "execution_started"
        assert res_ok.events[-1].event.kind == "execution_finished"
    finally:
        repo.close()
