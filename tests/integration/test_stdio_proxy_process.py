"""Integration tests for StdioProxy process lifecycle, framing, and error policies."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from aerlog.proxy.stdio_proxy import (
    EXIT_DIAGNOSTIC_WRITE_FAILED,
    EXIT_FRAME_TOO_LARGE,
    EXIT_SPAWN_NOT_FOUND,
    EXIT_SPAWN_PERMISSION,
    ProxyConfig,
    StdioProxy,
)

PYTHON = sys.executable


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _proxy_cmd(
    server_code: str,
    *,
    log_file: Path | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
    cmd = [PYTHON, "-m", "aerlog.proxy.stdio_proxy"]
    if log_file is not None:
        cmd.extend(["--log-file", str(log_file)])
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend(["--", PYTHON, "-u", "-c", server_code])
    return cmd


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _grandchild_prelude(pids_file: Path) -> str:
    return (
        "import json, os, pathlib, subprocess, sys, time\n"
        "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"pathlib.Path({str(pids_file)!r}).write_text(\n"
        "    json.dumps({'child': os.getpid(), 'grandchild': gc.pid})\n"
        ")\n"
    )


def test_normal_sequential_unknown_fields_and_notifications_byte_exact(tmp_path: Path) -> None:
    echo_server = (
        "import sys\n"
        "for line in sys.stdin.buffer:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n"
    )
    payload = (
        b'{"jsonrpc": "2.0",  "id": 1, "method": "initialize", "extra_top": {"a": [1, 2]}}\n'
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}\r\n'
        b'{"jsonrpc":"2.0","id":"req-2","method":"vendor/custom","params":{"k":"v"}}\n'
    )
    log_file = tmp_path / "proxy.jsonl"
    proc = subprocess.run(
        _proxy_cmd(echo_server, log_file=log_file),
        input=payload,
        capture_output=True,
        timeout=5,
        check=False,
    )

    assert proc.returncode == 0
    assert proc.stdout == payload
    assert proc.stderr == b""

    records = _read_jsonl(log_file)
    c2s_frames = [
        r
        for r in records
        if r.get("event") == "protocol_frame" and r.get("direction") == "client_to_server"
    ]
    s2c_frames = [
        r
        for r in records
        if r.get("event") == "protocol_frame" and r.get("direction") == "server_to_client"
    ]
    assert len(c2s_frames) == 3
    assert len(s2c_frames) == 3
    assert c2s_frames[0]["method"] == "initialize"
    assert "extra_top" in c2s_frames[0]["keys"]  # type: ignore[operator]
    assert c2s_frames[1]["kind"] == "notification"
    assert c2s_frames[1]["line_ending"] == "crlf"
    assert c2s_frames[2]["id"] == "req-2"
    assert c2s_frames[2]["method"] == "vendor/custom"


def test_concurrent_interleaved_requests_and_out_of_order_responses(tmp_path: Path) -> None:
    interleaved_server = (
        "import json, sys, threading, time\n"
        "lock = threading.Lock()\n"
        "def send(obj):\n"
        "    data = (json.dumps(obj) + '\\n').encode('utf-8')\n"
        "    with lock:\n"
        "        sys.stdout.buffer.write(data)\n"
        "        sys.stdout.buffer.flush()\n"
        "def handle(req):\n"
        "    if req['id'] == 1:\n"
        "        time.sleep(0.12)\n"
        "    send({'jsonrpc': '2.0', 'id': req['id'], 'result': {'handled': req['id']}})\n"
        "threads = []\n"
        "for raw in sys.stdin.buffer:\n"
        "    req = json.loads(raw.decode('utf-8'))\n"
        "    t = threading.Thread(target=handle, args=(req,))\n"
        "    t.start()\n"
        "    threads.append(t)\n"
        "for t in threads:\n"
        "    t.join()\n"
    )
    reqs = b'{"jsonrpc":"2.0","id":1,"method":"slow"}\n{"jsonrpc":"2.0","id":2,"method":"fast"}\n'
    log_file = tmp_path / "interleaved.jsonl"
    proc = subprocess.run(
        _proxy_cmd(interleaved_server, log_file=log_file),
        input=reqs,
        capture_output=True,
        timeout=5,
        check=False,
    )

    assert proc.returncode == 0
    responses = [json.loads(line) for line in proc.stdout.decode("utf-8").splitlines()]
    assert [r["id"] for r in responses] == [2, 1]


def test_malformed_json_invalid_utf8_trailing_cr_and_split_multibyte_utf8(tmp_path: Path) -> None:
    raw_echo = (
        "import sys\n"
        "while True:\n"
        "    chunk = sys.stdin.buffer.read(64)\n"
        "    if not chunk:\n"
        "        break\n"
        "    sys.stdout.buffer.write(chunk)\n"
        "    sys.stdout.buffer.flush()\n"
    )
    log_file = tmp_path / "bytes.jsonl"
    proc = subprocess.Popen(
        _proxy_cmd(raw_echo, log_file=log_file),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None and proc.stdout is not None

    bad_utf8 = b'{"bad":"\xff\xfe"}\n'
    bad_json = b"{not json\n"
    multibyte_ok = '{"jsonrpc":"2.0","id":7,"method":"echo","params":{"t":"🚀é"}}\n'.encode()
    trailing_cr = b'{"incomplete":1}\r'

    split_at = multibyte_ok.index("🚀".encode()) + 2
    chunks = [
        bad_utf8,
        bad_json,
        multibyte_ok[:split_at],
        multibyte_ok[split_at:],
        trailing_cr,
    ]
    for chunk in chunks:
        proc.stdin.write(chunk)
        proc.stdin.flush()
        time.sleep(0.02)
    proc.stdin.close()

    stdout_bytes = proc.stdout.read()
    proc.wait(timeout=5)

    assert proc.returncode == 0
    assert stdout_bytes == bad_utf8 + bad_json + multibyte_ok + trailing_cr

    records = _read_jsonl(log_file)
    events = [r["event"] for r in records]
    assert "malformed_utf8" in events
    assert "malformed_json" in events
    assert "incomplete_trailing_frame" in events
    ok_frames = [
        r
        for r in records
        if r.get("event") == "protocol_frame"
        and r.get("direction") == "client_to_server"
        and r.get("id") == 7
    ]
    assert len(ok_frames) == 1
    assert ok_frames[0]["method"] == "echo"


def test_max_frame_bytes_exact_boundary_and_fail_closed_cleanup(tmp_path: Path) -> None:
    limit = 64
    pids_file = tmp_path / "pids.json"
    server_code = _grandchild_prelude(pids_file) + (
        "for line in sys.stdin.buffer:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n"
        "time.sleep(5)\n"
    )

    # 1. Exact boundary frame (64 bytes including '\n') succeeds.
    exact_frame = b'{"jsonrpc":"2.0","id":1,"method":"' + (b"x" * (limit - 37)) + b'"}\n'
    assert len(exact_frame) == limit
    log_ok = tmp_path / "exact_ok.jsonl"
    ok_proc = subprocess.Popen(
        _proxy_cmd(server_code, log_file=log_ok, extra_args=["--max-frame-bytes", str(limit)]),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert ok_proc.stdin is not None and ok_proc.stdout is not None
    ok_proc.stdin.write(exact_frame)
    ok_proc.stdin.flush()
    received_line = ok_proc.stdout.readline()
    assert received_line == exact_frame
    ok_proc.send_signal(signal.SIGTERM)
    ok_proc.wait(timeout=5)

    # 2. Oversized frame (limit + 1 = 65 bytes) fails closed and cleans child group.
    pids_file.unlink(missing_ok=True)
    log_over = tmp_path / "oversized.jsonl"
    oversized_frame = b"y" * limit + b"\n"
    assert len(oversized_frame) == limit + 1

    over_proc = subprocess.Popen(
        _proxy_cmd(server_code, log_file=log_over, extra_args=["--max-frame-bytes", str(limit)]),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 5.0
    while not pids_file.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert pids_file.exists()
    pids = json.loads(pids_file.read_text(encoding="utf-8"))

    stdout_data, _ = over_proc.communicate(oversized_frame, timeout=5)
    assert over_proc.returncode == EXIT_FRAME_TOO_LARGE
    assert stdout_data == b""

    time.sleep(0.1)
    for pid in pids.values():
        assert not _pid_alive(int(pid))

    over_records = _read_jsonl(log_over)
    assert any(r.get("event") == "frame_too_large" for r in over_records)


def test_spawn_failure_missing_and_permission_denied(tmp_path: Path) -> None:
    missing_log = tmp_path / "missing.jsonl"
    missing_proc = subprocess.run(
        [
            PYTHON,
            "-m",
            "aerlog.proxy.stdio_proxy",
            "--log-file",
            str(missing_log),
            "--",
            str(tmp_path / "nonexistent-mcp-server"),
        ],
        input=b"",
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert missing_proc.returncode == EXIT_SPAWN_NOT_FOUND
    assert missing_proc.stdout == b""
    assert any(r.get("event") == "server_spawn_failed" for r in _read_jsonl(missing_log))

    non_exec = tmp_path / "not_executable.sh"
    non_exec.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    non_exec.chmod(0o644)

    perm_log = tmp_path / "perm.jsonl"
    perm_proc = subprocess.run(
        [
            PYTHON,
            "-m",
            "aerlog.proxy.stdio_proxy",
            "--log-file",
            str(perm_log),
            "--",
            str(non_exec),
        ],
        input=b"",
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert perm_proc.returncode == EXIT_SPAWN_PERMISSION
    assert perm_proc.stdout == b""
    assert any(r.get("event") == "server_spawn_failed" for r in _read_jsonl(perm_log))


def test_abrupt_server_exit_drains_stdout_and_cleans_grandchild(tmp_path: Path) -> None:
    pids_file = tmp_path / "grandchild.json"
    # Spawn a grandchild inheriting stdout/stderr and exit the server immediately with code 42.
    crash_server = _grandchild_prelude(pids_file) + (
        'sys.stdout.buffer.write(b\'{"jsonrpc":"2.0","method":"notifications/bye"}\\n\')\n'
        "sys.stdout.buffer.flush()\n"
        "sys.exit(42)\n"
    )
    log_file = tmp_path / "abrupt.jsonl"
    proc = subprocess.run(
        _proxy_cmd(crash_server, log_file=log_file, extra_args=[]),
        input=b"",
        capture_output=True,
        timeout=8,
        check=False,
    )

    assert proc.returncode == 42
    assert proc.stdout == b'{"jsonrpc":"2.0","method":"notifications/bye"}\n'

    pids = json.loads(pids_file.read_text(encoding="utf-8"))
    time.sleep(0.1)
    for pid in pids.values():
        assert not _pid_alive(int(pid))

    records = _read_jsonl(log_file)
    assert any(r.get("event") == "server_exited" and r.get("returncode") == 42 for r in records)


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_sigint_and_sigterm_reap_child_and_grandchild(tmp_path: Path, sig: signal.Signals) -> None:
    pids_file = tmp_path / f"pids_{sig.name}.json"
    server_code = _grandchild_prelude(pids_file) + "time.sleep(60)\n"
    log_file = tmp_path / f"sig_{sig.name}.jsonl"
    proc = subprocess.Popen(
        _proxy_cmd(server_code, log_file=log_file),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    deadline = time.monotonic() + 5.0
    while not pids_file.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert pids_file.exists()
    pids = json.loads(pids_file.read_text(encoding="utf-8"))

    proc.send_signal(sig)
    proc.wait(timeout=5)
    assert proc.returncode == 128 + sig.value

    time.sleep(0.1)
    for pid in pids.values():
        assert not _pid_alive(int(pid))


async def test_task_cancellation_with_open_pipe_leaves_zero_orphans(tmp_path: Path) -> None:
    pids_file = tmp_path / "task_cancel_pids.json"
    server_code = _grandchild_prelude(pids_file) + "time.sleep(60)\n"
    in_r, in_w = os.pipe()
    out_r, out_w = os.pipe()
    loop = asyncio.get_running_loop()

    stdin_reader = asyncio.StreamReader()
    in_transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(stdin_reader),
        os.fdopen(in_r, "rb", closefd=True),
    )
    out_transport, out_protocol = await loop.connect_write_pipe(
        lambda: asyncio.StreamReaderProtocol(asyncio.StreamReader(limit=64), loop=loop),
        os.fdopen(out_w, "wb", closefd=True),
    )
    stdout_writer = asyncio.StreamWriter(out_transport, out_protocol, None, loop)

    log_file = tmp_path / "task_cancel.jsonl"
    proxy = StdioProxy(
        ProxyConfig(
            command=(PYTHON, "-u", "-c", server_code),
            log_file=log_file,
        )
    )
    task = asyncio.create_task(proxy.run(stdin_reader=stdin_reader, stdout_writer=stdout_writer))

    try:
        deadline = time.monotonic() + 5.0
        while not pids_file.exists() and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        assert pids_file.exists()
        pids = json.loads(pids_file.read_text(encoding="utf-8"))

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        await asyncio.sleep(0.1)
        for pid in pids.values():
            assert not _pid_alive(int(pid))
    finally:
        in_transport.close()
        out_transport.close()
        os.close(in_w)
        os.close(out_r)


def test_diagnostic_write_failure_degrade_vs_strict(tmp_path: Path) -> None:
    echo_server = (
        "import sys\n"
        "for line in sys.stdin.buffer:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n"
    )
    msg = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'

    # Directory path fails open() with IsADirectoryError (an OSError).
    degrade_proc = subprocess.run(
        _proxy_cmd(echo_server, log_file=tmp_path, extra_args=["--write-policy", "degrade"]),
        input=msg,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert degrade_proc.returncode == 0
    assert degrade_proc.stdout == msg
    assert b"diagnostic_write_failed" in degrade_proc.stderr

    strict_proc = subprocess.run(
        _proxy_cmd(echo_server, log_file=tmp_path, extra_args=["--write-policy", "strict"]),
        input=msg,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert strict_proc.returncode == EXIT_DIAGNOSTIC_WRITE_FAILED
    assert strict_proc.stdout == b""
    assert b"diagnostic_write_failed" in strict_proc.stderr


def test_privacy_no_env_leak_secret_redaction_and_no_previews(tmp_path: Path) -> None:
    server_code = (
        "import sys\n"
        "sys.stderr.write('auth failed Authorization: Bearer supersecret_bearer_token\\n')\n"
        "sys.stderr.flush()\n"
        "for line in sys.stdin.buffer:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n"
    )
    env = os.environ.copy()
    env["AERLOG_TEST_SECRET_ENV"] = "env_secret_value_xyz"

    bad_json = b'{broken "api_key": "sk-secret1234567890"\n'
    valid = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"secret":"payload_secret_abc"}}\n'
    )

    log_redacted = tmp_path / "redacted.jsonl"
    proc = subprocess.run(
        _proxy_cmd(server_code, log_file=log_redacted),
        input=bad_json + valid,
        env=env,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == bad_json + valid

    log_text = log_redacted.read_text(encoding="utf-8")
    assert "AERLOG_TEST_SECRET_ENV" not in log_text
    assert "env_secret_value_xyz" not in log_text
    assert "payload_secret_abc" not in log_text
    assert "supersecret_bearer_token" not in log_text
    assert "sk-secret1234567890" not in log_text
    assert "[REDACTED]" in log_text

    # --no-previews omits both malformed previews and stderr text.
    log_no_prev = tmp_path / "no_previews.jsonl"
    proc2 = subprocess.run(
        _proxy_cmd(server_code, log_file=log_no_prev, extra_args=["--no-previews"]),
        input=bad_json + valid,
        env=env,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert proc2.returncode == 0
    for rec in _read_jsonl(log_no_prev):
        assert "preview" not in rec
        assert "preview_hex" not in rec
        assert "text" not in rec


def test_downstream_slow_consumer_backpressure_delivers_all_frames(tmp_path: Path) -> None:
    burst_server = (
        "import json, sys\n"
        "for i in range(400):\n"
        "    obj = {'jsonrpc': '2.0', 'id': i, 'result': {'pad': 'Z' * 1024}}\n"
        "    sys.stdout.buffer.write((json.dumps(obj) + '\\n').encode('utf-8'))\n"
        "sys.stdout.buffer.flush()\n"
    )
    log_file = tmp_path / "backpressure.jsonl"
    proc = subprocess.Popen(
        _proxy_cmd(burst_server, log_file=log_file),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.close()

    received_lines: list[bytes] = []
    # Slowly drain stdout to force OS pipe backpressure through drain().
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        received_lines.append(line)
        if len(received_lines) % 50 == 0:
            time.sleep(0.02)

    proc.wait(timeout=10)
    assert proc.returncode == 0
    assert len(received_lines) == 400
    assert [json.loads(line)["id"] for line in received_lines] == list(range(400))
