"""Integration tests for Phase 12 CLI hardening, help polish, and rendering safety."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from aerlog.capture import CaptureConfig, CapturePipeline, RawWireFrameInput
from aerlog.cli.app import app
from aerlog.events import RedactionMode, WireDirection, new_execution_id
from aerlog.storage.event_log import EVENTS_FILE_NAME, EXECUTIONS_DIR_NAME
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


def _run_cli(
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


async def _record_session(
    data_dir: Path,
    *,
    exec_id: str,
    frames: list[tuple[WireDirection, dict[str, Any]]],
    command: tuple[str, ...] = ("python", "srv.py"),
    redaction_mode: RedactionMode = "standard",
) -> None:
    from datetime import UTC, datetime

    sink = PersistentCaptureSink(
        data_dir,
        fsync_policy="lifecycle",
        redaction_mode=redaction_mode,
    )
    pipeline = CapturePipeline(
        sink,
        command=command,
        config=CaptureConfig(redaction_mode=redaction_mode),
        execution_id=exec_id,
    )
    await pipeline.start()
    for idx, (direction, obj) in enumerate(frames, start=1):
        await pipeline.enqueue(
            RawWireFrameInput(
                timestamp=datetime.now(UTC),
                monotonic_time_ns=idx * 1_000,
                direction=direction,
                raw_frame=(json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8"),
            )
        )
    await pipeline.finalize(termination_reason="completed", exit_code=0, returncode=0)


async def test_cli_polish_help_strict_sequence_rich_markup_and_replay_mutual_excl(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """Verify help accuracy, --sequence --strict, Rich markup literalism, and replay checks."""
    env = _xdg_env(isolated_xdg)
    data_dir = tmp_path / "cli_polish_data"
    exec_id = new_execution_id()

    # 1. executions --help does not advertise non-existent 'inspect' subcommand.
    ex_help = _run_cli("executions", "--help", env=env)
    assert ex_help.returncode == 0
    assert "and inspect" not in ex_help.stdout.lower()

    # 2. Literal Rich markup tokens inside stored payloads/errors render verbatim (not dropped).
    literal_tag = "[bold red]literal-bracket-token[/]"
    await _record_session(
        data_dir,
        exec_id=exec_id,
        frames=[
            (
                "client_to_server",
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "tag_tool", "arguments": {"text": literal_tag}},
                },
            ),
            (
                "server_to_client",
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32603, "message": f"failed {literal_tag}"},
                },
            ),
        ],
    )

    insp_seq = _run_cli("inspect", exec_id, "--sequence", "2", "--data-dir", str(data_dir), env=env)
    assert insp_seq.returncode == 0, insp_seq.stderr
    assert literal_tag in insp_seq.stdout

    # 3. diagnose text shows unfiltered_total when --min-severity filters out findings.
    diag = _run_cli(
        "diagnose",
        exec_id,
        "--min-severity",
        "critical",
        "--fail-on",
        "error",
        "--data-dir",
        str(data_dir),
        env=env,
    )
    assert diag.returncode == 2
    assert "unfiltered_total=1" in diag.stdout

    # 4. Append corrupt JSONL line and verify `inspect --sequence N --strict` exits with code 1.
    events_path = data_dir / EXECUTIONS_DIR_NAME / exec_id / EVENTS_FILE_NAME
    with events_path.open("a", encoding="utf-8") as handle:
        handle.write("{broken_corrupt_tail\n")

    strict_seq = _run_cli(
        "inspect",
        exec_id,
        "--sequence",
        "2",
        "--strict",
        "--data-dir",
        str(data_dir),
        env=env,
    )
    assert strict_seq.returncode == 1
    assert (
        "invalid json" in strict_seq.stderr.lower()
        or "jsondecodeerror" in strict_seq.stderr.lower()
    )

    # 5. Passing both execution_id and --cassette to replay fails cleanly with exit 1.
    cass_file = tmp_path / "dummy.cassette.json"
    cass_file.write_text("{}", encoding="utf-8")
    mut_excl = _run_cli(
        "replay", exec_id, "--cassette", str(cass_file), "--data-dir", str(data_dir), env=env
    )
    assert mut_excl.returncode == 1
    assert "mutually exclusive" in mut_excl.stderr


def test_cli_run_strict_hash_only_stderr_redaction_and_exec_id_collision(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """`aerlog run` respects strict_hash_only on stderr, redacts diag log cmd, and blocks reuse."""
    env = _xdg_env(isolated_xdg)
    data_dir = tmp_path / "run_hardening_data"
    srv = tmp_path / "echo.py"
    srv.write_text(
        "import sys\nfor line in sys.stdin:\n    sys.stdout.write(line)\n    sys.stdout.flush()\n",
        encoding="utf-8",
    )
    diag_log = tmp_path / "proxy_diag.jsonl"
    exec_id = new_execution_id()

    proc = _run_cli(
        "run",
        "--execution-id",
        exec_id,
        "--data-dir",
        str(data_dir),
        "--redaction-mode",
        "strict_hash_only",
        "--log-file",
        str(diag_log),
        "--",
        _PYTHON,
        str(srv),
        "--api-key",
        "ultra_secret_cli_flag",
        env=env,
        stdin_text='{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
    )
    assert proc.returncode == 0, proc.stderr
    assert "ultra_secret_cli_flag" not in proc.stderr
    assert "[REDACTED_ARGS]" in proc.stderr
    assert "ultra_secret_cli_flag" not in diag_log.read_text(encoding="utf-8")

    # Reusing same --execution-id must fail cleanly instead of corrupting events.jsonl.
    dup = _run_cli(
        "run",
        "--execution-id",
        exec_id,
        "--data-dir",
        str(data_dir),
        "--",
        _PYTHON,
        str(srv),
        env=env,
        stdin_text='{"jsonrpc":"2.0","id":2,"method":"ping"}\n',
    )
    assert dup.returncode == 1
    assert "already exists" in dup.stderr


def test_cli_replay_serve_keyboard_interrupt_exits_130(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`replay --serve` translates KeyboardInterrupt cleanly into exit code 130."""
    from typer.testing import CliRunner

    env = _xdg_env(isolated_xdg)
    data_dir = tmp_path / "sigint_replay_data"
    exec_id = new_execution_id()

    srv = tmp_path / "echo_sig.py"
    srv.write_text(
        "import json, sys\n"
        "for raw in sys.stdin:\n"
        "    m = json.loads(raw)\n"
        "    if 'id' in m:\n"
        "        print(json.dumps({'jsonrpc': '2.0', 'id': m['id'], 'result': {}}), flush=True)\n",
        encoding="utf-8",
    )
    cap = _run_cli(
        "run",
        "--quiet",
        "--execution-id",
        exec_id,
        "--data-dir",
        str(data_dir),
        "--",
        _PYTHON,
        str(srv),
        env=env,
        stdin_text='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n',
    )
    assert cap.returncode == 0, cap.stderr

    def _raise_sigint(coro: Any, *args: Any, **kwargs: Any) -> Any:
        _ = (args, kwargs)
        if asyncio.iscoroutine(coro):
            coro.close()
        raise KeyboardInterrupt

    monkeypatch.setattr(asyncio, "run", _raise_sigint)
    runner = CliRunner()
    res = runner.invoke(
        app,
        ["replay", exec_id, "--serve", "--no-save-report", "--data-dir", str(data_dir)],
    )
    assert res.exit_code == 130
