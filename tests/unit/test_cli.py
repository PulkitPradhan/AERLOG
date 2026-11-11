"""Unit tests for AERLOG root CLI, help, completion, validation hints, and exit codes."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aerlog import __version__
from aerlog.cli.app import app
from aerlog.events.ids import new_execution_id
from tests.conftest import IsolatedXdgPaths

runner = CliRunner()


def test_cli_help_shows_description_and_version_option(
    isolated_xdg: IsolatedXdgPaths,
) -> None:
    """``aerlog --help`` exits 0 and does not create config or data directories."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "AERLOG" in result.output
    assert "--version" in result.output
    assert not (isolated_xdg.config_home / "aerlog").exists()
    assert not (isolated_xdg.data_home / "aerlog").exists()


def test_cli_version_long_and_short_flags(isolated_xdg: IsolatedXdgPaths) -> None:
    """``aerlog --version`` and ``-V`` print the package version and exit 0."""
    for flag in ("--version", "-V"):
        result = runner.invoke(app, [flag])
        assert result.exit_code == 0
        assert result.output.strip() == f"aerlog {__version__}"

    assert not (isolated_xdg.config_home / "aerlog").exists()
    assert not (isolated_xdg.data_home / "aerlog").exists()


def test_cli_bare_invocation_shows_help() -> None:
    """Invoking ``aerlog`` with no arguments prints help and exits 0."""
    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "--version" in result.output


def test_python_module_entrypoint_help_and_version(
    isolated_xdg: IsolatedXdgPaths,
) -> None:
    """``python -m aerlog --help`` and ``--version`` succeed as subprocesses."""
    env = os.environ.copy()
    env["HOME"] = str(isolated_xdg.home)
    env["XDG_CONFIG_HOME"] = str(isolated_xdg.config_home)
    env["XDG_DATA_HOME"] = str(isolated_xdg.data_home)
    env.pop("AERLOG_CONFIG", None)

    help_proc = subprocess.run(
        [sys.executable, "-m", "aerlog", "--help"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_proc.returncode == 0
    assert "AERLOG" in help_proc.stdout
    assert help_proc.stderr == ""

    ver_proc = subprocess.run(
        [sys.executable, "-m", "aerlog", "--version"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert ver_proc.returncode == 0
    assert ver_proc.stdout.strip() == f"aerlog {__version__}"
    assert ver_proc.stderr == ""

    assert not (isolated_xdg.config_home / "aerlog").exists()
    assert not (isolated_xdg.data_home / "aerlog").exists()


def test_console_script_entrypoint_version(isolated_xdg: IsolatedXdgPaths) -> None:
    """Installed ``aerlog`` console script next to ``sys.executable`` executes cleanly."""
    script_path = Path(sys.executable).with_name("aerlog")
    assert script_path.exists(), f"Expected installed console script at {script_path}"

    env = os.environ.copy()
    env["HOME"] = str(isolated_xdg.home)
    env["XDG_CONFIG_HOME"] = str(isolated_xdg.config_home)
    env["XDG_DATA_HOME"] = str(isolated_xdg.data_home)
    env.pop("AERLOG_CONFIG", None)

    proc = subprocess.run(
        [str(script_path), "--version"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == f"aerlog {__version__}"
    assert proc.stderr == ""


def test_cli_version_succeeds_even_with_missing_or_invalid_aerlog_config(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Eager --version / -V exits 0 cleanly without loading config or creating XDG files."""
    broken_cfg = tmp_path / "broken.toml"
    broken_cfg.write_text("not = [valid = toml\n", encoding="utf-8")
    monkeypatch.setenv("AERLOG_CONFIG", str(broken_cfg))

    for flag in ("--version", "-V"):
        res = runner.invoke(app, [flag])
        assert res.exit_code == 0
        assert res.output.strip() == f"aerlog {__version__}"

    assert not (isolated_xdg.config_home / "aerlog").exists()
    assert not (isolated_xdg.data_home / "aerlog").exists()


def test_cli_shell_completion_and_help_trees_without_xdg_side_effects(
    isolated_xdg: IsolatedXdgPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--show-completion and all command --help screens succeed cleanly without touching XDG."""
    monkeypatch.setattr("shellingham.detect_shell", lambda *a, **kw: ("bash", "/bin/bash"))
    comp_res = runner.invoke(app, ["--show-completion"])
    assert comp_res.exit_code == 0
    assert "_COMPLETE" in comp_res.output

    root_help = runner.invoke(app, ["--help"])
    assert root_help.exit_code == 0
    assert "--install-completion" in root_help.output
    assert "--show-completion" in root_help.output
    assert "Workflow examples:" in root_help.output

    for sub_args in (
        ["executions"],
        ["cassette"],
        ["export"],
    ):
        bare_sub = runner.invoke(app, sub_args)
        assert bare_sub.exit_code == 0
        assert "--install-completion" not in bare_sub.output

    for help_args in (
        ["run", "--help"],
        ["list", "--help"],
        ["executions", "list", "--help"],
        ["inspect", "--help"],
        ["timeline", "--help"],
        ["diagnose", "--help"],
        ["cassette", "create", "--help"],
        ["cassette", "inspect", "--help"],
        ["replay", "--help"],
        ["export", "test", "--help"],
        ["export", "verify", "--help"],
    ):
        res = runner.invoke(app, help_args)
        assert res.exit_code == 0, f"{help_args} failed: {res.output}"
        assert "Example" in res.output or "Examples" in res.output

    assert not (isolated_xdg.config_home / "aerlog").exists()
    assert not (isolated_xdg.data_home / "aerlog").exists()


def test_cli_list_alias_parity_and_actionable_validation_hints(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """``list`` matches ``executions list``, and bad options/flags fail with explicit hints."""
    for fmt in ([], ["--json"]):
        a = runner.invoke(app, ["list", *fmt])
        b = runner.invoke(app, ["executions", "list", *fmt])
        assert a.exit_code == 0
        assert b.exit_code == 0
        assert a.output == b.output

    bad_status_a = runner.invoke(app, ["list", "--status", "nope"])
    bad_status_b = runner.invoke(app, ["executions", "list", "--status", "nope"])
    assert bad_status_a.exit_code == 1
    assert bad_status_b.exit_code == 1
    assert "Invalid --status" in bad_status_a.output
    assert "Hint:" in bad_status_a.output
    assert bad_status_a.output == bad_status_b.output

    exec_id = new_execution_id()
    bad_dir = runner.invoke(app, ["timeline", exec_id, "--direction", "sideways"])
    assert bad_dir.exit_code == 1
    assert "client_to_server" in bad_dir.output
    assert "Hint:" in bad_dir.output

    bad_kind = runner.invoke(app, ["timeline", exec_id, "--kind", "bogus_kind"])
    assert bad_kind.exit_code == 1
    assert "jsonrpc_request" in bad_kind.output
    assert "Hint:" in bad_kind.output

    bad_sev = runner.invoke(app, ["diagnose", exec_id, "--min-severity", "fatal"])
    assert bad_sev.exit_code == 1
    assert "critical" in bad_sev.output
    assert "Hint:" in bad_sev.output

    bad_fmt = runner.invoke(app, ["export", "test", exec_id, "--format", "yaml"])
    assert bad_fmt.exit_code == 1
    assert "Invalid --format" in bad_fmt.output

    # Invalid Click/Typer syntax option exits with code 2.
    syntax_err = runner.invoke(app, ["list", "--definitely-not-a-flag"])
    assert syntax_err.exit_code == 2

    # Run validation rejects missing command, bad flags, missing cwd, and unredacted without opt-in.
    for run_args, expected_text in (
        (["run"], "No target MCP server command"),
        (["run", "--"], "No target MCP server command"),
        (["run", "--redaction-mode", "bogus", "--", "echo", "hi"], "Invalid --redaction-mode"),
        (["run", "--backpressure-policy", "bogus", "--", "echo", "hi"], "Invalid --backpressure"),
        (["run", "--fsync-policy", "bogus", "--", "echo", "hi"], "Invalid --fsync-policy"),
        (["run", "--execution-id", "../bad", "--", "echo", "hi"], "Run option error"),
        (
            ["run", "--cwd", str(tmp_path / "does_not_exist"), "--", "echo", "hi"],
            "Working directory does not exist",
        ),
        (
            ["run", "--redaction-mode", "explicit_unredacted", "--", "echo", "hi"],
            "--allow-unredacted",
        ),
    ):
        r = runner.invoke(app, run_args)
        assert r.exit_code == 1, f"{run_args} -> {r.output}"
        assert expected_text in r.output, f"{run_args} -> {r.output}"

    assert not (isolated_xdg.config_home / "aerlog").exists()
    assert not (isolated_xdg.data_home / "aerlog").exists()
