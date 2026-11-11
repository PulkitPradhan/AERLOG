"""Tests for the minimal Phase 2 AERLOG CLI entry point."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from aerlog import __version__
from aerlog.cli.app import app
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
