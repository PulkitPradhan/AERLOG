"""Shared pytest fixtures for AERLOG tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass(frozen=True)
class IsolatedXdgPaths:
    """Temporary home and XDG base directories isolated per test."""

    home: Path
    config_home: Path
    data_home: Path


@pytest.fixture
def isolated_xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> IsolatedXdgPaths:
    """Isolate HOME, XDG variables, and AERLOG_CONFIG away from the user's machine."""
    home = tmp_path / "home"
    config_home = tmp_path / "xdg_config"
    data_home = tmp_path / "xdg_data"
    home.mkdir()

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
    monkeypatch.delenv("AERLOG_CONFIG", raising=False)

    return IsolatedXdgPaths(home=home, config_home=config_home, data_home=data_home)
