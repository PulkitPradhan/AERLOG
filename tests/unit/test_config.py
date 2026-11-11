"""Tests for AERLOG XDG path resolution and TOML configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from aerlog.config import (
    AerlogConfig,
    ConfigNotFoundError,
    ConfigParseError,
    ConfigValidationError,
    default_config_path,
    default_data_dir,
    load_config,
    resolve_config_path,
)
from tests.conftest import IsolatedXdgPaths


def test_default_xdg_paths_when_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Default paths resolve to ~/.config/aerlog/config.toml and ~/.local/share/aerlog."""
    fake_home = tmp_path / "userhome"
    monkeypatch.setenv("HOME", str(fake_home))
    env: dict[str, str] = {}

    assert default_config_path(env) == fake_home / ".config" / "aerlog" / "config.toml"
    assert default_data_dir(env) == fake_home / ".local" / "share" / "aerlog"


def test_xdg_env_vars_are_respected(tmp_path: Path) -> None:
    """Setting XDG_CONFIG_HOME and XDG_DATA_HOME overrides the default locations."""
    custom_cfg = tmp_path / "cfg"
    custom_data = tmp_path / "data"
    env = {
        "XDG_CONFIG_HOME": str(custom_cfg),
        "XDG_DATA_HOME": str(custom_data),
    }

    assert default_config_path(env) == custom_cfg / "aerlog" / "config.toml"
    assert default_data_dir(env) == custom_data / "aerlog"


def test_missing_default_config_returns_defaults_without_creating_dirs(
    isolated_xdg: IsolatedXdgPaths,
) -> None:
    """When the default config file does not exist, built-in defaults are returned cleanly."""
    cfg = load_config()

    assert isinstance(cfg, AerlogConfig)
    assert cfg.data_dir == isolated_xdg.data_home / "aerlog"
    assert cfg.log_level == "INFO"
    assert not (isolated_xdg.config_home / "aerlog").exists()
    assert not (isolated_xdg.data_home / "aerlog").exists()


def test_loads_default_xdg_config_file_when_present(
    isolated_xdg: IsolatedXdgPaths,
) -> None:
    """When $XDG_CONFIG_HOME/aerlog/config.toml exists, it is parsed and validated."""
    cfg_dir = isolated_xdg.config_home / "aerlog"
    cfg_dir.mkdir(parents=True)
    cfg_file = cfg_dir / "config.toml"
    custom_data = isolated_xdg.home / "custom-recordings"
    cfg_file.write_text(
        f'data_dir = "{custom_data}"\nlog_level = "DEBUG"\n',
        encoding="utf-8",
    )

    cfg = load_config()

    assert cfg.data_dir == custom_data
    assert cfg.log_level == "DEBUG"


def test_config_precedence_explicit_path_over_env_and_default(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit path overrides AERLOG_CONFIG, which overrides the XDG default path."""
    env_cfg = tmp_path / "env.toml"
    env_cfg.write_text('log_level = "WARNING"\n', encoding="utf-8")
    arg_cfg = tmp_path / "arg.toml"
    arg_cfg.write_text('log_level = "ERROR"\n', encoding="utf-8")

    monkeypatch.setenv("AERLOG_CONFIG", str(env_cfg))

    resolved_env, is_explicit_env = resolve_config_path()
    assert resolved_env == env_cfg
    assert is_explicit_env is True
    loaded_env = load_config()
    assert loaded_env.log_level == "WARNING"
    assert loaded_env.data_dir == isolated_xdg.data_home / "aerlog"

    resolved_arg, is_explicit_arg = resolve_config_path(arg_cfg)
    assert resolved_arg == arg_cfg
    assert is_explicit_arg is True
    assert load_config(arg_cfg).log_level == "ERROR"


def test_missing_explicit_config_fails_clearly(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing explicit path (argument or AERLOG_CONFIG) never falls back to defaults."""
    _ = isolated_xdg
    missing_arg = tmp_path / "does-not-exist.toml"
    with pytest.raises(ConfigNotFoundError):
        load_config(missing_arg)

    missing_env = tmp_path / "missing-from-env.toml"
    monkeypatch.setenv("AERLOG_CONFIG", str(missing_env))
    with pytest.raises(ConfigNotFoundError):
        load_config()


def test_invalid_toml_fails_clearly(tmp_path: Path) -> None:
    """Malformed TOML raises ConfigParseError rather than falling back."""
    bad_toml = tmp_path / "bad.toml"
    bad_toml.write_text("log_level = [unterminated\n", encoding="utf-8")

    with pytest.raises(ConfigParseError):
        load_config(bad_toml)


def test_invalid_schema_and_unknown_keys_fail_clearly(tmp_path: Path) -> None:
    """Invalid field values or unknown keys raise ConfigValidationError."""
    bad_level = tmp_path / "bad_level.toml"
    bad_level.write_text('log_level = "TRACE"\n', encoding="utf-8")
    with pytest.raises(ConfigValidationError):
        load_config(bad_level)

    unknown_key = tmp_path / "unknown_key.toml"
    unknown_key.write_text('unknown_setting = "abc"\n', encoding="utf-8")
    with pytest.raises(ConfigValidationError):
        load_config(unknown_key)

    empty_dir = tmp_path / "empty_dir.toml"
    empty_dir.write_text('data_dir = "   "\n', encoding="utf-8")
    with pytest.raises(ConfigValidationError):
        load_config(empty_dir)


def test_corrupt_default_config_fails_clearly(isolated_xdg: IsolatedXdgPaths) -> None:
    """An invalid default config file on disk must fail rather than fall back silently."""
    cfg_dir = isolated_xdg.config_home / "aerlog"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config.toml").write_text("not = valid = toml\n", encoding="utf-8")

    with pytest.raises(ConfigParseError):
        load_config()


def test_directory_path_and_empty_explicit_path_rejected(tmp_path: Path) -> None:
    """Passing a directory or empty explicit path raises ConfigValidationError."""
    with pytest.raises(ConfigValidationError):
        load_config(tmp_path)

    with pytest.raises(ConfigValidationError):
        load_config("   ")
