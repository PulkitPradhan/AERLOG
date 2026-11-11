"""Configuration schema and XDG path defaults for AERLOG."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

APP_DIR_NAME = "aerlog"
CONFIG_FILE_NAME = "config.toml"

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def _resolve_xdg_dir(
    env_var: str,
    fallback_relative: Path,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Resolve an XDG base directory without creating directories on disk.

    Args:
        env_var: Name of the XDG environment variable (e.g., ``XDG_CONFIG_HOME``).
        fallback_relative: Path relative to ``Path.home()`` when ``env_var`` is unset.
        env: Optional environment mapping for testing; defaults to ``os.environ``.

    Returns:
        Resolved base directory path joined with ``APP_DIR_NAME``.
    """
    environ = os.environ if env is None else env
    raw_value = environ.get(env_var, "").strip()
    base = Path(raw_value).expanduser() if raw_value else Path.home() / fallback_relative
    return base / APP_DIR_NAME


def default_config_path(env: Mapping[str, str] | None = None) -> Path:
    """Return the default AERLOG configuration file path.

    Args:
        env: Optional environment mapping; defaults to ``os.environ``.

    Returns:
        ``$XDG_CONFIG_HOME/aerlog/config.toml`` or ``~/.config/aerlog/config.toml``.
    """
    return _resolve_xdg_dir("XDG_CONFIG_HOME", Path(".config"), env) / CONFIG_FILE_NAME


def default_data_dir(env: Mapping[str, str] | None = None) -> Path:
    """Return the default AERLOG data directory path.

    Args:
        env: Optional environment mapping; defaults to ``os.environ``.

    Returns:
        ``$XDG_DATA_HOME/aerlog`` or ``~/.local/share/aerlog``.
    """
    return _resolve_xdg_dir("XDG_DATA_HOME", Path(".local") / "share", env)


class AerlogConfig(BaseModel):
    """Validated runtime configuration for AERLOG.

    Unknown keys are forbidden so typos in configuration files fail explicitly
    rather than being silently ignored.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    data_dir: Path = Field(
        default_factory=default_data_dir,
        description="Root directory for local AERLOG recordings and indexes.",
    )
    log_level: LogLevel = Field(
        default="INFO",
        description="Diagnostic verbosity for off-stdout logs.",
    )

    @field_validator("data_dir", mode="before")
    @classmethod
    def _validate_data_dir(cls, value: object) -> Path:
        """Expand user home prefixes and reject empty path strings."""
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                raise ValueError("data_dir must not be empty")
            return Path(stripped).expanduser()
        if isinstance(value, Path):
            if not str(value).strip():
                raise ValueError("data_dir must not be empty")
            return value.expanduser()
        raise TypeError("data_dir must be a path string or pathlib.Path")
