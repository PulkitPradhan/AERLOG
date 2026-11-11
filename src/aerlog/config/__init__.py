"""Configuration schema and loader for AERLOG."""

from __future__ import annotations

from aerlog.config.loader import (
    ConfigError,
    ConfigNotFoundError,
    ConfigParseError,
    ConfigValidationError,
    load_config,
    resolve_config_path,
)
from aerlog.config.schema import AerlogConfig, default_config_path, default_data_dir

__all__ = [
    "AerlogConfig",
    "ConfigError",
    "ConfigNotFoundError",
    "ConfigParseError",
    "ConfigValidationError",
    "default_config_path",
    "default_data_dir",
    "load_config",
    "resolve_config_path",
]
