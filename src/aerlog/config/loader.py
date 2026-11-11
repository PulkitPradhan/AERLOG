"""TOML configuration loader for AERLOG using Python stdlib ``tomllib``."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from aerlog.config.schema import AerlogConfig, default_config_path, default_data_dir

CONFIG_PATH_ENV_VAR = "AERLOG_CONFIG"


class ConfigError(Exception):
    """Base error raised for AERLOG configuration failures."""


class ConfigNotFoundError(ConfigError):
    """Raised when an explicitly specified configuration file does not exist."""


class ConfigParseError(ConfigError):
    """Raised when a configuration file cannot be read as valid UTF-8 TOML."""


class ConfigValidationError(ConfigError):
    """Raised when parsed configuration data violates the AERLOG schema."""


def resolve_config_path(
    explicit_path: Path | str | None = None,
    env: Mapping[str, str] | None = None,
) -> tuple[Path, bool]:
    """Determine the configuration file path and whether it was explicitly requested.

    Precedence:
        1. ``explicit_path`` argument.
        2. ``AERLOG_CONFIG`` environment variable (when non-empty).
        3. XDG default config path (``$XDG_CONFIG_HOME/aerlog/config.toml``).

    Args:
        explicit_path: Optional path provided directly by the caller.
        env: Optional environment mapping; defaults to ``os.environ``.

    Returns:
        Tuple of ``(resolved_path, is_explicit)``.

    Raises:
        ConfigValidationError: If ``explicit_path`` is an empty or whitespace string.
    """
    if explicit_path is not None:
        raw = str(explicit_path).strip()
        if not raw:
            raise ConfigValidationError("Explicit configuration path must not be empty")
        return Path(raw).expanduser(), True

    environ = os.environ if env is None else env
    env_path = environ.get(CONFIG_PATH_ENV_VAR, "").strip()
    if env_path:
        return Path(env_path).expanduser(), True

    return default_config_path(environ), False


def load_config(
    path: Path | str | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> AerlogConfig:
    """Load and validate AERLOG configuration without creating filesystem directories.

    A missing default configuration file resolves to validated built-in defaults.
    A missing *explicit* configuration file, or any existing configuration file
    with invalid TOML or schema violations, raises a ``ConfigError`` subclass.

    Args:
        path: Optional explicit configuration file path.
        env: Optional environment mapping; defaults to ``os.environ``.

    Returns:
        Validated :class:`AerlogConfig` instance.

    Raises:
        ConfigNotFoundError: If an explicit configuration path does not exist.
        ConfigParseError: If the file cannot be read or contains invalid TOML.
        ConfigValidationError: If the path is a directory or fails schema validation.
    """
    environ = os.environ if env is None else env
    config_path, is_explicit = resolve_config_path(path, environ)

    if not config_path.exists():
        if is_explicit:
            raise ConfigNotFoundError(f"Configuration file not found: {config_path}")
        return AerlogConfig(data_dir=default_data_dir(environ))

    if config_path.is_dir():
        raise ConfigValidationError(
            f"Configuration path is a directory, expected a TOML file: {config_path}"
        )

    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigParseError(f"Unable to read configuration file {config_path}: {exc}") from exc

    try:
        parsed: dict[str, Any] = tomllib.loads(raw_text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigParseError(f"Invalid TOML in {config_path}: {exc}") from exc

    payload: dict[str, Any] = dict(parsed)
    if "data_dir" not in payload:
        payload["data_dir"] = default_data_dir(environ)

    try:
        return AerlogConfig.model_validate(payload)
    except ValidationError as exc:
        raise ConfigValidationError(
            f"Invalid configuration schema in {config_path}: {exc}"
        ) from exc
