"""Configuration schema and XDG path defaults for AERLOG."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aerlog.events.types import CaptureBackpressurePolicy, RedactionMode

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


class CaptureSettings(BaseModel):
    """Capture pipeline durability and redaction configuration settings.

    Note:
        The default ``backpressure_policy="block"`` guarantees lossless, bounded-memory
        capture and may delay MCP forwarding when a capture sink sustains low throughput.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    backpressure_policy: CaptureBackpressurePolicy = Field(
        default="block",
        description="Backpressure strategy under slow/full capture buffers (never silent drop).",
    )
    redaction_mode: RedactionMode = Field(
        default="standard",
        description=(
            "Pre-persistence redaction policy ('standard', 'strict_hash_only', "
            "or explicit opt-in 'explicit_unredacted')."
        ),
    )
    max_queue_events: int = Field(
        default=2048,
        gt=0,
        description="Maximum buffered raw capture events in memory before backpressure engages.",
    )
    max_queue_bytes: int = Field(
        default=64 * 1024 * 1024,
        gt=0,
        description="Maximum estimated buffered capture bytes in memory.",
    )
    spill_write_timeout_s: float = Field(
        default=0.5,
        gt=0.0,
        description=(
            "Seconds before a stalled primary sink triggers recovery spooling under 'spill'."
        ),
    )
    drain_timeout_s: float = Field(
        default=10.0,
        gt=0.0,
        description="Seconds allowed to flush buffered capture events on proxy shutdown.",
    )


class StorageSettings(BaseModel):
    """Phase 5 local JSONL and SQLite persistence settings."""

    model_config = ConfigDict(extra="forbid", validate_default=True)

    fsync_policy: Literal["lifecycle", "every_batch", "none"] = Field(
        default="lifecycle",
        description="When to fsync JSONL event logs ('lifecycle', 'every_batch', or 'none').",
    )
    sqlite_synchronous: Literal["NORMAL", "FULL"] = Field(
        default="NORMAL",
        description="SQLite PRAGMA synchronous mode under WAL.",
    )
    persist_cwd: bool = Field(
        default=False,
        description=(
            "Whether to record host working directory paths (disabled by default for privacy)."
        ),
    )


class DiagnosticsSettings(BaseModel):
    """Phase 7 deterministic diagnostics configuration settings."""

    model_config = ConfigDict(extra="forbid", validate_default=True)

    request_timeout_ms: int | None = Field(
        default=None,
        gt=0,
        description=(
            "Optional configured request timeout threshold in milliseconds. "
            "Must be explicitly set; never defaulted silently."
        ),
    )
    repeated_call_threshold: int = Field(
        default=3,
        ge=2,
        description=(
            "Minimum count of identical repeated requests before flagging REPEATED_IDENTICAL_CALLS."
        ),
    )


class ReplaySettings(BaseModel):
    """Phase 8 safe offline cassette replay defaults (live replay blocked by default)."""

    model_config = ConfigDict(extra="forbid", validate_default=True)

    default_replay_mode: Literal["cassette"] = Field(
        default="cassette",
        description="Default replay mode ('cassette' offline only; live mode blocked).",
    )
    default_match_mode: Literal["strict", "tolerant"] = Field(
        default="strict",
        description="Request matching mode ('strict' ordered vs 'tolerant' normalized).",
    )
    unsafe_tool_policy: Literal["block", "warn"] = Field(
        default="block",
        description=(
            "Safety policy for potentially_mutating and unknown_unsafe interactions "
            "('block' by default; 'warn' with explicit --allow-mutating)."
        ),
    )
    missing_response_policy: Literal["error", "omit"] = Field(
        default="error",
        description=(
            "Behavior when a recorded request has no captured response ('error' or 'omit')."
        ),
    )


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
    capture: CaptureSettings = Field(
        default_factory=CaptureSettings,
        description="Phase 4 capture pipeline redaction and durability defaults.",
    )
    storage: StorageSettings = Field(
        default_factory=StorageSettings,
        description="Phase 5 persistent JSONL and SQLite storage settings.",
    )
    diagnostics: DiagnosticsSettings = Field(
        default_factory=DiagnosticsSettings,
        description="Phase 7 deterministic diagnostic rule thresholds.",
    )
    replay: ReplaySettings = Field(
        default_factory=ReplaySettings,
        description="Phase 8 offline cassette replay and side-effect safety defaults.",
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
