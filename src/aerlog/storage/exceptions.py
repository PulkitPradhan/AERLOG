"""Storage-layer exceptions for AERLOG JSONL and SQLite persistence."""

from __future__ import annotations

from aerlog.events.types import EVENT_SCHEMA_VERSION


class StorageError(Exception):
    """Base exception for AERLOG storage operations."""


class InvalidExecutionIdError(StorageError, ValueError):
    """Raised when an execution identifier is invalid or fails path-containment checks."""


class ExecutionNotFoundError(StorageError):
    """Raised when a requested execution recording does not exist."""


class StorageWriteError(StorageError, OSError):
    """Raised when persisting event logs, metadata, or index state fails."""


class StorageDiskFullError(StorageWriteError):
    """Raised explicitly on ``ENOSPC`` (no space left on device) during writes."""


class StorageCorruptionError(StorageError):
    """Raised in strict integrity mode when corrupt or partial JSONL records are encountered."""


class UnsupportedSchemaVersionError(StorageError):
    """Raised when on-disk SQLite or JSONL schema version is incompatible with this binary."""


EXPECTED_EVENT_SCHEMA_VERSION = EVENT_SCHEMA_VERSION

__all__ = [
    "EXPECTED_EVENT_SCHEMA_VERSION",
    "ExecutionNotFoundError",
    "InvalidExecutionIdError",
    "StorageCorruptionError",
    "StorageDiskFullError",
    "StorageError",
    "StorageWriteError",
    "UnsupportedSchemaVersionError",
]
