"""Durable local JSONL and SQLite persistence subsystem for AERLOG."""

from __future__ import annotations

from aerlog.storage.database import (
    DB_FILE_NAME,
    IndexedEventRow,
    IndexedExecutionRow,
    SQLiteMetadataStore,
    SqliteSynchronousMode,
)
from aerlog.storage.event_log import (
    EVENTS_FILE_NAME,
    EXECUTION_FILE_NAME,
    EXECUTIONS_DIR_NAME,
    MANIFEST_FILE_NAME,
    STORAGE_SCHEMA_VERSION,
    CorruptionIssueKind,
    CorruptRecordReport,
    ExecutionManifest,
    FsyncPolicy,
    IndexedLogEvent,
    JsonlEventLogReader,
    JsonlEventLogWriter,
    JsonlReadResult,
    WrittenEventSlice,
    relative_recording_dir,
    resolve_execution_dir,
    validate_execution_id,
)
from aerlog.storage.exceptions import (
    EXPECTED_EVENT_SCHEMA_VERSION,
    ExecutionNotFoundError,
    InvalidExecutionIdError,
    StorageCorruptionError,
    StorageDiskFullError,
    StorageError,
    StorageWriteError,
    UnsupportedSchemaVersionError,
)
from aerlog.storage.migrations import LATEST_DB_SCHEMA_VERSION
from aerlog.storage.repositories import (
    EventQueryResult,
    ReconciliationReport,
    RecordingRepository,
    SpoolImportReport,
    StoredExecutionRecord,
)
from aerlog.storage.retention import (
    RetentionPolicy,
    RetentionReport,
    apply_retention,
    compact_database,
)
from aerlog.storage.sink import PersistentCaptureSink

__all__ = [
    "DB_FILE_NAME",
    "EVENTS_FILE_NAME",
    "EXECUTIONS_DIR_NAME",
    "EXECUTION_FILE_NAME",
    "EXPECTED_EVENT_SCHEMA_VERSION",
    "LATEST_DB_SCHEMA_VERSION",
    "MANIFEST_FILE_NAME",
    "STORAGE_SCHEMA_VERSION",
    "CorruptRecordReport",
    "CorruptionIssueKind",
    "EventQueryResult",
    "ExecutionManifest",
    "ExecutionNotFoundError",
    "FsyncPolicy",
    "IndexedEventRow",
    "IndexedExecutionRow",
    "IndexedLogEvent",
    "InvalidExecutionIdError",
    "JsonlEventLogReader",
    "JsonlEventLogWriter",
    "JsonlReadResult",
    "PersistentCaptureSink",
    "ReconciliationReport",
    "RecordingRepository",
    "RetentionPolicy",
    "RetentionReport",
    "SQLiteMetadataStore",
    "SpoolImportReport",
    "SqliteSynchronousMode",
    "StorageCorruptionError",
    "StorageDiskFullError",
    "StorageError",
    "StorageWriteError",
    "StoredExecutionRecord",
    "UnsupportedSchemaVersionError",
    "WrittenEventSlice",
    "apply_retention",
    "compact_database",
    "relative_recording_dir",
    "resolve_execution_dir",
    "validate_execution_id",
]
