"""Initial SQLite metadata and event-index schema migration (v1)."""

from __future__ import annotations

import sqlite3

VERSION = 1
NAME = "0001_initial"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS executions (
    execution_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    storage_schema_version TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    duration_ns INTEGER,
    command_json TEXT NOT NULL,
    cwd TEXT,
    transport TEXT NOT NULL,
    redaction_mode TEXT NOT NULL,
    backpressure_policy TEXT NOT NULL,
    capture_completeness TEXT NOT NULL,
    termination_reason TEXT,
    exit_code INTEGER,
    returncode INTEGER,
    total_events INTEGER NOT NULL DEFAULT 0,
    dropped_events INTEGER NOT NULL DEFAULT 0,
    degraded_events INTEGER NOT NULL DEFAULT 0,
    warning_count INTEGER NOT NULL DEFAULT 0,
    gap_count INTEGER NOT NULL DEFAULT 0,
    unanswered_request_ids_json TEXT NOT NULL DEFAULT '[]',
    observed_trace_ids_json TEXT NOT NULL DEFAULT '[]',
    observed_mcp_versions_json TEXT NOT NULL DEFAULT '[]',
    recording_dir TEXT NOT NULL,
    jsonl_byte_offset INTEGER NOT NULL DEFAULT 0,
    jsonl_sha256 TEXT,
    last_indexed_sequence INTEGER NOT NULL DEFAULT 0,
    index_status TEXT NOT NULL DEFAULT 'in_progress'
);

CREATE TABLE IF NOT EXISTS events_index (
    execution_id TEXT NOT NULL REFERENCES executions(execution_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL UNIQUE,
    sequence INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    monotonic_time_ns INTEGER NOT NULL,
    direction TEXT NOT NULL,
    kind TEXT NOT NULL,
    method TEXT,
    jsonrpc_id_type TEXT,
    jsonrpc_id_text TEXT,
    observed_trace_id TEXT,
    observed_parent_span_id TEXT,
    synthetic_execution_trace_id TEXT,
    correlation_status TEXT,
    matched_request_event_id TEXT,
    tool_is_error INTEGER,
    degraded INTEGER NOT NULL DEFAULT 0,
    jsonl_byte_offset INTEGER NOT NULL,
    jsonl_byte_length INTEGER NOT NULL,
    PRIMARY KEY (execution_id, sequence)
);

CREATE TABLE IF NOT EXISTS execution_corruptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT NOT NULL REFERENCES executions(execution_id) ON DELETE CASCADE,
    line_number INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL,
    byte_length INTEGER NOT NULL,
    issue_kind TEXT NOT NULL,
    excerpt_sha256 TEXT,
    details TEXT NOT NULL,
    detected_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_executions_started_at
    ON executions(started_at DESC);

CREATE INDEX IF NOT EXISTS idx_executions_completeness
    ON executions(capture_completeness, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_events_trace
    ON events_index(observed_trace_id, execution_id, sequence);

CREATE INDEX IF NOT EXISTS idx_events_synth_trace
    ON events_index(synthetic_execution_trace_id, sequence);

CREATE INDEX IF NOT EXISTS idx_events_span
    ON events_index(observed_parent_span_id, execution_id, sequence);

CREATE INDEX IF NOT EXISTS idx_events_req_corr
    ON events_index(execution_id, matched_request_event_id);

CREATE INDEX IF NOT EXISTS idx_events_jsonrpc_id
    ON events_index(execution_id, jsonrpc_id_type, jsonrpc_id_text);

CREATE INDEX IF NOT EXISTS idx_events_time
    ON events_index(execution_id, timestamp, sequence);

CREATE INDEX IF NOT EXISTS idx_events_kind
    ON events_index(execution_id, kind, sequence);

CREATE INDEX IF NOT EXISTS idx_corruptions_exec
    ON execution_corruptions(execution_id, line_number);
"""


def apply(conn: sqlite3.Connection) -> None:
    """Create initial tables and targeted query indexes."""
    conn.executescript(SCHEMA_SQL)
