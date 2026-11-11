"""Shared type definitions, schema versioning, and OTel constant names for AERLOG events."""

from __future__ import annotations

from typing import Final, Literal

EVENT_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"

SchemaVersion = Literal["1.0.0"]

WireDirection = Literal["client_to_server", "server_to_client"]

EventDirection = Literal[
    "client_to_server",
    "server_to_client",
    "proxy",
    "server_stderr",
    "system",
]

EventKind = Literal[
    "execution_started",
    "execution_finished",
    "process_stderr",
    "jsonrpc_request",
    "jsonrpc_response",
    "jsonrpc_error",
    "jsonrpc_notification",
    "jsonrpc_unknown_object",
    "non_object_json_frame",
    "malformed_json_frame",
    "malformed_utf8_frame",
    "incomplete_trailing_frame",
    "frame_too_large",
    "transport_error",
    "proxy_signal",
    "child_shutdown_escalate",
    "capture_warning",
    "capture_gap",
]

JsonRpcIdType = Literal["int", "str", "bool", "null", "float", "array", "object", "missing"]

CorrelationStatus = Literal[
    "matched",
    "ambiguous_duplicate_id",
    "orphaned_response",
    "duplicate_response",
    "cancel_target_matched",
    "cancel_target_missing",
    "progress_target_matched",
    "progress_target_missing",
    "invalid_id",
]

CorrelationConfidence = Literal["exact", "heuristic", "none"]

TraceSource = Literal["w3c_meta", "synthetic_execution", "none"]

RedactionMode = Literal["standard", "strict_hash_only", "explicit_unredacted"]

PayloadMode = Literal[
    "redacted",
    "strict_hash_only",
    "full_unredacted",
    "redaction_failed",
    "metadata_only",
]

CaptureBackpressurePolicy = Literal["block", "spill", "mark_incomplete"]

CaptureCompleteness = Literal["complete", "spilled", "degraded", "incomplete"]

# Minimal derived OpenTelemetry GenAI & MCP semantic attribute keys.
# AERLOG derives these strictly as read-only metadata without depending on an OTel SDK.
OTEL_ATTR_MCP_METHOD: Final[str] = "mcp.method.name"
OTEL_ATTR_MCP_PROTOCOL_VERSION: Final[str] = "mcp.protocol.version"
OTEL_ATTR_MCP_RESOURCE_URI: Final[str] = "mcp.resource.uri"
OTEL_ATTR_JSONRPC_REQUEST_ID: Final[str] = "jsonrpc.request.id"
OTEL_ATTR_GEN_AI_OPERATION: Final[str] = "gen_ai.operation.name"
OTEL_ATTR_GEN_AI_TOOL_NAME: Final[str] = "gen_ai.tool.name"
OTEL_ATTR_GEN_AI_PROMPT_NAME: Final[str] = "gen_ai.prompt.name"

__all__ = [
    "EVENT_SCHEMA_VERSION",
    "OTEL_ATTR_GEN_AI_OPERATION",
    "OTEL_ATTR_GEN_AI_PROMPT_NAME",
    "OTEL_ATTR_GEN_AI_TOOL_NAME",
    "OTEL_ATTR_JSONRPC_REQUEST_ID",
    "OTEL_ATTR_MCP_METHOD",
    "OTEL_ATTR_MCP_PROTOCOL_VERSION",
    "OTEL_ATTR_MCP_RESOURCE_URI",
    "CaptureBackpressurePolicy",
    "CaptureCompleteness",
    "CorrelationConfidence",
    "CorrelationStatus",
    "EventDirection",
    "EventKind",
    "JsonRpcIdType",
    "PayloadMode",
    "RedactionMode",
    "SchemaVersion",
    "TraceSource",
    "WireDirection",
]
