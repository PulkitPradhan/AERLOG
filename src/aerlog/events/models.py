"""Pydantic v2 structured event envelope and lifecycle models for AERLOG."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aerlog.events.ids import new_event_id
from aerlog.events.types import (
    EVENT_SCHEMA_VERSION,
    CaptureBackpressurePolicy,
    CaptureCompleteness,
    CorrelationConfidence,
    CorrelationStatus,
    EventDirection,
    EventKind,
    JsonRpcIdType,
    PayloadMode,
    RedactionMode,
    SchemaVersion,
    TraceSource,
    WireDirection,
)
from aerlog.protocol.framing import LineEnding

JsonRpcIdValue = int | str | float | bool | list[Any] | dict[str, Any] | None


def classify_jsonrpc_id(raw_obj: Mapping[str, Any]) -> tuple[JsonRpcIdType, JsonRpcIdValue]:
    """Classify a JSON-RPC ``id`` field preserving exact runtime type distinction.

    Preserves ``1`` vs ``"1"`` vs ``True`` (because ``bool`` subclasses ``int``
    in Python) and marks absence distinctly from ``null``.
    """
    if "id" not in raw_obj:
        return "missing", None

    value = raw_obj["id"]
    if value is None:
        return "null", None
    if isinstance(value, bool):
        return "bool", value
    if isinstance(value, int):
        return "int", value
    if isinstance(value, float):
        return "float", value
    if isinstance(value, str):
        return "str", value
    if isinstance(value, list):
        return "array", value
    if isinstance(value, dict):
        return "object", value
    return "missing", None


def _ensure_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class WireFrameInfo(BaseModel):
    """Observed wire framing metadata captured without modifying protocol bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    byte_length: int = Field(ge=0)
    line_ending: LineEnding
    sha256: str | None = None
    jsonrpc_version: str | None = None
    raw_id_present: bool = False
    raw_id_type: JsonRpcIdType = "missing"
    is_valid_jsonrpc_id: bool = False
    keys: tuple[str, ...] = ()


class TraceContext(BaseModel):
    """Trace context distinguishing observed wire headers from synthetic execution IDs.

    Observed W3C headers are populated strictly from wire ``params._meta``.
    ``synthetic_execution_trace_id`` is purely an execution-level grouping key
    and never implies distributed parent/child causation on the wire.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    trace_source: TraceSource = "none"
    observed_trace_id: str | None = None
    observed_parent_span_id: str | None = None
    observed_trace_flags: str | None = None
    observed_traceparent: str | None = None
    observed_tracestate: str | None = None
    synthetic_execution_trace_id: str | None = None


class CorrelationInfo(BaseModel):
    """Derived request/response, cancellation, or progress correlation annotation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: CorrelationStatus
    confidence: CorrelationConfidence
    basis: str
    matched_request_event_id: str | None = None
    matched_request_sequence: int | None = None
    matched_request_method: str | None = None
    candidate_request_event_ids: tuple[str, ...] = ()
    origin_direction: WireDirection | None = None
    latency_ns: int | None = Field(default=None, ge=0)
    cancel_notified: bool = False
    late_after_cancel: bool = False
    post_exit_frame: bool = False


class DerivedMetadata(BaseModel):
    """Derived non-wire metadata such as OTel semantic attributes and anomaly tags."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    otel_attributes: dict[str, str | bool] = Field(default_factory=dict)
    tool_is_error: bool | None = None
    anomaly_flags: tuple[str, ...] = ()


class RedactionSummary(BaseModel):
    """Audit summary of redaction applied before persistence or spooling."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: RedactionMode = "standard"
    payload_mode: PayloadMode = "redacted"
    applied: bool = True
    degraded: bool = False
    findings_count: int = Field(default=0, ge=0)
    redacted_paths: tuple[str, ...] = ()
    error: str | None = None


class ExecutionStartedPayload(BaseModel):
    """Lifecycle payload recorded when a captured proxy session begins."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["execution_started"] = "execution_started"
    command: tuple[str, ...]
    cwd: str | None = None
    transport: Literal["stdio"] = "stdio"
    redaction_mode: RedactionMode
    backpressure_policy: CaptureBackpressurePolicy
    env_override_keys: tuple[str, ...] = ()
    redacted_env_overrides: dict[str, str] = Field(default_factory=dict)


class ExecutionFinishedPayload(BaseModel):
    """Lifecycle payload recorded when a captured proxy session finalizes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["execution_finished"] = "execution_finished"
    termination_reason: str
    exit_code: int
    returncode: int | None = None
    completeness: CaptureCompleteness
    total_events: int = Field(ge=0)
    dropped_events: int = Field(default=0, ge=0)
    degraded_events: int = Field(default=0, ge=0)
    unanswered_request_count: int = Field(default=0, ge=0)
    unanswered_request_ids: tuple[str, ...] = ()
    spool_file: str | None = None


class ProcessStderrPayload(BaseModel):
    """Redacted child stderr line/chunk captured off stdout."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["process_stderr"] = "process_stderr"
    byte_length: int = Field(ge=0)
    text: str | None = None
    truncated: bool = False


class JsonRpcRequestPayload(BaseModel):
    """Observed JSON-RPC request frame preserving unknown methods and fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["jsonrpc_request"] = "jsonrpc_request"
    method: str | None = None
    id: JsonRpcIdValue = None
    id_type: JsonRpcIdType
    params: Any = None
    has_params: bool = False
    extra_fields: dict[str, Any] = Field(default_factory=dict)


class JsonRpcResponsePayload(BaseModel):
    """Observed JSON-RPC success response preserving unknown result fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["jsonrpc_response"] = "jsonrpc_response"
    id: JsonRpcIdValue = None
    id_type: JsonRpcIdType
    result: Any = None
    extra_fields: dict[str, Any] = Field(default_factory=dict)


class JsonRpcErrorPayload(BaseModel):
    """Observed JSON-RPC error response preserving custom error and extra fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["jsonrpc_error"] = "jsonrpc_error"
    id: JsonRpcIdValue = None
    id_type: JsonRpcIdType
    error: Any = None
    error_code: int | None = None
    error_message: str | None = None
    error_data: Any = None
    extra_fields: dict[str, Any] = Field(default_factory=dict)


class JsonRpcNotificationPayload(BaseModel):
    """Observed JSON-RPC notification frame preserving unknown methods and fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["jsonrpc_notification"] = "jsonrpc_notification"
    method: str | None = None
    params: Any = None
    has_params: bool = False
    extra_fields: dict[str, Any] = Field(default_factory=dict)


class JsonRpcUnknownObjectPayload(BaseModel):
    """Valid JSON object lacking standard request/response/error/notification keys."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["jsonrpc_unknown_object"] = "jsonrpc_unknown_object"
    body: dict[str, Any] = Field(default_factory=dict)


class NonObjectJsonFramePayload(BaseModel):
    """Valid UTF-8/JSON frame whose root value is not a JSON object (e.g., list/primitive)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["non_object_json_frame"] = "non_object_json_frame"
    json_type: str
    value: Any = None
    is_jsonrpc_batch_candidate: bool = False
    item_count: int | None = None


class MalformedJsonFramePayload(BaseModel):
    """Valid UTF-8 wire frame that failed JSON parsing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["malformed_json_frame"] = "malformed_json_frame"
    error: str
    text: str | None = None
    truncated: bool = False


class MalformedUtf8FramePayload(BaseModel):
    """Wire frame that could not be decoded strictly as UTF-8."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["malformed_utf8_frame"] = "malformed_utf8_frame"
    error: str
    redacted_lossy_text: str | None = None
    raw_bytes_b64: str | None = None
    truncated: bool = False


class IncompleteTrailingFramePayload(BaseModel):
    """Trailing bytes flushed at EOF without a terminating newline delimiter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["incomplete_trailing_frame"] = "incomplete_trailing_frame"
    byte_length: int = Field(ge=0)
    text: str | None = None
    truncated: bool = False


class FrameTooLargePayload(BaseModel):
    """Fail-closed record emitted when a wire frame exceeds ``max_frame_bytes``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["frame_too_large"] = "frame_too_large"
    observed_bytes: int = Field(gt=0)
    max_frame_bytes: int = Field(gt=0)


class TransportErrorPayload(BaseModel):
    """Transport/pipe closure or OS I/O error observed at the proxy boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["transport_error"] = "transport_error"
    stream_direction: WireDirection | None = None
    reason: str
    error: str


class ProxySignalPayload(BaseModel):
    """Signal or cancellation event received by the proxy process."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["proxy_signal"] = "proxy_signal"
    signal_name: str


class ChildShutdownEscalatePayload(BaseModel):
    """Signal escalation emitted while terminating the target MCP server group."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["child_shutdown_escalate"] = "child_shutdown_escalate"
    signal_name: str
    pgid: int
    error: str | None = None


class CaptureWarningPayload(BaseModel):
    """Explicit non-fatal warning regarding capture, redaction, or anomaly observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["capture_warning"] = "capture_warning"
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class CaptureGapPayload(BaseModel):
    """Explicit gap marker indicating non-silent loss under ``mark_incomplete``/failure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["capture_gap"] = "capture_gap"
    dropped_count: int = Field(ge=1)
    reason: str
    first_gap_monotonic_ns: int = Field(ge=0)
    last_gap_monotonic_ns: int = Field(ge=0)
    details: dict[str, Any] = Field(default_factory=dict)


EventPayload = Annotated[
    ExecutionStartedPayload
    | ExecutionFinishedPayload
    | ProcessStderrPayload
    | JsonRpcRequestPayload
    | JsonRpcResponsePayload
    | JsonRpcErrorPayload
    | JsonRpcNotificationPayload
    | JsonRpcUnknownObjectPayload
    | NonObjectJsonFramePayload
    | MalformedJsonFramePayload
    | MalformedUtf8FramePayload
    | IncompleteTrailingFramePayload
    | FrameTooLargePayload
    | TransportErrorPayload
    | ProxySignalPayload
    | ChildShutdownEscalatePayload
    | CaptureWarningPayload
    | CaptureGapPayload,
    Field(discriminator="kind"),
]


class ExecutionEvent(BaseModel):
    """Canonical structured event envelope for AERLOG execution capture."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: SchemaVersion = EVENT_SCHEMA_VERSION
    event_id: str = Field(default_factory=new_event_id)
    execution_id: str
    sequence: int = Field(ge=1)
    timestamp: datetime
    monotonic_time_ns: int = Field(ge=0)
    direction: EventDirection
    kind: EventKind
    wire: WireFrameInfo | None = None
    trace: TraceContext | None = None
    correlation: CorrelationInfo | None = None
    derived: DerivedMetadata | None = None
    redaction: RedactionSummary = Field(default_factory=RedactionSummary)
    degraded: bool = False
    payload: EventPayload

    @field_validator("timestamp")
    @classmethod
    def _normalize_timestamp(cls, value: datetime) -> datetime:
        return _ensure_utc_datetime(value)

    @model_validator(mode="after")
    def _validate_kind_matches_payload(self) -> ExecutionEvent:
        if self.kind != self.payload.kind:
            raise ValueError(
                f"Envelope kind {self.kind!r} does not match payload kind {self.payload.kind!r}"
            )
        return self


class ExecutionHeader(BaseModel):
    """Run-level metadata established when a capture session starts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: SchemaVersion = EVENT_SCHEMA_VERSION
    execution_id: str
    started_at: datetime
    monotonic_start_ns: int = Field(ge=0)
    command: tuple[str, ...]
    cwd: str | None = None
    transport: Literal["stdio"] = "stdio"
    redaction_mode: RedactionMode = "standard"
    backpressure_policy: CaptureBackpressurePolicy = "block"

    @field_validator("started_at")
    @classmethod
    def _normalize_started_at(cls, value: datetime) -> datetime:
        return _ensure_utc_datetime(value)


class ExecutionSummary(BaseModel):
    """Finalized summary of a completed or interrupted capture session."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: SchemaVersion = EVENT_SCHEMA_VERSION
    execution_id: str
    started_at: datetime
    ended_at: datetime
    duration_ns: int = Field(ge=0)
    command: tuple[str, ...]
    cwd: str | None = None
    transport: Literal["stdio"] = "stdio"
    redaction_mode: RedactionMode = "standard"
    backpressure_policy: CaptureBackpressurePolicy = "block"
    capture_completeness: CaptureCompleteness
    termination_reason: str
    exit_code: int
    returncode: int | None = None
    total_events: int = Field(ge=0)
    dropped_events: int = Field(default=0, ge=0)
    degraded_events: int = Field(default=0, ge=0)
    warning_count: int = Field(default=0, ge=0)
    gap_count: int = Field(default=0, ge=0)
    unanswered_request_ids: tuple[str, ...] = ()
    observed_trace_ids: tuple[str, ...] = ()
    observed_mcp_protocol_versions: tuple[str, ...] = ()
    spool_file: str | None = None

    @field_validator("started_at", "ended_at")
    @classmethod
    def _normalize_datetimes(cls, value: datetime) -> datetime:
        return _ensure_utc_datetime(value)


__all__ = [
    "CaptureGapPayload",
    "CaptureWarningPayload",
    "ChildShutdownEscalatePayload",
    "CorrelationInfo",
    "DerivedMetadata",
    "EventPayload",
    "ExecutionEvent",
    "ExecutionFinishedPayload",
    "ExecutionHeader",
    "ExecutionStartedPayload",
    "ExecutionSummary",
    "FrameTooLargePayload",
    "IncompleteTrailingFramePayload",
    "JsonRpcErrorPayload",
    "JsonRpcIdValue",
    "JsonRpcNotificationPayload",
    "JsonRpcRequestPayload",
    "JsonRpcResponsePayload",
    "JsonRpcUnknownObjectPayload",
    "MalformedJsonFramePayload",
    "MalformedUtf8FramePayload",
    "NonObjectJsonFramePayload",
    "ProcessStderrPayload",
    "ProxySignalPayload",
    "RedactionSummary",
    "TraceContext",
    "TransportErrorPayload",
    "WireFrameInfo",
    "classify_jsonrpc_id",
]
