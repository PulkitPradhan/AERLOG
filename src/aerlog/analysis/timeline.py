"""Deterministic chronological timeline reconstruction from immutable stored events.

Reconstruction operates purely in memory over stored events without altering
events or fabricating parent-child causal trees that cannot be observed across
the ``stdio`` proxy boundary.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from aerlog.capture.redaction import EventRedactor, RedactionConfig
from aerlog.events.correlation import RequestCorrelator
from aerlog.events.ids import synthetic_trace_id_for_execution
from aerlog.events.models import (
    CaptureGapPayload,
    CaptureWarningPayload,
    ChildShutdownEscalatePayload,
    CorrelationInfo,
    ExecutionEvent,
    ExecutionFinishedPayload,
    ExecutionHeader,
    ExecutionStartedPayload,
    ExecutionSummary,
    FrameTooLargePayload,
    IncompleteTrailingFramePayload,
    JsonRpcErrorPayload,
    JsonRpcIdValue,
    JsonRpcNotificationPayload,
    JsonRpcRequestPayload,
    JsonRpcResponsePayload,
    JsonRpcUnknownObjectPayload,
    MalformedJsonFramePayload,
    MalformedUtf8FramePayload,
    NonObjectJsonFramePayload,
    ProcessStderrPayload,
    ProxySignalPayload,
    TransportErrorPayload,
)
from aerlog.events.types import (
    CorrelationStatus,
    EventDirection,
    EventKind,
    JsonRpcIdType,
    TraceSource,
    WireDirection,
)
from aerlog.storage.database import IndexedExecutionRow
from aerlog.storage.event_log import CorruptRecordReport, JsonlReadResult
from aerlog.storage.repositories import RecordingRepository

TIMELINE_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
DEFAULT_TIMELINE_LIMIT: Final[int] = 200

KNOWN_MCP_METHODS: Final[frozenset[str]] = frozenset(
    {
        "completion/complete",
        "elicitation/create",
        "initialize",
        "logging/setLevel",
        "notifications/cancelled",
        "notifications/elicitation/complete",
        "notifications/initialized",
        "notifications/message",
        "notifications/progress",
        "notifications/prompts/list_changed",
        "notifications/resources/list_changed",
        "notifications/resources/updated",
        "notifications/roots/list_changed",
        "notifications/subscriptions/acknowledged",
        "notifications/tools/list_changed",
        "ping",
        "prompts/get",
        "prompts/list",
        "resources/list",
        "resources/read",
        "resources/subscribe",
        "resources/templates/list",
        "resources/unsubscribe",
        "roots/list",
        "sampling/createMessage",
        "server/discover",
        "subscriptions/listen",
        "tools/call",
        "tools/list",
    }
)

SpanKind = Literal[
    "request_exchange",
    "orphan_response",
    "notification",
    "lifecycle",
    "stderr",
    "wire_anomaly",
    "capture_integrity",
]

SpanOutcome = Literal[
    "ok",
    "jsonrpc_error",
    "tool_error",
    "missing_response",
    "cancelled_no_response",
    "cancelled_late_response",
    "ambiguous_correlation",
    "orphaned_response",
    "duplicate_response",
    "invalid_id",
    "uncompleted_recording",
    "notification_only",
    "anomaly",
    "lifecycle",
]

DurationBasis = Literal[
    "exact_monotonic_delta",
    "unavailable_missing_response",
    "unavailable_ambiguous_correlation",
    "unavailable_orphan",
    "unavailable_invalid_id",
    "unavailable_synthetic_or_non_exchange",
]

EntryType = Literal[
    "lifecycle",
    "request",
    "response",
    "error_response",
    "notification",
    "stderr",
    "wire_anomaly",
    "capture_warning",
    "capture_gap",
]

_DEFAULT_PROXY_LIMITATIONS: Final[tuple[str, ...]] = (
    "Durations measure proxy pipe-read round-trip intervals (OS pipe scheduling and "
    "backpressure included), not isolated server handler compute time.",
    "Parent-child causal nesting between concurrent or separate requests cannot be "
    "inferred without explicit server/client W3C traceparent headers on the wire.",
    "Unanswered requests show only missing responses at proxy boundary; whether the "
    "server completed side effects before exit or cancellation cannot be established.",
    "Repeated method calls or duplicate IDs are factual wire observations and do not "
    "prove client retry intent.",
)


def format_id_display(id_type: JsonRpcIdType, id_value: JsonRpcIdValue) -> str | None:
    """Format a JSON-RPC ID preserving type distinction (e.g., ``int:1`` vs ``str:\"1\"``)."""
    if id_type == "missing":
        return None
    if id_type == "null":
        return "null"
    if id_type == "int":
        return f"int:{id_value}"
    if id_type == "str":
        return f'str:"{id_value}"'
    if id_type == "bool":
        return f"bool:{id_value}"
    if id_type == "float":
        return f"float:{id_value}"
    return f"{id_type}"


class RawEventRef(BaseModel):
    """Pointer preserving access back to the authoritative immutable stored event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execution_id: str
    sequence: int = Field(ge=1)
    event_id: str


class TimelineTraceLink(BaseModel):
    """Trace association keeping observed wire headers strictly separate from synthetic keys."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trace_source: TraceSource = "none"
    trace_id: str | None = None
    observed_trace_id: str | None = None
    observed_parent_span_id: str | None = None
    synthetic_execution_trace_id: str | None = None
    is_synthetic: bool = True


class RetryObservation(BaseModel):
    """Factual observation of a repeated method call or duplicate request ID."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["duplicate_in_flight_id", "observed_repeat_after_error", "observed_repeat_method"]
    prior_sequence: int = Field(ge=1)
    prior_event_id: str
    inferred: Literal[True] = True
    note: str


class TraceGroupSummary(BaseModel):
    """Summary of one trace group observed or synthetically grouped in an execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trace_id: str
    trace_source: TraceSource
    is_synthetic: bool
    event_count: int = Field(ge=1)
    request_count: int = Field(default=0, ge=0)
    first_sequence: int = Field(ge=1)
    last_sequence: int = Field(ge=1)
    observed_parent_span_ids: tuple[str, ...] = ()


class CorruptGapMarker(BaseModel):
    """Timeline marker representing detected JSONL truncation, corruption, or sequence gap."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    line_number: int = Field(ge=0)
    byte_offset: int = Field(ge=0)
    byte_length: int = Field(ge=0)
    issue_kind: str
    after_sequence: int | None = Field(default=None, ge=0)
    details: str


class TimelineSpan(BaseModel):
    """Flat chronological interaction unit derived strictly from observed events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    span_id: str
    span_kind: SpanKind
    trace: TimelineTraceLink
    origin_direction: EventDirection
    method: str | None = None
    is_unknown_method: bool = False
    request_id_display: str | None = None
    id_type: JsonRpcIdType = "missing"
    request_event_id: str | None = None
    request_sequence: int | None = Field(default=None, ge=1)
    response_event_id: str | None = None
    response_sequence: int | None = Field(default=None, ge=1)
    related_event_ids: tuple[str, ...] = ()
    start_monotonic_ns: int = Field(ge=0)
    end_monotonic_ns: int | None = Field(default=None, ge=0)
    start_offset_ns: int = Field(ge=0)
    end_offset_ns: int | None = Field(default=None, ge=0)
    duration_ns: int | None = Field(default=None, ge=0)
    duration_basis: DurationBasis
    outcome: SpanOutcome
    cancel_notified: bool = False
    post_exit: bool = False
    duplicate_response_count: int = Field(default=0, ge=0)
    tool_is_error: bool | None = None
    error_code: int | None = None
    retry_hint: RetryObservation | None = None
    uncertainty_notes: tuple[str, ...] = ()


class TimelineEntry(BaseModel):
    """Single chronological event row in the reconstructed execution timeline."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=1)
    event_id: str
    timestamp: datetime
    monotonic_time_ns: int = Field(ge=0)
    offset_ns: int = Field(ge=0)
    direction: EventDirection
    kind: EventKind
    span_id: str
    entry_type: EntryType
    method: str | None = None
    is_unknown_method: bool = False
    request_id_display: str | None = None
    summary_label: str
    correlation_status: CorrelationStatus | None = None
    paired_event_id: str | None = None
    paired_sequence: int | None = Field(default=None, ge=1)
    duration_ns: int | None = Field(default=None, ge=0)
    duration_basis: DurationBasis | None = None
    trace: TimelineTraceLink
    degraded: bool = False
    uncertainty_notes: tuple[str, ...] = ()
    raw_event_ref: RawEventRef


class ExecutionTimeline(BaseModel):
    """Root versioned chronological timeline reconstructed for one execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timeline_version: Literal["1.0.0"] = TIMELINE_SCHEMA_VERSION
    execution_id: str
    started_at: datetime | None = None
    ended_at: datetime | None = None
    execution_duration_ns: int | None = Field(default=None, ge=0)
    execution_duration_basis: str
    capture_completeness: str
    termination_reason: str | None = None
    exit_code: int | None = None
    returncode: int | None = None
    redaction_mode: str = "standard"
    command: tuple[str, ...] = ()
    unclean_shutdown: bool = False
    diverged_index: bool = False
    has_corruptions: bool = False
    total_events: int = Field(ge=0)
    request_count: int = Field(ge=0)
    response_count: int = Field(ge=0)
    error_response_count: int = Field(ge=0)
    tool_error_count: int = Field(ge=0)
    notification_count: int = Field(ge=0)
    missing_response_count: int = Field(ge=0)
    orphan_response_count: int = Field(ge=0)
    corrupt_record_count: int = Field(ge=0)
    entries: tuple[TimelineEntry, ...] = ()
    spans: tuple[TimelineSpan, ...] = ()
    missing_response_spans: tuple[TimelineSpan, ...] = ()
    trace_groups: tuple[TraceGroupSummary, ...] = ()
    corruption_markers: tuple[CorruptGapMarker, ...] = ()
    limitations: tuple[str, ...] = _DEFAULT_PROXY_LIMITATIONS


class TimelineSlice(BaseModel):
    """Bounded, paginated projection of :class:`ExecutionTimeline` entries for CLI/JSON."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timeline_version: Literal["1.0.0"] = TIMELINE_SCHEMA_VERSION
    execution_id: str
    capture_completeness: str
    has_corruptions: bool
    unclean_shutdown: bool
    diverged_index: bool
    redaction_mode: str
    total_entries: int = Field(ge=0)
    filtered_entries: int = Field(ge=0)
    returned_entries: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)
    truncated: bool
    remaining_entries: int = Field(ge=0)
    entries: tuple[TimelineEntry, ...]
    missing_response_spans: tuple[TimelineSpan, ...]
    trace_groups: tuple[TraceGroupSummary, ...]
    corruption_markers: tuple[CorruptGapMarker, ...]
    limitations: tuple[str, ...]


@dataclass(slots=True)
class _MutableSpanBuild:
    span_id: str
    span_kind: SpanKind
    trace: TimelineTraceLink
    origin_direction: EventDirection
    method: str | None
    is_unknown_method: bool
    request_id_display: str | None
    id_type: JsonRpcIdType
    request_event_id: str | None
    request_sequence: int | None
    start_monotonic_ns: int
    start_offset_ns: int
    response_event_id: str | None = None
    response_sequence: int | None = None
    end_monotonic_ns: int | None = None
    end_offset_ns: int | None = None
    duration_ns: int | None = None
    duration_basis: DurationBasis = "unavailable_synthetic_or_non_exchange"
    outcome: SpanOutcome = "lifecycle"
    cancel_notified: bool = False
    post_exit: bool = False
    duplicate_response_count: int = 0
    tool_is_error: bool | None = None
    error_code: int | None = None
    retry_hint: RetryObservation | None = None
    related_event_ids: list[str] = field(default_factory=list)
    uncertainty_notes: list[str] = field(default_factory=list)

    def to_model(self) -> TimelineSpan:
        """Convert mutable span accumulator into an immutable :class:`TimelineSpan`."""
        return TimelineSpan(
            span_id=self.span_id,
            span_kind=self.span_kind,
            trace=self.trace,
            origin_direction=self.origin_direction,
            method=self.method,
            is_unknown_method=self.is_unknown_method,
            request_id_display=self.request_id_display,
            id_type=self.id_type,
            request_event_id=self.request_event_id,
            request_sequence=self.request_sequence,
            response_event_id=self.response_event_id,
            response_sequence=self.response_sequence,
            related_event_ids=tuple(self.related_event_ids),
            start_monotonic_ns=self.start_monotonic_ns,
            end_monotonic_ns=self.end_monotonic_ns,
            start_offset_ns=self.start_offset_ns,
            end_offset_ns=self.end_offset_ns,
            duration_ns=self.duration_ns,
            duration_basis=self.duration_basis,
            outcome=self.outcome,
            cancel_notified=self.cancel_notified,
            post_exit=self.post_exit,
            duplicate_response_count=self.duplicate_response_count,
            tool_is_error=self.tool_is_error,
            error_code=self.error_code,
            retry_hint=self.retry_hint,
            uncertainty_notes=tuple(dict.fromkeys(self.uncertainty_notes)),
        )


@dataclass
class _TraceGroupAccumulator:
    """Mutable accumulator for distinct trace groups observed during reconstruction."""

    trace_id: str
    trace_source: TraceSource
    is_synthetic: bool
    event_count: int = 0
    request_count: int = 0
    first_sequence: int = 0
    last_sequence: int = 0
    parents: list[str] = field(default_factory=list)


def _redact_label_defense_in_depth(text: str, *, redactor: EventRedactor | None) -> str:
    """Apply defensive redaction on structural display labels without touching stored data."""
    if redactor is None:
        return text
    out = redactor.redact_text_value(text, path_label="timeline.label", max_chars=240)
    return out.text or "[REDACTED]"


def _safe_trace_link(event: ExecutionEvent, execution_id: str) -> TimelineTraceLink:
    tr = event.trace
    if tr is not None:
        if tr.trace_source == "w3c_meta" and tr.observed_trace_id is not None:
            return TimelineTraceLink(
                trace_source="w3c_meta",
                trace_id=tr.observed_trace_id,
                observed_trace_id=tr.observed_trace_id,
                observed_parent_span_id=tr.observed_parent_span_id,
                synthetic_execution_trace_id=tr.synthetic_execution_trace_id,
                is_synthetic=False,
            )
        if tr.synthetic_execution_trace_id is not None:
            return TimelineTraceLink(
                trace_source="synthetic_execution",
                trace_id=tr.synthetic_execution_trace_id,
                synthetic_execution_trace_id=tr.synthetic_execution_trace_id,
                is_synthetic=True,
            )
    synth = synthetic_trace_id_for_execution(execution_id)
    return TimelineTraceLink(
        trace_source="synthetic_execution",
        trace_id=synth,
        synthetic_execution_trace_id=synth,
        is_synthetic=True,
    )


def _safe_summary_label(
    event: ExecutionEvent,
    *,
    matched_method: str | None,
    redactor: EventRedactor | None,
) -> str:
    """Build structural, non-payload summary text safe for terminal tables."""
    payload = event.payload
    if isinstance(payload, ExecutionStartedPayload):
        return (
            f"execution started (transport={payload.transport}, "
            f"redaction={payload.redaction_mode}, policy={payload.backpressure_policy})"
        )
    if isinstance(payload, ExecutionFinishedPayload):
        return (
            f"execution finished (reason={payload.termination_reason}, "
            f"exit={payload.exit_code}, completeness={payload.completeness})"
        )
    if isinstance(payload, JsonRpcRequestPayload):
        name = payload.method or "<missing-method>"
        suffix_parts: list[str] = []
        if payload.method == "tools/call" and isinstance(payload.params, dict):
            tool_name = payload.params.get("name")
            if isinstance(tool_name, str) and tool_name:
                suffix_parts.append(f"tool={tool_name}")
        elif payload.method == "prompts/get" and isinstance(payload.params, dict):
            prompt_name = payload.params.get("name")
            if isinstance(prompt_name, str) and prompt_name:
                suffix_parts.append(f"prompt={prompt_name}")
        if payload.method is not None and payload.method not in KNOWN_MCP_METHODS:
            suffix_parts.append("unknown_method")
        if payload.extra_fields:
            suffix_parts.append(f"extra_fields={len(payload.extra_fields)}")
        base = f"{name} [{', '.join(suffix_parts)}]" if suffix_parts else name
        return _redact_label_defense_in_depth(base, redactor=redactor)
    if isinstance(payload, JsonRpcResponsePayload):
        target = matched_method or "request"
        tool_err = (event.derived is not None and event.derived.tool_is_error is True) or (
            isinstance(payload.result, dict) and payload.result.get("isError") is True
        )
        base = f"response for {target} [tool_error]" if tool_err else f"response for {target}"
        return _redact_label_defense_in_depth(base, redactor=redactor)
    if isinstance(payload, JsonRpcErrorPayload):
        code_txt = str(payload.error_code) if payload.error_code is not None else "unknown"
        base = f"error code={code_txt}"
        if matched_method is not None:
            base = f"{base} for {matched_method}"
        return _redact_label_defense_in_depth(base, redactor=redactor)
    if isinstance(payload, JsonRpcNotificationPayload):
        name = payload.method or "<missing-method>"
        suffix_parts = []
        if payload.method == "notifications/cancelled" and isinstance(payload.params, dict):
            req_id = payload.params.get("requestId")
            if req_id is not None:
                suffix_parts.append(f"target={req_id!r}")
        elif payload.method == "notifications/progress" and isinstance(payload.params, dict):
            tok = payload.params.get("progressToken")
            if tok is not None:
                suffix_parts.append(f"token={tok!r}")
        if payload.method is not None and payload.method not in KNOWN_MCP_METHODS:
            suffix_parts.append("unknown_method")
        base = f"{name} [{', '.join(suffix_parts)}]" if suffix_parts else name
        return _redact_label_defense_in_depth(base, redactor=redactor)
    if isinstance(payload, JsonRpcUnknownObjectPayload):
        return f"unknown JSON object ({len(payload.body)} keys)"
    if isinstance(payload, NonObjectJsonFramePayload):
        return f"non-object JSON ({payload.json_type})"
    if isinstance(payload, MalformedJsonFramePayload):
        byte_len = event.wire.byte_length if event.wire else 0
        return f"malformed JSON ({byte_len} bytes)"
    if isinstance(payload, MalformedUtf8FramePayload):
        byte_len = event.wire.byte_length if event.wire else 0
        return f"malformed UTF-8 ({byte_len} bytes)"
    if isinstance(payload, IncompleteTrailingFramePayload):
        return f"incomplete trailing EOF frame ({payload.byte_length} bytes)"
    if isinstance(payload, FrameTooLargePayload):
        return f"frame_too_large ({payload.observed_bytes} > {payload.max_frame_bytes} bytes)"
    if isinstance(payload, ProcessStderrPayload):
        return f"server stderr ({payload.byte_length} bytes)"
    if isinstance(payload, TransportErrorPayload):
        return _redact_label_defense_in_depth(f"transport {payload.reason}", redactor=redactor)
    if isinstance(payload, ProxySignalPayload):
        return f"proxy signal {payload.signal_name}"
    if isinstance(payload, ChildShutdownEscalatePayload):
        return f"child shutdown escalate {payload.signal_name} (pgid={payload.pgid})"
    if isinstance(payload, CaptureWarningPayload):
        return _redact_label_defense_in_depth(
            f"warning [{payload.code}]: {payload.message}", redactor=redactor
        )
    if isinstance(payload, CaptureGapPayload):
        return f"capture gap (dropped={payload.dropped_count}, reason={payload.reason})"
    return str(event.kind)


def _entry_type_for_event(event: ExecutionEvent) -> EntryType:
    if event.kind in {
        "execution_started",
        "execution_finished",
        "proxy_signal",
        "child_shutdown_escalate",
    }:
        return "lifecycle"
    if event.kind == "jsonrpc_request":
        return "request"
    if event.kind == "jsonrpc_response":
        return "response"
    if event.kind == "jsonrpc_error":
        return "error_response"
    if event.kind == "jsonrpc_notification":
        return "notification"
    if event.kind == "process_stderr":
        return "stderr"
    if event.kind == "capture_warning":
        return "capture_warning"
    if event.kind == "capture_gap":
        return "capture_gap"
    return "wire_anomaly"


def reconstruct_timeline_from_events(
    events: Sequence[ExecutionEvent],
    *,
    execution_id: str,
    header: ExecutionHeader | None = None,
    summary: ExecutionSummary | None = None,
    corruptions: Sequence[CorruptRecordReport] = (),
    unclean_shutdown: bool = False,
    diverged_index: bool = False,
) -> ExecutionTimeline:
    """Reconstruct an immutable :class:`ExecutionTimeline` from ordered stored events."""
    ordered = sorted(events, key=lambda item: item.sequence)
    redaction_mode = (
        summary.redaction_mode
        if summary is not None
        else header.redaction_mode
        if header is not None
        else ordered[0].redaction.mode
        if ordered
        else "standard"
    )
    redactor: EventRedactor | None = (
        EventRedactor(RedactionConfig(mode="standard"))
        if redaction_mode != "explicit_unredacted"
        else None
    )

    if header is not None:
        base_mono_ns = header.monotonic_start_ns
    elif ordered:
        base_mono_ns = ordered[0].monotonic_time_ns
    else:
        base_mono_ns = 0

    shadow_correlator = RequestCorrelator(execution_id)
    span_builds: list[_MutableSpanBuild] = []
    span_by_req_event_id: dict[str, _MutableSpanBuild] = {}
    events_by_id: dict[str, ExecutionEvent] = {ev.event_id: ev for ev in ordered}
    entries: list[TimelineEntry] = []

    # Track prior (direction, method) occurrences for factual repeat observation hints.
    prior_calls_by_method: dict[tuple[EventDirection, str], tuple[int, str, bool]] = {}

    trace_stats: dict[tuple[str, TraceSource, bool], _TraceGroupAccumulator] = {}

    def _record_trace_group(link: TimelineTraceLink, seq: int, is_req: bool) -> None:
        if link.trace_id is None:
            return
        key = (link.trace_id, link.trace_source, link.is_synthetic)
        bucket = trace_stats.get(key)
        if bucket is None:
            parent_ids: list[str] = []
            if link.observed_parent_span_id is not None:
                parent_ids.append(link.observed_parent_span_id)
            trace_stats[key] = _TraceGroupAccumulator(
                trace_id=link.trace_id,
                trace_source=link.trace_source,
                is_synthetic=link.is_synthetic,
                event_count=1,
                request_count=1 if is_req else 0,
                first_sequence=seq,
                last_sequence=seq,
                parents=parent_ids,
            )
        else:
            bucket.event_count += 1
            if is_req:
                bucket.request_count += 1
            bucket.first_sequence = min(bucket.first_sequence, seq)
            bucket.last_sequence = max(bucket.last_sequence, seq)
            if (
                link.observed_parent_span_id is not None
                and link.observed_parent_span_id not in bucket.parents
            ):
                bucket.parents.append(link.observed_parent_span_id)

    request_count = 0
    response_count = 0
    error_response_count = 0
    tool_error_count = 0
    notification_count = 0
    orphan_response_count = 0

    for ev in ordered:
        offset_ns = max(0, ev.monotonic_time_ns - base_mono_ns)
        trace_link = _safe_trace_link(ev, execution_id)
        entry_type = _entry_type_for_event(ev)
        uncertainty_notes: list[str] = []

        payload = ev.payload
        method: str | None = None
        is_unknown_method = False
        id_display: str | None = None
        corr_info: CorrelationInfo | None = ev.correlation
        paired_event_id: str | None = None
        paired_sequence: int | None = None
        entry_duration_ns: int | None = None
        entry_duration_basis: DurationBasis | None = None
        matched_method: str | None = None
        span_id = f"item_seq_{ev.sequence}"

        if isinstance(payload, JsonRpcRequestPayload):
            request_count += 1
            method = payload.method
            is_unknown_method = method is not None and method not in KNOWN_MCP_METHODS
            id_display = format_id_display(payload.id_type, payload.id)
            wire_dir: WireDirection = (
                "server_to_client" if ev.direction == "server_to_client" else "client_to_server"
            )
            shadow = shadow_correlator.process_request(
                event_id=ev.event_id,
                sequence=ev.sequence,
                monotonic_time_ns=ev.monotonic_time_ns,
                direction=wire_dir,
                method=payload.method,
                id_type=payload.id_type,
                request_id=payload.id,
                params=payload.params,
            )
            if corr_info is None:
                corr_info = shadow.correlation

            span_id = f"span_seq_{ev.sequence}"
            retry_hint: RetryObservation | None = None
            if corr_info is not None and corr_info.status == "ambiguous_duplicate_id":
                prior_id = (
                    corr_info.candidate_request_event_ids[-1]
                    if corr_info.candidate_request_event_ids
                    else ev.event_id
                )
                prior_ev = events_by_id.get(prior_id)
                retry_hint = RetryObservation(
                    kind="duplicate_in_flight_id",
                    prior_sequence=prior_ev.sequence if prior_ev else ev.sequence,
                    prior_event_id=prior_id,
                    note=(
                        "Observed duplicate in-flight request ID while earlier request was open; "
                        "retry intent cannot be inferred from proxy bytes alone."
                    ),
                )
                uncertainty_notes.append(
                    "Duplicate in-flight request ID observed; response pairing may be ambiguous."
                )
            elif method is not None:
                prior_info = prior_calls_by_method.get((ev.direction, method))
                if prior_info is not None:
                    prior_seq, prior_eid, prior_was_error = prior_info
                    retry_hint = RetryObservation(
                        kind=(
                            "observed_repeat_after_error"
                            if prior_was_error
                            else "observed_repeat_method"
                        ),
                        prior_sequence=prior_seq,
                        prior_event_id=prior_eid,
                        note=(
                            "Observed repeated method call in same direction; proxy cannot "
                            "determine whether this represents a client retry or distinct work."
                        ),
                    )
                prior_calls_by_method[(ev.direction, method)] = (ev.sequence, ev.event_id, False)

            span_build = _MutableSpanBuild(
                span_id=span_id,
                span_kind="request_exchange",
                trace=trace_link,
                origin_direction=ev.direction,
                method=method,
                is_unknown_method=is_unknown_method,
                request_id_display=id_display,
                id_type=payload.id_type,
                request_event_id=ev.event_id,
                request_sequence=ev.sequence,
                start_monotonic_ns=ev.monotonic_time_ns,
                start_offset_ns=offset_ns,
                duration_basis=(
                    "unavailable_invalid_id"
                    if corr_info is not None and corr_info.status == "invalid_id"
                    else "unavailable_missing_response"
                ),
                outcome=(
                    "invalid_id"
                    if corr_info is not None and corr_info.status == "invalid_id"
                    else "ambiguous_correlation"
                    if corr_info is not None and corr_info.status == "ambiguous_duplicate_id"
                    else "missing_response"
                ),
                retry_hint=retry_hint,
                uncertainty_notes=list(uncertainty_notes),
            )
            span_builds.append(span_build)
            span_by_req_event_id[ev.event_id] = span_build

        elif isinstance(payload, JsonRpcResponsePayload | JsonRpcErrorPayload):
            is_err = isinstance(payload, JsonRpcErrorPayload)
            if is_err:
                error_response_count += 1
            else:
                response_count += 1
            id_display = format_id_display(payload.id_type, payload.id)
            wire_dir = (
                "client_to_server" if ev.direction == "client_to_server" else "server_to_client"
            )
            shadow = shadow_correlator.process_response(
                event_id=ev.event_id,
                sequence=ev.sequence,
                monotonic_time_ns=ev.monotonic_time_ns,
                direction=wire_dir,
                id_type=payload.id_type,
                request_id=payload.id,
                is_error=is_err,
                result_or_error=(
                    payload.error if isinstance(payload, JsonRpcErrorPayload) else payload.result
                ),
            )
            if corr_info is None and shadow.correlation is not None:
                corr_info = shadow.correlation
                uncertainty_notes.append(
                    "Correlated deterministically during timeline reconstruction."
                )

            req_id = corr_info.matched_request_event_id if corr_info is not None else None
            target_span = span_by_req_event_id.get(req_id) if req_id is not None else None

            tool_is_err: bool | None = None
            if not is_err and isinstance(payload, JsonRpcResponsePayload):
                if ev.derived is not None and ev.derived.tool_is_error is not None:
                    tool_is_err = ev.derived.tool_is_error
                elif isinstance(payload.result, dict) and isinstance(
                    payload.result.get("isError"), bool
                ):
                    tool_is_err = payload.result["isError"]
                if tool_is_err is True:
                    tool_error_count += 1

            err_code = payload.error_code if isinstance(payload, JsonRpcErrorPayload) else None

            if target_span is not None and corr_info is not None:
                matched_method = target_span.method
                method = target_span.method
                is_unknown_method = target_span.is_unknown_method
                span_id = target_span.span_id
                paired_event_id = target_span.request_event_id
                paired_sequence = target_span.request_sequence

                if corr_info.status == "duplicate_response" or (
                    target_span.response_event_id is not None
                ):
                    target_span.duplicate_response_count += 1
                    target_span.related_event_ids.append(ev.event_id)
                    msg = (
                        f"Duplicate response seq #{ev.sequence} received after response "
                        f"seq #{target_span.response_sequence}."
                    )
                    target_span.uncertainty_notes.append(msg)
                    uncertainty_notes.append(msg)
                    entry_duration_ns = None
                    entry_duration_basis = "unavailable_ambiguous_correlation"
                else:
                    target_span.response_event_id = ev.event_id
                    target_span.response_sequence = ev.sequence
                    target_span.end_monotonic_ns = ev.monotonic_time_ns
                    target_span.end_offset_ns = offset_ns
                    target_span.post_exit = target_span.post_exit or corr_info.post_exit_frame
                    target_span.tool_is_error = tool_is_err
                    target_span.error_code = err_code

                    if (
                        corr_info.status == "ambiguous_duplicate_id"
                        or corr_info.confidence != "exact"
                    ):
                        target_span.duration_ns = None
                        target_span.duration_basis = "unavailable_ambiguous_correlation"
                        entry_duration_ns = None
                        entry_duration_basis = "unavailable_ambiguous_correlation"
                        target_span.outcome = "ambiguous_correlation"
                        msg = (
                            "Latency omitted: duplicate in-flight ID makes exact request pairing "
                            "ambiguous."
                        )
                        target_span.uncertainty_notes.append(msg)
                        uncertainty_notes.append(msg)
                    elif ev.monotonic_time_ns >= target_span.start_monotonic_ns:
                        exact_delta = ev.monotonic_time_ns - target_span.start_monotonic_ns
                        target_span.duration_ns = exact_delta
                        target_span.duration_basis = "exact_monotonic_delta"
                        entry_duration_ns = exact_delta
                        entry_duration_basis = "exact_monotonic_delta"
                        if is_err:
                            target_span.outcome = "jsonrpc_error"
                        elif tool_is_err is True:
                            target_span.outcome = "tool_error"
                        elif target_span.cancel_notified or corr_info.late_after_cancel:
                            target_span.outcome = "cancelled_late_response"
                            target_span.uncertainty_notes.append(
                                "Response arrived after cancellation notification."
                            )
                        else:
                            target_span.outcome = "ok"

                    if target_span.method is not None and (is_err or tool_is_err is True):
                        prior_calls_by_method[
                            (target_span.origin_direction, target_span.method)
                        ] = (
                            target_span.request_sequence or ev.sequence,
                            target_span.request_event_id or ev.event_id,
                            True,
                        )
            else:
                orphan_response_count += 1
                span_id = f"orphan_seq_{ev.sequence}"
                is_invalid = corr_info is not None and corr_info.status == "invalid_id"
                orphan_basis: DurationBasis = (
                    "unavailable_invalid_id" if is_invalid else "unavailable_orphan"
                )
                orphan_outcome: SpanOutcome = "invalid_id" if is_invalid else "orphaned_response"
                note = (
                    "Response has invalid/null JSON-RPC ID; cannot pair to a request."
                    if is_invalid
                    else "Orphaned response: no matching prior request found in recording."
                )
                uncertainty_notes.append(note)
                span_builds.append(
                    _MutableSpanBuild(
                        span_id=span_id,
                        span_kind="orphan_response",
                        trace=trace_link,
                        origin_direction=ev.direction,
                        method=None,
                        is_unknown_method=False,
                        request_id_display=id_display,
                        id_type=payload.id_type,
                        request_event_id=None,
                        request_sequence=None,
                        response_event_id=ev.event_id,
                        response_sequence=ev.sequence,
                        start_monotonic_ns=ev.monotonic_time_ns,
                        end_monotonic_ns=ev.monotonic_time_ns,
                        start_offset_ns=offset_ns,
                        end_offset_ns=offset_ns,
                        duration_ns=None,
                        duration_basis=orphan_basis,
                        outcome=orphan_outcome,
                        tool_is_error=tool_is_err,
                        error_code=err_code,
                        uncertainty_notes=[note],
                    )
                )

        elif isinstance(payload, JsonRpcNotificationPayload):
            notification_count += 1
            method = payload.method
            is_unknown_method = method is not None and method not in KNOWN_MCP_METHODS
            wire_dir = (
                "server_to_client" if ev.direction == "server_to_client" else "client_to_server"
            )
            shadow = shadow_correlator.process_notification(
                event_id=ev.event_id,
                direction=wire_dir,
                method=payload.method,
                params=payload.params,
            )
            if corr_info is None and shadow.correlation is not None:
                corr_info = shadow.correlation

            req_id = corr_info.matched_request_event_id if corr_info is not None else None
            target_span = span_by_req_event_id.get(req_id) if req_id is not None else None
            if target_span is not None:
                span_id = target_span.span_id
                paired_event_id = target_span.request_event_id
                paired_sequence = target_span.request_sequence
                target_span.related_event_ids.append(ev.event_id)
                if payload.method == "notifications/cancelled":
                    target_span.cancel_notified = True
                    target_span.uncertainty_notes.append(
                        f"Cancellation requested at seq #{ev.sequence}."
                    )
                    if target_span.method is not None:
                        prior_calls_by_method[
                            (target_span.origin_direction, target_span.method)
                        ] = (
                            target_span.request_sequence or ev.sequence,
                            target_span.request_event_id or ev.event_id,
                            True,
                        )
            else:
                span_id = f"notif_seq_{ev.sequence}"
                span_builds.append(
                    _MutableSpanBuild(
                        span_id=span_id,
                        span_kind="notification",
                        trace=trace_link,
                        origin_direction=ev.direction,
                        method=method,
                        is_unknown_method=is_unknown_method,
                        request_id_display=None,
                        id_type="missing",
                        request_event_id=None,
                        request_sequence=None,
                        start_monotonic_ns=ev.monotonic_time_ns,
                        end_monotonic_ns=ev.monotonic_time_ns,
                        start_offset_ns=offset_ns,
                        end_offset_ns=offset_ns,
                        duration_ns=None,
                        duration_basis="unavailable_synthetic_or_non_exchange",
                        outcome="notification_only",
                        related_event_ids=[ev.event_id],
                    )
                )

        else:
            if isinstance(payload, ExecutionFinishedPayload):
                shadow_correlator.mark_process_exited()
            span_kind: SpanKind = (
                "lifecycle"
                if entry_type == "lifecycle"
                else "stderr"
                if entry_type == "stderr"
                else "capture_integrity"
                if entry_type in {"capture_warning", "capture_gap"}
                else "wire_anomaly"
            )
            span_outcome: SpanOutcome = "lifecycle" if span_kind == "lifecycle" else "anomaly"
            span_id = f"{span_kind}_seq_{ev.sequence}"
            span_builds.append(
                _MutableSpanBuild(
                    span_id=span_id,
                    span_kind=span_kind,
                    trace=trace_link,
                    origin_direction=ev.direction,
                    method=None,
                    is_unknown_method=False,
                    request_id_display=None,
                    id_type="missing",
                    request_event_id=None,
                    request_sequence=None,
                    start_monotonic_ns=ev.monotonic_time_ns,
                    end_monotonic_ns=ev.monotonic_time_ns,
                    start_offset_ns=offset_ns,
                    end_offset_ns=offset_ns,
                    duration_ns=None,
                    duration_basis="unavailable_synthetic_or_non_exchange",
                    outcome=span_outcome,
                    related_event_ids=[ev.event_id],
                )
            )

        _record_trace_group(trace_link, ev.sequence, isinstance(payload, JsonRpcRequestPayload))

        label = _safe_summary_label(ev, matched_method=matched_method, redactor=redactor)
        entries.append(
            TimelineEntry(
                sequence=ev.sequence,
                event_id=ev.event_id,
                timestamp=ev.timestamp,
                monotonic_time_ns=ev.monotonic_time_ns,
                offset_ns=offset_ns,
                direction=ev.direction,
                kind=ev.kind,
                span_id=span_id,
                entry_type=entry_type,
                method=method,
                is_unknown_method=is_unknown_method,
                request_id_display=id_display,
                summary_label=label,
                correlation_status=corr_info.status if corr_info is not None else None,
                paired_event_id=paired_event_id,
                paired_sequence=paired_sequence,
                duration_ns=entry_duration_ns,
                duration_basis=entry_duration_basis,
                trace=trace_link,
                degraded=ev.degraded,
                uncertainty_notes=tuple(dict.fromkeys(uncertainty_notes)),
                raw_event_ref=RawEventRef(
                    execution_id=execution_id,
                    sequence=ev.sequence,
                    event_id=ev.event_id,
                ),
            )
        )

    has_corruptions = bool(corruptions)
    completeness = (
        "corrupted"
        if has_corruptions
        else "incomplete"
        if unclean_shutdown
        else summary.capture_completeness
        if summary is not None
        else "incomplete"
    )

    missing_spans: list[TimelineSpan] = []
    final_spans: list[TimelineSpan] = []
    for build in span_builds:
        if build.span_kind == "request_exchange" and build.response_event_id is None:
            if build.outcome != "invalid_id":
                build.duration_ns = None
                build.duration_basis = "unavailable_missing_response"
                if build.cancel_notified:
                    build.outcome = "cancelled_no_response"
                    build.uncertainty_notes.append(
                        "Cancellation sent; server emitted no response before recording ended."
                    )
                elif (
                    unclean_shutdown
                    or has_corruptions
                    or completeness
                    in {
                        "incomplete",
                        "corrupted",
                        "recording",
                    }
                ):
                    build.outcome = "uncompleted_recording"
                    build.uncertainty_notes.append(
                        "Recording incomplete or interrupted; missing response does not prove "
                        "server failure."
                    )
                else:
                    build.outcome = "missing_response"
                    build.uncertainty_notes.append(
                        "No matching response observed before execution ended."
                    )
            built = build.to_model()
            missing_spans.append(built)
            final_spans.append(built)
        else:
            final_spans.append(build.to_model())

    corruption_markers: list[CorruptGapMarker] = []
    for issue in corruptions:
        preceding = [ev.sequence for ev in ordered if ev.sequence <= issue.line_number]
        after_seq = max(preceding) if preceding else 0
        corruption_markers.append(
            CorruptGapMarker(
                line_number=issue.line_number,
                byte_offset=issue.byte_offset,
                byte_length=issue.byte_length,
                issue_kind=issue.issue_kind,
                after_sequence=after_seq,
                details=issue.details,
            )
        )

    trace_group_models = [
        TraceGroupSummary(
            trace_id=stats.trace_id,
            trace_source=stats.trace_source,
            is_synthetic=stats.is_synthetic,
            event_count=stats.event_count,
            request_count=stats.request_count,
            first_sequence=stats.first_sequence,
            last_sequence=stats.last_sequence,
            observed_parent_span_ids=tuple(stats.parents),
        )
        for stats in trace_stats.values()
    ]
    trace_group_models.sort(key=lambda grp: (grp.is_synthetic, grp.first_sequence))

    if summary is not None:
        exec_dur: int | None = summary.duration_ns
        exec_dur_basis = "summary_monotonic_duration"
    elif len(ordered) >= 2:
        exec_dur = max(0, ordered[-1].monotonic_time_ns - base_mono_ns)
        exec_dur_basis = "observed_event_span_incomplete"
    else:
        exec_dur = None
        exec_dur_basis = "unavailable_insufficient_events"

    limitations = list(_DEFAULT_PROXY_LIMITATIONS)
    if redaction_mode == "explicit_unredacted":
        limitations.append(
            "Recording was captured with redaction_mode='explicit_unredacted'; raw JSON events "
            "may contain unredacted credentials."
        )
    if has_corruptions:
        limitations.append(
            f"Detected {len(corruptions)} corrupt/partial JSONL record(s); preserved valid "
            "surrounding events without silent repair."
        )
    if diverged_index:
        limitations.append(
            "SQLite index state diverges from authoritative events.jsonl; timeline was built "
            "from authoritative events.jsonl."
        )

    started_at = (
        summary.started_at
        if summary is not None
        else header.started_at
        if header is not None
        else ordered[0].timestamp
        if ordered
        else None
    )
    ended_at = summary.ended_at if summary is not None else None
    cmd = summary.command if summary is not None else header.command if header is not None else ()

    return ExecutionTimeline(
        execution_id=execution_id,
        started_at=started_at,
        ended_at=ended_at,
        execution_duration_ns=exec_dur,
        execution_duration_basis=exec_dur_basis,
        capture_completeness=completeness,
        termination_reason=summary.termination_reason if summary is not None else None,
        exit_code=summary.exit_code if summary is not None else None,
        returncode=summary.returncode if summary is not None else None,
        redaction_mode=redaction_mode,
        command=cmd,
        unclean_shutdown=unclean_shutdown,
        diverged_index=diverged_index,
        has_corruptions=has_corruptions,
        total_events=len(ordered),
        request_count=request_count,
        response_count=response_count,
        error_response_count=error_response_count,
        tool_error_count=tool_error_count,
        notification_count=notification_count,
        missing_response_count=len(missing_spans),
        orphan_response_count=orphan_response_count,
        corrupt_record_count=len(corruption_markers),
        entries=tuple(entries),
        spans=tuple(final_spans),
        missing_response_spans=tuple(missing_spans),
        trace_groups=tuple(trace_group_models),
        corruption_markers=tuple(corruption_markers),
        limitations=tuple(limitations),
    )


def reconstruct_timeline(
    read_result: JsonlReadResult,
    *,
    index_row: IndexedExecutionRow | None = None,
    diverged_index: bool = False,
) -> ExecutionTimeline:
    """Reconstruct an :class:`ExecutionTimeline` from an authoritative :class:`JsonlReadResult`."""
    _ = index_row
    events = [item.event for item in read_result.events]
    return reconstruct_timeline_from_events(
        events,
        execution_id=read_result.execution_id,
        header=read_result.header,
        summary=read_result.summary,
        corruptions=read_result.corruptions,
        unclean_shutdown=read_result.unclean_shutdown,
        diverged_index=diverged_index,
    )


def reconstruct_execution_timeline(
    repo: RecordingRepository,
    execution_id: str,
    *,
    strict_integrity: bool = False,
    verify_checksums: bool = True,
) -> ExecutionTimeline:
    """Load authoritative stored events from ``repo`` and reconstruct the execution timeline."""
    stored = repo.get_execution(execution_id)
    read_res = repo.get_execution_events(
        execution_id,
        strict_integrity=strict_integrity,
        verify_checksums=verify_checksums,
        mark_missing=False,
    )
    return reconstruct_timeline(
        read_res,
        index_row=stored.index_row,
        diverged_index=stored.diverged,
    )


def slice_timeline(
    timeline: ExecutionTimeline,
    *,
    limit: int = DEFAULT_TIMELINE_LIMIT,
    offset: int = 0,
    direction: str | None = None,
    kind: str | None = None,
    method: str | None = None,
) -> TimelineSlice:
    """Filter and paginate :class:`ExecutionTimeline` entries with explicit truncation info."""
    if limit <= 0:
        raise ValueError(f"limit must be positive, got {limit}")
    if offset < 0:
        raise ValueError(f"offset must be non-negative, got {offset}")

    filtered = [
        entry
        for entry in timeline.entries
        if (direction is None or entry.direction == direction)
        and (kind is None or entry.kind == kind)
        and (method is None or entry.method == method)
    ]
    total_filtered = len(filtered)
    window = tuple(filtered[offset : offset + limit])
    remaining = max(0, total_filtered - (offset + len(window)))
    truncated = (offset + len(window)) < total_filtered

    return TimelineSlice(
        timeline_version=timeline.timeline_version,
        execution_id=timeline.execution_id,
        capture_completeness=timeline.capture_completeness,
        has_corruptions=timeline.has_corruptions,
        unclean_shutdown=timeline.unclean_shutdown,
        diverged_index=timeline.diverged_index,
        redaction_mode=timeline.redaction_mode,
        total_entries=len(timeline.entries),
        filtered_entries=total_filtered,
        returned_entries=len(window),
        offset=offset,
        limit=limit,
        truncated=truncated,
        remaining_entries=remaining,
        entries=window,
        missing_response_spans=timeline.missing_response_spans,
        trace_groups=timeline.trace_groups,
        corruption_markers=timeline.corruption_markers,
        limitations=timeline.limitations,
    )


__all__ = [
    "DEFAULT_TIMELINE_LIMIT",
    "KNOWN_MCP_METHODS",
    "TIMELINE_SCHEMA_VERSION",
    "CorruptGapMarker",
    "DurationBasis",
    "EntryType",
    "ExecutionTimeline",
    "RawEventRef",
    "RetryObservation",
    "SpanKind",
    "SpanOutcome",
    "TimelineEntry",
    "TimelineSlice",
    "TimelineSpan",
    "TimelineTraceLink",
    "TraceGroupSummary",
    "format_id_display",
    "reconstruct_execution_timeline",
    "reconstruct_timeline",
    "reconstruct_timeline_from_events",
    "slice_timeline",
]
