"""Single-consumer capture event normalizer turning wire/lifecycle inputs into ExecutionEvents."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from aerlog.capture.redaction import (
    EventRedactor,
    RedactionConfig,
    merge_redaction_summaries,
)
from aerlog.events.correlation import CorrelationWarning, RequestCorrelator
from aerlog.events.ids import new_event_id, synthetic_trace_id_for_execution
from aerlog.events.models import (
    CaptureGapPayload,
    CaptureWarningPayload,
    ChildShutdownEscalatePayload,
    CorrelationInfo,
    DerivedMetadata,
    ExecutionEvent,
    ExecutionFinishedPayload,
    ExecutionHeader,
    ExecutionStartedPayload,
    ExecutionSummary,
    FrameTooLargePayload,
    IncompleteTrailingFramePayload,
    JsonRpcErrorPayload,
    JsonRpcNotificationPayload,
    JsonRpcRequestPayload,
    JsonRpcResponsePayload,
    JsonRpcUnknownObjectPayload,
    MalformedJsonFramePayload,
    MalformedUtf8FramePayload,
    NonObjectJsonFramePayload,
    ProcessStderrPayload,
    ProxySignalPayload,
    RedactionSummary,
    TraceContext,
    TransportErrorPayload,
    WireFrameInfo,
    classify_jsonrpc_id,
)
from aerlog.events.types import (
    CaptureBackpressurePolicy,
    CaptureCompleteness,
    WireDirection,
)
from aerlog.protocol.framing import detect_line_ending

_STANDARD_REQUEST_KEYS = frozenset({"jsonrpc", "id", "method", "params"})
_STANDARD_NOTIFICATION_KEYS = frozenset({"jsonrpc", "method", "params"})
_STANDARD_RESPONSE_KEYS = frozenset({"jsonrpc", "id", "result"})
_STANDARD_ERROR_KEYS = frozenset({"jsonrpc", "id", "error"})

_MAX_CAPTURED_MALFORMED_CHARS = 16_384
_MAX_CAPTURED_RAW_B64_BYTES = 16_384


@dataclass(frozen=True, slots=True)
class RawWireFrameInput:
    """Raw protocol frame forwarded on stdin/stdout."""

    timestamp: datetime
    monotonic_time_ns: int
    direction: WireDirection
    raw_frame: bytes


@dataclass(frozen=True, slots=True)
class RawIncompleteFrameInput:
    """Trailing non-newline-terminated bytes observed at stream EOF."""

    timestamp: datetime
    monotonic_time_ns: int
    direction: WireDirection
    trailing_bytes: bytes


@dataclass(frozen=True, slots=True)
class RawFrameTooLargeInput:
    """Fail-closed oversized frame event observed by the proxy framer."""

    timestamp: datetime
    monotonic_time_ns: int
    direction: WireDirection
    observed_bytes: int
    max_frame_bytes: int


@dataclass(frozen=True, slots=True)
class RawStderrLineInput:
    """One raw line/chunk read from target server stderr."""

    timestamp: datetime
    monotonic_time_ns: int
    raw_line: bytes


@dataclass(frozen=True, slots=True)
class RawTransportErrorInput:
    """Transport read/write failure or closed pipe observed by proxy."""

    timestamp: datetime
    monotonic_time_ns: int
    stream_direction: WireDirection | None
    reason: str
    error: str


@dataclass(frozen=True, slots=True)
class RawProxySignalInput:
    """Signal or task cancellation intercepted by the proxy."""

    timestamp: datetime
    monotonic_time_ns: int
    signal_name: str


@dataclass(frozen=True, slots=True)
class RawChildShutdownEscalateInput:
    """Shutdown escalation signal sent to child process group."""

    timestamp: datetime
    monotonic_time_ns: int
    signal_name: str
    pgid: int
    error: str | None = None


@dataclass(frozen=True, slots=True)
class RawProcessExitedInput:
    """Marker indicating target server process exit was observed."""

    timestamp: datetime
    monotonic_time_ns: int
    returncode: int | None


@dataclass(frozen=True, slots=True)
class RawCaptureWarningInput:
    """Out-of-band warning injected into normalized execution stream."""

    timestamp: datetime
    monotonic_time_ns: int
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


RawCaptureInput = (
    RawWireFrameInput
    | RawIncompleteFrameInput
    | RawFrameTooLargeInput
    | RawStderrLineInput
    | RawTransportErrorInput
    | RawProxySignalInput
    | RawChildShutdownEscalateInput
    | RawProcessExitedInput
    | RawCaptureWarningInput
)


def _strip_wire_newline(raw_frame: bytes) -> bytes:
    payload = raw_frame[:-1] if raw_frame.endswith(b"\n") else raw_frame
    if payload.endswith(b"\r"):
        payload = payload[:-1]
    return payload


class EventNormalizer:
    """Transforms raw proxy observations into redacted, correlated ExecutionEvents."""

    def __init__(
        self,
        *,
        execution_id: str,
        started_at: datetime,
        monotonic_start_ns: int,
        command: Sequence[str],
        cwd: str | None = None,
        env_overrides: Mapping[str, str] | None = None,
        redaction_config: RedactionConfig | None = None,
        backpressure_policy: CaptureBackpressurePolicy = "block",
    ) -> None:
        self._execution_id = execution_id
        self._started_at = started_at
        self._monotonic_start_ns = monotonic_start_ns
        self._backpressure_policy: CaptureBackpressurePolicy = backpressure_policy
        self._redactor = EventRedactor(redaction_config)
        self._correlator = RequestCorrelator(execution_id)

        self._raw_command = tuple(command)
        self._redacted_command, self._cmd_redaction = self._redactor.redact_command(command)
        self._cwd = cwd
        self._env_override_keys, self._redacted_env_overrides, self._env_redaction = (
            self._redactor.redact_env_overrides(env_overrides)
        )

        self._sequence = 0
        self._degraded_events = 0
        self._warning_count = 0
        self._gap_count = 0
        self._dropped_events = 0
        self._last_returncode: int | None = None
        self._observed_trace_ids: list[str] = []

    @property
    def execution_id(self) -> str:
        """Return unique UUIDv4 execution identifier."""
        return self._execution_id

    @property
    def redactor(self) -> EventRedactor:
        """Return configured pre-persistence event redactor."""
        return self._redactor

    @property
    def event_count(self) -> int:
        """Number of normalized events emitted so far."""
        return self._sequence

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def _record_trace_id(self, trace: TraceContext | None) -> None:
        if (
            trace is not None
            and trace.observed_trace_id is not None
            and trace.observed_trace_id not in self._observed_trace_ids
        ):
            self._observed_trace_ids.append(trace.observed_trace_id)

    def _default_system_redaction(self) -> RedactionSummary:
        return RedactionSummary(
            mode=self._redactor.config.mode,
            payload_mode=self._redactor.default_payload_mode,
            applied=self._redactor.config.mode != "explicit_unredacted",
        )

    def _emit_warning_event(
        self,
        *,
        timestamp: datetime,
        monotonic_time_ns: int,
        code: str,
        message: str,
        details: Mapping[str, Any] | None = None,
    ) -> ExecutionEvent:
        details_out = self._redactor.redact_value(
            dict(details) if details else {}, root_path="warning.details"
        )
        redaction = details_out.summary
        degraded = redaction.degraded
        safe_details = details_out.value if isinstance(details_out.value, dict) else {}
        self._warning_count += 1
        if degraded:
            self._degraded_events += 1
        return ExecutionEvent(
            event_id=new_event_id(),
            execution_id=self._execution_id,
            sequence=self._next_sequence(),
            timestamp=timestamp,
            monotonic_time_ns=monotonic_time_ns,
            direction="system",
            kind="capture_warning",
            redaction=redaction,
            degraded=degraded,
            payload=CaptureWarningPayload(
                code=code,
                message=message,
                details=safe_details,
            ),
        )

    def _emit_correlation_warnings(
        self,
        *,
        timestamp: datetime,
        monotonic_time_ns: int,
        warnings: Sequence[CorrelationWarning],
    ) -> list[ExecutionEvent]:
        return [
            self._emit_warning_event(
                timestamp=timestamp,
                monotonic_time_ns=monotonic_time_ns,
                code=w.code,
                message=w.message,
                details=w.details,
            )
            for w in warnings
        ]

    def build_header(self) -> ExecutionHeader:
        """Build the immutable run header using the redacted command representation."""
        return ExecutionHeader(
            execution_id=self._execution_id,
            started_at=self._started_at,
            monotonic_start_ns=self._monotonic_start_ns,
            command=self._redacted_command,
            cwd=self._cwd,
            redaction_mode=self._redactor.config.mode,
            backpressure_policy=self._backpressure_policy,
        )

    def start_execution(self) -> list[ExecutionEvent]:
        """Emit initial ``execution_started`` (and warning if unredacted mode is active)."""
        merged_redaction = merge_redaction_summaries(
            self._redactor.config.mode,
            [self._cmd_redaction, self._env_redaction],
        )
        cwd_value: str | None = self._cwd
        if cwd_value is not None and self._redactor.config.mode == "strict_hash_only":
            cwd_value = None

        degraded = merged_redaction.degraded
        if degraded:
            self._degraded_events += 1

        events: list[ExecutionEvent] = [
            ExecutionEvent(
                event_id=new_event_id(),
                execution_id=self._execution_id,
                sequence=self._next_sequence(),
                timestamp=self._started_at,
                monotonic_time_ns=self._monotonic_start_ns,
                direction="proxy",
                kind="execution_started",
                trace=TraceContext(
                    trace_source="synthetic_execution",
                    synthetic_execution_trace_id=synthetic_trace_id_for_execution(
                        self._execution_id
                    ),
                ),
                redaction=merged_redaction,
                degraded=degraded,
                payload=ExecutionStartedPayload(
                    command=self._redacted_command,
                    cwd=cwd_value,
                    redaction_mode=self._redactor.config.mode,
                    backpressure_policy=self._backpressure_policy,
                    env_override_keys=self._env_override_keys,
                    redacted_env_overrides=self._redacted_env_overrides,
                ),
            )
        ]

        if self._redactor.config.mode == "explicit_unredacted":
            events.append(
                self._emit_warning_event(
                    timestamp=self._started_at,
                    monotonic_time_ns=self._monotonic_start_ns,
                    code="unredacted_capture_enabled",
                    message=(
                        "Capture started with redaction_mode='explicit_unredacted'; "
                        "raw payloads may contain sensitive values."
                    ),
                    details={"redaction_mode": "explicit_unredacted"},
                )
            )
        if degraded:
            events.append(
                self._emit_warning_event(
                    timestamp=self._started_at,
                    monotonic_time_ns=self._monotonic_start_ns,
                    code="redaction_failed",
                    message="Failed while redacting startup command or environment overrides",
                    details={"error": merged_redaction.error or "unknown"},
                )
            )
        return events

    def build_gap_event(
        self,
        *,
        timestamp: datetime,
        monotonic_time_ns: int,
        dropped_count: int,
        reason: str,
        first_gap_monotonic_ns: int,
        last_gap_monotonic_ns: int,
        details: Mapping[str, Any] | None = None,
    ) -> ExecutionEvent:
        """Create an explicit ``capture_gap`` event and record gap accounting."""
        self._dropped_events += dropped_count
        self._gap_count += 1
        return ExecutionEvent(
            event_id=new_event_id(),
            execution_id=self._execution_id,
            sequence=self._next_sequence(),
            timestamp=timestamp,
            monotonic_time_ns=monotonic_time_ns,
            direction="system",
            kind="capture_gap",
            redaction=self._default_system_redaction(),
            payload=CaptureGapPayload(
                dropped_count=dropped_count,
                reason=reason,
                first_gap_monotonic_ns=first_gap_monotonic_ns,
                last_gap_monotonic_ns=last_gap_monotonic_ns,
                details=dict(details) if details else {},
            ),
        )

    def normalize(self, raw_input: RawCaptureInput) -> list[ExecutionEvent]:
        """Normalize one raw observation into zero, one, or more ExecutionEvents."""
        if isinstance(raw_input, RawWireFrameInput):
            return self._normalize_wire_frame(raw_input)
        if isinstance(raw_input, RawIncompleteFrameInput):
            return self._normalize_incomplete_frame(raw_input)
        if isinstance(raw_input, RawFrameTooLargeInput):
            return [
                ExecutionEvent(
                    event_id=new_event_id(),
                    execution_id=self._execution_id,
                    sequence=self._next_sequence(),
                    timestamp=raw_input.timestamp,
                    monotonic_time_ns=raw_input.monotonic_time_ns,
                    direction=raw_input.direction,
                    kind="frame_too_large",
                    wire=WireFrameInfo(
                        byte_length=raw_input.observed_bytes,
                        line_ending="none",
                    ),
                    redaction=self._default_system_redaction(),
                    payload=FrameTooLargePayload(
                        observed_bytes=raw_input.observed_bytes,
                        max_frame_bytes=raw_input.max_frame_bytes,
                    ),
                )
            ]
        if isinstance(raw_input, RawStderrLineInput):
            return self._normalize_stderr(raw_input)
        if isinstance(raw_input, RawTransportErrorInput):
            err_redacted = self._redactor.redact_text_value(
                raw_input.error, path_label="transport_error"
            )
            degraded = err_redacted.summary.degraded
            if degraded:
                self._degraded_events += 1
            return [
                ExecutionEvent(
                    event_id=new_event_id(),
                    execution_id=self._execution_id,
                    sequence=self._next_sequence(),
                    timestamp=raw_input.timestamp,
                    monotonic_time_ns=raw_input.monotonic_time_ns,
                    direction="proxy",
                    kind="transport_error",
                    redaction=err_redacted.summary,
                    degraded=degraded,
                    payload=TransportErrorPayload(
                        stream_direction=raw_input.stream_direction,
                        reason=raw_input.reason,
                        error=err_redacted.text or "",
                    ),
                )
            ]
        if isinstance(raw_input, RawProxySignalInput):
            return [
                ExecutionEvent(
                    event_id=new_event_id(),
                    execution_id=self._execution_id,
                    sequence=self._next_sequence(),
                    timestamp=raw_input.timestamp,
                    monotonic_time_ns=raw_input.monotonic_time_ns,
                    direction="proxy",
                    kind="proxy_signal",
                    redaction=self._default_system_redaction(),
                    payload=ProxySignalPayload(signal_name=raw_input.signal_name),
                )
            ]
        if isinstance(raw_input, RawChildShutdownEscalateInput):
            return [
                ExecutionEvent(
                    event_id=new_event_id(),
                    execution_id=self._execution_id,
                    sequence=self._next_sequence(),
                    timestamp=raw_input.timestamp,
                    monotonic_time_ns=raw_input.monotonic_time_ns,
                    direction="proxy",
                    kind="child_shutdown_escalate",
                    redaction=self._default_system_redaction(),
                    payload=ChildShutdownEscalatePayload(
                        signal_name=raw_input.signal_name,
                        pgid=raw_input.pgid,
                        error=raw_input.error,
                    ),
                )
            ]
        if isinstance(raw_input, RawProcessExitedInput):
            self._last_returncode = raw_input.returncode
            self._correlator.mark_process_exited()
            return []
        if isinstance(raw_input, RawCaptureWarningInput):
            return [
                self._emit_warning_event(
                    timestamp=raw_input.timestamp,
                    monotonic_time_ns=raw_input.monotonic_time_ns,
                    code=raw_input.code,
                    message=raw_input.message,
                    details=raw_input.details,
                )
            ]
        raise TypeError(f"Unsupported RawCaptureInput type: {type(raw_input)!r}")

    def _normalize_stderr(self, item: RawStderrLineInput) -> list[ExecutionEvent]:
        decoded = item.raw_line.decode("utf-8", errors="replace")
        outcome = self._redactor.redact_text_value(decoded, path_label="stderr")
        degraded = outcome.summary.degraded
        if degraded:
            self._degraded_events += 1
        events = [
            ExecutionEvent(
                event_id=new_event_id(),
                execution_id=self._execution_id,
                sequence=self._next_sequence(),
                timestamp=item.timestamp,
                monotonic_time_ns=item.monotonic_time_ns,
                direction="server_stderr",
                kind="process_stderr",
                redaction=outcome.summary,
                degraded=degraded,
                payload=ProcessStderrPayload(
                    byte_length=len(item.raw_line),
                    text=outcome.text,
                    truncated=outcome.truncated,
                ),
            )
        ]
        if degraded:
            events.append(
                self._emit_warning_event(
                    timestamp=item.timestamp,
                    monotonic_time_ns=item.monotonic_time_ns,
                    code="redaction_failed",
                    message="Failed while redacting child stderr line; raw line withheld",
                    details={"error": outcome.summary.error or "unknown"},
                )
            )
        return events

    def _normalize_incomplete_frame(self, item: RawIncompleteFrameInput) -> list[ExecutionEvent]:
        decoded = item.trailing_bytes.decode("utf-8", errors="replace")
        outcome = self._redactor.redact_text_value(
            decoded,
            path_label="incomplete_trailing_frame",
            max_chars=_MAX_CAPTURED_MALFORMED_CHARS,
        )
        degraded = outcome.summary.degraded
        if degraded:
            self._degraded_events += 1
        wire = WireFrameInfo(
            byte_length=len(item.trailing_bytes),
            line_ending="none",
            sha256=hashlib.sha256(item.trailing_bytes).hexdigest(),
        )
        events = [
            ExecutionEvent(
                event_id=new_event_id(),
                execution_id=self._execution_id,
                sequence=self._next_sequence(),
                timestamp=item.timestamp,
                monotonic_time_ns=item.monotonic_time_ns,
                direction=item.direction,
                kind="incomplete_trailing_frame",
                wire=wire,
                redaction=outcome.summary,
                degraded=degraded,
                payload=IncompleteTrailingFramePayload(
                    byte_length=len(item.trailing_bytes),
                    text=outcome.text,
                    truncated=outcome.truncated,
                ),
            ),
            self._emit_warning_event(
                timestamp=item.timestamp,
                monotonic_time_ns=item.monotonic_time_ns,
                code="incomplete_trailing_frame",
                message="Stream reached EOF with trailing bytes lacking newline terminator",
                details={
                    "direction": item.direction,
                    "byte_length": len(item.trailing_bytes),
                },
            ),
        ]
        return events

    def _normalize_wire_frame(self, item: RawWireFrameInput) -> list[ExecutionEvent]:
        raw_frame = item.raw_frame
        line_ending = detect_line_ending(raw_frame)
        sha256 = hashlib.sha256(raw_frame).hexdigest()
        body_bytes = _strip_wire_newline(raw_frame)

        try:
            text = body_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            lossy = body_bytes.decode("utf-8", errors="replace")
            text_out = self._redactor.redact_text_value(
                lossy,
                path_label="malformed_utf8",
                max_chars=_MAX_CAPTURED_MALFORMED_CHARS,
            )
            raw_b64: str | None = None
            b64_truncated = text_out.truncated
            if self._redactor.config.mode == "explicit_unredacted":
                raw_b64 = base64.b64encode(body_bytes[:_MAX_CAPTURED_RAW_B64_BYTES]).decode("ascii")
                b64_truncated = len(body_bytes) > _MAX_CAPTURED_RAW_B64_BYTES
            degraded = text_out.summary.degraded
            if degraded:
                self._degraded_events += 1
            return [
                ExecutionEvent(
                    event_id=new_event_id(),
                    execution_id=self._execution_id,
                    sequence=self._next_sequence(),
                    timestamp=item.timestamp,
                    monotonic_time_ns=item.monotonic_time_ns,
                    direction=item.direction,
                    kind="malformed_utf8_frame",
                    wire=WireFrameInfo(
                        byte_length=len(raw_frame),
                        line_ending=line_ending,
                        sha256=sha256,
                    ),
                    redaction=text_out.summary,
                    degraded=degraded,
                    payload=MalformedUtf8FramePayload(
                        error=f"utf8_decode_error: {exc}",
                        redacted_lossy_text=text_out.text,
                        raw_bytes_b64=raw_b64,
                        truncated=b64_truncated,
                    ),
                ),
                self._emit_warning_event(
                    timestamp=item.timestamp,
                    monotonic_time_ns=item.monotonic_time_ns,
                    code="malformed_utf8_frame",
                    message="Wire frame contained invalid UTF-8 bytes",
                    details={"direction": item.direction, "byte_length": len(raw_frame)},
                ),
            ]

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            json_text_out = self._redactor.redact_text_value(
                text,
                path_label="malformed_json",
                max_chars=_MAX_CAPTURED_MALFORMED_CHARS,
            )
            degraded = json_text_out.summary.degraded
            if degraded:
                self._degraded_events += 1
            return [
                ExecutionEvent(
                    event_id=new_event_id(),
                    execution_id=self._execution_id,
                    sequence=self._next_sequence(),
                    timestamp=item.timestamp,
                    monotonic_time_ns=item.monotonic_time_ns,
                    direction=item.direction,
                    kind="malformed_json_frame",
                    wire=WireFrameInfo(
                        byte_length=len(raw_frame),
                        line_ending=line_ending,
                        sha256=sha256,
                    ),
                    redaction=json_text_out.summary,
                    degraded=degraded,
                    payload=MalformedJsonFramePayload(
                        error=f"json_decode_error: {exc}",
                        text=json_text_out.text,
                        truncated=json_text_out.truncated,
                    ),
                ),
                self._emit_warning_event(
                    timestamp=item.timestamp,
                    monotonic_time_ns=item.monotonic_time_ns,
                    code="malformed_json_frame",
                    message="Wire frame failed JSON decoding",
                    details={"direction": item.direction, "byte_length": len(raw_frame)},
                ),
            ]

        if not isinstance(parsed, dict):
            is_batch = (
                isinstance(parsed, list)
                and bool(parsed)
                and all(isinstance(elem, dict) for elem in parsed)
            )
            val_out = self._redactor.redact_value(parsed, root_path="value")
            degraded = val_out.summary.degraded
            if degraded:
                self._degraded_events += 1
            return [
                ExecutionEvent(
                    event_id=new_event_id(),
                    execution_id=self._execution_id,
                    sequence=self._next_sequence(),
                    timestamp=item.timestamp,
                    monotonic_time_ns=item.monotonic_time_ns,
                    direction=item.direction,
                    kind="non_object_json_frame",
                    wire=WireFrameInfo(
                        byte_length=len(raw_frame),
                        line_ending=line_ending,
                        sha256=sha256,
                    ),
                    redaction=val_out.summary,
                    degraded=degraded,
                    payload=NonObjectJsonFramePayload(
                        json_type=type(parsed).__name__,
                        value=val_out.value,
                        is_jsonrpc_batch_candidate=is_batch,
                        item_count=len(parsed) if isinstance(parsed, list) else None,
                    ),
                ),
                self._emit_warning_event(
                    timestamp=item.timestamp,
                    monotonic_time_ns=item.monotonic_time_ns,
                    code="non_object_json_frame",
                    message=f"Observed non-object JSON frame of type {type(parsed).__name__}",
                    details={
                        "direction": item.direction,
                        "json_type": type(parsed).__name__,
                        "is_batch_candidate": is_batch,
                    },
                ),
            ]

        return self._normalize_json_object(item, parsed, line_ending=line_ending, sha256=sha256)

    def _redact_otel_attributes(
        self,
        raw_attrs: dict[str, str | bool],
    ) -> tuple[dict[str, str | bool], RedactionSummary]:
        if not raw_attrs:
            return {}, self._default_system_redaction()
        outcome = self._redactor.redact_value(raw_attrs, root_path="derived.otel_attributes")
        if outcome.summary.degraded or not isinstance(outcome.value, dict):
            return {}, outcome.summary
        cleaned: dict[str, str | bool] = {}
        for k, v in outcome.value.items():
            if isinstance(v, bool | str):
                cleaned[k] = v
        return cleaned, outcome.summary

    def _normalize_json_object(
        self,
        item: RawWireFrameInput,
        parsed: dict[str, Any],
        *,
        line_ending: Any,
        sha256: str,
    ) -> list[ExecutionEvent]:
        event_id = new_event_id()
        seq = self._next_sequence()
        raw_id_type, raw_id_value = classify_jsonrpc_id(parsed)
        jsonrpc_ver = parsed.get("jsonrpc") if isinstance(parsed.get("jsonrpc"), str) else None
        raw_method = parsed.get("method")
        method = raw_method if isinstance(raw_method, str) else None
        has_id = "id" in parsed

        wire = WireFrameInfo(
            byte_length=len(item.raw_frame),
            line_ending=line_ending,
            sha256=sha256,
            jsonrpc_version=jsonrpc_ver,
            raw_id_present=has_id,
            raw_id_type=raw_id_type,
            is_valid_jsonrpc_id=raw_id_type in {"int", "str"},
            keys=tuple(sorted(str(k) for k in parsed)),
        )

        mode = self._redactor.config.mode
        summaries: list[RedactionSummary] = []

        # Redact scalar/non-standard IDs so secrets embedded in unexpected string IDs are scrubbed.
        safe_id_val = raw_id_value
        if raw_id_type in {"str", "array", "object"}:
            id_out = self._redactor.redact_value(raw_id_value, root_path="id")
            summaries.append(id_out.summary)
            safe_id_val = id_out.value

        corr_meta: Any
        payload: Any
        trace_ctx: TraceContext | None = None
        corr_info: CorrelationInfo | None = None
        derived: DerivedMetadata | None = None
        warnings: tuple[CorrelationWarning, ...] = ()

        if "method" in parsed and has_id:
            corr_meta = self._correlator.process_request(
                event_id=event_id,
                sequence=seq,
                monotonic_time_ns=item.monotonic_time_ns,
                direction=item.direction,
                method=method,
                id_type=raw_id_type,
                request_id=raw_id_value,
                params=parsed.get("params"),
            )
            has_params = "params" in parsed
            params_out = (
                self._redactor.redact_value(parsed.get("params"), root_path="params")
                if has_params
                else None
            )
            if params_out is not None:
                summaries.append(params_out.summary)
            raw_extras = {k: v for k, v in parsed.items() if k not in _STANDARD_REQUEST_KEYS}
            extra_out = (
                self._redactor.redact_value(raw_extras, root_path="extra_fields")
                if raw_extras
                else None
            )
            if extra_out is not None:
                summaries.append(extra_out.summary)
            payload = JsonRpcRequestPayload(
                method=method,
                id=safe_id_val,
                id_type=raw_id_type,
                has_params=has_params,
                params=params_out.value if params_out is not None else None,
                extra_fields=(
                    extra_out.value
                    if extra_out is not None and isinstance(extra_out.value, dict)
                    else {}
                ),
            )
            kind: Any = "jsonrpc_request"

        elif "method" in parsed:
            corr_meta = self._correlator.process_notification(
                event_id=event_id,
                direction=item.direction,
                method=method,
                params=parsed.get("params"),
            )
            has_params = "params" in parsed
            params_out = (
                self._redactor.redact_value(parsed.get("params"), root_path="params")
                if has_params
                else None
            )
            if params_out is not None:
                summaries.append(params_out.summary)
            raw_extras = {k: v for k, v in parsed.items() if k not in _STANDARD_NOTIFICATION_KEYS}
            extra_out = (
                self._redactor.redact_value(raw_extras, root_path="extra_fields")
                if raw_extras
                else None
            )
            if extra_out is not None:
                summaries.append(extra_out.summary)
            payload = JsonRpcNotificationPayload(
                method=method,
                has_params=has_params,
                params=params_out.value if params_out is not None else None,
                extra_fields=(
                    extra_out.value
                    if extra_out is not None and isinstance(extra_out.value, dict)
                    else {}
                ),
            )
            kind = "jsonrpc_notification"

        elif "result" in parsed:
            corr_meta = self._correlator.process_response(
                event_id=event_id,
                sequence=seq,
                monotonic_time_ns=item.monotonic_time_ns,
                direction=item.direction,
                id_type=raw_id_type,
                request_id=raw_id_value,
                is_error=False,
                result_or_error=parsed.get("result"),
            )
            result_out = self._redactor.redact_value(parsed.get("result"), root_path="result")
            summaries.append(result_out.summary)
            raw_extras = {k: v for k, v in parsed.items() if k not in _STANDARD_RESPONSE_KEYS}
            extra_out = (
                self._redactor.redact_value(raw_extras, root_path="extra_fields")
                if raw_extras
                else None
            )
            if extra_out is not None:
                summaries.append(extra_out.summary)
            payload = JsonRpcResponsePayload(
                id=safe_id_val,
                id_type=raw_id_type,
                result=result_out.value,
                extra_fields=(
                    extra_out.value
                    if extra_out is not None and isinstance(extra_out.value, dict)
                    else {}
                ),
            )
            kind = "jsonrpc_response"

        elif "error" in parsed:
            raw_err = parsed.get("error")
            corr_meta = self._correlator.process_response(
                event_id=event_id,
                sequence=seq,
                monotonic_time_ns=item.monotonic_time_ns,
                direction=item.direction,
                id_type=raw_id_type,
                request_id=raw_id_value,
                is_error=True,
                result_or_error=raw_err,
            )
            err_out = self._redactor.redact_value(raw_err, root_path="error")
            summaries.append(err_out.summary)
            raw_extras = {k: v for k, v in parsed.items() if k not in _STANDARD_ERROR_KEYS}
            extra_out = (
                self._redactor.redact_value(raw_extras, root_path="extra_fields")
                if raw_extras
                else None
            )
            if extra_out is not None:
                summaries.append(extra_out.summary)

            redacted_err = err_out.value
            err_code = (
                redacted_err.get("code")
                if isinstance(redacted_err, dict)
                and isinstance(redacted_err.get("code"), int)
                and not isinstance(redacted_err.get("code"), bool)
                else None
            )
            err_msg = (
                redacted_err.get("message")
                if isinstance(redacted_err, dict) and isinstance(redacted_err.get("message"), str)
                else None
            )
            err_data = redacted_err.get("data") if isinstance(redacted_err, dict) else None
            payload = JsonRpcErrorPayload(
                id=safe_id_val,
                id_type=raw_id_type,
                error=redacted_err,
                error_code=err_code,
                error_message=err_msg,
                error_data=err_data,
                extra_fields=(
                    extra_out.value
                    if extra_out is not None and isinstance(extra_out.value, dict)
                    else {}
                ),
            )
            kind = "jsonrpc_error"

        else:
            corr_meta = None
            body_out = self._redactor.redact_value(parsed, root_path="body")
            summaries.append(body_out.summary)
            payload = JsonRpcUnknownObjectPayload(
                body=body_out.value if isinstance(body_out.value, dict) else {},
            )
            kind = "jsonrpc_unknown_object"

        if corr_meta is not None:
            trace_ctx = corr_meta.trace
            corr_info = corr_meta.correlation
            warnings = corr_meta.warnings
            if corr_meta.derived is not None:
                safe_otel, otel_summary = self._redact_otel_attributes(
                    corr_meta.derived.otel_attributes
                )
                if corr_meta.derived.otel_attributes:
                    summaries.append(otel_summary)
                derived = DerivedMetadata(
                    otel_attributes=safe_otel,
                    tool_is_error=corr_meta.derived.tool_is_error,
                    anomaly_flags=corr_meta.derived.anomaly_flags,
                )

        merged_redaction = merge_redaction_summaries(mode, summaries)
        degraded = merged_redaction.degraded
        if degraded:
            self._degraded_events += 1
        self._record_trace_id(trace_ctx)

        events: list[ExecutionEvent] = [
            ExecutionEvent(
                event_id=event_id,
                execution_id=self._execution_id,
                sequence=seq,
                timestamp=item.timestamp,
                monotonic_time_ns=item.monotonic_time_ns,
                direction=item.direction,
                kind=kind,
                wire=wire,
                trace=trace_ctx,
                correlation=corr_info,
                derived=derived,
                redaction=merged_redaction,
                degraded=degraded,
                payload=payload,
            )
        ]

        if degraded:
            events.append(
                self._emit_warning_event(
                    timestamp=item.timestamp,
                    monotonic_time_ns=item.monotonic_time_ns,
                    code="redaction_failed",
                    message="Redaction failed for one or more frame fields; unsafe fields withheld",
                    details={
                        "direction": item.direction,
                        "kind": kind,
                        "error": merged_redaction.error or "unknown",
                    },
                )
            )
        events.extend(
            self._emit_correlation_warnings(
                timestamp=item.timestamp,
                monotonic_time_ns=item.monotonic_time_ns,
                warnings=warnings,
            )
        )
        return events

    def finalize_execution(
        self,
        *,
        ended_at: datetime,
        monotonic_end_ns: int,
        termination_reason: str,
        exit_code: int,
        returncode: int | None = None,
        spilled: bool = False,
        force_incomplete: bool = False,
        spool_file: str | None = None,
    ) -> tuple[ExecutionEvent, ExecutionSummary]:
        """Emit ``execution_finished`` and construct the final :class:`ExecutionSummary`."""
        effective_rc = self._last_returncode if returncode is None else returncode
        unanswered = self._correlator.unanswered_request_labels()

        if force_incomplete or self._dropped_events > 0 or self._gap_count > 0:
            completeness: CaptureCompleteness = "incomplete"
        elif self._degraded_events > 0:
            completeness = "degraded"
        elif spilled:
            completeness = "spilled"
        else:
            completeness = "complete"

        final_seq = self._next_sequence()
        finished_event = ExecutionEvent(
            event_id=new_event_id(),
            execution_id=self._execution_id,
            sequence=final_seq,
            timestamp=ended_at,
            monotonic_time_ns=monotonic_end_ns,
            direction="proxy",
            kind="execution_finished",
            redaction=self._default_system_redaction(),
            payload=ExecutionFinishedPayload(
                termination_reason=termination_reason,
                exit_code=exit_code,
                returncode=effective_rc,
                completeness=completeness,
                total_events=final_seq,
                dropped_events=self._dropped_events,
                degraded_events=self._degraded_events,
                unanswered_request_count=len(unanswered),
                unanswered_request_ids=unanswered,
                spool_file=spool_file,
            ),
        )
        summary = ExecutionSummary(
            execution_id=self._execution_id,
            started_at=self._started_at,
            ended_at=ended_at,
            duration_ns=max(0, monotonic_end_ns - self._monotonic_start_ns),
            command=self._redacted_command,
            cwd=self._cwd if self._redactor.config.mode != "strict_hash_only" else None,
            redaction_mode=self._redactor.config.mode,
            backpressure_policy=self._backpressure_policy,
            capture_completeness=completeness,
            termination_reason=termination_reason,
            exit_code=exit_code,
            returncode=effective_rc,
            total_events=final_seq,
            dropped_events=self._dropped_events,
            degraded_events=self._degraded_events,
            warning_count=self._warning_count,
            gap_count=self._gap_count,
            unanswered_request_ids=unanswered,
            observed_trace_ids=tuple(self._observed_trace_ids),
            observed_mcp_protocol_versions=self._correlator.observed_protocol_versions,
            spool_file=spool_file,
        )
        return finished_event, summary


__all__ = [
    "EventNormalizer",
    "RawCaptureInput",
    "RawCaptureWarningInput",
    "RawChildShutdownEscalateInput",
    "RawFrameTooLargeInput",
    "RawIncompleteFrameInput",
    "RawProcessExitedInput",
    "RawProxySignalInput",
    "RawStderrLineInput",
    "RawTransportErrorInput",
    "RawWireFrameInput",
]
