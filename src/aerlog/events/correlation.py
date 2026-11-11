"""Deterministic request/response, cancellation, progress, and OTel metadata correlation.

Correlates JSON-RPC messages purely from observed wire fields without mutating
wire bytes or fabricating trace parent/child hierarchies.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from aerlog.events.ids import extract_observed_trace_from_params
from aerlog.events.models import (
    CorrelationInfo,
    DerivedMetadata,
    JsonRpcIdValue,
    TraceContext,
)
from aerlog.events.types import (
    OTEL_ATTR_GEN_AI_OPERATION,
    OTEL_ATTR_GEN_AI_PROMPT_NAME,
    OTEL_ATTR_GEN_AI_TOOL_NAME,
    OTEL_ATTR_JSONRPC_REQUEST_ID,
    OTEL_ATTR_MCP_METHOD,
    OTEL_ATTR_MCP_PROTOCOL_VERSION,
    OTEL_ATTR_MCP_RESOURCE_URI,
    JsonRpcIdType,
    WireDirection,
)

ValidIdType = Literal["int", "str"]
CorrelationKey = tuple[WireDirection, ValidIdType, int | str]
ProgressTokenKey = tuple[WireDirection, ValidIdType, int | str]


def opposite_wire_direction(direction: WireDirection) -> WireDirection:
    """Return the reverse stdio stream direction."""
    return "server_to_client" if direction == "client_to_server" else "client_to_server"


def _as_valid_key_part(
    id_type: JsonRpcIdType, id_value: JsonRpcIdValue
) -> tuple[ValidIdType, int | str] | None:
    if id_type == "int" and isinstance(id_value, int) and not isinstance(id_value, bool):
        return "int", id_value
    if id_type == "str" and isinstance(id_value, str):
        return "str", id_value
    return None


def _as_valid_scalar_id(raw_value: object) -> tuple[ValidIdType, int | str] | None:
    if isinstance(raw_value, bool):
        return None
    if isinstance(raw_value, int):
        return "int", raw_value
    if isinstance(raw_value, str):
        return "str", raw_value
    return None


def _format_id_label(origin_direction: WireDirection, id_type: JsonRpcIdType, value: object) -> str:
    return f"{origin_direction}:{id_type}:{value!r}"


@dataclass(slots=True)
class PendingRequest:
    """In-flight JSON-RPC request awaiting a response or execution end."""

    event_id: str
    sequence: int
    monotonic_time_ns: int
    origin_direction: WireDirection
    id_type: ValidIdType
    request_id: int | str
    method: str | None
    progress_token_key: ProgressTokenKey | None = None
    trace_context: TraceContext | None = None
    saw_duplicate_sibling: bool = False
    cancel_notified: bool = False
    cancel_event_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class CompletedRequestRef:
    """Reference to a request that already received at least one response."""

    event_id: str
    sequence: int
    method: str | None


@dataclass(frozen=True, slots=True)
class CorrelationWarning:
    """Warning emitted by the correlator for anomalous wire conditions."""

    code: str
    message: str
    details: dict[str, Any]


@dataclass(frozen=True, slots=True)
class CorrelatedFrameMetadata:
    """Result of correlating one parsed JSON-RPC object frame."""

    trace: TraceContext | None
    correlation: CorrelationInfo | None
    derived: DerivedMetadata | None
    warnings: tuple[CorrelationWarning, ...]
    observed_protocol_version: str | None = None


class RequestCorrelator:
    """Tracks in-flight requests, cancellations, progress tokens, and wire trace headers."""

    def __init__(self, execution_id: str) -> None:
        self._execution_id = execution_id
        self._pending: dict[CorrelationKey, deque[PendingRequest]] = {}
        self._completed: dict[CorrelationKey, list[CompletedRequestRef]] = {}
        self._progress_tokens: dict[ProgressTokenKey, deque[PendingRequest]] = {}
        self._observed_protocol_versions: list[str] = []
        self._latest_protocol_version: str | None = None
        self._process_exited = False

    def mark_process_exited(self) -> None:
        """Mark target server subprocess as exited so subsequent frames flag post-exit arrival."""
        self._process_exited = True

    @property
    def observed_protocol_versions(self) -> tuple[str, ...]:
        """Return distinct MCP protocol versions observed on the wire in encounter order."""
        return tuple(self._observed_protocol_versions)

    def unanswered_requests(self) -> tuple[PendingRequest, ...]:
        """Return all open in-flight requests remaining when execution finishes."""
        items: list[PendingRequest] = []
        for q in self._pending.values():
            items.extend(q)
        items.sort(key=lambda req: req.sequence)
        return tuple(items)

    def unanswered_request_labels(self) -> tuple[str, ...]:
        """Return human-readable identifiers for open unanswered requests."""
        return tuple(
            _format_id_label(req.origin_direction, req.id_type, req.request_id)
            for req in self.unanswered_requests()
        )

    def _record_protocol_version(self, version: object) -> str | None:
        if isinstance(version, str) and version.strip():
            ver = version.strip()
            if ver not in self._observed_protocol_versions:
                self._observed_protocol_versions.append(ver)
            self._latest_protocol_version = ver
            return ver
        return None

    def _extract_trace(
        self,
        params: object,
        warnings: list[CorrelationWarning],
    ) -> TraceContext:
        extracted = extract_observed_trace_from_params(params, execution_id=self._execution_id)
        if extracted.invalid_traceparent_present:
            warnings.append(
                CorrelationWarning(
                    code="invalid_w3c_traceparent",
                    message="Ignored malformed W3C traceparent header in params._meta",
                    details={},
                )
            )

        tp = extracted.observed_traceparent
        return TraceContext(
            trace_source=extracted.trace_source,
            observed_trace_id=tp.trace_id if tp is not None else None,
            observed_parent_span_id=tp.parent_span_id if tp is not None else None,
            observed_trace_flags=tp.trace_flags if tp is not None else None,
            observed_traceparent=tp.raw if tp is not None else None,
            observed_tracestate=extracted.observed_tracestate,
            synthetic_execution_trace_id=extracted.synthetic_execution_trace_id,
        )

    def _build_otel_attributes(
        self,
        *,
        method: str | None,
        params: object,
        request_id: int | str | None,
        protocol_version: str | None,
    ) -> dict[str, str | bool]:
        attrs: dict[str, str | bool] = {}
        if method is not None:
            attrs[OTEL_ATTR_MCP_METHOD] = method
        if request_id is not None:
            attrs[OTEL_ATTR_JSONRPC_REQUEST_ID] = str(request_id)
        effective_ver = protocol_version or self._latest_protocol_version
        if effective_ver is not None:
            attrs[OTEL_ATTR_MCP_PROTOCOL_VERSION] = effective_ver

        if method == "tools/call":
            attrs[OTEL_ATTR_GEN_AI_OPERATION] = "execute_tool"
            if isinstance(params, Mapping) and isinstance(params.get("name"), str):
                attrs[OTEL_ATTR_GEN_AI_TOOL_NAME] = params["name"]
        elif method == "prompts/get":
            if isinstance(params, Mapping) and isinstance(params.get("name"), str):
                attrs[OTEL_ATTR_GEN_AI_PROMPT_NAME] = params["name"]
        elif (
            method in {"resources/read", "resources/subscribe", "resources/unsubscribe"}
            and isinstance(params, Mapping)
            and isinstance(params.get("uri"), str)
        ):
            attrs[OTEL_ATTR_MCP_RESOURCE_URI] = params["uri"]

        return attrs

    def _register_progress_token(
        self,
        pending: PendingRequest,
        params: object,
        warnings: list[CorrelationWarning],
    ) -> None:
        if not isinstance(params, Mapping):
            return
        meta = params.get("_meta")
        if not isinstance(meta, Mapping) or "progressToken" not in meta:
            return
        parsed_token = _as_valid_scalar_id(meta["progressToken"])
        if parsed_token is None:
            return

        token_key: ProgressTokenKey = (pending.origin_direction, parsed_token[0], parsed_token[1])
        queue = self._progress_tokens.setdefault(token_key, deque())
        if queue:
            warnings.append(
                CorrelationWarning(
                    code="duplicate_progress_token",
                    message="Reused active _meta.progressToken while previous request is in flight",
                    details={
                        "origin_direction": pending.origin_direction,
                        "progress_token": parsed_token[1],
                        "existing_request_event_ids": [p.event_id for p in queue],
                    },
                )
            )
        queue.append(pending)
        pending.progress_token_key = token_key

    def _unregister_progress_token(self, pending: PendingRequest) -> None:
        token_key = pending.progress_token_key
        if token_key is None:
            return
        queue = self._progress_tokens.get(token_key)
        if queue is None:
            return
        remaining = deque(item for item in queue if item.event_id != pending.event_id)
        if remaining:
            self._progress_tokens[token_key] = remaining
        else:
            del self._progress_tokens[token_key]

    def process_request(
        self,
        *,
        event_id: str,
        sequence: int,
        monotonic_time_ns: int,
        direction: WireDirection,
        method: str | None,
        id_type: JsonRpcIdType,
        request_id: JsonRpcIdValue,
        params: object,
    ) -> CorrelatedFrameMetadata:
        """Register an observed JSON-RPC request and extract trace/OTel metadata."""
        warnings: list[CorrelationWarning] = []
        anomalies: list[str] = []

        if self._process_exited:
            anomalies.append("post_exit_frame")
            warnings.append(
                CorrelationWarning(
                    code="post_exit_frame",
                    message="Observed request frame after server process exit",
                    details={"direction": direction, "method": method},
                )
            )

        observed_ver: str | None = None
        if method == "initialize" and isinstance(params, Mapping):
            observed_ver = self._record_protocol_version(params.get("protocolVersion"))
        elif isinstance(params, Mapping) and isinstance(params.get("_meta"), Mapping):
            meta = params["_meta"]
            observed_ver = self._record_protocol_version(
                meta.get("mcpProtocolVersion")
                or meta.get("io.modelcontextprotocol/protocolVersion")
            )

        trace_ctx = self._extract_trace(params, warnings)

        key_part = _as_valid_key_part(id_type, request_id)
        correlation: CorrelationInfo | None = None
        valid_id_val: int | str | None = None

        if key_part is None:
            anomalies.append("invalid_request_id")
            warnings.append(
                CorrelationWarning(
                    code="invalid_jsonrpc_request_id",
                    message=f"JSON-RPC request carries non-standard id type {id_type!r}",
                    details={"direction": direction, "id_type": id_type, "method": method},
                )
            )
            correlation = CorrelationInfo(
                status="invalid_id",
                confidence="none",
                basis=f"invalid_request_id_type:{id_type}",
                origin_direction=direction,
                post_exit_frame=self._process_exited,
            )
        else:
            valid_type, valid_id_val = key_part
            comp_key: CorrelationKey = (direction, valid_type, valid_id_val)
            queue = self._pending.setdefault(comp_key, deque())
            pending = PendingRequest(
                event_id=event_id,
                sequence=sequence,
                monotonic_time_ns=monotonic_time_ns,
                origin_direction=direction,
                id_type=valid_type,
                request_id=valid_id_val,
                method=method,
                trace_context=trace_ctx,
            )
            if queue:
                anomalies.append("duplicate_in_flight_id")
                existing_ids = tuple(item.event_id for item in queue)
                for item in queue:
                    item.saw_duplicate_sibling = True
                pending.saw_duplicate_sibling = True
                warnings.append(
                    CorrelationWarning(
                        code="duplicate_in_flight_request_id",
                        message=(
                            "Observed duplicate in-flight JSON-RPC request ID in same direction"
                        ),
                        details={
                            "direction": direction,
                            "id_type": valid_type,
                            "id": valid_id_val,
                            "existing_request_event_ids": list(existing_ids),
                        },
                    )
                )
                correlation = CorrelationInfo(
                    status="ambiguous_duplicate_id",
                    confidence="none",
                    basis="duplicate_id_while_request_in_flight",
                    candidate_request_event_ids=existing_ids,
                    origin_direction=direction,
                    post_exit_frame=self._process_exited,
                )
            elif self._process_exited:
                correlation = CorrelationInfo(
                    status="matched",
                    confidence="none",
                    basis="outbound_request_after_exit",
                    origin_direction=direction,
                    post_exit_frame=True,
                )

            queue.append(pending)
            self._register_progress_token(pending, params, warnings)

        otel_attrs = self._build_otel_attributes(
            method=method,
            params=params,
            request_id=valid_id_val,
            protocol_version=observed_ver,
        )
        derived = DerivedMetadata(
            otel_attributes=otel_attrs,
            anomaly_flags=tuple(anomalies),
        )
        return CorrelatedFrameMetadata(
            trace=trace_ctx,
            correlation=correlation,
            derived=derived,
            warnings=tuple(warnings),
            observed_protocol_version=observed_ver,
        )

    def process_response(
        self,
        *,
        event_id: str,
        sequence: int,
        monotonic_time_ns: int,
        direction: WireDirection,
        id_type: JsonRpcIdType,
        request_id: JsonRpcIdValue,
        is_error: bool,
        result_or_error: object,
    ) -> CorrelatedFrameMetadata:
        """Correlate a JSON-RPC success or error response against pending requests."""
        warnings: list[CorrelationWarning] = []
        anomalies: list[str] = []

        if self._process_exited:
            anomalies.append("post_exit_frame")
            warnings.append(
                CorrelationWarning(
                    code="post_exit_frame",
                    message="Observed response frame after server process exit",
                    details={"direction": direction},
                )
            )

        observed_ver: str | None = None
        if not is_error and isinstance(result_or_error, Mapping):
            observed_ver = self._record_protocol_version(result_or_error.get("protocolVersion"))

        key_part = _as_valid_key_part(id_type, request_id)
        origin_dir = opposite_wire_direction(direction)
        trace_ctx: TraceContext | None = None
        tool_is_error: bool | None = None
        otel_attrs: dict[str, str | bool] = {}

        if key_part is None:
            anomalies.append("invalid_response_id")
            if not (is_error and id_type == "null"):
                warnings.append(
                    CorrelationWarning(
                        code="invalid_jsonrpc_response_id",
                        message=f"JSON-RPC response carries invalid id type {id_type!r}",
                        details={"direction": direction, "id_type": id_type, "is_error": is_error},
                    )
                )
            correlation = CorrelationInfo(
                status="invalid_id",
                confidence="none",
                basis=f"invalid_response_id_type:{id_type}",
                origin_direction=origin_dir,
                post_exit_frame=self._process_exited,
            )
            derived = DerivedMetadata(
                otel_attributes=otel_attrs,
                anomaly_flags=tuple(anomalies),
            )
            return CorrelatedFrameMetadata(
                trace=trace_ctx,
                correlation=correlation,
                derived=derived,
                warnings=tuple(warnings),
                observed_protocol_version=observed_ver,
            )

        valid_type, valid_id_val = key_part
        comp_key: CorrelationKey = (origin_dir, valid_type, valid_id_val)
        queue = self._pending.get(comp_key)

        if queue:
            candidate_ids = tuple(item.event_id for item in queue)
            had_ambiguity = len(queue) > 1 or queue[0].saw_duplicate_sibling
            matched = queue.popleft()
            if not queue:
                del self._pending[comp_key]
            self._unregister_progress_token(matched)
            self._completed.setdefault(comp_key, []).append(
                CompletedRequestRef(
                    event_id=matched.event_id,
                    sequence=matched.sequence,
                    method=matched.method,
                )
            )
            trace_ctx = matched.trace_context
            if matched.method is not None:
                otel_attrs[OTEL_ATTR_MCP_METHOD] = matched.method
            otel_attrs[OTEL_ATTR_JSONRPC_REQUEST_ID] = str(valid_id_val)
            effective_ver = observed_ver or self._latest_protocol_version
            if effective_ver is not None:
                otel_attrs[OTEL_ATTR_MCP_PROTOCOL_VERSION] = effective_ver

            if (
                not is_error
                and matched.method == "tools/call"
                and isinstance(result_or_error, Mapping)
            ):
                raw_is_error = result_or_error.get("isError")
                if isinstance(raw_is_error, bool):
                    tool_is_error = raw_is_error

            if matched.cancel_notified:
                anomalies.append("late_after_cancel")

            if had_ambiguity:
                anomalies.append("ambiguous_duplicate_id")
                warnings.append(
                    CorrelationWarning(
                        code="ambiguous_response_correlation",
                        message=(
                            "Matched response heuristically (FIFO) among duplicate in-flight IDs"
                        ),
                        details={
                            "direction": direction,
                            "origin_direction": origin_dir,
                            "id": valid_id_val,
                            "candidate_request_event_ids": list(candidate_ids),
                        },
                    )
                )
                correlation = CorrelationInfo(
                    status="ambiguous_duplicate_id",
                    confidence="heuristic",
                    basis="fifo_among_duplicate_in_flight_ids",
                    matched_request_event_id=matched.event_id,
                    matched_request_sequence=matched.sequence,
                    matched_request_method=matched.method,
                    candidate_request_event_ids=candidate_ids,
                    origin_direction=origin_dir,
                    latency_ns=None,
                    cancel_notified=matched.cancel_notified,
                    late_after_cancel=matched.cancel_notified,
                    post_exit_frame=self._process_exited,
                )
            else:
                delta_ns = max(0, monotonic_time_ns - matched.monotonic_time_ns)
                correlation = CorrelationInfo(
                    status="matched",
                    confidence="exact",
                    basis="exact_opposite_direction_id",
                    matched_request_event_id=matched.event_id,
                    matched_request_sequence=matched.sequence,
                    matched_request_method=matched.method,
                    origin_direction=origin_dir,
                    latency_ns=delta_ns,
                    cancel_notified=matched.cancel_notified,
                    late_after_cancel=matched.cancel_notified,
                    post_exit_frame=self._process_exited,
                )
        else:
            prev_completed = self._completed.get(comp_key)
            if prev_completed:
                anomalies.append("duplicate_response")
                last_ref = prev_completed[-1]
                warnings.append(
                    CorrelationWarning(
                        code="duplicate_response",
                        message="Observed extra response for already-completed request ID",
                        details={
                            "direction": direction,
                            "origin_direction": origin_dir,
                            "id": valid_id_val,
                            "prior_request_event_id": last_ref.event_id,
                        },
                    )
                )
                correlation = CorrelationInfo(
                    status="duplicate_response",
                    confidence="heuristic",
                    basis="response_after_request_already_completed",
                    matched_request_event_id=last_ref.event_id,
                    matched_request_sequence=last_ref.sequence,
                    matched_request_method=last_ref.method,
                    candidate_request_event_ids=tuple(ref.event_id for ref in prev_completed),
                    origin_direction=origin_dir,
                    post_exit_frame=self._process_exited,
                )
            else:
                anomalies.append("orphaned_response")
                warnings.append(
                    CorrelationWarning(
                        code="orphaned_response",
                        message="Observed JSON-RPC response with no matching request",
                        details={
                            "direction": direction,
                            "origin_direction": origin_dir,
                            "id_type": valid_type,
                            "id": valid_id_val,
                        },
                    )
                )
                correlation = CorrelationInfo(
                    status="orphaned_response",
                    confidence="none",
                    basis="no_matching_pending_or_completed_request",
                    origin_direction=origin_dir,
                    post_exit_frame=self._process_exited,
                )

        if trace_ctx is None:
            trace_ctx = TraceContext(
                trace_source="synthetic_execution",
                synthetic_execution_trace_id=self._extract_trace(
                    None, []
                ).synthetic_execution_trace_id,
            )

        derived = DerivedMetadata(
            otel_attributes=otel_attrs,
            tool_is_error=tool_is_error,
            anomaly_flags=tuple(anomalies),
        )
        return CorrelatedFrameMetadata(
            trace=trace_ctx,
            correlation=correlation,
            derived=derived,
            warnings=tuple(warnings),
            observed_protocol_version=observed_ver,
        )

    def process_notification(
        self,
        *,
        event_id: str,
        direction: WireDirection,
        method: str | None,
        params: object,
    ) -> CorrelatedFrameMetadata:
        """Extract trace/OTel tags and correlate cancellation or progress notifications."""
        warnings: list[CorrelationWarning] = []
        anomalies: list[str] = []

        if self._process_exited:
            anomalies.append("post_exit_frame")
            warnings.append(
                CorrelationWarning(
                    code="post_exit_frame",
                    message="Observed notification frame after server process exit",
                    details={"direction": direction, "method": method},
                )
            )

        trace_ctx = self._extract_trace(params, warnings)
        correlation: CorrelationInfo | None = None

        if method == "notifications/cancelled" and isinstance(params, Mapping):
            target_part = _as_valid_scalar_id(params.get("requestId"))
            if target_part is not None:
                comp_key: CorrelationKey = (direction, target_part[0], target_part[1])
                queue = self._pending.get(comp_key)
                if queue:
                    candidate_ids = tuple(item.event_id for item in queue)
                    for item in queue:
                        item.cancel_notified = True
                        item.cancel_event_ids.append(event_id)
                    if len(queue) == 1:
                        target = queue[0]
                        if target.trace_context is not None and trace_ctx.observed_trace_id is None:
                            trace_ctx = target.trace_context
                        correlation = CorrelationInfo(
                            status="cancel_target_matched",
                            confidence="exact",
                            basis="cancelled_same_direction_request_id",
                            matched_request_event_id=target.event_id,
                            matched_request_sequence=target.sequence,
                            matched_request_method=target.method,
                            origin_direction=direction,
                            cancel_notified=True,
                            post_exit_frame=self._process_exited,
                        )
                    else:
                        anomalies.append("ambiguous_cancel_target")
                        correlation = CorrelationInfo(
                            status="cancel_target_matched",
                            confidence="heuristic",
                            basis="cancelled_multiple_in_flight_requests",
                            matched_request_event_id=queue[0].event_id,
                            matched_request_sequence=queue[0].sequence,
                            matched_request_method=queue[0].method,
                            candidate_request_event_ids=candidate_ids,
                            origin_direction=direction,
                            cancel_notified=True,
                            post_exit_frame=self._process_exited,
                        )
                else:
                    anomalies.append("cancel_target_missing")
                    warnings.append(
                        CorrelationWarning(
                            code="cancel_target_missing",
                            message="Cancellation notification targets no currently open request",
                            details={"direction": direction, "request_id": target_part[1]},
                        )
                    )
                    correlation = CorrelationInfo(
                        status="cancel_target_missing",
                        confidence="none",
                        basis="no_open_request_for_cancelled_request_id",
                        origin_direction=direction,
                        cancel_notified=True,
                        post_exit_frame=self._process_exited,
                    )

        elif method == "notifications/progress" and isinstance(params, Mapping):
            parsed_token = _as_valid_scalar_id(params.get("progressToken"))
            if parsed_token is not None:
                origin_dir = opposite_wire_direction(direction)
                tok_key: ProgressTokenKey = (origin_dir, parsed_token[0], parsed_token[1])
                tok_queue = self._progress_tokens.get(tok_key)
                if tok_queue:
                    target = tok_queue[-1]
                    if target.trace_context is not None and trace_ctx.observed_trace_id is None:
                        trace_ctx = target.trace_context
                    confidence: Literal["exact", "heuristic"] = (
                        "exact" if len(tok_queue) == 1 else "heuristic"
                    )
                    correlation = CorrelationInfo(
                        status="progress_target_matched",
                        confidence=confidence,
                        basis="progress_token_opposite_direction_match",
                        matched_request_event_id=target.event_id,
                        matched_request_sequence=target.sequence,
                        matched_request_method=target.method,
                        candidate_request_event_ids=(
                            tuple(item.event_id for item in tok_queue) if len(tok_queue) > 1 else ()
                        ),
                        origin_direction=origin_dir,
                        cancel_notified=target.cancel_notified,
                        post_exit_frame=self._process_exited,
                    )
                else:
                    anomalies.append("progress_target_missing")
                    warnings.append(
                        CorrelationWarning(
                            code="progress_target_missing",
                            message=(
                                "Progress notification references unknown or completed "
                                "progressToken"
                            ),
                            details={
                                "direction": direction,
                                "progress_token": parsed_token[1],
                            },
                        )
                    )
                    correlation = CorrelationInfo(
                        status="progress_target_missing",
                        confidence="none",
                        basis="no_active_request_for_progress_token",
                        origin_direction=origin_dir,
                        post_exit_frame=self._process_exited,
                    )

        otel_attrs = self._build_otel_attributes(
            method=method,
            params=params,
            request_id=None,
            protocol_version=None,
        )
        derived = DerivedMetadata(
            otel_attributes=otel_attrs,
            anomaly_flags=tuple(anomalies),
        )
        return CorrelatedFrameMetadata(
            trace=trace_ctx,
            correlation=correlation,
            derived=derived,
            warnings=tuple(warnings),
        )


__all__ = [
    "CompletedRequestRef",
    "CorrelatedFrameMetadata",
    "CorrelationWarning",
    "PendingRequest",
    "RequestCorrelator",
    "opposite_wire_direction",
]
