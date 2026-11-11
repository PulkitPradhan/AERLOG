"""Deterministic rules for missing responses, wire timeouts, and configured thresholds."""

from __future__ import annotations

import re
from typing import Final

from aerlog.analysis.diagnostics import (
    DiagnosticContext,
    DiagnosticDraft,
    DiagnosticEvidence,
    DiagnosticSeverity,
)
from aerlog.analysis.rules.protocol_errors import is_explicit_wire_timeout_error
from aerlog.events.models import (
    CaptureGapPayload,
    CaptureWarningPayload,
    ExecutionFinishedPayload,
    JsonRpcErrorPayload,
    JsonRpcNotificationPayload,
)

_CANCEL_TIMEOUT_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:timeout|timed?\s*out)\b",
    re.IGNORECASE,
)


def is_timeout_cancel_reason(reason: object) -> bool:
    """Return True if a cancellation reason explicitly reports a timeout."""
    return isinstance(reason, str) and bool(_CANCEL_TIMEOUT_RE.search(reason))


def _trailing_boundary_event(ctx: DiagnosticContext) -> DiagnosticEvidence | None:
    """Return boundary evidence (``execution_finished`` or last event) for open requests."""
    if not ctx.events:
        return None
    for ev in reversed(ctx.events):
        if isinstance(ev.payload, ExecutionFinishedPayload):
            return ctx.evidence_from_event(
                ev,
                role="execution_boundary",
                observed_summary=(
                    f"execution finished (reason={ev.payload.termination_reason}, "
                    f"exit_code={ev.payload.exit_code}, returncode={ev.payload.returncode})"
                ),
            )
    last_ev = ctx.events[-1]
    entry = ctx.entries_by_event_id.get(last_ev.event_id)
    return ctx.evidence_from_event(
        last_ev,
        role="last_recorded_event",
        observed_summary=(
            f"last captured event before recording ended ({entry.summary_label})"
            if entry is not None
            else f"last captured event ({last_ev.kind})"
        ),
    )


def detect_missing_responses(ctx: DiagnosticContext) -> list[DiagnosticDraft]:
    """Detect requests without any paired response or cancellation."""
    drafts: list[DiagnosticDraft] = []
    boundary_ev = _trailing_boundary_event(ctx)
    has_finished = ctx.summary is not None or any(
        isinstance(ev.payload, ExecutionFinishedPayload) for ev in ctx.events
    )

    for span in ctx.timeline.spans:
        if span.span_kind != "request_exchange":
            continue
        if span.outcome not in ("missing_response", "uncompleted_recording"):
            continue
        if span.request_event_id is None:
            continue

        evidence = ctx.evidence_for_span(span, include_related=True)
        if boundary_ev is not None and all(
            item.event_id != boundary_ev.event_id for item in evidence
        ):
            evidence.append(boundary_ev)
        if not evidence:
            continue

        elapsed_ns = max(0, ctx.last_monotonic_ns - span.start_monotonic_ns)
        severity: DiagnosticSeverity = "error" if has_finished else "warning"
        drafts.append(
            ctx.build_draft(
                code="REQUEST_WITHOUT_RESPONSE",
                category="observed_transport_or_lifecycle_failure",
                severity=severity,
                certainty="observed",
                title="JSON-RPC request observed without matching response",
                what_was_observed=(
                    f"Request {span.method or '<unknown>'} ({span.request_id_display or '-'}) at "
                    f"seq #{span.request_sequence} received no matching response before capture "
                    f"ended ({elapsed_ns / 1_000_000:.1f} ms observed remaining in session)."
                ),
                evidence=evidence,
                observed_values={
                    "method": span.method,
                    "request_id": span.request_id_display,
                    "origin_direction": span.origin_direction,
                    "outcome": span.outcome,
                    "elapsed_until_end_ns": elapsed_ns,
                    "execution_completeness": ctx.timeline.capture_completeness,
                },
                reasonable_conclusions=(
                    "No matching response frame crossed the stdio proxy before the recording "
                    "ended or process terminated.",
                ),
                cannot_be_concluded=(
                    "Cannot determine whether the server finished internal side effects before "
                    "termination, stalled inside a handler, or dropped output framing.",
                ),
                additional_evidence_needed=(
                    "Server application logs covering request processing after the request "
                    "sequence and any configured timeout budget (--request-timeout-ms).",
                ),
            )
        )

    return drafts


def detect_observed_timeouts(ctx: DiagnosticContext) -> list[DiagnosticDraft]:
    """Detect explicit wire-observed request timeouts and internal capture/drain timeouts."""
    drafts: list[DiagnosticDraft] = []

    for ev in ctx.events:
        entry = ctx.entries_by_event_id.get(ev.event_id)
        span = ctx.spans_by_id.get(entry.span_id) if entry is not None else None

        if isinstance(ev.payload, JsonRpcErrorPayload) and is_explicit_wire_timeout_error(
            ev.payload
        ):
            err = ev.payload
            evidence: list[DiagnosticEvidence] = []
            if span is not None and span.request_event_id is not None:
                req_ev = ctx.events_by_id.get(span.request_event_id)
                if req_ev is not None:
                    evidence.append(
                        ctx.evidence_from_event(
                            req_ev,
                            role="timed_out_request",
                            observed_summary=f"request {span.method or '-'} seq #{req_ev.sequence}",
                            span_id=span.span_id,
                        )
                    )
            safe_msg = ctx.safe_text(err.error_message, path_label="diagnostic.timeout.error")
            evidence.append(
                ctx.evidence_from_event(
                    ev,
                    role="timeout_error_response",
                    observed_summary=(
                        f"explicit wire timeout error code={err.error_code}"
                        + (f" ({safe_msg})" if safe_msg else "")
                    ),
                    span_id=span.span_id if span is not None else None,
                )
            )
            drafts.append(
                ctx.build_draft(
                    code="OBSERVED_REQUEST_TIMEOUT",
                    category="observed_transport_or_lifecycle_failure",
                    severity="error",
                    certainty="observed",
                    title="Explicit wire timeout error reported by peer",
                    what_was_observed=(
                        f"Observed JSON-RPC timeout error (code={err.error_code}) at "
                        f"seq #{ev.sequence}"
                        + (f" for {span.method}" if span and span.method else "")
                        + (f": {safe_msg}" if safe_msg else ".")
                    ),
                    evidence=evidence,
                    observed_values={
                        "source": "jsonrpc_error",
                        "error_code": err.error_code,
                        "error_message": safe_msg or None,
                        "method": span.method if span else None,
                        "duration_ns": span.duration_ns if span else None,
                    },
                    reasonable_conclusions=(
                        "The peer explicitly reported a timeout condition over JSON-RPC on the "
                        "wire.",
                    ),
                    cannot_be_concluded=(
                        "Cannot prove whether latency stemmed from server deadlock, slow upstream "
                        "network call, host overload, or an aggressively low peer timeout.",
                    ),
                    additional_evidence_needed=(
                        "Server handler timing logs, upstream dependency latencies, and "
                        "client/server timeout configuration.",
                    ),
                )
            )

        elif (
            isinstance(ev.payload, JsonRpcNotificationPayload)
            and ev.payload.method == "notifications/cancelled"
            and isinstance(ev.payload.params, dict)
            and is_timeout_cancel_reason(ev.payload.params.get("reason"))
        ):
            reason_txt = ctx.safe_text(
                str(ev.payload.params.get("reason", "")),
                path_label="diagnostic.timeout.cancel_reason",
            )
            evidence = []
            target_span = span
            if target_span is None and ev.correlation and ev.correlation.matched_request_event_id:
                req_entry = ctx.entries_by_event_id.get(ev.correlation.matched_request_event_id)
                if req_entry is not None:
                    target_span = ctx.spans_by_id.get(req_entry.span_id)
            if target_span is not None and target_span.request_event_id is not None:
                req_ev = ctx.events_by_id.get(target_span.request_event_id)
                if req_ev is not None:
                    evidence.append(
                        ctx.evidence_from_event(
                            req_ev,
                            role="cancelled_request",
                            observed_summary=(
                                f"request {target_span.method or '-'} seq #{req_ev.sequence}"
                            ),
                            span_id=target_span.span_id,
                        )
                    )
            evidence.append(
                ctx.evidence_from_event(
                    ev,
                    role="timeout_cancellation_notification",
                    observed_summary=f"notifications/cancelled reason={reason_txt!r}",
                    span_id=target_span.span_id if target_span else None,
                )
            )
            drafts.append(
                ctx.build_draft(
                    code="OBSERVED_REQUEST_TIMEOUT",
                    category="observed_transport_or_lifecycle_failure",
                    severity="error",
                    certainty="observed",
                    title="Request cancelled explicitly due to observed client timeout",
                    what_was_observed=(
                        f"Observed notifications/cancelled at seq #{ev.sequence} stating a "
                        f"timeout reason ({reason_txt})."
                    ),
                    evidence=evidence,
                    observed_values={
                        "source": "cancellation_reason",
                        "reason": reason_txt,
                        "method": target_span.method if target_span else None,
                    },
                    reasonable_conclusions=(
                        "The cancelling peer explicitly attributed cancellation to a timeout on "
                        "the wire.",
                    ),
                    cannot_be_concluded=(
                        "Cannot determine whether the server stalled or was performing valid long "
                        "work beyond the caller's deadline.",
                    ),
                    additional_evidence_needed=(
                        "Client request timeout budget settings and server execution profiling.",
                    ),
                )
            )

        elif isinstance(ev.payload, CaptureWarningPayload):
            warn = ev.payload
            is_timeout_warn = "timeout" in warn.code.lower() or (
                warn.code == "capture_spill_activated"
                and (
                    "timeout" in str(warn.details.get("reason", "")).lower()
                    or "stalled" in str(warn.details.get("reason", "")).lower()
                )
            )
            if not is_timeout_warn:
                continue
            safe_msg = ctx.safe_text(warn.message, path_label="diagnostic.capture_warning")
            drafts.append(
                ctx.build_draft(
                    code="CAPTURE_TIMEOUT_OBSERVED",
                    category="observed_transport_or_lifecycle_failure",
                    severity="warning",
                    certainty="observed",
                    title="Capture subsystem write/drain timeout observed",
                    what_was_observed=(
                        f"Capture warning [{warn.code}] at seq #{ev.sequence}: {safe_msg}"
                    ),
                    evidence=[
                        ctx.evidence_from_event(
                            ev,
                            role="capture_timeout_warning",
                            observed_summary=f"{warn.code}: {safe_msg}",
                        )
                    ],
                    observed_values={"warning_code": warn.code},
                    reasonable_conclusions=(
                        "AERLOG's capture pipeline hit an internal write/drain timeout threshold "
                        "(distinct from MCP tool execution timing).",
                    ),
                    cannot_be_concluded=(
                        "Does not by itself imply the target MCP server malfunctioned.",
                    ),
                    additional_evidence_needed=(
                        "Disk I/O latency, SQLite lock contention, or recovery spool metrics.",
                    ),
                )
            )

        elif isinstance(ev.payload, CaptureGapPayload) and "timeout" in ev.payload.reason.lower():
            gap = ev.payload
            drafts.append(
                ctx.build_draft(
                    code="CAPTURE_TIMEOUT_OBSERVED",
                    category="observed_transport_or_lifecycle_failure",
                    severity="warning",
                    certainty="observed",
                    title="Capture pipeline drain timeout produced a capture gap",
                    what_was_observed=(
                        f"Capture gap at seq #{ev.sequence} reported reason={gap.reason!r} with "
                        f"dropped_count={gap.dropped_count}."
                    ),
                    evidence=[
                        ctx.evidence_from_event(
                            ev,
                            role="capture_timeout_gap",
                            observed_summary=(
                                f"capture_gap reason={gap.reason} dropped={gap.dropped_count}"
                            ),
                        )
                    ],
                    observed_values={
                        "reason": gap.reason,
                        "dropped_count": gap.dropped_count,
                    },
                    reasonable_conclusions=(
                        "Capture drain exceeded configured timeout during shutdown or overflow.",
                    ),
                    cannot_be_concluded=(
                        "Contents of the dropped capture events cannot be reconstructed from "
                        "this gap.",
                    ),
                    additional_evidence_needed=(
                        "Increased capture.drain_timeout_s or backpressure_policy='spill'/'block'.",
                    ),
                )
            )

    return drafts


def detect_configured_request_timeouts(ctx: DiagnosticContext) -> list[DiagnosticDraft]:
    """Check observed/elapsed durations against explicit caller-configured request timeout."""
    threshold_ns = ctx.options.request_timeout_ns
    threshold_ms = ctx.options.request_timeout_ms
    if threshold_ns is None or threshold_ms is None:
        return []

    drafts: list[DiagnosticDraft] = []
    last_ev = ctx.events[-1] if ctx.events else None

    for span in ctx.timeline.spans:
        if span.span_kind != "request_exchange" or span.request_event_id is None:
            continue

        if span.duration_basis == "exact_monotonic_delta" and span.duration_ns is not None:
            if span.duration_ns <= threshold_ns:
                continue
            evidence = ctx.evidence_for_span(span)
            if not evidence:
                continue
            drafts.append(
                ctx.build_draft(
                    code="CONFIGURED_REQUEST_TIMEOUT_EXCEEDED",
                    category="configured_threshold_observation",
                    severity="warning",
                    certainty="configured_threshold",
                    title="Observed round-trip duration exceeded configured timeout threshold",
                    what_was_observed=(
                        f"Request {span.method or '-'} ({span.request_id_display or '-'}) at "
                        f"seq #{span.request_sequence} completed in "
                        f"{span.duration_ns / 1_000_000:.1f} ms, exceeding configured "
                        f"request_timeout_ms={threshold_ms} ms."
                    ),
                    evidence=evidence,
                    observed_values={
                        "method": span.method,
                        "duration_ns": span.duration_ns,
                        "threshold_ns": threshold_ns,
                        "request_timeout_ms": threshold_ms,
                        "response_observed": True,
                    },
                    reasonable_conclusions=(
                        "Measured monotonic pipe round-trip latency exceeded the caller's "
                        f"configured {threshold_ms} ms threshold.",
                    ),
                    cannot_be_concluded=(
                        "Cannot separate pure server handler compute time from OS pipe scheduling, "
                        "proxy forwarding overhead, or capture backpressure delays.",
                        "Cannot determine whether the configured threshold is realistic for "
                        "this tool.",
                    ),
                    additional_evidence_needed=(
                        "Server-side handler duration histograms or trace spans emitted by the "
                        "MCP server itself.",
                    ),
                )
            )

        elif span.response_event_id is None and span.outcome != "invalid_id":
            elapsed_ns = max(0, ctx.last_monotonic_ns - span.start_monotonic_ns)
            if elapsed_ns < threshold_ns:
                continue
            evidence = ctx.evidence_for_span(span, include_related=True)
            if last_ev is not None and all(e.event_id != last_ev.event_id for e in evidence):
                evidence.append(
                    ctx.evidence_from_event(
                        last_ev,
                        role="session_end_observation",
                        observed_summary=f"session ended at seq #{last_ev.sequence}",
                    )
                )
            if not evidence:
                continue
            drafts.append(
                ctx.build_draft(
                    code="CONFIGURED_REQUEST_TIMEOUT_EXCEEDED",
                    category="configured_threshold_observation",
                    severity="warning",
                    certainty="configured_threshold",
                    title=(
                        "Unanswered request exceeded configured timeout threshold before session "
                        "end"
                    ),
                    what_was_observed=(
                        f"Unanswered request {span.method or '-'} "
                        f"({span.request_id_display or '-'}) at seq #{span.request_sequence} "
                        f"remained open at least {elapsed_ns / 1_000_000:.1f} ms, exceeding "
                        f"configured request_timeout_ms={threshold_ms} ms."
                    ),
                    evidence=evidence,
                    observed_values={
                        "method": span.method,
                        "elapsed_ns": elapsed_ns,
                        "threshold_ns": threshold_ns,
                        "request_timeout_ms": threshold_ms,
                        "response_observed": False,
                    },
                    reasonable_conclusions=(
                        "The request stayed unanswered across at least the configured timeout "
                        "duration before the recording terminated.",
                    ),
                    cannot_be_concluded=(
                        "Cannot prove the server hung permanently vs. being aborted right after "
                        "threshold elapsed.",
                    ),
                    additional_evidence_needed=(
                        "Server-side logs showing request progress prior to process termination.",
                    ),
                )
            )

    return drafts


__all__ = [
    "detect_configured_request_timeouts",
    "detect_missing_responses",
    "detect_observed_timeouts",
    "is_timeout_cancel_reason",
]
