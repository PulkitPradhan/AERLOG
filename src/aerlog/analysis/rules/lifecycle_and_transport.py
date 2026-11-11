"""Deterministic rules for process exits, signals, transport, wire framing, and integrity."""

from __future__ import annotations

from aerlog.analysis.diagnostics import (
    DiagnosticContext,
    DiagnosticDraft,
    DiagnosticEvidence,
    DiagnosticSeverity,
)
from aerlog.events.models import (
    CaptureGapPayload,
    ChildShutdownEscalatePayload,
    ExecutionFinishedPayload,
    ExecutionStartedPayload,
    FrameTooLargePayload,
    IncompleteTrailingFramePayload,
    MalformedJsonFramePayload,
    MalformedUtf8FramePayload,
    NonObjectJsonFramePayload,
    ProcessStderrPayload,
    ProxySignalPayload,
    TransportErrorPayload,
)

_ABNORMAL_TERMINATION_REASONS = frozenset(
    {
        "aborted",
        "diagnostic_write_failed",
        "server_exited",
        "server_stdout_eof",
        "signal",
        "spawn_failed",
    }
)


def detect_process_exit_and_signals(ctx: DiagnosticContext) -> list[DiagnosticDraft]:
    """Detect non-zero or premature server exits, OS signals, shutdown escalation, pipe errors."""
    drafts: list[DiagnosticDraft] = []

    finish_ev = next(
        (ev for ev in reversed(ctx.events) if isinstance(ev.payload, ExecutionFinishedPayload)),
        None,
    )
    signal_evs = [ev for ev in ctx.events if isinstance(ev.payload, ProxySignalPayload)]
    stderr_evs = [ev for ev in ctx.events if isinstance(ev.payload, ProcessStderrPayload)]

    for sig_ev in signal_evs:
        assert isinstance(sig_ev.payload, ProxySignalPayload)
        sig_name = sig_ev.payload.signal_name
        evidence: list[DiagnosticEvidence] = [
            ctx.evidence_from_event(
                sig_ev,
                role="proxy_signal",
                observed_summary=f"signal {sig_name} observed by proxy",
            )
        ]
        if finish_ev is not None:
            evidence.append(
                ctx.evidence_from_event(
                    finish_ev,
                    role="execution_finished",
                    observed_summary=(
                        f"finished returncode={ctx.timeline.returncode} "
                        f"exit_code={ctx.timeline.exit_code}"
                    ),
                )
            )
        graceful_sigint = (
            sig_name == "SIGINT"
            and ctx.timeline.returncode in (None, 0)
            and ctx.timeline.missing_response_count == 0
        )
        sev: DiagnosticSeverity = "info" if graceful_sigint else "warning"
        drafts.append(
            ctx.build_draft(
                code="SIGNAL_INTERRUPTED_EXECUTION",
                category="observed_transport_or_lifecycle_failure",
                severity=sev,
                certainty="observed",
                title=f"Execution interrupted by OS/proxy signal ({sig_name})",
                what_was_observed=(
                    f"Proxy recorded signal {sig_name!r} at seq #{sig_ev.sequence}; session "
                    f"terminated with reason={ctx.timeline.termination_reason or '-'}, "
                    f"returncode={ctx.timeline.returncode}."
                ),
                evidence=evidence,
                observed_values={
                    "signal_name": sig_name,
                    "termination_reason": ctx.timeline.termination_reason,
                    "returncode": ctx.timeline.returncode,
                },
                reasonable_conclusions=(
                    f"The execution terminated or began shutdown upon observing {sig_name}.",
                ),
                cannot_be_concluded=(
                    "Cannot identify the external process or user action that originated an "
                    "OS signal delivered to the proxy.",
                ),
                additional_evidence_needed=(
                    "Supervisor/shell process audit logs or orchestrator timeout triggers.",
                ),
            )
        )

    # Detect unexpected child/proxy exits without false-firing on clean returncode==0 EOF.
    finish_payload = (
        finish_ev.payload
        if finish_ev is not None and isinstance(finish_ev.payload, ExecutionFinishedPayload)
        else None
    )
    term_reason = (
        finish_payload.termination_reason if finish_payload else ctx.timeline.termination_reason
    )
    returncode = finish_payload.returncode if finish_payload else ctx.timeline.returncode
    exit_code = finish_payload.exit_code if finish_payload else ctx.timeline.exit_code

    nonzero_rc = returncode is not None and returncode != 0
    abnormal_exit_state = term_reason in _ABNORMAL_TERMINATION_REASONS and (
        (exit_code is not None and exit_code != 0)
        or ctx.timeline.missing_response_count > 0
        or nonzero_rc
    )

    if nonzero_rc or abnormal_exit_state:
        anchor_ev = finish_ev or (ctx.events[-1] if ctx.events else None)
        if anchor_ev is not None:
            evidence = [
                ctx.evidence_from_event(
                    anchor_ev,
                    role="termination_event",
                    observed_summary=(
                        f"termination reason={term_reason or '-'} "
                        f"exit_code={exit_code} returncode={returncode}"
                    ),
                )
            ]
            # Attach trailing stderr presence metadata only (never raw unredacted text).
            for err_ev in stderr_evs[-3:]:
                assert isinstance(err_ev.payload, ProcessStderrPayload)
                evidence.append(
                    ctx.evidence_from_event(
                        err_ev,
                        role="contextual_stderr",
                        observed_summary=(
                            f"child stderr chunk ({err_ev.payload.byte_length} bytes) prior to exit"
                        ),
                    )
                )
            for missing_span in ctx.timeline.missing_response_spans[:5]:
                if missing_span.request_event_id:
                    req_ev = ctx.events_by_id.get(missing_span.request_event_id)
                    if req_ev is not None:
                        evidence.append(
                            ctx.evidence_from_event(
                                req_ev,
                                role="unanswered_request_at_exit",
                                observed_summary=(
                                    f"unanswered {missing_span.method or '-'} "
                                    f"at seq #{req_ev.sequence}"
                                ),
                                span_id=missing_span.span_id,
                            )
                        )
            drafts.append(
                ctx.build_draft(
                    code="UNEXPECTED_PROCESS_EXIT",
                    category="observed_transport_or_lifecycle_failure",
                    severity="error",
                    certainty="observed",
                    title="Target MCP server or proxy exited abnormally",
                    what_was_observed=(
                        f"Execution terminated at seq #{anchor_ev.sequence} with "
                        f"reason={term_reason!r}, returncode={returncode}, exit_code={exit_code}, "
                        f"unanswered_requests={ctx.timeline.missing_response_count}."
                    ),
                    evidence=evidence,
                    observed_values={
                        "termination_reason": term_reason,
                        "returncode": returncode,
                        "exit_code": exit_code,
                        "missing_response_count": ctx.timeline.missing_response_count,
                        "stderr_event_count": len(stderr_evs),
                    },
                    reasonable_conclusions=(
                        "The server child process or proxy exited with non-zero status or closed "
                        "prematurely while requests remained unanswered.",
                    ),
                    cannot_be_concluded=(
                        "Cannot determine internal process crash cause (e.g., unhandled exception, "
                        "OOM kill, missing dependency, or failed startup check) from exit status "
                        "alone.",
                    ),
                    additional_evidence_needed=(
                        "Redacted stderr events referenced above (`aerlog inspect --sequence <N>`)"
                        ", OS crash/coredump logs, or server application logs.",
                    ),
                )
            )

        # Handle POSIX negative returncode if no ProxySignalPayload was recorded separately.
        if not signal_evs and returncode is not None and returncode < 0 and anchor_ev is not None:
            sig_num = -returncode
            drafts.append(
                ctx.build_draft(
                    code="SIGNAL_INTERRUPTED_EXECUTION",
                    category="observed_transport_or_lifecycle_failure",
                    severity="warning",
                    certainty="observed",
                    title=f"Target server terminated by OS signal {sig_num}",
                    what_was_observed=(
                        f"Recorded returncode={returncode} at seq #{anchor_ev.sequence}, "
                        f"indicating target process terminated on OS signal {sig_num}."
                    ),
                    evidence=[
                        ctx.evidence_from_event(
                            anchor_ev,
                            role="signal_returncode",
                            observed_summary=f"child returncode={returncode} (signal {sig_num})",
                        )
                    ],
                    observed_values={"signal_number": sig_num, "returncode": returncode},
                    reasonable_conclusions=(
                        f"The child MCP server exited due to POSIX signal {sig_num}.",
                    ),
                    cannot_be_concluded=(
                        "Cannot establish which process sent the signal (user, OS OOM killer, "
                        "or parent supervisor).",
                    ),
                    additional_evidence_needed=(
                        "Kernel/dmesg OOM logs and supervisor process management logs.",
                    ),
                )
            )

    for ev in ctx.events:
        if isinstance(ev.payload, ChildShutdownEscalatePayload):
            esc = ev.payload
            safe_err = ctx.safe_text(esc.error, path_label="diagnostic.shutdown.error")
            drafts.append(
                ctx.build_draft(
                    code="CHILD_SHUTDOWN_ESCALATED",
                    category="observed_transport_or_lifecycle_failure",
                    severity="warning",
                    certainty="observed",
                    title=(
                        f"Shutdown escalated to {esc.signal_name} for target server process group"
                    ),
                    what_was_observed=(
                        f"Proxy escalated shutdown at seq #{ev.sequence} using {esc.signal_name} "
                        f"against pgid={esc.pgid}" + (f" ({safe_err})" if safe_err else "") + "."
                    ),
                    evidence=[
                        ctx.evidence_from_event(
                            ev,
                            role="shutdown_escalation",
                            observed_summary=(
                                f"child_shutdown_escalate {esc.signal_name} pgid={esc.pgid}"
                            ),
                        )
                    ],
                    observed_values={"signal_name": esc.signal_name, "pgid": esc.pgid},
                    reasonable_conclusions=(
                        "The child process group did not exit within the graceful shutdown window "
                        "and required forced signal escalation.",
                    ),
                    cannot_be_concluded=(
                        "Cannot determine whether the server ignored signals intentionally, "
                        "deadlocked during cleanup, or blocked on child subprocesses.",
                    ),
                    additional_evidence_needed=(
                        "Server shutdown handler logs and process tree state at exit time.",
                    ),
                )
            )

        elif isinstance(ev.payload, TransportErrorPayload):
            tr = ev.payload
            safe_err = ctx.safe_text(tr.error, path_label="diagnostic.transport.error")
            drafts.append(
                ctx.build_draft(
                    code="TRANSPORT_FAILURE_OBSERVED",
                    category="observed_transport_or_lifecycle_failure",
                    severity="error",
                    certainty="observed",
                    title=f"Stdio transport failure observed ({tr.reason})",
                    what_was_observed=(
                        f"Observed transport_error at seq #{ev.sequence} "
                        f"(stream={tr.stream_direction or '-'}, reason={tr.reason!r}"
                        + (f": {safe_err}" if safe_err else "")
                        + ")."
                    ),
                    evidence=[
                        ctx.evidence_from_event(
                            ev,
                            role="transport_error",
                            observed_summary=f"transport_error {tr.reason}: {safe_err}",
                        )
                    ],
                    observed_values={
                        "reason": tr.reason,
                        "stream_direction": tr.stream_direction,
                    },
                    reasonable_conclusions=(
                        "Reading from or writing to a stdio pipe failed during proxy forwarding.",
                    ),
                    cannot_be_concluded=(
                        "Cannot prove without lifecycle context whether the peer exited cleanly "
                        "mid-flush vs. crashed on pipe teardown.",
                    ),
                    additional_evidence_needed=(
                        "Adjacent process exit/signal events and peer logs.",
                    ),
                )
            )

    return drafts


def detect_wire_anomalies(ctx: DiagnosticContext) -> list[DiagnosticDraft]:
    """Detect malformed frames, fail-closed oversized frames, and incomplete EOF bytes."""
    drafts: list[DiagnosticDraft] = []

    for ev in ctx.events:
        if (
            isinstance(
                ev.payload,
                MalformedUtf8FramePayload | MalformedJsonFramePayload | NonObjectJsonFramePayload,
            )
            or ev.kind == "jsonrpc_unknown_object"
        ):
            byte_len = ev.wire.byte_length if ev.wire else None
            drafts.append(
                ctx.build_draft(
                    code="MALFORMED_WIRE_FRAME",
                    category="observed_transport_or_lifecycle_failure",
                    severity="error",
                    certainty="observed",
                    title=f"Invalid or non-JSON-RPC wire frame ({ev.kind})",
                    what_was_observed=(
                        f"Observed {ev.kind} on {ev.direction} stream at seq #{ev.sequence}"
                        + (f" ({byte_len} bytes)" if byte_len is not None else "")
                        + "."
                    ),
                    evidence=[
                        ctx.evidence_from_event(
                            ev,
                            role="malformed_frame",
                            observed_summary=(
                                f"{ev.kind} on {ev.direction} ({byte_len or '?'} bytes)"
                            ),
                        )
                    ],
                    observed_values={
                        "frame_kind": ev.kind,
                        "direction": ev.direction,
                        "byte_length": byte_len,
                    },
                    reasonable_conclusions=(
                        "A newline-delimited frame on stdout/stdin did not represent a valid "
                        "JSON-RPC 2.0 object.",
                    ),
                    cannot_be_concluded=(
                        "Cannot establish whether server printed plain text/banner logs onto "
                        "protocol stdout vs. experienced partial write corruption.",
                    ),
                    additional_evidence_needed=(
                        f"Inspect the redacted frame metadata at seq #{ev.sequence} and verify the "
                        "emitting process routes non-protocol logs to stderr.",
                    ),
                )
            )

        elif isinstance(ev.payload, FrameTooLargePayload):
            ftl = ev.payload
            drafts.append(
                ctx.build_draft(
                    code="OVERSIZED_WIRE_FRAME",
                    category="observed_transport_or_lifecycle_failure",
                    severity="error",
                    certainty="observed",
                    title="Wire frame exceeded proxy max_frame_bytes fail-closed limit",
                    what_was_observed=(
                        f"Observed oversized frame on {ev.direction} at seq #{ev.sequence}: "
                        f"{ftl.observed_bytes} bytes exceeded limit {ftl.max_frame_bytes} bytes."
                    ),
                    evidence=[
                        ctx.evidence_from_event(
                            ev,
                            role="oversized_frame",
                            observed_summary=(
                                f"frame_too_large {ftl.observed_bytes} > "
                                f"{ftl.max_frame_bytes} bytes"
                            ),
                        )
                    ],
                    observed_values={
                        "observed_bytes": ftl.observed_bytes,
                        "max_frame_bytes": ftl.max_frame_bytes,
                        "direction": ev.direction,
                    },
                    reasonable_conclusions=(
                        "The proxy aborted framing fail-closed because an incoming frame exceeded "
                        "configured memory bounds.",
                    ),
                    cannot_be_concluded=(
                        "Cannot inspect content of the rejected oversized frame beyond its size "
                        "or whether payload bloat came from legitimate binary output vs. unbounded "
                        "serialization loop.",
                    ),
                    additional_evidence_needed=(
                        "Server serialization logs or pagination limits on the offending method.",
                    ),
                )
            )

        elif isinstance(ev.payload, IncompleteTrailingFramePayload):
            inc = ev.payload
            drafts.append(
                ctx.build_draft(
                    code="INCOMPLETE_TRAILING_FRAME",
                    category="observed_transport_or_lifecycle_failure",
                    severity="warning",
                    certainty="observed",
                    title="Stream reached EOF with incomplete trailing bytes lacking newline",
                    what_was_observed=(
                        f"Stream {ev.direction} hit EOF at seq #{ev.sequence} with "
                        f"{inc.byte_length} trailing byte(s) and no terminating newline."
                    ),
                    evidence=[
                        ctx.evidence_from_event(
                            ev,
                            role="incomplete_trailing_frame",
                            observed_summary=(
                                f"incomplete trailing frame ({inc.byte_length} bytes)"
                            ),
                        )
                    ],
                    observed_values={"byte_length": inc.byte_length, "direction": ev.direction},
                    reasonable_conclusions=(
                        "The sender closed stdout/stdin or crashed mid-frame before writing a "
                        "newline delimiter.",
                    ),
                    cannot_be_concluded=(
                        "Cannot determine whether the trailing bytes represent an interrupted "
                        "crash write or non-terminated diagnostic stdout text.",
                    ),
                    additional_evidence_needed=(
                        "Process exit status and trailing byte excerpt via raw event inspection.",
                    ),
                )
            )

    return drafts


def detect_cooperative_cancellations(ctx: DiagnosticContext) -> list[DiagnosticDraft]:
    """Record info-level diagnostics for requests cancelled cleanly with no response."""
    drafts: list[DiagnosticDraft] = []

    for span in ctx.timeline.spans:
        if span.span_kind != "request_exchange" or span.outcome != "cancelled_no_response":
            continue
        evidence = ctx.evidence_for_span(span, include_related=True)
        if not evidence:
            continue
        drafts.append(
            ctx.build_draft(
                code="CANCEL_REQUESTED_NO_RESPONSE",
                category="inferred_behavioral_pattern",
                severity="info",
                certainty="inferred_pattern",
                title="Cancelled request terminated without a server response",
                what_was_observed=(
                    f"Request {span.method or '-'} ({span.request_id_display or '-'}) at "
                    f"seq #{span.request_sequence} received notifications/cancelled and emitted "
                    "no subsequent response."
                ),
                evidence=evidence,
                observed_values={
                    "method": span.method,
                    "request_id": span.request_id_display,
                    "outcome": span.outcome,
                },
                reasonable_conclusions=(
                    "Observing no reply after cancellation is consistent with normal cooperative "
                    "MCP cancellation.",
                ),
                cannot_be_concluded=(
                    "Cannot prove whether the server cleanly aborted work upon cancellation or "
                    "ignored the cancellation notification while stopping silently.",
                ),
                additional_evidence_needed=(
                    "Cancellation reason field and server-side cancellation handler logs.",
                ),
            )
        )

    return drafts


def detect_capture_integrity(ctx: DiagnosticContext) -> list[DiagnosticDraft]:
    """Detect corrupt JSONL records, capture gaps, and incomplete/spilled recordings."""
    drafts: list[DiagnosticDraft] = []

    if ctx.timeline.corruption_markers:
        corr_evidence = [
            ctx.evidence_from_corruption(marker) for marker in ctx.timeline.corruption_markers
        ]
        lines = [m.line_number for m in ctx.timeline.corruption_markers]
        drafts.append(
            ctx.build_draft(
                code="CORRUPT_RECORDING_DETECTED",
                category="observed_transport_or_lifecycle_failure",
                severity="error",
                certainty="observed",
                title="Authoritative events.jsonl log contains corrupt, partial, or gapped lines",
                what_was_observed=(
                    f"Detected {len(ctx.timeline.corruption_markers)} JSONL integrity issue(s) at "
                    f"line(s) {lines}."
                ),
                evidence=corr_evidence,
                observed_values={
                    "corrupt_record_count": len(ctx.timeline.corruption_markers),
                    "line_numbers": lines,
                },
                reasonable_conclusions=(
                    "Authoritative recording integrity verification detected truncated, modified, "
                    "or sequence-gapped JSONL lines; later events may be missing.",
                ),
                cannot_be_concluded=(
                    "Cannot reconstruct what protocol traffic was lost inside corrupted or "
                    "unflushed byte offsets.",
                ),
                additional_evidence_needed=(
                    "Any leftover 0o600 recovery spool files or host disk/crash logs (`--strict` "
                    "for strict failure mode).",
                ),
            )
        )

    for ev in ctx.events:
        if isinstance(ev.payload, CaptureGapPayload):
            gap = ev.payload
            drafts.append(
                ctx.build_draft(
                    code="CAPTURE_GAP_DETECTED",
                    category="observed_transport_or_lifecycle_failure",
                    severity="error",
                    certainty="observed",
                    title="Non-silent capture gap recorded in event stream",
                    what_was_observed=(
                        f"CaptureGapPayload at seq #{ev.sequence} recorded {gap.dropped_count} "
                        f"unrecorded event(s) (reason={gap.reason!r})."
                    ),
                    evidence=[
                        ctx.evidence_from_event(
                            ev,
                            role="capture_gap",
                            observed_summary=(
                                f"capture_gap dropped={gap.dropped_count} reason={gap.reason}"
                            ),
                        )
                    ],
                    observed_values={
                        "dropped_count": gap.dropped_count,
                        "reason": gap.reason,
                        "first_gap_monotonic_ns": gap.first_gap_monotonic_ns,
                        "last_gap_monotonic_ns": gap.last_gap_monotonic_ns,
                    },
                    reasonable_conclusions=(
                        "Because of overflow under 'mark_incomplete' or sink failure, some wire or "
                        "lifecycle events in that interval were not persisted.",
                    ),
                    cannot_be_concluded=(
                        "Cannot know which MCP methods, errors, or IDs occurred during the dropped "
                        "interval; correlation of surrounding requests may be incomplete.",
                    ),
                    additional_evidence_needed=(
                        "Use backpressure_policy='block' or 'spill' to avoid capture gaps.",
                    ),
                )
            )

    summary_completeness = (
        ctx.summary.capture_completeness
        if ctx.summary is not None
        else ctx.timeline.capture_completeness
    )
    has_start = any(isinstance(ev.payload, ExecutionStartedPayload) for ev in ctx.events)
    has_finish = any(isinstance(ev.payload, ExecutionFinishedPayload) for ev in ctx.events)
    incomplete_reasons: list[str] = []
    if ctx.timeline.unclean_shutdown:
        incomplete_reasons.append("unclean_shutdown")
    if ctx.timeline.diverged_index:
        incomplete_reasons.append("diverged_sqlite_index")
    if summary_completeness in {"incomplete", "spilled", "degraded"}:
        incomplete_reasons.append(f"completeness={summary_completeness}")
    if has_start and not has_finish:
        incomplete_reasons.append("missing_execution_finished_event")

    if incomplete_reasons and ctx.events:
        finish_or_last = next(
            (ev for ev in reversed(ctx.events) if isinstance(ev.payload, ExecutionFinishedPayload)),
            ctx.events[-1],
        )
        start_ev = next(
            (ev for ev in ctx.events if isinstance(ev.payload, ExecutionStartedPayload)),
            ctx.events[0],
        )
        evidence = [
            ctx.evidence_from_event(
                start_ev,
                role="execution_start",
                observed_summary=f"execution start seq #{start_ev.sequence}",
            )
        ]
        if finish_or_last.event_id != start_ev.event_id:
            evidence.append(
                ctx.evidence_from_event(
                    finish_or_last,
                    role="last_or_finish_event",
                    observed_summary=(
                        f"latest event seq #{finish_or_last.sequence} ({finish_or_last.kind})"
                    ),
                )
            )
        drafts.append(
            ctx.build_draft(
                code="INCOMPLETE_CAPTURE_RECORDING",
                category="observed_transport_or_lifecycle_failure",
                severity="warning",
                certainty="observed",
                title="Recording is marked incomplete, spilled, degraded, or diverged",
                what_was_observed=(
                    "Recording flags incomplete/non-ideal capture state "
                    f"({', '.join(incomplete_reasons)})."
                ),
                evidence=evidence,
                observed_values={
                    "reasons": incomplete_reasons,
                    "capture_completeness": ctx.timeline.capture_completeness,
                    "unclean_shutdown": ctx.timeline.unclean_shutdown,
                    "diverged_index": ctx.timeline.diverged_index,
                },
                reasonable_conclusions=(
                    "Either capture did not finalize cleanly, SQLite index diverged from "
                    "events.jsonl, or events spilled/degraded during recording.",
                ),
                cannot_be_concluded=(
                    "Cannot prove all runtime traffic reached the disk log if shutdown was "
                    "interrupted before final flush.",
                ),
                additional_evidence_needed=(
                    "Recovery spool import status and repository index reconciliation state.",
                ),
            )
        )

    return drafts


__all__ = [
    "detect_capture_integrity",
    "detect_cooperative_cancellations",
    "detect_process_exit_and_signals",
    "detect_wire_anomalies",
]
