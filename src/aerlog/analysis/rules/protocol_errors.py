"""Deterministic rules for JSON-RPC errors, MCP tool errors, and correlation anomalies."""

from __future__ import annotations

import re
from typing import Final

from aerlog.analysis.diagnostics import (
    DiagnosticContext,
    DiagnosticDraft,
    DiagnosticEvidence,
)
from aerlog.events.models import (
    JsonRpcErrorPayload,
    JsonRpcNotificationPayload,
    JsonRpcRequestPayload,
    JsonRpcResponsePayload,
)

_TIMEOUT_ERROR_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:request\s+timed?\s*out|timed?\s*out|timeout)\b",
    re.IGNORECASE,
)


def is_explicit_wire_timeout_error(payload: JsonRpcErrorPayload) -> bool:
    """Return True if a JSON-RPC error response explicitly signals a timeout."""
    if payload.error_code == -32001:
        return True
    return bool(payload.error_message and _TIMEOUT_ERROR_RE.search(payload.error_message))


def _tool_name_for_request(req: JsonRpcRequestPayload | None) -> str | None:
    if req is None or req.method != "tools/call" or not isinstance(req.params, dict):
        return None
    name = req.params.get("name")
    return name if isinstance(name, str) and name else None


def detect_protocol_and_tool_errors(ctx: DiagnosticContext) -> list[DiagnosticDraft]:
    """Detect explicit JSON-RPC errors, -32602 invalid params, and MCP tool isError."""
    drafts: list[DiagnosticDraft] = []

    for ev in ctx.events:
        entry = ctx.entries_by_event_id.get(ev.event_id)
        span = ctx.spans_by_id.get(entry.span_id) if entry is not None else None
        req_ev = (
            ctx.events_by_id.get(span.request_event_id)
            if span is not None and span.request_event_id is not None
            else None
        )
        req_payload = req_ev.payload if isinstance(req_ev, object) and req_ev is not None else None
        req_rpc = req_payload if isinstance(req_payload, JsonRpcRequestPayload) else None
        method = span.method if span is not None else (req_rpc.method if req_rpc else None)
        tool_name = _tool_name_for_request(req_rpc)

        if isinstance(ev.payload, JsonRpcErrorPayload):
            err = ev.payload
            # Explicit timeout errors (-32001 / timeout message) belong to OBSERVED_REQUEST_TIMEOUT.
            if is_explicit_wire_timeout_error(err):
                continue

            evidence: list[DiagnosticEvidence] = []
            if req_ev is not None and span is not None:
                req_entry = ctx.entries_by_event_id.get(req_ev.event_id)
                evidence.append(
                    ctx.evidence_from_event(
                        req_ev,
                        role="request",
                        observed_summary=(
                            req_entry.summary_label if req_entry else f"request {method or '-'}"
                        ),
                        span_id=span.span_id,
                    )
                )
            safe_msg = ctx.safe_text(err.error_message, path_label="diagnostic.jsonrpc.error")
            evidence.append(
                ctx.evidence_from_event(
                    ev,
                    role="error_response",
                    observed_summary=(
                        f"JSON-RPC error code={err.error_code}"
                        + (f" message={safe_msg!r}" if safe_msg else "")
                    ),
                    span_id=span.span_id if span is not None else None,
                )
            )

            observed_vals = {
                "error_code": err.error_code,
                "error_message": safe_msg or None,
                "method": method,
                "tool_name": tool_name,
                "direction": ev.direction,
            }

            if err.error_code == -32602:
                target_desc = f" for {method}" if method else ""
                if tool_name:
                    target_desc += f" (tool={tool_name})"
                drafts.append(
                    ctx.build_draft(
                        code="INVALID_ARGUMENTS_OBSERVED",
                        category="observed_protocol_error",
                        severity="error",
                        certainty="observed",
                        title="Server rejected request arguments (-32602 Invalid params)",
                        what_was_observed=(
                            f"Observed JSON-RPC error code -32602 at seq #{ev.sequence}"
                            f"{target_desc}" + (f": {safe_msg}" if safe_msg else ".")
                        ),
                        evidence=evidence,
                        observed_values=observed_vals,
                        reasonable_conclusions=(
                            "The responder explicitly rejected the request parameters with "
                            "JSON-RPC error -32602 (Invalid params) on the wire.",
                        ),
                        cannot_be_concluded=(
                            "Cannot determine from the -32602 response alone whether the client "
                            "supplied invalid fields or the server enforces stricter validation "
                            "than its published schema.",
                            "Cannot establish whether client LLM reasoning vs. wrapper code caused "
                            "the parameter mismatch.",
                        ),
                        additional_evidence_needed=(
                            "Published tool inputSchema from tools/list and server-side validation "
                            "logs detailing which field failed.",
                        ),
                    )
                )
            else:
                target_desc = f" for {method}" if method else ""
                if tool_name:
                    target_desc += f" (tool={tool_name})"
                conclusions = [
                    f"The peer emitted an explicit JSON-RPC error response (code="
                    f"{err.error_code}) rather than a success result.",
                ]
                cannot_conclude = [
                    "Cannot verify internal server exception details, upstream API states, "
                    "or whether transient retry would succeed without server logs.",
                ]
                if method == "server/discover" and err.error_code == -32601:
                    conclusions.append(
                        "When an MCP client probes 'server/discover' in auto mode against a legacy "
                        "server, a -32601 (Method not found) response can indicate expected "
                        "handshake fallback to 'initialize'."
                    )
                    cannot_conclude.append(
                        "Cannot distinguish intentional MCP auto-mode fallback from an unexpected "
                        "server capability defect without checking whether a subsequent "
                        "'initialize' exchange succeeded."
                    )
                drafts.append(
                    ctx.build_draft(
                        code="JSONRPC_ERROR_RESPONSE",
                        category="observed_protocol_error",
                        severity="error",
                        certainty="observed",
                        title=f"JSON-RPC error response observed (code={err.error_code})",
                        what_was_observed=(
                            f"Observed JSON-RPC error response code={err.error_code} at "
                            f"seq #{ev.sequence}{target_desc}"
                            + (f" ({safe_msg})" if safe_msg else "")
                            + "."
                        ),
                        evidence=evidence,
                        observed_values=observed_vals,
                        reasonable_conclusions=conclusions,
                        cannot_be_concluded=cannot_conclude,
                        additional_evidence_needed=(
                            "Server stderr/application logs and upstream dependency diagnostics "
                            "corresponding to the same timestamp window.",
                        ),
                    )
                )

        elif isinstance(ev.payload, JsonRpcResponsePayload):
            is_tool_err = (ev.derived is not None and ev.derived.tool_is_error is True) or (
                isinstance(ev.payload.result, dict) and ev.payload.result.get("isError") is True
            )
            if not is_tool_err:
                continue

            evidence = []
            if req_ev is not None and span is not None:
                req_entry = ctx.entries_by_event_id.get(req_ev.event_id)
                evidence.append(
                    ctx.evidence_from_event(
                        req_ev,
                        role="request",
                        observed_summary=(
                            req_entry.summary_label if req_entry else "tools/call request"
                        ),
                        span_id=span.span_id,
                    )
                )
            evidence.append(
                ctx.evidence_from_event(
                    ev,
                    role="tool_error_response",
                    observed_summary=(
                        f"MCP response at seq #{ev.sequence} set result.isError=true"
                        + (f" (tool={tool_name})" if tool_name else "")
                    ),
                    span_id=span.span_id if span is not None else None,
                )
            )
            drafts.append(
                ctx.build_draft(
                    code="MCP_TOOL_EXECUTION_ERROR",
                    category="observed_protocol_error",
                    severity="error",
                    certainty="observed",
                    title="MCP tool execution returned isError=true",
                    what_was_observed=(
                        f"Observed MCP response with isError=true at seq #{ev.sequence}"
                        + (f" for tool '{tool_name}'" if tool_name else "")
                        + "."
                    ),
                    evidence=evidence,
                    observed_values={
                        "method": method or "tools/call",
                        "tool_name": tool_name,
                        "direction": ev.direction,
                        "duration_ns": span.duration_ns if span is not None else None,
                    },
                    reasonable_conclusions=(
                        "The MCP server reported an application-level tool failure via "
                        "result.isError=true.",
                    ),
                    cannot_be_concluded=(
                        "Cannot prove whether failure resulted from invalid tool inputs, missing "
                        "server permissions, external service outage, or internal tool bugs.",
                    ),
                    additional_evidence_needed=(
                        "Server/tool execution logs and redacted response error text stored in "
                        "the raw response event.",
                    ),
                )
            )

    return drafts


def _is_protocol_null_error(ev_payload: object, corr_status: str | None) -> bool:
    if corr_status != "invalid_id" or not isinstance(ev_payload, JsonRpcErrorPayload):
        return False
    return ev_payload.id_type == "null" and ev_payload.error_code in (-32700, -32600)


def detect_correlation_anomalies(ctx: DiagnosticContext) -> list[DiagnosticDraft]:
    """Detect orphaned responses, duplicate responses, duplicate IDs, invalid IDs, bad cancels."""
    drafts: list[DiagnosticDraft] = []

    for ev in ctx.events:
        corr = ev.correlation
        entry = ctx.entries_by_event_id.get(ev.event_id)
        span_id = entry.span_id if entry is not None else None
        status = corr.status if corr is not None else (entry.correlation_status if entry else None)
        if status is None:
            continue

        if status == "orphaned_response":
            evidence = [
                ctx.evidence_from_event(
                    ev,
                    role="orphaned_response",
                    observed_summary=(
                        entry.summary_label if entry else f"orphaned response seq #{ev.sequence}"
                    ),
                    span_id=span_id,
                )
            ]
            drafts.append(
                ctx.build_draft(
                    code="ORPHANED_RESPONSE",
                    category="observed_protocol_error",
                    severity="warning",
                    certainty="observed",
                    title="Response observed without matching prior request",
                    what_was_observed=(
                        f"Observed {ev.kind} at seq #{ev.sequence} ({ev.direction}) whose JSON-RPC "
                        "ID matches no prior open request in the captured recording."
                    ),
                    evidence=evidence,
                    observed_values={
                        "direction": ev.direction,
                        "request_id": entry.request_id_display if entry else None,
                    },
                    reasonable_conclusions=(
                        "The response frame cannot be paired to any captured request in this "
                        "recording.",
                    ),
                    cannot_be_concluded=(
                        "Cannot distinguish a server protocol bug (unsolicited/mis-typed ID) from "
                        "capture starting mid-session or earlier capture gaps.",
                    ),
                    additional_evidence_needed=(
                        "Earlier capture frames, server request dispatch logs, and client ID "
                        "generation state.",
                    ),
                )
            )

        elif status == "duplicate_response":
            evidence = []
            if corr is not None and corr.matched_request_event_id:
                req_ev = ctx.events_by_id.get(corr.matched_request_event_id)
                if req_ev is not None:
                    evidence.append(
                        ctx.evidence_from_event(
                            req_ev,
                            role="original_request",
                            observed_summary=f"original request seq #{req_ev.sequence}",
                            span_id=span_id,
                        )
                    )
            span = ctx.spans_by_id.get(span_id) if span_id is not None else None
            if (
                span is not None
                and span.response_event_id is not None
                and span.response_event_id != ev.event_id
            ):
                first_resp = ctx.events_by_id.get(span.response_event_id)
                if first_resp is not None:
                    evidence.append(
                        ctx.evidence_from_event(
                            first_resp,
                            role="prior_response",
                            observed_summary=f"earlier response seq #{first_resp.sequence}",
                            span_id=span_id,
                        )
                    )
            evidence.append(
                ctx.evidence_from_event(
                    ev,
                    role="duplicate_response",
                    observed_summary=(
                        entry.summary_label if entry else f"duplicate response seq #{ev.sequence}"
                    ),
                    span_id=span_id,
                )
            )
            drafts.append(
                ctx.build_draft(
                    code="DUPLICATE_RESPONSE",
                    category="observed_protocol_error",
                    severity="warning",
                    certainty="observed",
                    title="Multiple JSON-RPC responses observed for already-answered request",
                    what_was_observed=(
                        f"Observed extra response at seq #{ev.sequence} for request ID "
                        f"{entry.request_id_display if entry else '-'} after an earlier response."
                    ),
                    evidence=evidence,
                    observed_values={
                        "direction": ev.direction,
                        "request_id": entry.request_id_display if entry else None,
                    },
                    reasonable_conclusions=(
                        "More than one response frame used the same request ID after the first "
                        "response already arrived.",
                    ),
                    cannot_be_concluded=(
                        "Cannot determine whether the server emitted duplicate responses or a "
                        "client reused a request ID across poorly framed boundaries.",
                    ),
                    additional_evidence_needed=(
                        "Server handler dispatch logs and client request ID allocator logs.",
                    ),
                )
            )

        elif status == "ambiguous_duplicate_id" and isinstance(
            ev.payload, JsonRpcRequestPayload | JsonRpcResponsePayload | JsonRpcErrorPayload
        ):
            evidence = []
            if corr is not None:
                for cand_id in corr.candidate_request_event_ids:
                    cand_ev = ctx.events_by_id.get(cand_id)
                    if cand_ev is not None and cand_ev.event_id != ev.event_id:
                        evidence.append(
                            ctx.evidence_from_event(
                                cand_ev,
                                role="candidate_request",
                                observed_summary=(
                                    f"overlapping in-flight request seq #{cand_ev.sequence}"
                                ),
                                span_id=span_id,
                            )
                        )
            req_id_lbl = entry.request_id_display if entry else "-"
            evidence.append(
                ctx.evidence_from_event(
                    ev,
                    role="ambiguous_frame",
                    observed_summary=(
                        entry.summary_label if entry else f"ambiguous ID frame seq #{ev.sequence}"
                    ),
                    span_id=span_id,
                )
            )
            drafts.append(
                ctx.build_draft(
                    code="AMBIGUOUS_CORRELATION_ID",
                    category="observed_protocol_error",
                    severity="warning",
                    certainty="observed",
                    title="Duplicate in-flight JSON-RPC ID makes pairing ambiguous",
                    what_was_observed=(
                        f"Observed duplicate in-flight JSON-RPC ID {req_id_lbl} "
                        f"at seq #{ev.sequence}; exact 1:1 request/response pairing cannot be "
                        "proved."
                    ),
                    evidence=evidence,
                    observed_values={
                        "direction": ev.direction,
                        "request_id": entry.request_id_display if entry else None,
                    },
                    reasonable_conclusions=(
                        "Multiple concurrent requests in the same stream direction shared the same "
                        "typed JSON-RPC ID before earlier requests completed; latency for affected "
                        "exchanges is omitted intentionally.",
                    ),
                    cannot_be_concluded=(
                        "Cannot verify which concurrent handler instance produced a given response "
                        "if the server processed requests out of order.",
                    ),
                    additional_evidence_needed=(
                        "Unique wire request IDs or explicit server trace/span logs associating "
                        "request handlers with response frames.",
                    ),
                )
            )

        elif status == "invalid_id" and not _is_protocol_null_error(ev.payload, status):
            evidence = [
                ctx.evidence_from_event(
                    ev,
                    role="invalid_id_frame",
                    observed_summary=(
                        entry.summary_label
                        if entry
                        else f"invalid JSON-RPC id at seq #{ev.sequence}"
                    ),
                    span_id=span_id,
                )
            ]
            id_type = getattr(ev.payload, "id_type", None)
            drafts.append(
                ctx.build_draft(
                    code="INVALID_JSONRPC_ID",
                    category="observed_protocol_error",
                    severity="warning",
                    certainty="observed",
                    title="Non-standard or invalid JSON-RPC ID type observed",
                    what_was_observed=(
                        f"Observed {ev.kind} at seq #{ev.sequence} ({ev.direction}) carrying "
                        f"non-correlatable ID type {id_type!r}."
                    ),
                    evidence=evidence,
                    observed_values={"id_type": id_type, "direction": ev.direction},
                    reasonable_conclusions=(
                        "The frame violates standard MCP/JSON-RPC string/integer scalar ID "
                        "conventions and cannot be reliably correlated.",
                    ),
                    cannot_be_concluded=(
                        "Cannot establish whether sender serialization bug or custom non-MCP "
                        "tooling emitted the invalid ID type.",
                    ),
                    additional_evidence_needed=(
                        "Raw wire event inspection and sender JSON-RPC serializer configuration.",
                    ),
                )
            )

        elif status == "cancel_target_missing" and isinstance(
            ev.payload, JsonRpcNotificationPayload
        ):
            evidence = [
                ctx.evidence_from_event(
                    ev,
                    role="cancel_notification",
                    observed_summary=(
                        entry.summary_label
                        if entry
                        else f"notifications/cancelled seq #{ev.sequence}"
                    ),
                    span_id=span_id,
                )
            ]
            target_raw = (
                ev.payload.params.get("requestId") if isinstance(ev.payload.params, dict) else None
            )
            drafts.append(
                ctx.build_draft(
                    code="CANCEL_TARGET_MISSING",
                    category="observed_protocol_error",
                    severity="warning",
                    certainty="observed",
                    title="Cancellation notification references no open in-flight request",
                    what_was_observed=(
                        f"Observed notifications/cancelled at seq #{ev.sequence} ({ev.direction}) "
                        f"targeting requestId={target_raw!r}, which matched no currently open "
                        "request."
                    ),
                    evidence=evidence,
                    observed_values={
                        "direction": ev.direction,
                        "target_request_id": target_raw,
                    },
                    reasonable_conclusions=(
                        "No request with that ID was open at the moment the proxy observed the "
                        "cancellation notification.",
                    ),
                    cannot_be_concluded=(
                        "Cannot distinguish an asynchronous wire race (server already replied "
                        "just before client cancelled) from a stale or incorrect target requestId.",
                    ),
                    additional_evidence_needed=(
                        "Adjacent sequence entries in the timeline and client cancellation "
                        "dispatch timestamps.",
                    ),
                )
            )

    return drafts


__all__ = [
    "detect_correlation_anomalies",
    "detect_protocol_and_tool_errors",
    "is_explicit_wire_timeout_error",
]
