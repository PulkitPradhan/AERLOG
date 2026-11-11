"""Deterministic multi-event behavioral pattern rules for diagnostics."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from aerlog.analysis.diagnostics import (
    DiagnosticContext,
    DiagnosticDraft,
    DiagnosticEvidence,
)
from aerlog.events.models import ExecutionEvent, JsonRpcRequestPayload


def _canonical_params_digest(
    ctx: DiagnosticContext,
    *,
    direction: str,
    method: str,
    params: Any,
) -> tuple[str, str | None]:
    """Build deterministic canonical SHA-256 prefix without exposing raw param values."""
    normalized: Any
    tool_name: str | None = None
    if isinstance(params, Mapping):
        filtered = {k: v for k, v in params.items() if k != "_meta"}
        if method in {"tools/call", "prompts/get"} and isinstance(filtered.get("name"), str):
            tool_name = str(filtered["name"])
        normalized = filtered
    else:
        normalized = params

    canonical = json.dumps(
        normalized,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return ctx.digest_value(f"{direction}|{method}|{canonical}"), tool_name


def detect_repeated_identical_calls(ctx: DiagnosticContext) -> list[DiagnosticDraft]:
    """Detect repeated identical requests reaching configured ``repeated_call_threshold``."""
    threshold = ctx.options.repeated_call_threshold
    grouped: dict[tuple[str, str, str], list[ExecutionEvent]] = defaultdict(list)
    tool_names: dict[tuple[str, str, str], str | None] = {}

    for ev in ctx.events:
        if not isinstance(ev.payload, JsonRpcRequestPayload):
            continue
        req = ev.payload
        if not req.method:
            continue
        # Under strict_hash_only, parameter bodies were intentionally withheld; never equate them.
        if (
            req.has_params
            and req.params is None
            and ev.redaction.payload_mode == "strict_hash_only"
        ):
            continue

        digest, tool_name = _canonical_params_digest(
            ctx,
            direction=ev.direction,
            method=req.method,
            params=req.params if req.has_params else None,
        )
        key: tuple[str, str, str] = (ev.direction, req.method, digest)
        grouped[key].append(ev)
        if key not in tool_names:
            tool_names[key] = tool_name

    drafts: list[DiagnosticDraft] = []
    for key, events in grouped.items():
        if len(events) < threshold:
            continue
        direction, method, params_digest = key
        tool_name = tool_names.get(key)
        evidence: list[DiagnosticEvidence] = []
        outcomes: dict[str, int] = {}

        for ev in events:
            entry = ctx.entries_by_event_id.get(ev.event_id)
            span = ctx.spans_by_id.get(entry.span_id) if entry is not None else None
            outcome = span.outcome if span is not None else "unknown"
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
            summary = entry.summary_label if entry is not None else f"{method} seq #{ev.sequence}"
            evidence.append(
                ctx.evidence_from_event(
                    ev,
                    role="repeated_identical_request",
                    observed_summary=f"{summary} (outcome={outcome})",
                    span_id=span.span_id if span is not None else None,
                )
            )

        target_desc = f"{method} (tool={tool_name})" if tool_name else method
        seqs = [ev.sequence for ev in events]
        drafts.append(
            ctx.build_draft(
                code="REPEATED_IDENTICAL_CALLS",
                category="inferred_behavioral_pattern",
                severity="warning",
                certainty="inferred_pattern",
                title=f"Repeated identical {method} requests observed ({len(events)}x)",
                what_was_observed=(
                    f"Observed {len(events)} identical {target_desc} requests ({direction}) with "
                    f"matching canonical params digest {params_digest} at sequences {seqs} "
                    f"(threshold={threshold}; outcomes={outcomes})."
                ),
                evidence=evidence,
                observed_values={
                    "method": method,
                    "tool_name": tool_name,
                    "direction": direction,
                    "repeat_count": len(events),
                    "threshold": threshold,
                    "params_sha256_prefix": params_digest,
                    "outcomes": outcomes,
                },
                reasonable_conclusions=(
                    f"Identical {method} payloads crossed the stdio wire {len(events)} times "
                    "without variation in non-_meta parameters.",
                ),
                cannot_be_concluded=(
                    "Cannot distinguish an intentional idempotent polling/refresh cadence from a "
                    "stuck agent retry loop without client orchestration context.",
                    "Cannot judge whether repeated execution triggered unintended external side "
                    "effects.",
                ),
                additional_evidence_needed=(
                    "Agent planning logs or tool idempotency guarantees explaining why identical "
                    "parameters were re-submitted.",
                ),
            )
        )

    return drafts


__all__ = ["detect_repeated_identical_calls"]
