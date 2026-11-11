"""Deterministic, evidence-linked failure diagnostics for recorded MCP executions.

Every diagnostic distinguishes directly observed wire/lifecycle symptoms from
inferred patterns, strictly cites supporting ``event_id``/``sequence`` or JSONL
corruption evidence, and explicitly declares what cannot be concluded without
additional server, host, or agent telemetry.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aerlog.analysis.timeline import (
    TIMELINE_SCHEMA_VERSION,
    CorruptGapMarker,
    ExecutionTimeline,
    TimelineEntry,
    TimelineSpan,
    TimelineTraceLink,
    reconstruct_timeline,
    reconstruct_timeline_from_events,
)
from aerlog.capture.redaction import EventRedactor, RedactionConfig
from aerlog.events.models import ExecutionEvent, ExecutionHeader, ExecutionSummary
from aerlog.events.types import EventDirection, EventKind
from aerlog.storage.database import IndexedExecutionRow
from aerlog.storage.event_log import JsonlReadResult
from aerlog.storage.repositories import RecordingRepository

DIAGNOSTICS_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"

DiagnosticSeverity = Literal["info", "warning", "error", "critical"]
DiagnosticCertainty = Literal["observed", "configured_threshold", "inferred_pattern"]
DiagnosticCategory = Literal[
    "observed_protocol_error",
    "observed_transport_or_lifecycle_failure",
    "configured_threshold_observation",
    "inferred_behavioral_pattern",
]
EvidenceSourceKind = Literal["event", "timeline_corruption_marker"]

SEVERITY_ORDER: Final[dict[DiagnosticSeverity, int]] = {
    "info": 0,
    "warning": 1,
    "error": 2,
    "critical": 3,
}

_ALL_SEVERITIES: Final[tuple[DiagnosticSeverity, ...]] = (
    "info",
    "warning",
    "error",
    "critical",
)
_ALL_CATEGORIES: Final[tuple[DiagnosticCategory, ...]] = (
    "observed_protocol_error",
    "observed_transport_or_lifecycle_failure",
    "configured_threshold_observation",
    "inferred_behavioral_pattern",
)

_DEFAULT_DIAGNOSTIC_LIMITATIONS: Final[tuple[str, ...]] = (
    "Diagnostics analyze captured stdio wire bytes, proxy process lifecycle events, "
    "redacted stderr metadata, and explicit configuration thresholds only.",
    "Internal server source-code state, external API failures, and host LLM reasoning "
    "are outside proxy visibility and cannot be established from recordings alone.",
    "Observed durations reflect proxy pipe-read intervals including OS scheduling and "
    "capture backpressure, not isolated server handler compute time.",
)


class DiagnosticOptions(BaseModel):
    """Explicit runtime thresholds and options controlling deterministic diagnosis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_timeout_ms: int | None = Field(default=None, gt=0)
    repeated_call_threshold: int = Field(default=3, ge=2)

    @property
    def request_timeout_ns(self) -> int | None:
        """Configured request timeout expressed in nanoseconds, or ``None``."""
        if self.request_timeout_ms is None:
            return None
        return self.request_timeout_ms * 1_000_000


class DiagnosticEvidence(BaseModel):
    """Single verifiable evidence anchor linking a diagnostic to stored artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_kind: EvidenceSourceKind
    execution_id: str
    event_id: str | None = None
    sequence: int | None = Field(default=None, ge=1)
    line_number: int | None = Field(default=None, ge=0)
    byte_offset: int | None = Field(default=None, ge=0)
    byte_length: int | None = Field(default=None, ge=0)
    timestamp: datetime | None = None
    offset_ns: int | None = Field(default=None, ge=0)
    direction: EventDirection | None = None
    kind: EventKind | None = None
    span_id: str | None = None
    trace: TimelineTraceLink | None = None
    role: str
    observed_summary: str

    @model_validator(mode="after")
    def _validate_anchor_fields(self) -> DiagnosticEvidence:
        if self.source_kind == "event" and (not self.event_id or self.sequence is None):
            raise ValueError("Event evidence must include both event_id and sequence >= 1")
        if self.source_kind == "timeline_corruption_marker" and (
            self.line_number is None or self.byte_offset is None
        ):
            raise ValueError("Corruption marker evidence must include line_number and byte_offset")
        return self


class DiagnosticItem(BaseModel):
    """One deterministic, evidence-linked diagnostic finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    diagnostic_id: str
    code: str
    category: DiagnosticCategory
    severity: DiagnosticSeverity
    certainty: DiagnosticCertainty
    title: str
    what_was_observed: str
    evidence: tuple[DiagnosticEvidence, ...] = Field(min_length=1)
    event_ids: tuple[str, ...] = ()
    sequence_numbers: tuple[int, ...] = ()
    span_ids: tuple[str, ...] = ()
    observed_values: dict[str, Any] = Field(default_factory=dict)
    reasonable_conclusions: tuple[str, ...] = Field(min_length=1)
    cannot_be_concluded: tuple[str, ...] = Field(min_length=1)
    additional_evidence_needed: tuple[str, ...] = Field(min_length=1)
    next_steps: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_evidence_consistency(self) -> DiagnosticItem:
        ev_ids = {item.event_id for item in self.evidence if item.event_id is not None}
        seqs = {item.sequence for item in self.evidence if item.sequence is not None}
        for eid in self.event_ids:
            if eid not in ev_ids:
                raise ValueError(f"Cited event_id {eid!r} missing from evidence items")
        for seq in self.sequence_numbers:
            if seq not in seqs:
                raise ValueError(f"Cited sequence {seq} missing from evidence items")
        return self


class DiagnosticReport(BaseModel):
    """Immutable deterministic diagnostic report for one recorded execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    diagnostics_version: Literal["1.0.0"] = DIAGNOSTICS_SCHEMA_VERSION
    timeline_version: Literal["1.0.0"] = TIMELINE_SCHEMA_VERSION
    execution_id: str
    capture_completeness: str
    redaction_mode: str = "standard"
    has_corruptions: bool = False
    unclean_shutdown: bool = False
    diverged_index: bool = False
    request_timeout_ms: int | None = None
    repeated_call_threshold: int = Field(default=3, ge=2)
    min_severity: DiagnosticSeverity = "info"
    total_diagnostics: int = Field(ge=0)
    unfiltered_total_diagnostics: int = Field(ge=0)
    counts_by_severity: dict[DiagnosticSeverity, int]
    counts_by_category: dict[DiagnosticCategory, int]
    diagnostics: tuple[DiagnosticItem, ...] = ()
    analysis_limitations: tuple[str, ...] = _DEFAULT_DIAGNOSTIC_LIMITATIONS


@dataclass(frozen=True, slots=True)
class DiagnosticDraft:
    """Unsorted intermediate diagnostic finding produced by a rule."""

    code: str
    category: DiagnosticCategory
    severity: DiagnosticSeverity
    certainty: DiagnosticCertainty
    title: str
    what_was_observed: str
    evidence: tuple[DiagnosticEvidence, ...]
    observed_values: dict[str, Any]
    reasonable_conclusions: tuple[str, ...]
    cannot_be_concluded: tuple[str, ...]
    additional_evidence_needed: tuple[str, ...]
    next_steps: tuple[str, ...]


class DiagnosticRule(Protocol):
    """Callable deterministic rule evaluating one failure or anomaly class."""

    def __call__(self, ctx: DiagnosticContext, /) -> list[DiagnosticDraft]: ...


class DiagnosticContext:
    """Shared read-only evaluation context passed cleanly to every diagnostic rule."""

    def __init__(
        self,
        *,
        timeline: ExecutionTimeline,
        events: Sequence[ExecutionEvent],
        header: ExecutionHeader | None = None,
        summary: ExecutionSummary | None = None,
        options: DiagnosticOptions | None = None,
    ) -> None:
        self.execution_id: str = timeline.execution_id
        self.timeline: ExecutionTimeline = timeline
        self.events: tuple[ExecutionEvent, ...] = tuple(
            sorted(events, key=lambda item: item.sequence)
        )
        self.events_by_id: dict[str, ExecutionEvent] = {ev.event_id: ev for ev in self.events}
        self.events_by_sequence: dict[int, ExecutionEvent] = {ev.sequence: ev for ev in self.events}
        self.entries_by_event_id: dict[str, TimelineEntry] = {
            entry.event_id: entry for entry in timeline.entries
        }
        self.entries_by_sequence: dict[int, TimelineEntry] = {
            entry.sequence: entry for entry in timeline.entries
        }
        self.spans_by_id: dict[str, TimelineSpan] = {span.span_id: span for span in timeline.spans}
        self.header: ExecutionHeader | None = header
        self.summary: ExecutionSummary | None = summary
        self.options: DiagnosticOptions = options or DiagnosticOptions()
        # Defense-in-depth standard redactor prevents exposing secrets in diagnostic prose.
        self.redactor: EventRedactor = EventRedactor(RedactionConfig(mode="standard"))

    @property
    def last_monotonic_ns(self) -> int:
        """Return latest observed monotonic timestamp across timeline entries/events."""
        if self.timeline.entries:
            return self.timeline.entries[-1].monotonic_time_ns
        if self.events:
            return self.events[-1].monotonic_time_ns
        return 0

    def safe_text(self, text: str | None, *, path_label: str, max_chars: int = 160) -> str:
        """Apply defense-in-depth standard redaction on short wire/error excerpts."""
        if not text:
            return ""
        outcome = self.redactor.redact_text_value(text, path_label=path_label, max_chars=max_chars)
        return outcome.text or "[REDACTED]"

    def digest_value(self, canonical_json: str) -> str:
        """Return short SHA-256 hex digest for comparing payloads without exposing contents."""
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()[:16]

    def evidence_from_event(
        self,
        event: ExecutionEvent,
        *,
        role: str,
        observed_summary: str,
        span_id: str | None = None,
    ) -> DiagnosticEvidence:
        """Build a verifiable event-backed :class:`DiagnosticEvidence` item."""
        entry = self.entries_by_event_id.get(event.event_id)
        resolved_span_id = span_id or (entry.span_id if entry is not None else None)
        safe_summary = self.safe_text(
            observed_summary, path_label=f"diagnostic.evidence.{role}", max_chars=240
        )
        return DiagnosticEvidence(
            source_kind="event",
            execution_id=self.execution_id,
            event_id=event.event_id,
            sequence=event.sequence,
            timestamp=event.timestamp,
            offset_ns=entry.offset_ns if entry is not None else None,
            direction=event.direction,
            kind=event.kind,
            span_id=resolved_span_id,
            trace=entry.trace if entry is not None else None,
            role=role,
            observed_summary=safe_summary,
        )

    def evidence_for_span(
        self,
        span: TimelineSpan,
        *,
        include_related: bool = False,
    ) -> list[DiagnosticEvidence]:
        """Collect verifiable event evidence items linked to ``span``."""
        items: list[DiagnosticEvidence] = []
        seen_ids: set[str] = set()

        def _append_eid(eid: str | None, *, role: str) -> None:
            if eid is None or eid in seen_ids:
                return
            ev = self.events_by_id.get(eid)
            entry = self.entries_by_event_id.get(eid)
            if ev is None:
                return
            seen_ids.add(eid)
            label = entry.summary_label if entry is not None else ev.kind
            items.append(
                self.evidence_from_event(
                    ev,
                    role=role,
                    observed_summary=label,
                    span_id=span.span_id,
                )
            )

        _append_eid(span.request_event_id, role="request")
        _append_eid(span.response_event_id, role="response")
        if include_related:
            for rel_id in span.related_event_ids:
                _append_eid(rel_id, role="related")
        return items

    def evidence_from_corruption(
        self,
        marker: CorruptGapMarker,
        *,
        role: str = "corrupt_jsonl_record",
    ) -> DiagnosticEvidence:
        """Build evidence referencing an explicit JSONL corruption marker."""
        return DiagnosticEvidence(
            source_kind="timeline_corruption_marker",
            execution_id=self.execution_id,
            line_number=marker.line_number,
            byte_offset=marker.byte_offset,
            byte_length=marker.byte_length,
            role=role,
            observed_summary=self.safe_text(
                f"line {marker.line_number} [{marker.issue_kind}]: {marker.details}",
                path_label="diagnostic.corruption",
                max_chars=240,
            ),
        )

    def build_draft(
        self,
        *,
        code: str,
        category: DiagnosticCategory,
        severity: DiagnosticSeverity,
        certainty: DiagnosticCertainty,
        title: str,
        what_was_observed: str,
        evidence: Sequence[DiagnosticEvidence],
        observed_values: dict[str, Any] | None = None,
        reasonable_conclusions: Sequence[str],
        cannot_be_concluded: Sequence[str],
        additional_evidence_needed: Sequence[str],
        next_steps: Sequence[str] | None = None,
    ) -> DiagnosticDraft:
        """Validate and assemble a redacted :class:`DiagnosticDraft`."""
        ev_tuple = tuple(evidence)
        if not ev_tuple:
            raise ValueError(f"Diagnostic {code!r} requires at least one evidence item")
        seqs = sorted({item.sequence for item in ev_tuple if item.sequence is not None})
        steps = list(next_steps or ())
        if seqs:
            inspect_cmd = f"aerlog inspect {self.execution_id} --sequence {seqs[0]}"
            if inspect_cmd not in steps:
                steps.append(inspect_cmd)
            offset_val = max(0, seqs[0] - 5)
            tl_cmd = f"aerlog timeline {self.execution_id} --offset {offset_val} --limit 25"
            if tl_cmd not in steps:
                steps.append(tl_cmd)
        elif not steps:
            steps.append(f"aerlog timeline {self.execution_id}")

        safe_observed: dict[str, Any] = {}
        if observed_values:
            obs_out = self.redactor.redact_value(
                dict(observed_values), root_path=f"diagnostic.{code}.observed_values"
            )
            if not obs_out.summary.degraded and isinstance(obs_out.value, dict):
                safe_observed = obs_out.value

        return DiagnosticDraft(
            code=code,
            category=category,
            severity=severity,
            certainty=certainty,
            title=title,
            what_was_observed=self.safe_text(
                what_was_observed, path_label=f"diagnostic.{code}.observed", max_chars=500
            ),
            evidence=ev_tuple,
            observed_values=safe_observed,
            reasonable_conclusions=tuple(reasonable_conclusions),
            cannot_be_concluded=tuple(cannot_be_concluded),
            additional_evidence_needed=tuple(additional_evidence_needed),
            next_steps=tuple(steps),
        )


def _draft_sort_key(draft: DiagnosticDraft) -> tuple[int, int, str, str]:
    seqs = [ev.sequence for ev in draft.evidence if ev.sequence is not None]
    lines = [ev.line_number for ev in draft.evidence if ev.line_number is not None]
    first_pos = min(seqs) if seqs else (min(lines) if lines else 0)
    return (-SEVERITY_ORDER[draft.severity], first_pos, draft.code, draft.what_was_observed)


def _finalize_item(index: int, draft: DiagnosticDraft) -> DiagnosticItem:
    event_ids = tuple(
        dict.fromkeys(item.event_id for item in draft.evidence if item.event_id is not None)
    )
    sequence_numbers = tuple(
        sorted({item.sequence for item in draft.evidence if item.sequence is not None})
    )
    span_ids = tuple(
        dict.fromkeys(item.span_id for item in draft.evidence if item.span_id is not None)
    )
    return DiagnosticItem(
        diagnostic_id=f"diag_{index:04d}",
        code=draft.code,
        category=draft.category,
        severity=draft.severity,
        certainty=draft.certainty,
        title=draft.title,
        what_was_observed=draft.what_was_observed,
        evidence=draft.evidence,
        event_ids=event_ids,
        sequence_numbers=sequence_numbers,
        span_ids=span_ids,
        observed_values=draft.observed_values,
        reasonable_conclusions=draft.reasonable_conclusions,
        cannot_be_concluded=draft.cannot_be_concluded,
        additional_evidence_needed=draft.additional_evidence_needed,
        next_steps=draft.next_steps,
    )


def _summarize_counts(
    items: Sequence[DiagnosticItem],
) -> tuple[dict[DiagnosticSeverity, int], dict[DiagnosticCategory, int]]:
    sev_counts: dict[DiagnosticSeverity, int] = dict.fromkeys(_ALL_SEVERITIES, 0)
    cat_counts: dict[DiagnosticCategory, int] = dict.fromkeys(_ALL_CATEGORIES, 0)
    for item in items:
        sev_counts[item.severity] += 1
        cat_counts[item.category] += 1
    return sev_counts, cat_counts


def _default_rules() -> tuple[DiagnosticRule, ...]:
    from aerlog.analysis.rules import ALL_DIAGNOSTIC_RULES

    return ALL_DIAGNOSTIC_RULES


def diagnose_context(
    ctx: DiagnosticContext,
    *,
    rules: Sequence[DiagnosticRule] | None = None,
    min_severity: DiagnosticSeverity = "info",
) -> DiagnosticReport:
    """Evaluate deterministic diagnostic rules against ``ctx`` and build a sorted report."""
    active_rules = _default_rules() if rules is None else tuple(rules)
    drafts: list[DiagnosticDraft] = []
    for rule in active_rules:
        drafts.extend(rule(ctx))

    drafts.sort(key=_draft_sort_key)
    all_items = tuple(_finalize_item(idx, draft) for idx, draft in enumerate(drafts, start=1))
    min_rank = SEVERITY_ORDER[min_severity]
    filtered_items = tuple(item for item in all_items if SEVERITY_ORDER[item.severity] >= min_rank)
    sev_counts, cat_counts = _summarize_counts(filtered_items)

    return DiagnosticReport(
        execution_id=ctx.execution_id,
        capture_completeness=ctx.timeline.capture_completeness,
        redaction_mode=ctx.timeline.redaction_mode,
        has_corruptions=ctx.timeline.has_corruptions,
        unclean_shutdown=ctx.timeline.unclean_shutdown,
        diverged_index=ctx.timeline.diverged_index,
        request_timeout_ms=ctx.options.request_timeout_ms,
        repeated_call_threshold=ctx.options.repeated_call_threshold,
        min_severity=min_severity,
        total_diagnostics=len(filtered_items),
        unfiltered_total_diagnostics=len(all_items),
        counts_by_severity=sev_counts,
        counts_by_category=cat_counts,
        diagnostics=filtered_items,
    )


def diagnose_timeline(
    timeline: ExecutionTimeline,
    events: Sequence[ExecutionEvent],
    *,
    header: ExecutionHeader | None = None,
    summary: ExecutionSummary | None = None,
    options: DiagnosticOptions | None = None,
    min_severity: DiagnosticSeverity = "info",
    rules: Sequence[DiagnosticRule] | None = None,
) -> DiagnosticReport:
    """Diagnose an already reconstructed :class:`ExecutionTimeline` paired with its events."""
    ctx = DiagnosticContext(
        timeline=timeline,
        events=events,
        header=header,
        summary=summary,
        options=options,
    )
    return diagnose_context(ctx, rules=rules, min_severity=min_severity)


def diagnose_events(
    events: Sequence[ExecutionEvent],
    *,
    execution_id: str,
    header: ExecutionHeader | None = None,
    summary: ExecutionSummary | None = None,
    options: DiagnosticOptions | None = None,
    min_severity: DiagnosticSeverity = "info",
    rules: Sequence[DiagnosticRule] | None = None,
) -> DiagnosticReport:
    """Reconstruct a timeline from raw events in memory and produce a :class:`DiagnosticReport`."""
    timeline = reconstruct_timeline_from_events(
        events,
        execution_id=execution_id,
        header=header,
        summary=summary,
    )
    return diagnose_timeline(
        timeline,
        events,
        header=header,
        summary=summary,
        options=options,
        min_severity=min_severity,
        rules=rules,
    )


def diagnose_jsonl_result(
    read_result: JsonlReadResult,
    *,
    index_row: IndexedExecutionRow | None = None,
    diverged_index: bool = False,
    options: DiagnosticOptions | None = None,
    min_severity: DiagnosticSeverity = "info",
    rules: Sequence[DiagnosticRule] | None = None,
) -> DiagnosticReport:
    """Diagnose a loaded :class:`JsonlReadResult` directly without database writes."""
    timeline = reconstruct_timeline(
        read_result,
        index_row=index_row,
        diverged_index=diverged_index,
    )
    events = [item.event for item in read_result.events]
    return diagnose_timeline(
        timeline,
        events,
        header=read_result.header,
        summary=read_result.summary,
        options=options,
        min_severity=min_severity,
        rules=rules,
    )


def diagnose_execution(
    repo: RecordingRepository,
    execution_id: str,
    *,
    options: DiagnosticOptions | None = None,
    min_severity: DiagnosticSeverity = "info",
    strict_integrity: bool = False,
    verify_checksums: bool = True,
    rules: Sequence[DiagnosticRule] | None = None,
) -> DiagnosticReport:
    """Read authoritative stored events from ``repo`` and generate a :class:`DiagnosticReport`.

    Strictly read-only: never mutates stored events or SQLite state.
    """
    stored = repo.get_execution(execution_id)
    read_res = repo.get_execution_events(
        execution_id,
        strict_integrity=strict_integrity,
        verify_checksums=verify_checksums,
        mark_missing=False,
    )
    return diagnose_jsonl_result(
        read_res,
        index_row=stored.index_row,
        diverged_index=stored.diverged,
        options=options,
        min_severity=min_severity,
        rules=rules,
    )


def report_exceeds_severity(
    report: DiagnosticReport,
    *,
    threshold: DiagnosticSeverity | None,
) -> bool:
    """Return True if ``report`` contains any diagnostic meeting or exceeding ``threshold``."""
    if threshold is None:
        return False
    min_rank = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[item.severity] >= min_rank for item in report.diagnostics)


def apply_min_severity_filter(
    report: DiagnosticReport,
    *,
    min_severity: DiagnosticSeverity,
) -> DiagnosticReport:
    """Return a copy of ``report`` retaining only findings at or above ``min_severity``."""
    min_rank = SEVERITY_ORDER[min_severity]
    filtered = tuple(
        item for item in report.diagnostics if SEVERITY_ORDER[item.severity] >= min_rank
    )
    sev_counts, cat_counts = _summarize_counts(filtered)
    return report.model_copy(
        update={
            "min_severity": min_severity,
            "total_diagnostics": len(filtered),
            "counts_by_severity": sev_counts,
            "counts_by_category": cat_counts,
            "diagnostics": filtered,
        }
    )


def summarize_diagnostic_counts(
    items: Sequence[DiagnosticItem],
) -> dict[DiagnosticSeverity, int]:
    """Return counts keyed by severity level."""
    counts: dict[DiagnosticSeverity, int] = dict.fromkeys(_ALL_SEVERITIES, 0)
    for item in items:
        counts[item.severity] += 1
    return counts


def parse_severity(value: str) -> DiagnosticSeverity:
    """Validate a CLI severity string cleanly or raise ``ValueError``."""
    normalized = value.strip().lower()
    if normalized == "info":
        return "info"
    if normalized == "warning":
        return "warning"
    if normalized == "error":
        return "error"
    if normalized == "critical":
        return "critical"
    allowed = ", ".join(_ALL_SEVERITIES)
    raise ValueError(f"Invalid severity {value!r}; expected one of: {allowed}")


def diagnostic_timeline_context_check(item: DiagnosticItem, timeline: ExecutionTimeline) -> bool:
    """Verify every sequence number cited in ``item`` exists in ``timeline`` or corruptions."""
    valid_seqs = {entry.sequence for entry in timeline.entries}
    valid_lines = {marker.line_number for marker in timeline.corruption_markers}
    return all(seq in valid_seqs for seq in item.sequence_numbers) and all(
        ev.line_number in valid_lines
        for ev in item.evidence
        if ev.source_kind == "timeline_corruption_marker"
    )


def format_short_trace(trace: TimelineTraceLink | None) -> str:
    """Format trace context distinguishing observed W3C headers from synthetic keys."""
    if trace is None or trace.trace_id is None:
        return "none"
    prefix = "synthetic" if trace.is_synthetic else "observed_w3c"
    return f"{prefix}:{trace.trace_id}"


def first_rule_callable(fn: Callable[[DiagnosticContext], list[DiagnosticDraft]]) -> DiagnosticRule:
    """Identity typed helper preserving rule signature readability."""
    return fn


__all__ = [
    "DIAGNOSTICS_SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "DiagnosticCategory",
    "DiagnosticCertainty",
    "DiagnosticContext",
    "DiagnosticDraft",
    "DiagnosticEvidence",
    "DiagnosticItem",
    "DiagnosticOptions",
    "DiagnosticReport",
    "DiagnosticRule",
    "DiagnosticSeverity",
    "EvidenceSourceKind",
    "apply_min_severity_filter",
    "diagnose_context",
    "diagnose_events",
    "diagnose_execution",
    "diagnose_jsonl_result",
    "diagnose_timeline",
    "diagnostic_timeline_context_check",
    "first_rule_callable",
    "format_short_trace",
    "parse_severity",
    "report_exceeds_severity",
    "summarize_diagnostic_counts",
]
