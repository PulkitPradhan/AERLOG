"""Privacy-safe CLI formatters for execution listing, inspection, and timelines."""

from __future__ import annotations

import io
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from aerlog.analysis.diagnostics import (
    DiagnosticReport,
    format_short_trace,
)
from aerlog.analysis.timeline import (
    ExecutionTimeline,
    TimelineSlice,
)
from aerlog.capture.redaction import EventRedactor, RedactionConfig
from aerlog.events.models import ExecutionEvent
from aerlog.storage.database import IndexedExecutionRow


def format_duration_ns(duration_ns: int | None) -> str:
    """Format nanosecond durations concisely for terminal inspection."""
    if duration_ns is None:
        return "-"
    if duration_ns < 1_000:
        return f"{duration_ns}ns"
    if duration_ns < 1_000_000:
        return f"{duration_ns / 1_000:.1f}us"
    if duration_ns < 1_000_000_000:
        return f"{duration_ns / 1_000_000:.2f}ms"
    return f"{duration_ns / 1_000_000_000:.3f}s"


def format_offset_ns(offset_ns: int) -> str:
    """Format elapsed monotonic offset in seconds with millisecond precision."""
    return f"+{offset_ns / 1_000_000_000:06.3f}s"


def _direction_label(direction: str) -> str:
    if direction == "client_to_server":
        return "client -> server"
    if direction == "server_to_client":
        return "server -> client"
    return direction


def _defensive_redact_command_args(command: Sequence[str], *, redaction_mode: str) -> list[str]:
    """Apply defense-in-depth redaction on display command args without mutating storage."""
    if redaction_mode == "explicit_unredacted":
        return list(command)
    redactor = EventRedactor(RedactionConfig(mode="standard"))
    safe_cmd, _ = redactor.redact_command(command)
    return list(safe_cmd)


def _defensive_redact_command(command: Sequence[str], *, redaction_mode: str) -> str:
    """Apply defense-in-depth redaction on display command string without mutating storage."""
    safe_cmd = _defensive_redact_command_args(command, redaction_mode=redaction_mode)
    return " ".join(safe_cmd) if safe_cmd else "-"


def _render_to_str(render_fn: Any) -> str:
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, color_system=None, width=140)
    render_fn(console)
    return buf.getvalue()


def render_executions_list_text(rows: Sequence[IndexedExecutionRow]) -> str:
    """Render execution catalog rows cleanly without raw payloads or host paths."""
    if not rows:
        return "No recorded executions found.\n"

    def _draw(console: Console) -> None:
        table = Table(title="AERLOG RECORDED EXECUTIONS", box=box.SIMPLE_HEAVY, show_lines=False)
        table.add_column("EXECUTION ID", no_wrap=True)
        table.add_column("STARTED (UTC)", no_wrap=True)
        table.add_column("STATUS", no_wrap=True)
        table.add_column("EVENTS", justify="right", no_wrap=True)
        table.add_column("DURATION", justify="right", no_wrap=True)
        table.add_column("COMMAND")

        for row in rows:
            started_txt = row.started_at.strftime("%Y-%m-%d %H:%M:%S")
            cmd_txt = _defensive_redact_command(row.command, redaction_mode=row.redaction_mode)
            table.add_row(
                row.execution_id,
                started_txt,
                row.capture_completeness,
                str(row.total_events),
                format_duration_ns(row.duration_ns),
                cmd_txt,
            )
        console.print(table)

    return _render_to_str(_draw)


def executions_list_to_json(
    rows: Sequence[IndexedExecutionRow],
    *,
    limit: int,
    offset: int,
) -> str:
    """Serialize listed execution metadata cleanly to JSON."""
    payload = {
        "executions": [
            {
                "execution_id": row.execution_id,
                "schema_version": row.schema_version,
                "storage_schema_version": row.storage_schema_version,
                "started_at": row.started_at.isoformat(),
                "ended_at": row.ended_at.isoformat() if row.ended_at else None,
                "duration_ns": row.duration_ns,
                "command": _defensive_redact_command_args(
                    row.command, redaction_mode=row.redaction_mode
                ),
                "transport": row.transport,
                "redaction_mode": row.redaction_mode,
                "backpressure_policy": row.backpressure_policy,
                "capture_completeness": row.capture_completeness,
                "termination_reason": row.termination_reason,
                "exit_code": row.exit_code,
                "total_events": row.total_events,
                "dropped_events": row.dropped_events,
                "degraded_events": row.degraded_events,
                "warning_count": row.warning_count,
                "gap_count": row.gap_count,
                "index_status": row.index_status,
            }
            for row in rows
        ],
        "returned_count": len(rows),
        "limit": limit,
        "offset": offset,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_execution_inspection_text(timeline: ExecutionTimeline) -> str:
    """Render high-level execution inspection overview without sensitive payload dumps."""

    def _draw(console: Console) -> None:
        console.print("AERLOG EXECUTION INSPECTOR")
        console.print(f"Execution:   {timeline.execution_id}")
        console.print(f"Status:      {timeline.capture_completeness}")
        console.print(f"Redaction:   {timeline.redaction_mode}")
        console.print(
            f"Command:     "
            f"{_defensive_redact_command(timeline.command, redaction_mode=timeline.redaction_mode)}"
        )
        console.print(
            f"Started:     {timeline.started_at.isoformat() if timeline.started_at else '-'}"
        )
        console.print(f"Ended:       {timeline.ended_at.isoformat() if timeline.ended_at else '-'}")
        console.print(
            f"Duration:    {format_duration_ns(timeline.execution_duration_ns)} "
            f"({timeline.execution_duration_basis})"
        )
        console.print(
            f"Termination: {timeline.termination_reason or '-'} "
            f"(exit_code={timeline.exit_code if timeline.exit_code is not None else '-'})"
        )
        console.print(
            f"Counts:      events={timeline.total_events}, requests={timeline.request_count}, "
            f"responses={timeline.response_count}, rpc_errors={timeline.error_response_count}, "
            f"tool_errors={timeline.tool_error_count}, "
            f"notifications={timeline.notification_count}, "
            f"missing={timeline.missing_response_count}, orphans={timeline.orphan_response_count}, "
            f"corrupt={timeline.corrupt_record_count}"
        )

        if timeline.trace_groups:
            console.print("\nTRACE GROUPS")
            for grp in timeline.trace_groups:
                kind_lbl = (
                    "synthetic (not observed on wire)" if grp.is_synthetic else "observed W3C"
                )
                parent_txt = (
                    f" parent_spans={','.join(grp.observed_parent_span_ids)}"
                    if grp.observed_parent_span_ids
                    else ""
                )
                console.print(
                    f"  - [{kind_lbl}] trace_id={grp.trace_id} "
                    f"(events={grp.event_count}, requests={grp.request_count}, "
                    f"seq={grp.first_sequence}..{grp.last_sequence}){parent_txt}"
                )

        if timeline.missing_response_spans:
            console.print("\nMISSING / UNRESOLVED REQUESTS")
            for sp in timeline.missing_response_spans:
                console.print(
                    f"  - seq #{sp.request_sequence} {_direction_label(sp.origin_direction)} "
                    f"{sp.method or '-'} id={sp.request_id_display or '-'} "
                    f"outcome={sp.outcome}"
                )
                for note in sp.uncertainty_notes:
                    console.print(f"      note: {note}")

        if timeline.corruption_markers:
            console.print("\nCORRUPTION / INTEGRITY MARKERS")
            for marker in timeline.corruption_markers:
                console.print(
                    f"  - line {marker.line_number} (offset={marker.byte_offset}, "
                    f"bytes={marker.byte_length}) [{marker.issue_kind}]: {marker.details}"
                )

        console.print("\nLIMITATIONS")
        for lim in timeline.limitations:
            console.print(f"  - {lim}")
        console.print(
            f"\nInspect timeline: aerlog timeline {timeline.execution_id}\n"
            f"Inspect raw event: aerlog inspect {timeline.execution_id} --sequence <N>"
        )

    return _render_to_str(_draw)


def execution_inspection_to_json(timeline: ExecutionTimeline) -> str:
    """Serialize high-level execution inspection summary cleanly to JSON."""
    payload = {
        "timeline_version": timeline.timeline_version,
        "execution_id": timeline.execution_id,
        "started_at": timeline.started_at.isoformat() if timeline.started_at else None,
        "ended_at": timeline.ended_at.isoformat() if timeline.ended_at else None,
        "execution_duration_ns": timeline.execution_duration_ns,
        "execution_duration_basis": timeline.execution_duration_basis,
        "capture_completeness": timeline.capture_completeness,
        "termination_reason": timeline.termination_reason,
        "exit_code": timeline.exit_code,
        "returncode": timeline.returncode,
        "redaction_mode": timeline.redaction_mode,
        "command": _defensive_redact_command_args(
            timeline.command, redaction_mode=timeline.redaction_mode
        ),
        "unclean_shutdown": timeline.unclean_shutdown,
        "diverged_index": timeline.diverged_index,
        "has_corruptions": timeline.has_corruptions,
        "counts": {
            "total_events": timeline.total_events,
            "request_count": timeline.request_count,
            "response_count": timeline.response_count,
            "error_response_count": timeline.error_response_count,
            "tool_error_count": timeline.tool_error_count,
            "notification_count": timeline.notification_count,
            "missing_response_count": timeline.missing_response_count,
            "orphan_response_count": timeline.orphan_response_count,
            "corrupt_record_count": timeline.corrupt_record_count,
        },
        "trace_groups": [g.model_dump(mode="json") for g in timeline.trace_groups],
        "missing_response_spans": [
            s.model_dump(mode="json") for s in timeline.missing_response_spans
        ],
        "corruption_markers": [c.model_dump(mode="json") for c in timeline.corruption_markers],
        "limitations": list(timeline.limitations),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_timeline_slice_text(timeline_slice: TimelineSlice) -> str:
    """Render bounded chronological timeline entries and truncation/uncertainty banners."""

    def _draw(console: Console) -> None:
        console.print(
            f"AERLOG TIMELINE — {timeline_slice.execution_id} "
            f"[status={timeline_slice.capture_completeness}, "
            f"redaction={timeline_slice.redaction_mode}]"
        )

        if timeline_slice.trace_groups:
            group_bits = []
            for grp in timeline_slice.trace_groups:
                tag = "synthetic" if grp.is_synthetic else "observed_w3c"
                group_bits.append(f"{tag}:{grp.trace_id}")
            console.print(f"Traces: {', '.join(group_bits)}")

        table = Table(box=box.SIMPLE_HEAVY, show_lines=False)
        table.add_column("SEQ", justify="right", no_wrap=True)
        table.add_column("OFFSET", no_wrap=True)
        table.add_column("DIRECTION", no_wrap=True)
        table.add_column("TYPE", no_wrap=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("CORRELATION", no_wrap=True)
        table.add_column("DURATION", justify="right", no_wrap=True)
        table.add_column("SUMMARY")

        for entry in timeline_slice.entries:
            corr_txt: str = entry.correlation_status or "-"
            if entry.paired_sequence is not None:
                corr_txt = f"{corr_txt} (#{entry.paired_sequence})"
            table.add_row(
                str(entry.sequence),
                format_offset_ns(entry.offset_ns),
                _direction_label(entry.direction),
                entry.entry_type,
                entry.request_id_display or "-",
                corr_txt,
                format_duration_ns(entry.duration_ns),
                entry.summary_label,
            )

        console.print(table)

        if timeline_slice.missing_response_spans:
            console.print("MISSING RESPONSES")
            for sp in timeline_slice.missing_response_spans:
                console.print(
                    f"  - seq #{sp.request_sequence}: {sp.method or '-'} "
                    f"({sp.request_id_display or '-'}) -> {sp.outcome}"
                )

        if timeline_slice.corruption_markers:
            console.print("CORRUPT / PARTIAL RECORDS")
            for marker in timeline_slice.corruption_markers:
                console.print(
                    f"  - line {marker.line_number} [{marker.issue_kind}] "
                    f"after seq #{marker.after_sequence}: {marker.details}"
                )

        start_idx = timeline_slice.offset + 1 if timeline_slice.returned_entries else 0
        end_idx = timeline_slice.offset + timeline_slice.returned_entries
        if timeline_slice.truncated:
            console.print(
                f"\n[TRUNCATED] Showing entries {start_idx}..{end_idx} of "
                f"{timeline_slice.filtered_entries} "
                f"(total recorded={timeline_slice.total_entries}; "
                f"{timeline_slice.remaining_entries} remaining). "
                f"Pass --offset {end_idx} --limit {timeline_slice.limit} to inspect more."
            )
        else:
            console.print(
                f"\nShowing {timeline_slice.returned_entries} of "
                f"{timeline_slice.filtered_entries} matching entries "
                f"(total recorded={timeline_slice.total_entries})."
            )

        console.print("LIMITATIONS")
        for lim in timeline_slice.limitations:
            console.print(f"  - {lim}")

    return _render_to_str(_draw)


def timeline_slice_to_json(timeline_slice: TimelineSlice) -> str:
    """Serialize paginated timeline slice cleanly to JSON for stdout."""
    return timeline_slice.model_dump_json(indent=2)


def render_single_event_text(event: ExecutionEvent, *, redaction_mode: str) -> str:
    """Render one stored event respecting its stored redaction policy."""

    def _draw(console: Console) -> None:
        console.print(
            f"AERLOG EVENT — execution={event.execution_id} seq=#{event.sequence} "
            f"(redaction={redaction_mode})"
        )
        ts_text = (
            event.timestamp.isoformat()
            if isinstance(event.timestamp, datetime)
            else str(event.timestamp)
        )
        console.print(
            f"Event ID:  {event.event_id}\n"
            f"Timestamp: {ts_text}\n"
            f"Direction: {event.direction}\n"
            f"Kind:      {event.kind}\n"
            f"Degraded:  {event.degraded}"
        )
        console.print(json.dumps(event.model_dump(mode="json"), indent=2, ensure_ascii=False))

    return _render_to_str(_draw)


def single_event_to_json(event: ExecutionEvent, *, redaction_mode: str) -> str:
    """Serialize single stored event lookup cleanly to JSON."""
    payload = {
        "execution_id": event.execution_id,
        "sequence": event.sequence,
        "redaction_mode": redaction_mode,
        "event": event.model_dump(mode="json"),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_diagnostics_text(report: DiagnosticReport) -> str:
    """Render deterministic evidence-linked diagnostics cleanly for terminal output."""

    def _draw(console: Console) -> None:
        console.print("AERLOG DIAGNOSTICS")
        console.print(f"Execution:   {report.execution_id}")
        console.print(f"Status:      {report.capture_completeness}")
        console.print(f"Redaction:   {report.redaction_mode}")
        timeout_txt = (
            f"{report.request_timeout_ms} ms"
            if report.request_timeout_ms is not None
            else "none (not configured)"
        )
        console.print(f"Req Timeout: {timeout_txt}")
        sev = report.counts_by_severity
        console.print(
            f"Findings:    total={report.total_diagnostics} "
            f"(critical={sev.get('critical', 0)}, error={sev.get('error', 0)}, "
            f"warning={sev.get('warning', 0)}, info={sev.get('info', 0)}; "
            f"min_severity={report.min_severity})"
        )

        if not report.diagnostics:
            console.print("\nNo observable diagnostic issues detected.")
        else:
            console.print("\nDIAGNOSTIC FINDINGS")
            for item in report.diagnostics:
                console.print(
                    f"\n[{item.severity.upper()}] {item.code} ({item.diagnostic_id}; "
                    f"certainty={item.certainty}, category={item.category})"
                )
                console.print(f"  Title:        {item.title}")
                console.print(f"  Observed:     {item.what_was_observed}")
                console.print("  Evidence:")
                for ev in item.evidence:
                    if ev.source_kind == "event":
                        trace_txt = format_short_trace(ev.trace)
                        span_txt = ev.span_id or "-"
                        console.print(
                            f"    - seq #{ev.sequence} event_id={ev.event_id} "
                            f"span={span_txt} trace={trace_txt} [{ev.role}]: {ev.observed_summary}"
                        )
                    else:
                        console.print(
                            f"    - line {ev.line_number} offset={ev.byte_offset} "
                            f"bytes={ev.byte_length} [{ev.role}]: {ev.observed_summary}"
                        )
                console.print("  Conclusion(s):")
                for c in item.reasonable_conclusions:
                    console.print(f"    - {c}")
                console.print("  Cannot conclude:")
                for unc in item.cannot_be_concluded:
                    console.print(f"    - {unc}")
                console.print("  Additional evidence needed:")
                for need in item.additional_evidence_needed:
                    console.print(f"    - {need}")
                console.print("  Next steps:")
                for step in item.next_steps:
                    console.print(f"    - {step}")

        console.print("\nANALYSIS LIMITATIONS")
        for lim in report.analysis_limitations:
            console.print(f"  - {lim}")

    return _render_to_str(_draw)


def diagnostics_report_to_json(report: DiagnosticReport) -> str:
    """Serialize :class:`DiagnosticReport` cleanly to JSON for stdout."""
    return report.model_dump_json(indent=2)


__all__ = [
    "diagnostics_report_to_json",
    "execution_inspection_to_json",
    "executions_list_to_json",
    "format_duration_ns",
    "format_offset_ns",
    "render_diagnostics_text",
    "render_execution_inspection_text",
    "render_executions_list_text",
    "render_single_event_text",
    "render_timeline_slice_text",
    "single_event_to_json",
    "timeline_slice_to_json",
]
