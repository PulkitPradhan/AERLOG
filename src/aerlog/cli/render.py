"""Privacy-safe CLI formatters for execution listing, inspection, and timelines."""

from __future__ import annotations

import io
import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
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
from aerlog.export.regression import (
    RegressionExportBundleResult,
    RegressionFixture,
    RegressionRunResult,
)
from aerlog.replay.cassette import Cassette
from aerlog.replay.runner import ReplayReport
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


def render_cassette_summary_text(cassette: Cassette, *, path: Path | None = None) -> str:
    """Render privacy-safe cassette structure and safety classification table."""

    def _draw(console: Console) -> None:
        console.print("AERLOG REPLAY CASSETTE")
        console.print(f"Cassette ID:        {cassette.cassette_id}")
        console.print(f"Schema Version:     {cassette.cassette_schema_version}")
        console.print(f"Source Execution:   {cassette.source_execution_id}")
        console.print(f"Created At (UTC):   {cassette.created_at.isoformat()}")
        console.print(f"Source Status:      {cassette.source_capture_completeness}")
        console.print(f"Source Redaction:   {cassette.source_redaction_mode}")
        console.print(f"Contains Raw Secs:  {cassette.contains_raw_secrets}")
        console.print(f"Redacted Markers:   {cassette.contains_redacted_placeholders}")
        console.print(f"SHA-256 Digest:     {cassette.cassette_sha256 or '-'}")
        if path is not None:
            console.print(f"Cassette File:      {path}")
        if cassette.command_summary:
            console.print(f"Command (redacted): {' '.join(cassette.command_summary)}")
        console.print(
            f"Interactions:       {len(cassette.interactions)} requests, "
            f"{len(cassette.standalone_notifications)} standalone notifications, "
            f"{len(cassette.cancellations)} cancellations"
        )

        if cassette.interactions:
            table = Table(box=box.SIMPLE_HEAVY, show_lines=False)
            table.add_column("IDX", justify="right", no_wrap=True)
            table.add_column("REQ SEQ", justify="right", no_wrap=True)
            table.add_column("METHOD", no_wrap=True)
            table.add_column("TOOL", no_wrap=True)
            table.add_column("SAFETY CLASS", no_wrap=True)
            table.add_column("REPLAYABLE", no_wrap=True)
            table.add_column("RECORDED OUTCOME")
            for slot in cassette.interactions:
                table.add_row(
                    str(slot.interaction_index),
                    str(slot.request_sequence),
                    slot.method,
                    slot.tool_name or "-",
                    slot.side_effect_class,
                    "yes" if slot.replayable else "no",
                    slot.outcome,
                )
            console.print(table)

    return _render_to_str(_draw)


def cassette_summary_to_json(cassette: Cassette, *, path: Path | None = None) -> str:
    """Serialize structural cassette metadata safely to JSON without exposing raw payloads."""
    payload = {
        "cassette_schema_version": cassette.cassette_schema_version,
        "cassette_id": cassette.cassette_id,
        "created_at": cassette.created_at.isoformat(),
        "source_execution_id": cassette.source_execution_id,
        "source_timeline_version": cassette.source_timeline_version,
        "source_capture_completeness": cassette.source_capture_completeness,
        "source_redaction_mode": cassette.source_redaction_mode,
        "source_unclean_shutdown": cassette.source_unclean_shutdown,
        "source_has_corruptions": cassette.source_has_corruptions,
        "contains_raw_secrets": cassette.contains_raw_secrets,
        "contains_redacted_placeholders": cassette.contains_redacted_placeholders,
        "command_summary": list(cassette.command_summary),
        "observed_mcp_protocol_versions": list(cassette.observed_mcp_protocol_versions),
        "cassette_sha256": cassette.cassette_sha256,
        "cassette_path": str(path) if path is not None else None,
        "interaction_count": len(cassette.interactions),
        "standalone_notification_count": len(cassette.standalone_notifications),
        "cancellation_count": len(cassette.cancellations),
        "interactions": [
            {
                "interaction_index": slot.interaction_index,
                "request_sequence": slot.request_sequence,
                "response_sequence": slot.response_sequence,
                "origin_direction": slot.origin_direction,
                "method": slot.method,
                "tool_name": slot.tool_name,
                "side_effect_class": slot.side_effect_class,
                "side_effect_reason": slot.side_effect_reason,
                "outcome": slot.outcome,
                "replayable": slot.replayable,
                "non_replayable_reason": slot.non_replayable_reason,
                "exact_params_sha256": slot.exact_params_sha256,
                "normalized_params_sha256": slot.normalized_params_sha256,
            }
            for slot in cassette.interactions
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_replay_report_text(
    report: ReplayReport,
    *,
    report_path: Path | None = None,
) -> str:
    """Render offline cassette :class:`ReplayReport` summary cleanly for terminal output."""

    def _draw(console: Console) -> None:
        console.print("AERLOG CASSETTE REPLAY REPORT")
        console.print(f"Replay ID:          {report.replay_id} (is_replay={report.is_replay})")
        console.print(f"Source Execution:   {report.source_execution_id}")
        console.print(f"Cassette ID:        {report.cassette_id}")
        console.print(f"Replay Mode:        {report.replay_mode} ({report.driver_mode})")
        console.print(f"Match Mode:         {report.match_mode}")
        console.print(f"Unsafe Policy:      {report.unsafe_tool_policy}")
        console.print(f"Missing Policy:     {report.missing_response_policy}")
        console.print(f"Overall Status:     {report.overall_status}")
        if report_path is not None:
            console.print(f"Report File:        {report_path}")
        console.print(
            f"Summary Counts:     steps={report.total_steps}, matched={report.matched_count}, "
            f"diverged={report.diverged_count}, blocked={report.blocked_count}, "
            f"unmatched={report.unmatched_count}, missing={report.missing_response_count}, "
            f"safety_notices={report.safety_warning_count}"
        )

        if report.steps:
            table = Table(box=box.SIMPLE_HEAVY, show_lines=False)
            table.add_column("STEP", justify="right", no_wrap=True)
            table.add_column("KIND", no_wrap=True)
            table.add_column("METHOD", no_wrap=True)
            table.add_column("TOOL", no_wrap=True)
            table.add_column("SLOT", justify="right", no_wrap=True)
            table.add_column("SAFETY CLASS", no_wrap=True)
            table.add_column("OUTCOME")
            for step in report.steps:
                slot_str = (
                    str(step.matched_interaction_index)
                    if step.matched_interaction_index is not None
                    else "-"
                )
                table.add_row(
                    str(step.step_index),
                    step.kind,
                    step.method,
                    step.tool_name or "-",
                    slot_str,
                    step.side_effect_class or "-",
                    step.replayed_status,
                )
            console.print(table)

        if report.safety_notices:
            console.print("SAFETY AUDIT NOTICES")
            for notice in report.safety_notices:
                console.print(f"  - [{notice.severity.upper()}] {notice.code}: {notice.message}")

        if report.divergences:
            console.print("\nREPLAY DIVERGENCES")
            for div in report.divergences:
                step_txt = f"step #{div.step_index}" if div.step_index is not None else "session"
                console.print(
                    f"  - [{div.severity.upper()}] {div.kind} ({step_txt}): {div.message}"
                )

        console.print("\nREPLAY LIMITATIONS")
        for lim in report.limitations:
            console.print(f"  - {lim}")

    return _render_to_str(_draw)


def replay_report_to_json(
    report: ReplayReport,
    *,
    report_path: Path | None = None,
) -> str:
    """Serialize :class:`ReplayReport` cleanly to JSON for stdout."""
    payload = report.model_dump(mode="json")
    payload["report_path"] = str(report_path) if report_path is not None else None
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_export_bundle_text(bundle: RegressionExportBundleResult) -> str:
    """Render exported regression bundle metadata cleanly for terminal output."""
    fixture = bundle.fixture

    def _draw(console: Console) -> None:
        console.print("AERLOG REGRESSION EXPORT")
        console.print(f"Fixture ID:         {fixture.fixture_id}")
        console.print(f"Source Execution:   {fixture.source_execution_id}")
        console.print(f"Slug:               {bundle.slug}")
        console.print(
            f"Anchored At:        {fixture.anchored_at.isoformat()} "
            f"(basis={fixture.timestamp_anchor_basis})"
        )
        console.print(f"Format:             {bundle.export_format}")
        console.print(f"Fixture File:       {bundle.fixture_path}")
        if bundle.pytest_path is not None:
            console.print(f"Pytest File:        {bundle.pytest_path}")
        console.print(f"Fixture SHA-256:    {fixture.fixture_sha256}")
        console.print(
            f"Safety State:       sanitized={fixture.sanitized_for_export}, "
            f"raw_secrets={fixture.contains_raw_secrets}, "
            f"redacted_placeholders={fixture.contains_redacted_placeholders}, "
            f"findings={fixture.redaction_findings_count}"
        )
        console.print(
            f"Pinned Replay Mode: match={fixture.match_mode}, "
            f"unsafe_policy={fixture.unsafe_tool_policy}, "
            f"missing_policy={fixture.missing_response_policy}"
        )
        diag_text = (
            ", ".join(fixture.source_diagnostic_codes)
            if fixture.source_diagnostic_codes
            else "none"
        )
        console.print(f"Source Diagnostics: {diag_text}")
        cats = (
            ", ".join(fixture.normalization.normalized_categories)
            if fixture.normalization.normalized_categories
            else "none"
        )
        console.print(
            f"Normalization:      volatile={fixture.normalization.normalize_volatile}, "
            f"categories=[{cats}], variable_paths={len(fixture.normalization.variable_fields)}"
        )

        if fixture.steps:
            table = Table(box=box.SIMPLE_HEAVY, show_lines=False)
            table.add_column("STEP", justify="right", no_wrap=True)
            table.add_column("SEQ", justify="right", no_wrap=True)
            table.add_column("KIND", no_wrap=True)
            table.add_column("METHOD", no_wrap=True)
            table.add_column("TOOL", no_wrap=True)
            table.add_column("EXPECTED OUTCOME")
            table.add_column("ERR / IS_ERR", no_wrap=True)
            for step in fixture.steps:
                exp = step.expected
                detail_parts: list[str] = []
                if exp.expected_error_code is not None:
                    detail_parts.append(f"code={exp.expected_error_code}")
                if exp.expected_tool_is_error is not None:
                    detail_parts.append(f"isError={exp.expected_tool_is_error}")
                detail = ", ".join(detail_parts) if detail_parts else "-"
                table.add_row(
                    str(step.step_index),
                    str(step.source_sequence),
                    step.kind,
                    step.method,
                    step.tool_name or "-",
                    exp.expected_outcome_kind,
                    detail,
                )
            console.print(table)

        console.print("\nEXPORT LIMITATIONS")
        for lim in fixture.limitations:
            console.print(f"  - {lim}")

    return _render_to_str(_draw)


def export_bundle_to_json(bundle: RegressionExportBundleResult) -> str:
    """Serialize export bundle metadata safely to JSON without echoing raw secret payloads."""
    fixture = bundle.fixture
    payload = {
        "fixture_schema_version": fixture.fixture_schema_version,
        "fixture_id": fixture.fixture_id,
        "fixture_sha256": fixture.fixture_sha256,
        "source_execution_id": fixture.source_execution_id,
        "slug": bundle.slug,
        "export_format": bundle.export_format,
        "output_dir": str(bundle.output_dir),
        "fixture_path": str(bundle.fixture_path),
        "pytest_path": str(bundle.pytest_path) if bundle.pytest_path is not None else None,
        "overwritten_files": [str(p) for p in bundle.overwritten_files],
        "anchored_at": fixture.anchored_at.isoformat(),
        "timestamp_anchor_basis": fixture.timestamp_anchor_basis,
        "source_capture_completeness": fixture.source_capture_completeness,
        "source_redaction_mode": fixture.source_redaction_mode,
        "source_unclean_shutdown": fixture.source_unclean_shutdown,
        "source_has_corruptions": fixture.source_has_corruptions,
        "source_diagnostic_codes": list(fixture.source_diagnostic_codes),
        "sanitized_for_export": fixture.sanitized_for_export,
        "sanitized_from_unredacted_source": bundle.sanitized_from_unredacted_source,
        "contains_raw_secrets": fixture.contains_raw_secrets,
        "contains_redacted_placeholders": fixture.contains_redacted_placeholders,
        "redaction_findings_count": fixture.redaction_findings_count,
        "match_mode": fixture.match_mode,
        "unsafe_tool_policy": fixture.unsafe_tool_policy,
        "missing_response_policy": fixture.missing_response_policy,
        "normalization": fixture.normalization.model_dump(mode="json"),
        "expected_overall_status": fixture.expected_overall_status,
        "step_count": len(fixture.steps),
        "steps": [
            {
                "step_index": step.step_index,
                "source_sequence": step.source_sequence,
                "kind": step.kind,
                "method": step.method,
                "tool_name": step.tool_name,
                "side_effect_class": step.side_effect_class,
                "variable_fields": list(step.variable_fields),
                "constant_fields": list(step.constant_fields),
                "expected": step.expected.model_dump(mode="json"),
            }
            for step in fixture.steps
        ],
        "limitations": list(fixture.limitations),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_regression_verify_text(
    result: RegressionRunResult,
    *,
    fixture: RegressionFixture,
    fixture_path: Path,
    cassette_override_path: Path | None = None,
) -> str:
    """Render offline :class:`RegressionRunResult` verification summary for terminal output."""

    def _draw(console: Console) -> None:
        status_label = "PASSED" if result.passed else "FAILED"
        console.print("AERLOG REGRESSION VERIFICATION")
        console.print(f"Status:             {status_label}")
        console.print(f"Fixture ID:         {result.fixture_id}")
        console.print(f"Fixture File:       {fixture_path}")
        console.print(f"Source Execution:   {result.source_execution_id}")
        console.print(f"Target Cassette:    {result.replay_cassette_id}")
        if cassette_override_path is not None:
            console.print(f"Cassette Override:  {cassette_override_path}")
        console.print(
            f"Steps:              total={result.total_steps}, passed={result.passed_steps}, "
            f"failed={result.failed_steps}"
        )
        console.print(
            f"Counts:             matched={result.matched_count}, "
            f"diverged={result.diverged_count}, blocked={result.blocked_count}, "
            f"unmatched={result.unmatched_count}, missing={result.missing_response_count}"
        )
        if fixture.source_diagnostic_codes:
            console.print(f"Source Diagnostics: {', '.join(fixture.source_diagnostic_codes)}")

        if result.failures:
            console.print("\nREGRESSION FAILURES")
            for fail in result.failures:
                step_lbl = f"step #{fail.step_index}" if fail.step_index is not None else "session"
                seq_lbl = (
                    f"seq #{fail.source_sequence}" if fail.source_sequence is not None else "-"
                )
                target = fail.method or "-"
                if fail.tool_name:
                    target += f" ({fail.tool_name})"
                console.print(f"  - {step_lbl} ({seq_lbl}) {target} [{fail.field}]: {fail.message}")
                console.print(f"      expected: {fail.expected!r}")
                console.print(f"      actual:   {fail.actual!r}")

    return _render_to_str(_draw)


def regression_verify_to_json(
    result: RegressionRunResult,
    *,
    fixture: RegressionFixture,
    fixture_path: Path,
    cassette_override_path: Path | None = None,
) -> str:
    """Serialize :class:`RegressionRunResult` cleanly to JSON for stdout."""
    payload = result.model_dump(mode="json")
    payload["fixture_path"] = str(fixture_path)
    payload["cassette_override_path"] = (
        str(cassette_override_path) if cassette_override_path is not None else None
    )
    payload["source_diagnostic_codes"] = list(fixture.source_diagnostic_codes)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_run_start_stderr(
    *,
    execution_id: str,
    command: Sequence[str],
) -> str:
    """Format a concise redaction-safe proxy start notice exclusively for ``stderr``."""
    safe_cmd = _defensive_redact_command(command, redaction_mode="standard")
    return f"[aerlog] Recording MCP execution {execution_id} (cmd={safe_cmd!r})\n"


def render_run_summary_stderr(
    *,
    execution_id: str,
    command: Sequence[str],
    redaction_mode: str,
    termination_reason: str,
    exit_code: int,
    client_frames: int,
    server_frames: int,
    data_dir: Path,
) -> str:
    """Format a concise redaction-safe proxy run summary exclusively for ``stderr``."""
    _ = redaction_mode
    safe_cmd = _defensive_redact_command(command, redaction_mode="standard")
    return (
        f"[aerlog] execution={execution_id} status={termination_reason} "
        f"exit_code={exit_code} frames={client_frames}/{server_frames} "
        f"cmd={safe_cmd!r} data_dir={data_dir}\n"
    )


__all__ = [
    "cassette_summary_to_json",
    "diagnostics_report_to_json",
    "execution_inspection_to_json",
    "executions_list_to_json",
    "export_bundle_to_json",
    "format_duration_ns",
    "format_offset_ns",
    "regression_verify_to_json",
    "render_cassette_summary_text",
    "render_diagnostics_text",
    "render_execution_inspection_text",
    "render_executions_list_text",
    "render_export_bundle_text",
    "render_regression_verify_text",
    "render_replay_report_text",
    "render_run_start_stderr",
    "render_run_summary_stderr",
    "render_single_event_text",
    "render_timeline_slice_text",
    "replay_report_to_json",
    "single_event_to_json",
    "timeline_slice_to_json",
]
