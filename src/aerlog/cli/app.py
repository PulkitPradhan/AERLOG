"""AERLOG CLI entry point for listing, inspection, timeline, diagnostics, and offline replay."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from aerlog import __version__
from aerlog.analysis.diagnostics import (
    DiagnosticOptions,
    DiagnosticSeverity,
    apply_min_severity_filter,
    diagnose_execution,
    parse_severity,
    report_exceeds_severity,
)
from aerlog.analysis.timeline import (
    DEFAULT_TIMELINE_LIMIT,
    reconstruct_execution_timeline,
    slice_timeline,
)
from aerlog.cli.render import (
    cassette_summary_to_json,
    diagnostics_report_to_json,
    execution_inspection_to_json,
    executions_list_to_json,
    export_bundle_to_json,
    regression_verify_to_json,
    render_cassette_summary_text,
    render_diagnostics_text,
    render_execution_inspection_text,
    render_executions_list_text,
    render_export_bundle_text,
    render_regression_verify_text,
    render_replay_report_text,
    render_single_event_text,
    render_timeline_slice_text,
    replay_report_to_json,
    single_event_to_json,
    timeline_slice_to_json,
)
from aerlog.config import AerlogConfig, ConfigError, load_config
from aerlog.export import (
    ExportFormat,
    RegressionFixtureValidationError,
    UnredactedExportRefusedError,
    export_execution_regression_test,
    load_regression_fixture,
    run_regression_fixture,
    validate_export_slug,
)
from aerlog.replay import (
    Cassette,
    MissingResponsePolicy,
    ReplayError,
    ReplayMatchMode,
    UnsafeToolPolicy,
    build_cassette_from_execution,
    ensure_replay_mode_allowed,
    load_cassette,
    replay_cassette,
    save_cassette,
    save_replay_report,
    serve_cassette_stdio,
)
from aerlog.storage.database import DB_FILE_NAME, IndexedExecutionRow
from aerlog.storage.event_log import JsonlEventLogReader
from aerlog.storage.exceptions import (
    ExecutionNotFoundError,
    InvalidExecutionIdError,
    StorageCorruptionError,
    StorageError,
    UnsupportedSchemaVersionError,
)
from aerlog.storage.repositories import RecordingRepository

app = typer.Typer(
    name="aerlog",
    help="AERLOG — Local-first MCP execution recorder, diagnostic workbench, and replay harness.",
    add_completion=False,
)

executions_app = typer.Typer(
    name="executions",
    help="List and inspect recorded MCP executions.",
    invoke_without_command=True,
    add_completion=False,
)
app.add_typer(executions_app, name="executions")

cassette_app = typer.Typer(
    name="cassette",
    help="Create and inspect offline replay cassettes.",
    invoke_without_command=True,
    add_completion=False,
)
app.add_typer(cassette_app, name="cassette")

export_app = typer.Typer(
    name="export",
    help="Export and verify deterministic offline MCP regression tests.",
    invoke_without_command=True,
    add_completion=False,
)
app.add_typer(export_app, name="export")


_ALLOWED_COMPLETENESS = frozenset(
    {"recording", "complete", "spilled", "degraded", "incomplete", "corrupted"}
)


def _version_callback(value: bool) -> None:
    """Print the AERLOG package version and exit immediately."""
    if value:
        typer.echo(f"aerlog {__version__}")
        raise typer.Exit(code=0)


def _resolve_runtime(
    *,
    config_path: Path | None,
    data_dir: Path | None,
) -> tuple[AerlogConfig, Path]:
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    resolved_dir = cfg.data_dir if data_dir is None else data_dir.expanduser()
    return cfg, resolved_dir


def _resolve_data_dir(
    *,
    config_path: Path | None,
    data_dir: Path | None,
) -> Path:
    _, resolved_dir = _resolve_runtime(config_path=config_path, data_dir=data_dir)
    return resolved_dir


def _warn_unredacted_if_applicable(redaction_mode: str) -> None:
    if redaction_mode == "explicit_unredacted":
        typer.echo(
            "WARNING: Recording was captured with redaction_mode='explicit_unredacted'; "
            "output may contain sensitive unredacted data.",
            err=True,
        )


def _list_unindexed_executions_read_only(
    data_dir: Path,
    *,
    completeness: str | None,
    limit: int,
    offset: int,
) -> tuple[IndexedExecutionRow, ...]:
    """Read execution headers/summaries straight from disk when ``aerlog.db`` does not exist."""
    reader = JsonlEventLogReader(data_dir)
    rows: list[IndexedExecutionRow] = []
    for eid in reader.discover_execution_ids():
        res = reader.read_execution(eid, strict=False, verify_checksums=False)
        status = (
            "corrupted"
            if res.has_corruptions
            else "incomplete"
            if res.unclean_shutdown
            else res.summary.capture_completeness
            if res.summary is not None
            else "incomplete"
        )
        if completeness is not None and status != completeness:
            continue
        cmd = (
            res.summary.command
            if res.summary is not None
            else res.header.command
            if res.header is not None
            else ()
        )
        started_at = (
            res.summary.started_at
            if res.summary is not None
            else res.header.started_at
            if res.header is not None
            else res.events[0].event.timestamp
            if res.events
            else None
        )
        if started_at is None:
            continue
        redaction_mode = (
            res.summary.redaction_mode
            if res.summary is not None
            else res.header.redaction_mode
            if res.header is not None
            else "standard"
        )
        backpressure_policy = (
            res.summary.backpressure_policy
            if res.summary is not None
            else res.header.backpressure_policy
            if res.header is not None
            else "block"
        )
        rows.append(
            IndexedExecutionRow(
                execution_id=eid,
                schema_version=(
                    res.summary.schema_version
                    if res.summary is not None
                    else res.header.schema_version
                    if res.header is not None
                    else "1.0.0"
                ),
                storage_schema_version="1.0.0",
                started_at=started_at,
                ended_at=res.summary.ended_at if res.summary else None,
                duration_ns=res.summary.duration_ns if res.summary else None,
                command=cmd,
                cwd=None,
                transport="stdio",
                redaction_mode=redaction_mode,
                backpressure_policy=backpressure_policy,
                capture_completeness=status,
                termination_reason=res.summary.termination_reason if res.summary else None,
                exit_code=res.summary.exit_code if res.summary else None,
                returncode=res.summary.returncode if res.summary else None,
                total_events=len(res.events),
                dropped_events=res.summary.dropped_events if res.summary else 0,
                degraded_events=res.summary.degraded_events if res.summary else 0,
                warning_count=res.summary.warning_count if res.summary else 0,
                gap_count=res.summary.gap_count if res.summary else 0,
                unanswered_request_ids=(res.summary.unanswered_request_ids if res.summary else ()),
                observed_trace_ids=res.summary.observed_trace_ids if res.summary else (),
                observed_mcp_versions=(
                    res.summary.observed_mcp_protocol_versions if res.summary else ()
                ),
                recording_dir=f"executions/{eid}",
                jsonl_byte_offset=res.byte_size,
                jsonl_sha256=res.events_file_sha256,
                last_indexed_sequence=res.last_valid_sequence,
                index_status="unindexed",
            )
        )
    rows.sort(key=lambda r: r.started_at, reverse=True)
    return tuple(rows[offset : offset + limit])


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show the AERLOG version and exit.",
        ),
    ] = None,
) -> None:
    """AERLOG command-line interface root."""
    _ = version
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


@executions_app.callback()
def executions_root(ctx: typer.Context) -> None:
    """Execution catalog subcommands."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


@executions_app.command("list")
def executions_list(
    status: Annotated[
        str | None,
        typer.Option(
            "--status", help="Filter by completeness status (e.g., complete, incomplete)."
        ),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, help="Maximum executions to return."),
    ] = 50,
    offset: Annotated[
        int,
        typer.Option("--offset", min=0, help="Number of newest executions to skip."),
    ] = 0,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit structured JSON to stdout."),
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Override AERLOG data directory."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to AERLOG configuration TOML file."),
    ] = None,
) -> None:
    """List recorded MCP executions read-only."""
    if status is not None and status not in _ALLOWED_COMPLETENESS:
        allowed = ", ".join(sorted(_ALLOWED_COMPLETENESS))
        typer.echo(
            f"Invalid --status {status!r}; expected one of: {allowed}",
            err=True,
        )
        raise typer.Exit(code=1)

    resolved_dir = _resolve_data_dir(config_path=config, data_dir=data_dir)
    repo = RecordingRepository(resolved_dir)
    try:
        if not repo.has_existing_storage():
            rows: tuple[IndexedExecutionRow, ...] = ()
        elif (resolved_dir / DB_FILE_NAME).exists():
            rows = repo.list_executions(
                completeness=status,  # type: ignore[arg-type]
                limit=limit,
                offset=offset,
            )
        else:
            rows = _list_unindexed_executions_read_only(
                resolved_dir,
                completeness=status,
                limit=limit,
                offset=offset,
            )
    except UnsupportedSchemaVersionError as exc:
        typer.echo(f"Storage schema error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        repo.close()

    if json_output:
        typer.echo(executions_list_to_json(rows, limit=limit, offset=offset))
    else:
        typer.echo(render_executions_list_text(rows), nl=False)


@app.command("inspect")
def inspect_execution(
    execution_id: Annotated[str, typer.Argument(help="Execution UUID to inspect.")],
    sequence: Annotated[
        int | None,
        typer.Option(
            "--sequence",
            min=1,
            help="Inspect a single stored event by 1-based sequence number.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Fail with non-zero exit if corrupt JSONL records exist."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit structured JSON to stdout."),
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Override AERLOG data directory."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to AERLOG configuration TOML file."),
    ] = None,
) -> None:
    """Inspect a recorded execution summary or a single stored event by sequence."""
    resolved_dir = _resolve_data_dir(config_path=config, data_dir=data_dir)
    repo = RecordingRepository(resolved_dir)
    try:
        if sequence is not None:
            stored = repo.get_execution(execution_id)
            redaction_mode = (
                stored.summary.redaction_mode
                if stored.summary is not None
                else stored.header.redaction_mode
                if stored.header is not None
                else "standard"
            )
            event = repo.get_event_by_sequence(execution_id, sequence)
            _warn_unredacted_if_applicable(redaction_mode)
            if json_output:
                typer.echo(single_event_to_json(event, redaction_mode=redaction_mode))
            else:
                typer.echo(render_single_event_text(event, redaction_mode=redaction_mode), nl=False)
            return

        timeline = reconstruct_execution_timeline(
            repo,
            execution_id,
            strict_integrity=strict,
        )
    except (
        ExecutionNotFoundError,
        InvalidExecutionIdError,
        StorageCorruptionError,
        UnsupportedSchemaVersionError,
        ValueError,
    ) as exc:
        typer.echo(f"Inspection error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        repo.close()

    _warn_unredacted_if_applicable(timeline.redaction_mode)
    if timeline.has_corruptions:
        typer.echo(
            f"WARNING: Execution contains {timeline.corrupt_record_count} corrupt or partial "
            "JSONL record(s).",
            err=True,
        )

    if json_output:
        typer.echo(execution_inspection_to_json(timeline))
    else:
        typer.echo(render_execution_inspection_text(timeline), nl=False)


@app.command("timeline")
def view_timeline(
    execution_id: Annotated[str, typer.Argument(help="Execution UUID to reconstruct.")],
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, help="Maximum timeline entries to display."),
    ] = DEFAULT_TIMELINE_LIMIT,
    offset: Annotated[
        int,
        typer.Option("--offset", min=0, help="Number of filtered timeline entries to skip."),
    ] = 0,
    direction: Annotated[
        str | None,
        typer.Option("--direction", help="Filter entries by direction (e.g., client_to_server)."),
    ] = None,
    kind: Annotated[
        str | None,
        typer.Option("--kind", help="Filter entries by event kind (e.g., jsonrpc_request)."),
    ] = None,
    method: Annotated[
        str | None,
        typer.Option("--method", help="Filter entries by JSON-RPC method name."),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Fail with non-zero exit if corrupt JSONL records exist."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit structured JSON timeline slice to stdout."),
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Override AERLOG data directory."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to AERLOG configuration TOML file."),
    ] = None,
) -> None:
    """Reconstruct and display a chronological timeline for a recorded execution."""
    resolved_dir = _resolve_data_dir(config_path=config, data_dir=data_dir)
    repo = RecordingRepository(resolved_dir)
    try:
        timeline = reconstruct_execution_timeline(
            repo,
            execution_id,
            strict_integrity=strict,
        )
        sliced = slice_timeline(
            timeline,
            limit=limit,
            offset=offset,
            direction=direction,
            kind=kind,
            method=method,
        )
    except (
        ExecutionNotFoundError,
        InvalidExecutionIdError,
        StorageCorruptionError,
        UnsupportedSchemaVersionError,
        ValueError,
    ) as exc:
        typer.echo(f"Timeline error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        repo.close()

    _warn_unredacted_if_applicable(sliced.redaction_mode)
    if sliced.has_corruptions:
        typer.echo(
            f"WARNING: Execution contains {len(sliced.corruption_markers)} corrupt or partial "
            "JSONL record(s).",
            err=True,
        )

    if json_output:
        typer.echo(timeline_slice_to_json(sliced))
    else:
        typer.echo(render_timeline_slice_text(sliced), nl=False)


@app.command("diagnose")
def diagnose_recorded_execution(
    execution_id: Annotated[str, typer.Argument(help="Execution UUID to diagnose.")],
    request_timeout_ms: Annotated[
        int | None,
        typer.Option(
            "--request-timeout-ms",
            min=1,
            help="Optional request timeout threshold in milliseconds.",
        ),
    ] = None,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity",
            help="Minimum diagnostic severity to display (info, warning, error, critical).",
        ),
    ] = "info",
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit with code 2 if any finding meets or exceeds severity.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Fail with code 1 if corrupt JSONL records exist."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit structured JSON diagnostic report to stdout."),
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Override AERLOG data directory."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to AERLOG configuration TOML file."),
    ] = None,
) -> None:
    """Run deterministic, evidence-linked diagnostics over a recorded execution."""
    try:
        parsed_min_sev: DiagnosticSeverity = parse_severity(min_severity)
        parsed_fail_on: DiagnosticSeverity | None = (
            parse_severity(fail_on) if fail_on is not None else None
        )
    except ValueError as exc:
        typer.echo(f"Diagnostics option error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    cfg, resolved_dir = _resolve_runtime(config_path=config, data_dir=data_dir)
    effective_timeout = (
        request_timeout_ms if request_timeout_ms is not None else cfg.diagnostics.request_timeout_ms
    )
    options = DiagnosticOptions(
        request_timeout_ms=effective_timeout,
        repeated_call_threshold=cfg.diagnostics.repeated_call_threshold,
    )

    repo = RecordingRepository(resolved_dir)
    try:
        full_report = diagnose_execution(
            repo,
            execution_id,
            options=options,
            min_severity="info",
            strict_integrity=strict,
        )
    except (
        ExecutionNotFoundError,
        InvalidExecutionIdError,
        StorageCorruptionError,
        UnsupportedSchemaVersionError,
        ValueError,
    ) as exc:
        typer.echo(f"Diagnostics error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        repo.close()

    _warn_unredacted_if_applicable(full_report.redaction_mode)
    if full_report.has_corruptions:
        typer.echo(
            "WARNING: Execution contains corrupt or partial JSONL record(s); "
            "diagnostics reflect verified prefix records and corruption markers.",
            err=True,
        )

    gate_triggered = report_exceeds_severity(full_report, threshold=parsed_fail_on)
    display_report = apply_min_severity_filter(full_report, min_severity=parsed_min_sev)

    if json_output:
        typer.echo(diagnostics_report_to_json(display_report))
    else:
        typer.echo(render_diagnostics_text(display_report), nl=False)

    if gate_triggered:
        raise typer.Exit(code=2)


def _warn_cassette_raw_secrets_if_applicable(cassette: Cassette) -> None:
    if cassette.contains_raw_secrets:
        typer.echo(
            "WARNING: Cassette was created from an 'explicit_unredacted' recording "
            "(contains_raw_secrets=True); sensitive unredacted data may be present.",
            err=True,
        )


def _parse_match_mode(value: str) -> ReplayMatchMode:
    normalized = value.strip().lower()
    if normalized == "strict":
        return "strict"
    if normalized == "tolerant":
        return "tolerant"
    raise ValueError(f"Invalid --match {value!r}; expected 'strict' or 'tolerant'")


def _parse_missing_policy(value: str) -> MissingResponsePolicy:
    normalized = value.strip().lower()
    if normalized == "error":
        return "error"
    if normalized == "omit":
        return "omit"
    raise ValueError(f"Invalid --missing-policy {value!r}; expected 'error' or 'omit'")


@cassette_app.callback()
def cassette_root(ctx: typer.Context) -> None:
    """Offline replay cassette management commands."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


@cassette_app.command("create")
def cassette_create(
    execution_id: Annotated[str, typer.Argument(help="Execution UUID to convert into a cassette.")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional custom output path for the cassette file."),
    ] = None,
    allow_unredacted_cassette: Annotated[
        bool,
        typer.Option(
            "--allow-unredacted-cassette",
            help="Explicitly permit creating a cassette from an 'explicit_unredacted' recording.",
        ),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Fail with code 1 if corrupt JSONL records exist."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit cassette summary JSON to stdout."),
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Override AERLOG data directory."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to AERLOG configuration TOML file."),
    ] = None,
) -> None:
    """Create a hashed offline replay cassette from an existing execution recording."""
    _, resolved_dir = _resolve_runtime(config_path=config, data_dir=data_dir)
    repo = RecordingRepository(resolved_dir)
    try:
        cassette = build_cassette_from_execution(
            repo,
            execution_id,
            strict_integrity=strict,
            allow_unredacted_cassette=allow_unredacted_cassette,
        )
        saved_path = save_cassette(cassette, data_dir=resolved_dir, output_path=output)
    except (
        ExecutionNotFoundError,
        InvalidExecutionIdError,
        StorageCorruptionError,
        UnsupportedSchemaVersionError,
        StorageError,
        ReplayError,
        ValueError,
    ) as exc:
        typer.echo(f"Cassette creation error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        repo.close()

    _warn_cassette_raw_secrets_if_applicable(cassette)
    if cassette.source_has_corruptions:
        typer.echo(
            "WARNING: Source recording contains corrupt/partial JSONL records; cassette covers "
            "verified prefix events only.",
            err=True,
        )

    if json_output:
        typer.echo(cassette_summary_to_json(cassette, path=saved_path))
    else:
        typer.echo(render_cassette_summary_text(cassette, path=saved_path), nl=False)


@cassette_app.command("inspect")
def cassette_inspect(
    cassette_id_or_path: Annotated[
        str, typer.Argument(help="Cassette UUID or path to a .cassette.json file.")
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit cassette metadata JSON to stdout."),
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Override AERLOG data directory."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to AERLOG configuration TOML file."),
    ] = None,
) -> None:
    """Inspect and SHA-256 verify an offline replay cassette read-only."""
    _, resolved_dir = _resolve_runtime(config_path=config, data_dir=data_dir)
    try:
        cassette, resolved_path = load_cassette(cassette_id_or_path, data_dir=resolved_dir)
    except (
        InvalidExecutionIdError,
        ReplayError,
        ValueError,
    ) as exc:
        typer.echo(f"Cassette inspection error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    _warn_cassette_raw_secrets_if_applicable(cassette)
    if json_output:
        typer.echo(cassette_summary_to_json(cassette, path=resolved_path))
    else:
        typer.echo(render_cassette_summary_text(cassette, path=resolved_path), nl=False)


@app.command("replay")
def replay_recorded_execution(
    execution_id: Annotated[
        str | None,
        typer.Argument(
            help="Recorded execution UUID to replay (optional when --cassette is given)."
        ),
    ] = None,
    cassette_path: Annotated[
        Path | None,
        typer.Option("--cassette", help="Path to an existing offline .cassette.json file."),
    ] = None,
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            help="Replay mode ('cassette' offline only; 'live' is blocked fail-closed).",
        ),
    ] = "cassette",
    match: Annotated[
        str | None,
        typer.Option("--match", help="Request matching mode: 'strict' or 'tolerant'."),
    ] = None,
    serve: Annotated[
        bool,
        typer.Option(
            "--serve",
            help="Run an offline cassette-backed mock MCP stdio server on stdin/stdout.",
        ),
    ] = False,
    allow_mutating: Annotated[
        bool,
        typer.Option(
            "--allow-mutating",
            help=(
                "Allow offline replay of potentially_mutating and unknown_unsafe interactions "
                "with audit warnings."
            ),
        ),
    ] = False,
    allow_unredacted_cassette: Annotated[
        bool,
        typer.Option(
            "--allow-unredacted-cassette",
            help="Permit building an in-session cassette from an 'explicit_unredacted' recording.",
        ),
    ] = False,
    exact_id: Annotated[
        bool,
        typer.Option("--exact-id", help="Require exact incoming JSON-RPC request IDs to match."),
    ] = False,
    missing_policy: Annotated[
        str | None,
        typer.Option(
            "--missing-policy",
            help="Behavior when recorded request lacked a response: 'error' or 'omit'.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict", help="Fail with code 1 if source recording has JSONL corruptions."
        ),
    ] = False,
    fail_on_divergence: Annotated[
        bool,
        typer.Option(
            "--fail-on-divergence",
            help="Exit with code 2 if any request diverged, remained unconsumed, or was blocked.",
        ),
    ] = False,
    no_save_report: Annotated[
        bool,
        typer.Option(
            "--no-save-report", help="Do not write ReplayReport under <data_dir>/replays."
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit structured JSON ReplayReport to stdout."),
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Override AERLOG data directory."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to AERLOG configuration TOML file."),
    ] = None,
) -> None:
    """Replay recorded MCP interactions safely offline from a cassette without real tools."""
    try:
        validated_mode = ensure_replay_mode_allowed(mode)
    except (ReplayError, ValueError) as exc:
        typer.echo(f"Replay blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if execution_id is None and cassette_path is None:
        typer.echo("Replay error: specify an execution_id or pass '--cassette <path>'.", err=True)
        raise typer.Exit(code=1)
    if serve and json_output:
        typer.echo(
            "Replay error: '--json' cannot be combined with '--serve' because stdout carries "
            "live JSON-RPC frames.",
            err=True,
        )
        raise typer.Exit(code=1)

    cfg, resolved_dir = _resolve_runtime(config_path=config, data_dir=data_dir)
    try:
        effective_match: ReplayMatchMode = (
            _parse_match_mode(match) if match is not None else cfg.replay.default_match_mode
        )
        effective_missing: MissingResponsePolicy = (
            _parse_missing_policy(missing_policy)
            if missing_policy is not None
            else cfg.replay.missing_response_policy
        )
    except ValueError as exc:
        typer.echo(f"Replay option error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    unsafe_policy: UnsafeToolPolicy = "warn" if allow_mutating else cfg.replay.unsafe_tool_policy

    try:
        if cassette_path is not None:
            cassette, _ = load_cassette(cassette_path, data_dir=resolved_dir)
        else:
            assert execution_id is not None
            repo = RecordingRepository(resolved_dir)
            try:
                cassette = build_cassette_from_execution(
                    repo,
                    execution_id,
                    strict_integrity=strict,
                    allow_unredacted_cassette=allow_unredacted_cassette,
                )
            finally:
                repo.close()
    except (
        ExecutionNotFoundError,
        InvalidExecutionIdError,
        StorageCorruptionError,
        UnsupportedSchemaVersionError,
        ReplayError,
        ValueError,
    ) as exc:
        typer.echo(f"Replay error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    _warn_cassette_raw_secrets_if_applicable(cassette)
    if cassette.source_has_corruptions:
        typer.echo(
            "WARNING: Source recording has corruptions; cassette contains verified prefix only.",
            err=True,
        )

    if serve:
        report = asyncio.run(
            serve_cassette_stdio(
                cassette,
                mode=validated_mode,
                match_mode=effective_match,
                unsafe_tool_policy=unsafe_policy,
                missing_response_policy=effective_missing,
                require_exact_id=exact_id,
            )
        )
    else:
        report = replay_cassette(
            cassette,
            mode=validated_mode,
            match_mode=effective_match,
            unsafe_tool_policy=unsafe_policy,
            missing_response_policy=effective_missing,
            require_exact_id=exact_id,
        )

    saved_report_path: Path | None = None
    if not no_save_report:
        try:
            saved_report_path = save_replay_report(report, data_dir=resolved_dir)
        except StorageError as exc:
            typer.echo(f"Replay report persistence error: {exc}", err=True)
            raise typer.Exit(code=1) from exc

    if serve:
        typer.echo(
            render_replay_report_text(report, report_path=saved_report_path),
            err=True,
            nl=False,
        )
    elif json_output:
        typer.echo(replay_report_to_json(report, report_path=saved_report_path))
    else:
        typer.echo(render_replay_report_text(report, report_path=saved_report_path), nl=False)

    if fail_on_divergence and (
        report.diverged_count > 0 or report.blocked_count > 0 or report.unmatched_count > 0
    ):
        raise typer.Exit(code=2)


def _parse_export_format(value: str) -> ExportFormat:
    normalized = value.strip().lower()
    if normalized == "both":
        return "both"
    if normalized == "json":
        return "json"
    raise ValueError(f"Invalid --format {value!r}; expected 'both' or 'json'")


@export_app.callback()
def export_root(ctx: typer.Context) -> None:
    """Offline MCP regression fixture export and verification commands."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


@export_app.command("test")
def export_test(
    execution_id: Annotated[
        str,
        typer.Argument(help="Execution UUID to export as a deterministic regression fixture."),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Target directory for exported fixture and pytest file.",
        ),
    ] = Path("tests/generated"),
    name: Annotated[
        str | None,
        typer.Option(
            "--name",
            help=(
                "Optional lowercase alphanumeric/underscore filename slug "
                "(defaults to exec_<execution_id>)."
            ),
        ),
    ] = None,
    export_format: Annotated[
        str | None,
        typer.Option(
            "--format",
            help="Artifacts to generate: 'both' (.fixture.json + test_*.py) or 'json' only.",
        ),
    ] = None,
    match: Annotated[
        str | None,
        typer.Option(
            "--match", help="Replay match mode pinned in fixture: 'strict' or 'tolerant'."
        ),
    ] = None,
    allow_mutating: Annotated[
        bool,
        typer.Option(
            "--allow-mutating",
            help=(
                "Allow offline replay of potentially_mutating and unknown_unsafe tools with audit "
                "notices."
            ),
        ),
    ] = False,
    missing_policy: Annotated[
        str | None,
        typer.Option(
            "--missing-policy",
            help="Behavior pinned when recorded request lacked response: 'error' or 'omit'.",
        ),
    ] = None,
    raw: Annotated[
        bool,
        typer.Option(
            "--raw",
            help=(
                "Skip default secret/path/volatile export sanitization (requires "
                "--allow-unredacted-export)."
            ),
        ),
    ] = False,
    allow_unredacted_export: Annotated[
        bool,
        typer.Option(
            "--allow-unredacted-export",
            help="Explicitly confirm opt-in when exporting unredacted '--raw' payloads.",
        ),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict", help="Fail with code 1 if source recording has JSONL corruptions."
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit structured export metadata JSON to stdout."),
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Override AERLOG data directory."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to AERLOG configuration TOML file."),
    ] = None,
) -> None:
    """Export an offline SHA-256-sealed regression fixture and pytest module."""
    cfg, resolved_dir = _resolve_runtime(config_path=config, data_dir=data_dir)
    try:
        effective_format: ExportFormat = (
            _parse_export_format(export_format)
            if export_format is not None
            else cfg.export.default_format
        )
        effective_match: ReplayMatchMode = (
            _parse_match_mode(match) if match is not None else cfg.replay.default_match_mode
        )
        effective_missing: MissingResponsePolicy = (
            _parse_missing_policy(missing_policy)
            if missing_policy is not None
            else cfg.replay.missing_response_policy
        )
        if name is not None:
            validate_export_slug(name)
        if raw and not allow_unredacted_export:
            raise UnredactedExportRefusedError(
                "Unredacted '--raw' export refused without explicit '--allow-unredacted-export'."
            )
    except (ReplayError, ValueError) as exc:
        typer.echo(f"Export option error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    unsafe_policy: UnsafeToolPolicy = "warn" if allow_mutating else cfg.replay.unsafe_tool_policy
    effective_sanitize = False if raw else cfg.export.sanitize_by_default
    effective_normalize = False if raw else cfg.export.normalize_volatile

    repo = RecordingRepository(resolved_dir)
    try:
        if not repo.has_existing_storage():
            raise ExecutionNotFoundError(
                f"No AERLOG storage found at {resolved_dir}; execution {execution_id!r} not found."
            )
        bundle = export_execution_regression_test(
            repo,
            execution_id,
            output_dir=output,
            slug=name,
            export_format=effective_format,
            match_mode=effective_match,
            unsafe_tool_policy=unsafe_policy,
            missing_response_policy=effective_missing,
            sanitize=effective_sanitize,
            normalize_volatile=effective_normalize,
            raw=raw,
            allow_unredacted_export=allow_unredacted_export,
            strict_integrity=strict,
        )
    except (
        ExecutionNotFoundError,
        InvalidExecutionIdError,
        StorageCorruptionError,
        UnsupportedSchemaVersionError,
        StorageError,
        ReplayError,
        ValueError,
    ) as exc:
        typer.echo(f"Export error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        repo.close()

    if bundle.sanitized_from_unredacted_source:
        typer.echo(
            "WARNING: Source recording used redaction_mode='explicit_unredacted'; default export "
            "sanitization was applied to strip secrets and normalize volatile fields.",
            err=True,
        )
    if bundle.fixture.contains_raw_secrets:
        typer.echo(
            "WARNING: Exported fixture contains raw unredacted payloads "
            "(contains_raw_secrets=True); restrict access accordingly.",
            err=True,
        )
    if bundle.fixture.source_has_corruptions:
        typer.echo(
            "WARNING: Source recording has corruptions; exported fixture covers verified prefix "
            "events only.",
            err=True,
        )
    for overwritten_path in bundle.overwritten_files:
        typer.echo(
            f"NOTICE: Overwrote existing export artifact {overwritten_path}",
            err=True,
        )

    if json_output:
        typer.echo(export_bundle_to_json(bundle))
    else:
        typer.echo(render_export_bundle_text(bundle), nl=False)


@export_app.command("verify")
def export_verify(
    fixture_path: Annotated[
        Path,
        typer.Argument(help="Path to an exported .fixture.json file."),
    ],
    cassette_path: Annotated[
        Path | None,
        typer.Option(
            "--cassette",
            help="Optional replacement .cassette.json file to detect changed-server drift.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit structured JSON verification output to stdout."),
    ] = False,
) -> None:
    """Verify an exported regression fixture offline cleanly or against a replacement cassette."""
    override_cassette: Cassette | None = None
    try:
        fixture = load_regression_fixture(fixture_path)
        if cassette_path is not None:
            override_cassette, _ = load_cassette(cassette_path)
        result = run_regression_fixture(fixture, override_cassette=override_cassette)
    except (
        RegressionFixtureValidationError,
        InvalidExecutionIdError,
        ReplayError,
        ValueError,
    ) as exc:
        typer.echo(f"Verification error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if result.contains_raw_secrets:
        typer.echo(
            "WARNING: Verified fixture or override cassette contains raw unredacted payloads "
            "(contains_raw_secrets=True).",
            err=True,
        )

    if json_output:
        typer.echo(
            regression_verify_to_json(
                result,
                fixture=fixture,
                fixture_path=fixture_path,
                cassette_override_path=cassette_path,
            )
        )
    else:
        typer.echo(
            render_regression_verify_text(
                result,
                fixture=fixture,
                fixture_path=fixture_path,
                cassette_override_path=cassette_path,
            ),
            nl=False,
        )

    if not result.passed:
        raise typer.Exit(code=2)


def main() -> None:
    """Console script entry point for ``aerlog``."""
    app()


__all__ = ["app", "cassette_app", "executions_app", "export_app", "main"]
