"""AERLOG CLI entry point with Phase 6 read-only execution listing and inspection."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from aerlog import __version__
from aerlog.analysis.timeline import (
    DEFAULT_TIMELINE_LIMIT,
    reconstruct_execution_timeline,
    slice_timeline,
)
from aerlog.cli.render import (
    execution_inspection_to_json,
    executions_list_to_json,
    render_execution_inspection_text,
    render_executions_list_text,
    render_single_event_text,
    render_timeline_slice_text,
    single_event_to_json,
    timeline_slice_to_json,
)
from aerlog.config import ConfigError, load_config
from aerlog.storage.database import DB_FILE_NAME, IndexedExecutionRow
from aerlog.storage.event_log import JsonlEventLogReader
from aerlog.storage.exceptions import (
    ExecutionNotFoundError,
    InvalidExecutionIdError,
    StorageCorruptionError,
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


_ALLOWED_COMPLETENESS = frozenset(
    {"recording", "complete", "spilled", "degraded", "incomplete", "corrupted"}
)


def _version_callback(value: bool) -> None:
    """Print the AERLOG package version and exit immediately."""
    if value:
        typer.echo(f"aerlog {__version__}")
        raise typer.Exit(code=0)


def _resolve_data_dir(
    *,
    config_path: Path | None,
    data_dir: Path | None,
) -> Path:
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    return cfg.data_dir if data_dir is None else data_dir.expanduser()


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


def main() -> None:
    """Console script entry point for ``aerlog``."""
    app()


__all__ = ["app", "executions_app", "main"]
