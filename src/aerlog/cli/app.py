"""AERLOG CLI entry point for listing, inspection, timeline, diagnostics, and offline replay."""

from __future__ import annotations

import asyncio
import contextlib
import os
from pathlib import Path
from typing import Annotated, NoReturn, TextIO, TypeVar, get_args

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
from aerlog.capture import CaptureConfig, CaptureProxyObserver
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
    render_run_start_stderr,
    render_run_summary_stderr,
    render_single_event_text,
    render_timeline_slice_text,
    replay_report_to_json,
    single_event_to_json,
    timeline_slice_to_json,
)
from aerlog.config import AerlogConfig, ConfigError, load_config
from aerlog.events.ids import new_execution_id
from aerlog.events.types import (
    CaptureBackpressurePolicy,
    CaptureCompleteness,
    EventDirection,
    EventKind,
    RedactionMode,
)
from aerlog.export import (
    ExportError,
    ExportFormat,
    RegressionFixtureValidationError,
    UnredactedExportRefusedError,
    export_execution_regression_test,
    load_regression_fixture,
    run_regression_fixture,
    validate_export_slug,
)
from aerlog.protocol.framing import DEFAULT_MAX_FRAME_BYTES
from aerlog.proxy.stdio_proxy import ProxyConfig, ProxyResult, run_stdio_proxy
from aerlog.replay import (
    Cassette,
    CassetteValidationError,
    MissingResponsePolicy,
    ReplayError,
    ReplayInterruptedError,
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
from aerlog.storage.event_log import (
    FsyncPolicy,
    JsonlEventLogReader,
    resolve_execution_dir,
    validate_execution_id,
)
from aerlog.storage.exceptions import (
    ExecutionNotFoundError,
    InvalidExecutionIdError,
    StorageCorruptionError,
    StorageError,
    UnsupportedSchemaVersionError,
)
from aerlog.storage.repositories import RecordingRepository
from aerlog.storage.sink import PersistentCaptureSink

_ROOT_EPILOG = (
    "Workflow examples:\n\n"
    "  aerlog run -- python path/to/mcp_server.py\n\n"
    "  aerlog list\n\n"
    "  aerlog inspect <execution_id>\n\n"
    "  aerlog timeline <execution_id>\n\n"
    "  aerlog diagnose <execution_id>\n\n"
    "  aerlog replay <execution_id> --mode cassette\n\n"
    "  aerlog export test <execution_id> --output tests/generated\n\n"
    "  aerlog export verify tests/generated/<name>.fixture.json\n\n"
    "Exit codes: 0 success | 1 operational/validation error | "
    "2 CLI usage error or --fail-on/--fail-on-divergence/verify gate failure"
)

app = typer.Typer(
    name="aerlog",
    help="AERLOG — Local-first MCP execution recorder, diagnostic workbench, and replay harness.",
    add_completion=True,
)

executions_app = typer.Typer(
    name="executions",
    help="List recorded MCP executions.",
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


_ALLOWED_COMPLETENESS_VALUES: tuple[CaptureCompleteness, ...] = get_args(CaptureCompleteness)
_ALLOWED_DIRECTIONS_VALUES: tuple[EventDirection, ...] = get_args(EventDirection)
_ALLOWED_EVENT_KINDS_VALUES: tuple[EventKind, ...] = get_args(EventKind)
_ALLOWED_BACKPRESSURE_VALUES: tuple[CaptureBackpressurePolicy, ...] = get_args(
    CaptureBackpressurePolicy
)
_ALLOWED_REDACTION_MODES_VALUES: tuple[RedactionMode, ...] = get_args(RedactionMode)
_ALLOWED_FSYNC_POLICIES_VALUES: tuple[FsyncPolicy, ...] = get_args(FsyncPolicy)

_ChoiceT = TypeVar("_ChoiceT", bound=str)


def _cli_error(
    prefix: str,
    message: object,
    *,
    hint: str | None = None,
    code: int = 1,
    cause: BaseException | None = None,
) -> NoReturn:
    """Emit a consistent error and optional actionable hint strictly to ``stderr``."""
    typer.echo(f"{prefix}: {message}", err=True)
    if hint:
        typer.echo(f"Hint: {hint}", err=True)
    if cause is not None:
        raise typer.Exit(code=code) from cause
    raise typer.Exit(code=code)


def _storage_error_hint(exc: BaseException) -> str | None:
    if isinstance(exc, ExecutionNotFoundError):
        return (
            "Run 'aerlog list' to list recorded executions or 'aerlog run -- <cmd>' to capture one."
        )
    if isinstance(exc, InvalidExecutionIdError):
        return "Provide a valid execution UUID shown by 'aerlog list'."
    if isinstance(exc, StorageCorruptionError):
        return "Omit '--strict' to read verified prefix records safely."
    if isinstance(exc, UnsupportedSchemaVersionError):
        return "Upgrade AERLOG to inspect recordings created with a newer schema version."
    if isinstance(exc, StorageError):
        return "Verify '--data-dir' permissions, path, and free disk space."
    if isinstance(exc, (ExportError, RegressionFixtureValidationError)):
        return "Verify the output directory is writable and check '--name' and source files."
    if isinstance(exc, CassetteValidationError):
        return "Ensure the cassette file was not modified after creation."
    return None


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
        _cli_error(
            "Configuration error",
            exc,
            hint="Verify '--config' / AERLOG_CONFIG TOML syntax and field names.",
            code=1,
            cause=exc,
        )
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


@app.callback(invoke_without_command=True, epilog=_ROOT_EPILOG)
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


def _execute_executions_list(
    *,
    status: str | None,
    limit: int,
    offset: int,
    json_output: bool,
    data_dir: Path | None,
    config: Path | None,
) -> None:
    parsed_status: CaptureCompleteness | None = None
    if status is not None:
        try:
            parsed_status = _parse_typed_choice(
                status,
                allowed=_ALLOWED_COMPLETENESS_VALUES,
                flag_name="--status",
            )
        except ValueError as exc:
            _cli_error(
                "List option error",
                exc,
                hint="Pass one of the listed status filters or omit '--status' to list all runs.",
                code=1,
                cause=exc,
            )

    resolved_dir = _resolve_data_dir(config_path=config, data_dir=data_dir)
    repo = RecordingRepository(resolved_dir)
    try:
        if not repo.has_existing_storage():
            rows: tuple[IndexedExecutionRow, ...] = ()
        elif (resolved_dir / DB_FILE_NAME).exists():
            rows = repo.list_executions(
                completeness=parsed_status,
                limit=limit,
                offset=offset,
            )
        else:
            rows = _list_unindexed_executions_read_only(
                resolved_dir,
                completeness=parsed_status,
                limit=limit,
                offset=offset,
            )
    except (StorageError, UnsupportedSchemaVersionError, ValueError) as exc:
        _cli_error("Storage list error", exc, hint=_storage_error_hint(exc), code=1, cause=exc)
    finally:
        repo.close()

    if json_output:
        typer.echo(executions_list_to_json(rows, limit=limit, offset=offset))
    else:
        typer.echo(render_executions_list_text(rows), nl=False)


def _parse_typed_choice(
    value: str,
    *,
    allowed: tuple[_ChoiceT, ...],
    flag_name: str,
) -> _ChoiceT:
    normalized = value.strip()
    for item in allowed:
        if normalized == item or normalized.lower() == item:
            return item
    choices = ", ".join(sorted(allowed))
    raise ValueError(f"Invalid {flag_name} {value!r}; expected one of: {choices}")


@app.command(
    "run",
    epilog=(
        "Examples:\n\n"
        "  aerlog run -- python path/to/mcp_server.py\n\n"
        "  aerlog run --quiet --backpressure-policy spill -- python srv.py --port 8080\n\n"
        "Note: stdout carries only raw MCP JSON-RPC frames; notices/errors go strictly to stderr."
    ),
)
def run_mcp_proxy(
    command: Annotated[
        list[str] | None,
        typer.Argument(help="Target MCP server command and arguments (pass after '--')."),
    ] = None,
    cwd: Annotated[
        Path | None,
        typer.Option("--cwd", help="Working directory for the launched MCP server subprocess."),
    ] = None,
    max_frame_bytes: Annotated[
        int,
        typer.Option(
            "--max-frame-bytes",
            min=1,
            help="Maximum single newline-delimited protocol frame size in bytes.",
        ),
    ] = DEFAULT_MAX_FRAME_BYTES,
    backpressure_policy: Annotated[
        str | None,
        typer.Option(
            "--backpressure-policy",
            help="Capture queue policy: 'block' (lossless default), 'spill', or 'mark_incomplete'.",
        ),
    ] = None,
    redaction_mode: Annotated[
        str | None,
        typer.Option(
            "--redaction-mode",
            help="Redaction policy: 'standard', 'strict_hash_only', or 'explicit_unredacted'.",
        ),
    ] = None,
    allow_unredacted: Annotated[
        bool,
        typer.Option(
            "--allow-unredacted",
            help="Explicitly confirm opt-in when using redaction_mode='explicit_unredacted'.",
        ),
    ] = False,
    persist_cwd: Annotated[
        bool | None,
        typer.Option(
            "--persist-cwd/--no-persist-cwd",
            help="Persist host cwd metadata in storage (disabled by default for privacy).",
        ),
    ] = None,
    fsync_policy: Annotated[
        str | None,
        typer.Option(
            "--fsync-policy",
            help="JSONL durability fsync policy: 'lifecycle', 'every_batch', or 'none'.",
        ),
    ] = None,
    log_file: Annotated[
        Path | None,
        typer.Option(
            "--log-file",
            help="Optional 0o600 JSONL file path for low-level proxy transport telemetry.",
        ),
    ] = None,
    execution_id: Annotated[
        str | None,
        typer.Option(
            "--execution-id",
            help="Optional explicit UUID for the recorded execution.",
        ),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress informational notices on stderr (critical errors and warnings remain).",
        ),
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
    """Launch an MCP stdio server through the transparent capture proxy cleanly."""
    if not command:
        _cli_error(
            "Run option error",
            "No target MCP server command was provided.",
            hint="Pass the server command after '--', e.g.: aerlog run -- python server.py",
            code=1,
        )

    cfg, resolved_dir = _resolve_runtime(config_path=config, data_dir=data_dir)
    try:
        effective_bp: CaptureBackpressurePolicy = (
            _parse_typed_choice(
                backpressure_policy,
                allowed=_ALLOWED_BACKPRESSURE_VALUES,
                flag_name="--backpressure-policy",
            )
            if backpressure_policy is not None
            else cfg.capture.backpressure_policy
        )
        effective_redaction: RedactionMode = (
            _parse_typed_choice(
                redaction_mode,
                allowed=_ALLOWED_REDACTION_MODES_VALUES,
                flag_name="--redaction-mode",
            )
            if redaction_mode is not None
            else cfg.capture.redaction_mode
        )
        effective_fsync: FsyncPolicy = (
            _parse_typed_choice(
                fsync_policy,
                allowed=_ALLOWED_FSYNC_POLICIES_VALUES,
                flag_name="--fsync-policy",
            )
            if fsync_policy is not None
            else cfg.storage.fsync_policy
        )
        resolved_exec_id = (
            validate_execution_id(execution_id) if execution_id is not None else new_execution_id()
        )
        if execution_id is not None and (
            resolve_execution_dir(resolved_dir, resolved_exec_id).exists()
        ):
            raise ValueError(
                f"Execution ID {resolved_exec_id!r} already exists in {resolved_dir}; "
                "omit '--execution-id' or provide a new UUID."
            )
        resolved_cwd = cwd.expanduser() if cwd is not None else None
        if resolved_cwd is not None and not resolved_cwd.is_dir():
            raise ValueError(f"Working directory does not exist: {resolved_cwd}")
    except (InvalidExecutionIdError, ValueError) as exc:
        _cli_error("Run option error", exc, code=1, cause=exc)

    if effective_redaction == "explicit_unredacted" and not allow_unredacted:
        _cli_error(
            "Run security error",
            "Unredacted live capture ('--redaction-mode explicit_unredacted') requires explicit "
            "'--allow-unredacted'.",
            hint="Use '--redaction-mode standard' or add '--allow-unredacted' explicitly.",
            code=1,
        )

    effective_persist_cwd = cfg.storage.persist_cwd if persist_cwd is None else persist_cwd
    capture_cfg = CaptureConfig(
        backpressure_policy=effective_bp,
        redaction_mode=effective_redaction,
        max_queue_events=cfg.capture.max_queue_events,
        max_queue_bytes=cfg.capture.max_queue_bytes,
        spill_dir=resolved_dir / "spool",
        spill_write_timeout_s=cfg.capture.spill_write_timeout_s,
        drain_timeout_s=cfg.capture.drain_timeout_s,
    )
    proxy_cfg = ProxyConfig(
        command=tuple(command),
        cwd=resolved_cwd,
        log_file=log_file.expanduser() if log_file is not None else None,
        max_frame_bytes=max_frame_bytes,
        include_previews=effective_redaction != "strict_hash_only",
    )

    if effective_redaction == "explicit_unredacted":
        typer.echo(
            "WARNING: Live capture running with redaction_mode='explicit_unredacted'; "
            "raw unredacted payloads may be persisted to disk.",
            err=True,
        )
    if not quiet:
        typer.echo(
            render_run_start_stderr(
                execution_id=resolved_exec_id,
                command=proxy_cfg.command,
                redaction_mode=effective_redaction,
            ),
            err=True,
            nl=False,
        )

    async def _run_proxy_capture() -> ProxyResult:
        sink = PersistentCaptureSink(
            resolved_dir,
            fsync_policy=effective_fsync,
            sqlite_synchronous=cfg.storage.sqlite_synchronous,
            redaction_mode=effective_redaction,
            persist_cwd=effective_persist_cwd,
        )
        observer = CaptureProxyObserver(
            sink,
            config=capture_cfg,
            execution_id=resolved_exec_id,
        )
        try:
            with contextlib.ExitStack() as stack:
                diag_stream = (
                    None
                    if proxy_cfg.log_file is not None
                    else stack.enter_context(open(os.devnull, "w", encoding="utf-8"))
                )
                return (
                    await run_stdio_proxy(
                        proxy_cfg,
                        observer=observer,
                    )
                    if diag_stream is None
                    else await _run_with_diag_stream(
                        proxy_cfg, observer=observer, diag_stream=diag_stream
                    )
                )
        finally:
            with contextlib.suppress(Exception):
                await observer.force_close()
            await sink.close()

    try:
        result = asyncio.run(_run_proxy_capture())
    except KeyboardInterrupt as exc:
        raise typer.Exit(code=130) from exc
    except (StorageError, OSError, ValueError) as exc:
        _cli_error(
            "Run error",
            exc,
            hint="Verify the target command, '--data-dir' permissions, and available disk space.",
            code=1,
            cause=exc,
        )

    if result.termination_reason in {
        "spawn_failed",
        "frame_too_large",
        "diagnostic_write_failed",
    }:
        typer.echo(
            f"Run error: Proxy stopped with {result.termination_reason} "
            f"(exit_code={result.exit_code}).",
            err=True,
        )
    if not quiet:
        typer.echo(
            render_run_summary_stderr(
                execution_id=resolved_exec_id,
                command=proxy_cfg.command,
                redaction_mode=effective_redaction,
                termination_reason=result.termination_reason,
                exit_code=result.exit_code,
                client_frames=result.client_frames,
                server_frames=result.server_frames,
                data_dir=resolved_dir,
            ),
            err=True,
            nl=False,
        )

    if result.exit_code != 0:
        raise typer.Exit(code=result.exit_code)


async def _run_with_diag_stream(
    proxy_cfg: ProxyConfig,
    *,
    observer: CaptureProxyObserver,
    diag_stream: TextIO,
) -> ProxyResult:
    from aerlog.proxy.stdio_proxy import StdioProxy

    return await StdioProxy(proxy_cfg).run(
        diag_stream=diag_stream,
        observer=observer,
    )


@app.command(
    "list",
    epilog="Examples:\n\n  aerlog list\n\n  aerlog list --status complete --limit 20 --json",
)
def list_executions_alias(
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
    """List recorded MCP executions read-only (alias for 'aerlog executions list')."""
    _execute_executions_list(
        status=status,
        limit=limit,
        offset=offset,
        json_output=json_output,
        data_dir=data_dir,
        config=config,
    )


@executions_app.callback(
    epilog=(
        "Examples:\n\n  aerlog executions list\n\n  aerlog executions list --status complete --json"
    )
)
def executions_root(ctx: typer.Context) -> None:
    """Execution catalog subcommands."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


@executions_app.command(
    "list",
    epilog="Example: aerlog executions list --status complete --limit 25 --json",
)
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
    _execute_executions_list(
        status=status,
        limit=limit,
        offset=offset,
        json_output=json_output,
        data_dir=data_dir,
        config=config,
    )


@app.command(
    "inspect",
    epilog=(
        "Examples:\n\n"
        "  aerlog inspect <execution_id>\n\n"
        "  aerlog inspect <execution_id> --sequence 3 --json"
    ),
)
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
        typer.Option("--strict", help="Fail with code 1 if corrupt JSONL records exist."),
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
            event = repo.get_event_by_sequence(
                execution_id,
                sequence,
                strict_integrity=strict,
            )
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
        StorageError,
        ValueError,
    ) as exc:
        _cli_error("Inspection error", exc, hint=_storage_error_hint(exc), code=1, cause=exc)
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


@app.command(
    "timeline",
    epilog=(
        "Examples:\n\n"
        "  aerlog timeline <execution_id>\n\n"
        "  aerlog timeline <execution_id> --direction client_to_server --method tools/call --json"
    ),
)
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
        typer.Option("--strict", help="Fail with code 1 if corrupt JSONL records exist."),
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
    try:
        validated_direction = (
            _parse_typed_choice(
                direction,
                allowed=_ALLOWED_DIRECTIONS_VALUES,
                flag_name="--direction",
            )
            if direction is not None
            else None
        )
        validated_kind = (
            _parse_typed_choice(
                kind,
                allowed=_ALLOWED_EVENT_KINDS_VALUES,
                flag_name="--kind",
            )
            if kind is not None
            else None
        )
    except ValueError as exc:
        _cli_error(
            "Timeline option error",
            exc,
            hint="Use one of the listed filter values or omit the option to show all events.",
            code=1,
            cause=exc,
        )

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
            direction=validated_direction,
            kind=validated_kind,
            method=method,
        )
    except (
        ExecutionNotFoundError,
        InvalidExecutionIdError,
        StorageCorruptionError,
        UnsupportedSchemaVersionError,
        StorageError,
        ValueError,
    ) as exc:
        _cli_error("Timeline error", exc, hint=_storage_error_hint(exc), code=1, cause=exc)
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


@app.command(
    "diagnose",
    epilog=(
        "Examples:\n\n"
        "  aerlog diagnose <execution_id>\n\n"
        "  aerlog diagnose <execution_id> --min-severity warning --fail-on error --json"
    ),
)
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
            help=(
                "Exit with code 2 if any unfiltered finding meets or exceeds severity "
                "(info, warning, error, critical)."
            ),
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
        _cli_error(
            "Diagnostics option error",
            exc,
            hint="Allowed severities: info, warning, error, critical.",
            code=1,
            cause=exc,
        )

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
        StorageError,
        ValueError,
    ) as exc:
        _cli_error("Diagnostics error", exc, hint=_storage_error_hint(exc), code=1, cause=exc)
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


@cassette_app.callback(
    epilog=(
        "Examples:\n\n"
        "  aerlog cassette create <execution_id>\n\n"
        "  aerlog cassette inspect <cassette_id_or_path> --json"
    )
)
def cassette_root(ctx: typer.Context) -> None:
    """Offline replay cassette management commands."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


@cassette_app.command(
    "create",
    epilog="Example: aerlog cassette create <execution_id> -o my.cassette.json --json",
)
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
        ExportError,
        ReplayError,
        ValueError,
    ) as exc:
        _cli_error(
            "Cassette creation error",
            exc,
            hint=_storage_error_hint(exc)
            or "Check the execution ID and any unredacted opt-in requirements.",
            code=1,
            cause=exc,
        )
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


@cassette_app.command(
    "inspect",
    epilog="Example: aerlog cassette inspect <cassette_id_or_path> --json",
)
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
        candidate = Path(cassette_id_or_path).expanduser()
        target: str | Path = candidate if candidate.is_file() else cassette_id_or_path
        cassette, resolved_path = load_cassette(target, data_dir=resolved_dir)
    except (
        InvalidExecutionIdError,
        ReplayError,
        ValueError,
    ) as exc:
        _cli_error(
            "Cassette inspection error",
            exc,
            hint="Pass a valid .cassette.json file path or cassette UUID inside '--data-dir'.",
            code=1,
            cause=exc,
        )

    _warn_cassette_raw_secrets_if_applicable(cassette)
    if json_output:
        typer.echo(cassette_summary_to_json(cassette, path=resolved_path))
    else:
        typer.echo(render_cassette_summary_text(cassette, path=resolved_path), nl=False)


@app.command(
    "replay",
    epilog=(
        "Examples:\n\n"
        "  aerlog replay <execution_id> --mode cassette\n\n"
        "  aerlog replay --cassette my.cassette.json --fail-on-divergence --json\n\n"
        "  aerlog replay <execution_id> --serve"
    ),
)
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
        _cli_error(
            "Replay blocked",
            exc,
            hint="Use offline cassette replay: aerlog replay <execution_id> --mode cassette",
            code=1,
            cause=exc,
        )

    if execution_id is None and cassette_path is None:
        _cli_error(
            "Replay error",
            "specify an execution_id or pass '--cassette <path>'.",
            hint="Run 'aerlog list' to find recorded execution UUIDs.",
            code=1,
        )
    if execution_id is not None and cassette_path is not None:
        _cli_error(
            "Replay error",
            "'execution_id' and '--cassette' are mutually exclusive; specify only one.",
            hint="Pass either an execution UUID or '--cassette <path>'.",
            code=1,
        )
    if serve and json_output:
        _cli_error(
            "Replay error",
            "'--json' cannot be combined with '--serve' because stdout carries JSON-RPC frames.",
            hint="Remove '--json' when running '--serve' (the summary prints to stderr).",
            code=1,
        )

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
        _cli_error("Replay option error", exc, code=1, cause=exc)

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
        StorageError,
        ExportError,
        ReplayError,
        ValueError,
    ) as exc:
        _cli_error(
            "Replay error",
            exc,
            hint=_storage_error_hint(exc),
            code=1,
            cause=exc,
        )

    _warn_cassette_raw_secrets_if_applicable(cassette)
    if cassette.source_has_corruptions:
        typer.echo(
            "WARNING: Source recording has corruptions; cassette contains verified prefix only.",
            err=True,
        )

    if serve:
        try:
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
        except ReplayInterruptedError as exc:
            raise typer.Exit(code=exc.exit_code) from exc
        except KeyboardInterrupt as exc:
            raise typer.Exit(code=130) from exc
        except (ReplayError, OSError, ValueError) as exc:
            _cli_error(
                "Replay server error",
                exc,
                hint="Verify client stdio frames and replay flags before retrying.",
                code=1,
                cause=exc,
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
        except (StorageError, ReplayError, ValueError) as exc:
            _cli_error(
                "Replay report persistence error",
                exc,
                hint="Pass '--no-save-report' or check write permissions under '--data-dir'.",
                code=1,
                cause=exc,
            )

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


@export_app.callback(
    epilog=(
        "Examples:\n\n"
        "  aerlog export test <execution_id> --output tests/generated\n\n"
        "  aerlog export verify tests/generated/exec_<id>.fixture.json"
    )
)
def export_root(ctx: typer.Context) -> None:
    """Offline MCP regression fixture export and verification commands."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


@export_app.command(
    "test",
    epilog=(
        "Examples:\n\n"
        "  aerlog export test <execution_id> --output tests/generated\n\n"
        "  aerlog export test <execution_id> --name login_fail --format json --json"
    ),
)
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
        _cli_error(
            "Export option error",
            exc,
            hint=(
                "Omit '--raw' for safe sanitized export or use lowercase alphanumeric/underscore "
                "names."
            ),
            code=1,
            cause=exc,
        )

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
        ExportError,
        ReplayError,
        ValueError,
    ) as exc:
        _cli_error(
            "Export error",
            exc,
            hint=_storage_error_hint(exc),
            code=1,
            cause=exc,
        )
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


@export_app.command(
    "verify",
    epilog=(
        "Examples:\n\n"
        "  aerlog export verify tests/generated/case.fixture.json\n\n"
        "  aerlog export verify tests/generated/case.fixture.json "
        "--cassette <cassette_id_or_path> --json"
    ),
)
def export_verify(
    fixture_path: Annotated[
        Path,
        typer.Argument(help="Path to an exported .fixture.json file."),
    ],
    cassette: Annotated[
        str | None,
        typer.Option(
            "--cassette",
            help="Optional replacement cassette UUID or .cassette.json path to detect drift.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit structured JSON verification output to stdout."),
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Override AERLOG data directory for cassette UUID lookup."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to AERLOG configuration TOML file."),
    ] = None,
) -> None:
    """Verify an exported regression fixture offline cleanly or against a replacement cassette."""
    resolved_dir: Path | None = None
    if cassette is not None or config is not None or data_dir is not None:
        _, resolved_dir = _resolve_runtime(config_path=config, data_dir=data_dir)

    override_cassette: Cassette | None = None
    override_path: Path | None = None
    try:
        fixture = load_regression_fixture(fixture_path)
        if cassette is not None:
            candidate = Path(cassette).expanduser()
            target: str | Path = candidate if candidate.is_file() else cassette
            override_cassette, override_path = load_cassette(target, data_dir=resolved_dir)
        result = run_regression_fixture(fixture, override_cassette=override_cassette)
    except (
        RegressionFixtureValidationError,
        InvalidExecutionIdError,
        StorageError,
        ReplayError,
        ValueError,
    ) as exc:
        _cli_error(
            "Verification error",
            exc,
            hint=("Confirm the fixture JSON is unmodified and any '--cassette' UUID/path exists."),
            code=1,
            cause=exc,
        )

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
                cassette_override_path=override_path,
            )
        )
    else:
        typer.echo(
            render_regression_verify_text(
                result,
                fixture=fixture,
                fixture_path=fixture_path,
                cassette_override_path=override_path,
            ),
            nl=False,
        )

    if not result.passed:
        raise typer.Exit(code=2)


def main() -> None:
    """Console script entry point for ``aerlog``."""
    app()


__all__ = ["app", "cassette_app", "executions_app", "export_app", "main"]
