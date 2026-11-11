"""Minimal Phase 2 CLI entry point for AERLOG."""

from __future__ import annotations

from typing import Annotated

import typer

from aerlog import __version__

app = typer.Typer(
    name="aerlog",
    help="AERLOG — Local-first MCP execution recorder, diagnostic workbench, and replay harness.",
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    """Print the AERLOG package version and exit immediately."""
    if value:
        typer.echo(f"aerlog {__version__}")
        raise typer.Exit(code=0)


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


def main() -> None:
    """Console script entry point for ``aerlog``."""
    app()
