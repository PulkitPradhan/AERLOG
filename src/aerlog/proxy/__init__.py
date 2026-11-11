"""Transparent MCP stdio proxy and off-stdout diagnostic subsystem."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aerlog.proxy.diagnostics import (
    BackpressurePolicy,
    DiagnosticConfig,
    DiagnosticFatalWriteError,
    DiagnosticSink,
    DiagnosticWritePolicy,
)
from aerlog.proxy.forwarding import (
    StreamForwardResult,
    forward_protocol_stream,
    forward_stderr_stream,
)
from aerlog.proxy.subprocess import (
    ManagedProcess,
    SpawnError,
    group_alive,
    spawn_mcp_server,
    terminate_process_group,
    wait_for_process_exit,
)

if TYPE_CHECKING:
    from aerlog.proxy.stdio_proxy import (
        EXIT_DIAGNOSTIC_WRITE_FAILED,
        EXIT_FRAME_TOO_LARGE,
        EXIT_OK,
        EXIT_SPAWN_NOT_FOUND,
        EXIT_SPAWN_PERMISSION,
        ProxyConfig,
        ProxyResult,
        StdioProxy,
        run_stdio_proxy,
    )

_STDIO_PROXY_EXPORTS = frozenset(
    {
        "EXIT_DIAGNOSTIC_WRITE_FAILED",
        "EXIT_FRAME_TOO_LARGE",
        "EXIT_OK",
        "EXIT_SPAWN_NOT_FOUND",
        "EXIT_SPAWN_PERMISSION",
        "ProxyConfig",
        "ProxyResult",
        "StdioProxy",
        "run_stdio_proxy",
    }
)


def __getattr__(name: str) -> object:
    """Lazily expose stdio_proxy symbols to avoid runpy import warnings."""
    if name in _STDIO_PROXY_EXPORTS:
        from aerlog.proxy import stdio_proxy

        return getattr(stdio_proxy, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "EXIT_DIAGNOSTIC_WRITE_FAILED",
    "EXIT_FRAME_TOO_LARGE",
    "EXIT_OK",
    "EXIT_SPAWN_NOT_FOUND",
    "EXIT_SPAWN_PERMISSION",
    "BackpressurePolicy",
    "DiagnosticConfig",
    "DiagnosticFatalWriteError",
    "DiagnosticSink",
    "DiagnosticWritePolicy",
    "ManagedProcess",
    "ProxyConfig",
    "ProxyResult",
    "SpawnError",
    "StdioProxy",
    "StreamForwardResult",
    "forward_protocol_stream",
    "forward_stderr_stream",
    "group_alive",
    "run_stdio_proxy",
    "spawn_mcp_server",
    "terminate_process_group",
    "wait_for_process_exit",
]
