"""Standalone stdlib-only MCP stdio example server for the AERLOG quickstart.

Run directly through the AERLOG capture proxy without external dependencies:

    aerlog run -- python examples/quickstart_server.py

Flags:
    --error          Return a JSON-RPC -32603 error on ``tools/call`` requests.
    --delay-ms MS    Default artificial delay in milliseconds for ``slow_lookup``.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

TOOLS: list[dict[str, Any]] = [
    {
        "name": "echo_message",
        "description": "Echo a text message back cleanly (read-only demonstration tool).",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
        "annotations": {
            "title": "Echo Message",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "slow_lookup",
        "description": "Simulate a slow read-only lookup for timeout diagnostics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "delay_ms": {"type": "integer", "minimum": 0, "maximum": 10000},
            },
            "required": ["query"],
        },
        "annotations": {
            "title": "Slow Lookup",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
]


def _write_message(payload: dict[str, Any]) -> None:
    """Write one newline-delimited JSON-RPC frame to stdout and flush immediately."""
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _error_response(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _handle_request(
    msg: dict[str, Any],
    *,
    simulate_error: bool,
    default_delay_ms: int,
) -> dict[str, Any] | None:
    """Process one parsed JSON-RPC object and return an optional response."""
    method = msg.get("method")
    has_id = "id" in msg
    req_id = msg.get("id")
    params = msg.get("params")
    params_dict = params if isinstance(params, dict) else {}

    if not has_id:
        # Notifications (such as notifications/initialized) must never emit responses.
        return None

    if not isinstance(method, str) or not method:
        return _error_response(req_id, -32600, "Invalid Request: missing method")

    if method == "initialize":
        proto = params_dict.get("protocolVersion")
        negotiated = proto if isinstance(proto, str) and proto else "2025-11-25"
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "aerlog-quickstart-server", "version": "0.1.0"},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        tool_name = params_dict.get("name")
        arguments = params_dict.get("arguments")
        args = arguments if isinstance(arguments, dict) else {}

        if simulate_error:
            sys.stderr.write(
                f"[quickstart_server] returning simulated -32603 error for {tool_name!r}\n"
            )
            sys.stderr.flush()
            return _error_response(
                req_id,
                -32603,
                "Simulated tool failure triggered by --error mode",
            )

        if tool_name == "echo_message":
            text = str(args.get("message", ""))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"echo:{text}"}],
                    "isError": False,
                },
            }

        if tool_name == "slow_lookup":
            raw_delay = args.get("delay_ms", default_delay_ms)
            delay_ms = int(raw_delay) if isinstance(raw_delay, (int, float)) else default_delay_ms
            bounded_ms = min(max(delay_ms, 0), 10_000)
            if bounded_ms > 0:
                time.sleep(bounded_ms / 1000.0)
            query = str(args.get("query", ""))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {"type": "text", "text": f"lookup:{query} (delay_ms={bounded_ms})"}
                    ],
                    "isError": False,
                },
            }

        return _error_response(req_id, -32602, f"Unknown tool: {tool_name!r}")

    return _error_response(req_id, -32601, f"Method not found: {method}")


def main(argv: list[str] | None = None) -> int:
    """Run the stdio JSON-RPC loop cleanly until EOF."""
    parser = argparse.ArgumentParser(
        description="Stdlib-only MCP stdio example server for the AERLOG quickstart."
    )
    parser.add_argument(
        "--error",
        action="store_true",
        help="Fail tools/call requests with a JSON-RPC -32603 error.",
    )
    parser.add_argument(
        "--delay-ms",
        type=int,
        default=50,
        help="Default delay in milliseconds for slow_lookup (default: 50).",
    )
    parsed = parser.parse_args(argv)

    for raw_line in sys.stdin:
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            _write_message(_error_response(None, -32700, f"Parse error: {exc.msg}"))
            continue

        if not isinstance(obj, dict):
            _write_message(_error_response(None, -32600, "Invalid Request: expected JSON object"))
            continue

        reply = _handle_request(
            obj,
            simulate_error=bool(parsed.error),
            default_delay_ms=max(0, int(parsed.delay_ms)),
        )
        if reply is not None:
            _write_message(reply)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
