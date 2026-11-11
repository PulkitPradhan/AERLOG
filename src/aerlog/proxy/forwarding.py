"""Bidirectional protocol forwarding and child stderr isolation."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from aerlog.protocol.framing import FrameAccumulator, FrameTooLargeError
from aerlog.protocol.jsonrpc import inspect_frame, redact_text
from aerlog.proxy.diagnostics import DiagnosticSink

STDERR_LINE_MAX_CHARS = 4096

StreamDirection = Literal["client_to_server", "server_to_client"]


class ProxyObserver(Protocol):
    """Structural observer protocol notified read-only of proxy wire and lifecycle events."""

    async def on_execution_started(
        self,
        *,
        command: Sequence[str],
        cwd: Path | None,
        env_overrides: Mapping[str, str] | None,
        monotonic_time_ns: int,
    ) -> None: ...

    async def on_wire_frame(
        self,
        direction: StreamDirection,
        raw_frame: bytes,
        monotonic_time_ns: int,
    ) -> None: ...

    async def on_incomplete_frame(
        self,
        direction: StreamDirection,
        trailing_bytes: bytes,
        monotonic_time_ns: int,
    ) -> None: ...

    async def on_frame_too_large(
        self,
        direction: StreamDirection,
        observed_bytes: int,
        max_frame_bytes: int,
        monotonic_time_ns: int,
    ) -> None: ...

    async def on_stderr_line(self, raw_line: bytes, monotonic_time_ns: int) -> None: ...

    async def on_transport_error(
        self,
        stream_direction: StreamDirection | None,
        reason: str,
        error: str,
        monotonic_time_ns: int,
    ) -> None: ...

    async def on_proxy_signal(self, signal_name: str, monotonic_time_ns: int) -> None: ...

    async def on_child_shutdown_escalate(
        self,
        signal_name: str,
        pgid: int,
        error: str | None,
        monotonic_time_ns: int,
    ) -> None: ...

    async def on_process_exited(self, returncode: int | None, monotonic_time_ns: int) -> None: ...

    async def on_execution_finished(
        self,
        *,
        termination_reason: str,
        exit_code: int,
        returncode: int | None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class StreamForwardResult:
    """Summary of one completed unidirectional forwarding pump."""

    direction: str
    frames_forwarded: int
    bytes_forwarded: int
    eof_incomplete_frame: bool
    write_closed: bool


async def forward_protocol_stream(
    direction: StreamDirection,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    sink: DiagnosticSink,
    *,
    max_frame_bytes: int,
    chunk_size: int = 65536,
    close_writer_on_eof: bool = False,
    observer: ProxyObserver | None = None,
) -> StreamForwardResult:
    """Forward newline-delimited frames unchanged while logging read-only observations.

    Protocol frames are forwarded byte-for-byte before or independently of any
    diagnostic metadata serialization; ``drain()`` propagates downstream pipe
    backpressure upstream without unbounded buffering.

    Raises:
        FrameTooLargeError: If a single frame exceeds ``max_frame_bytes``.
    """
    accumulator = FrameAccumulator(direction=direction, max_frame_bytes=max_frame_bytes)
    diag_cfg = sink.config
    frames_forwarded = 0
    bytes_forwarded = 0
    eof_incomplete_frame = False
    write_closed = False

    try:
        while True:
            chunk = await reader.read(chunk_size)
            if not chunk:
                break

            try:
                frames = accumulator.feed(chunk)
            except FrameTooLargeError as exc:
                await sink.emit(
                    "frame_too_large",
                    direction=direction,
                    observed_bytes=exc.observed_bytes,
                    max_frame_bytes=exc.max_frame_bytes,
                )
                if observer is not None:
                    await observer.on_frame_too_large(
                        direction,
                        exc.observed_bytes,
                        exc.max_frame_bytes,
                        time.monotonic_ns(),
                    )
                raise

            for frame in frames:
                read_ns = time.monotonic_ns()
                observation = inspect_frame(
                    direction,
                    frame,
                    include_previews=diag_cfg.include_previews,
                    preview_max_chars=diag_cfg.preview_max_chars,
                    preview_max_hex_bytes=diag_cfg.preview_max_hex_bytes,
                )
                await sink.emit(observation.event_kind, **observation.to_diagnostic_fields())

                notified_observer = False
                try:
                    writer.write(frame)
                    await writer.drain()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    if observer is not None and not notified_observer:
                        await observer.on_wire_frame(direction, frame, read_ns)
                    raise
                frames_forwarded += 1
                bytes_forwarded += len(frame)
                if observer is not None:
                    await observer.on_wire_frame(direction, frame, read_ns)
                    notified_observer = True

        trailing = accumulator.flush_eof()
        if trailing is not None:
            eof_incomplete_frame = True
            read_ns = time.monotonic_ns()
            fields: dict[str, object] = {
                "direction": direction,
                "byte_length": len(trailing),
            }
            if diag_cfg.include_previews:
                decoded = trailing[: diag_cfg.preview_max_chars].decode("utf-8", errors="replace")
                fields["preview"] = redact_text(decoded)[: diag_cfg.preview_max_chars]
            await sink.emit("incomplete_trailing_frame", **fields)
            if observer is not None:
                await observer.on_incomplete_frame(direction, trailing, read_ns)

            writer.write(trailing)
            await writer.drain()
            bytes_forwarded += len(trailing)
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        write_closed = True
        await sink.emit("transport_write_closed", direction=direction, error=repr(exc))
        if observer is not None:
            await observer.on_transport_error(
                direction,
                "transport_write_closed",
                repr(exc),
                time.monotonic_ns(),
            )
    finally:
        if close_writer_on_eof:
            with suppress(OSError, BrokenPipeError, ConnectionResetError):
                writer.close()
                await writer.wait_closed()

    return StreamForwardResult(
        direction=direction,
        frames_forwarded=frames_forwarded,
        bytes_forwarded=bytes_forwarded,
        eof_incomplete_frame=eof_incomplete_frame,
        write_closed=write_closed,
    )


async def forward_stderr_stream(
    reader: asyncio.StreamReader,
    sink: DiagnosticSink,
    *,
    chunk_size: int = 65536,
    max_line_chars: int = STDERR_LINE_MAX_CHARS,
    observer: ProxyObserver | None = None,
) -> None:
    """Read child ``stderr`` lines and emit redacted diagnostics off ``stdout``."""
    buffer = bytearray()
    diag_cfg = sink.config

    def _emit_line(raw_line: bytes) -> dict[str, object]:
        if not diag_cfg.include_previews:
            return {"byte_length": len(raw_line)}
        decoded = raw_line.decode("utf-8", errors="replace")
        redacted = redact_text(decoded)
        truncated = redacted[:max_line_chars]
        return {
            "byte_length": len(raw_line),
            "text": truncated,
            "truncated": len(redacted) > max_line_chars,
        }

    while True:
        chunk = await reader.read(chunk_size)
        if not chunk:
            break
        buffer.extend(chunk)
        while (newline_idx := buffer.find(b"\n")) != -1:
            line = bytes(buffer[:newline_idx])
            del buffer[: newline_idx + 1]
            if line.endswith(b"\r"):
                line = line[:-1]
            line_ns = time.monotonic_ns()
            await sink.emit("server_stderr", **_emit_line(line))
            if observer is not None:
                await observer.on_stderr_line(line, line_ns)

    if buffer:
        tail = bytes(buffer)
        line_ns = time.monotonic_ns()
        await sink.emit("server_stderr", **_emit_line(tail))
        if observer is not None:
            await observer.on_stderr_line(tail, line_ns)
