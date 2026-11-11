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
STDERR_LINE_MAX_BUFFER_BYTES = 262_144

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
    ) -> None:
        """Record proxy startup parameters before the server subprocess spawns."""
        ...

    async def on_wire_frame(
        self,
        direction: StreamDirection,
        raw_frame: bytes,
        monotonic_time_ns: int,
    ) -> None:
        """Observe one complete unmodified wire frame forwarded between client and server."""
        ...

    async def on_incomplete_frame(
        self,
        direction: StreamDirection,
        trailing_bytes: bytes,
        monotonic_time_ns: int,
    ) -> None:
        """Observe trailing unterminated wire bytes encountered at stream EOF."""
        ...

    async def on_frame_too_large(
        self,
        direction: StreamDirection,
        observed_bytes: int,
        max_frame_bytes: int,
        monotonic_time_ns: int,
    ) -> None:
        """Observe a fail-closed oversized wire frame exceeding ``max_frame_bytes``."""
        ...

    async def on_stderr_line(self, raw_line: bytes, monotonic_time_ns: int) -> None:
        """Observe one line read from child server ``stderr``."""
        ...

    async def on_transport_error(
        self,
        stream_direction: StreamDirection | None,
        reason: str,
        error: str,
        monotonic_time_ns: int,
    ) -> None:
        """Observe a pipe closure, spawn failure, or transport OS error."""
        ...

    async def on_proxy_signal(self, signal_name: str, monotonic_time_ns: int) -> None:
        """Observe an OS signal or task cancellation delivered to the proxy."""
        ...

    async def on_child_shutdown_escalate(
        self,
        signal_name: str,
        pgid: int,
        error: str | None,
        monotonic_time_ns: int,
    ) -> None:
        """Observe ``SIGTERM``/``SIGKILL`` escalation against the server process group."""
        ...

    async def on_process_exited(self, returncode: int | None, monotonic_time_ns: int) -> None:
        """Observe child server subprocess termination and exit code."""
        ...

    async def on_execution_finished(
        self,
        *,
        termination_reason: str,
        exit_code: int,
        returncode: int | None,
    ) -> None:
        """Finalize capture when proxy forwarding and process cleanup complete."""
        ...


@dataclass(frozen=True, slots=True)
class StreamForwardResult:
    """Summary of one completed unidirectional forwarding pump."""

    direction: StreamDirection
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

                try:
                    writer.write(frame)
                    await writer.drain()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    if observer is not None:
                        await observer.on_wire_frame(direction, frame, read_ns)
                    raise
                frames_forwarded += 1
                bytes_forwarded += len(frame)
                if observer is not None:
                    await observer.on_wire_frame(direction, frame, read_ns)

        trailing = accumulator.flush_eof()
        if trailing is not None:
            eof_incomplete_frame = True
            read_ns = time.monotonic_ns()
            fields: dict[str, object] = {
                "direction": direction,
                "byte_length": len(trailing),
            }
            if diag_cfg.include_previews:
                char_limit = max(0, diag_cfg.preview_max_chars)
                if char_limit > 0:
                    window = trailing[: max(char_limit * 8, 4096)].decode("utf-8", errors="replace")
                    fields["preview"] = redact_text(window)[:char_limit]
                else:
                    fields["preview"] = ""
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
    max_line_bytes: int = STDERR_LINE_MAX_BUFFER_BYTES,
    observer: ProxyObserver | None = None,
) -> None:
    """Read child ``stderr`` lines with bounded line buffering and emit redacted diagnostics."""
    char_limit = max(0, max_line_chars)
    byte_cap = max(max(0, max_line_bytes), max(1, char_limit * 8))
    buffer = bytearray()
    discarding_tail = False
    oversized_total_bytes = 0
    diag_cfg = sink.config

    async def _flush_line(raw_line: bytes, *, true_byte_length: int) -> None:
        if raw_line.endswith(b"\r"):
            raw_line = raw_line[:-1]
            true_byte_length = max(len(raw_line), true_byte_length - 1)
        line_ns = time.monotonic_ns()
        if diag_cfg.include_previews:
            decoded = raw_line.decode("utf-8", errors="replace")
            redacted = redact_text(decoded)
            preview = redacted[:char_limit] if char_limit > 0 else ""
            fields: dict[str, object] = {
                "byte_length": true_byte_length,
                "text": preview,
                "truncated": (true_byte_length > len(raw_line)) or (len(redacted) > char_limit),
            }
        else:
            fields = {"byte_length": true_byte_length}
        await sink.emit("server_stderr", **fields)
        if observer is not None:
            await observer.on_stderr_line(raw_line, line_ns)

    while True:
        chunk = await reader.read(chunk_size)
        if not chunk:
            break

        pos = 0
        chunk_len = len(chunk)
        while pos < chunk_len:
            newline_idx = chunk.find(b"\n", pos)
            if discarding_tail:
                if newline_idx == -1:
                    oversized_total_bytes += chunk_len - pos
                    pos = chunk_len
                else:
                    oversized_total_bytes += newline_idx - pos
                    await _flush_line(bytes(buffer), true_byte_length=oversized_total_bytes)
                    buffer.clear()
                    discarding_tail = False
                    oversized_total_bytes = 0
                    pos = newline_idx + 1
                continue

            if newline_idx != -1:
                seg_len = newline_idx - pos
                total_len = len(buffer) + seg_len
                if total_len > byte_cap:
                    room = max(0, byte_cap - len(buffer))
                    if room:
                        buffer.extend(chunk[pos : pos + room])
                    bounded = bytes(buffer)
                    buffer.clear()
                    await _flush_line(bounded, true_byte_length=total_len)
                elif buffer:
                    buffer.extend(chunk[pos:newline_idx])
                    complete = bytes(buffer)
                    buffer.clear()
                    await _flush_line(complete, true_byte_length=len(complete))
                else:
                    direct = chunk[pos:newline_idx]
                    await _flush_line(direct, true_byte_length=len(direct))
                pos = newline_idx + 1
            else:
                remaining = chunk_len - pos
                room = byte_cap - len(buffer)
                if remaining <= room:
                    buffer.extend(chunk[pos:])
                else:
                    if room > 0:
                        buffer.extend(chunk[pos : pos + room])
                    discarding_tail = True
                    oversized_total_bytes = len(buffer) + (remaining - max(0, room))
                pos = chunk_len

    if buffer or discarding_tail:
        tail = bytes(buffer)
        final_len = oversized_total_bytes if discarding_tail else len(tail)
        buffer.clear()
        await _flush_line(tail, true_byte_length=final_len)
