"""Byte-exact newline framing with hard single-frame size limits.

MCP stdio transport frames UTF-8 JSON-RPC messages using ``\\n`` delimiters.
This module operates purely on raw ``bytes`` so valid, unknown, CRLF, or
malformed frames can be forwarded unchanged without JSON re-serialization.
"""

from __future__ import annotations

from typing import Literal

DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024  # 16 MiB

LineEnding = Literal["lf", "crlf", "none"]


class FrameTooLargeError(Exception):
    """Raised when a single protocol frame exceeds ``max_frame_bytes``."""

    def __init__(self, direction: str, observed_bytes: int, max_frame_bytes: int) -> None:
        self.direction = direction
        self.observed_bytes = observed_bytes
        self.max_frame_bytes = max_frame_bytes
        super().__init__(
            f"Frame on {direction} exceeded limit ({observed_bytes} > {max_frame_bytes} bytes)"
        )


def detect_line_ending(raw_frame: bytes) -> LineEnding:
    """Identify the line terminator of ``raw_frame`` without modifying it."""
    if raw_frame.endswith(b"\r\n"):
        return "crlf"
    if raw_frame.endswith(b"\n"):
        return "lf"
    return "none"


class FrameAccumulator:
    """Incrementally extracts newline-delimited byte frames from arbitrary chunks.

    Enforces ``max_frame_bytes`` on each individual frame (including its
    terminating ``\\n``) so multiple smaller frames arriving in the same read
    chunk succeed while any single oversized frame fails closed immediately.
    """

    def __init__(self, direction: str, max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> None:
        if max_frame_bytes <= 0:
            raise ValueError("max_frame_bytes must be a positive integer")
        self.direction = direction
        self._max_frame_bytes = max_frame_bytes
        self._buffer = bytearray()

    @property
    def max_frame_bytes(self) -> int:
        """Maximum permitted size in bytes for any single frame."""
        return self._max_frame_bytes

    @property
    def buffered_bytes(self) -> int:
        """Number of incomplete trailing bytes currently buffered."""
        return len(self._buffer)

    def feed(self, chunk: bytes) -> list[bytes]:
        """Consume an incoming byte chunk and return complete ``\\n`` frames.

        Args:
            chunk: Arbitrary byte slice read from an underlying stream.

        Returns:
            List of complete frames, each ending with ``b"\\n"`` and unchanged
            from the input bytes.

        Raises:
            FrameTooLargeError: If any complete or still-incomplete frame exceeds
                ``max_frame_bytes``.
        """
        if not chunk:
            return []

        frames: list[bytes] = []
        pos = 0
        chunk_len = len(chunk)

        while pos < chunk_len:
            newline_idx = chunk.find(b"\n", pos)
            if newline_idx == -1:
                segment = chunk[pos:]
                total_len = len(self._buffer) + len(segment)
                if total_len > self._max_frame_bytes:
                    self._buffer.clear()
                    raise FrameTooLargeError(self.direction, total_len, self._max_frame_bytes)
                self._buffer.extend(segment)
                break

            segment = chunk[pos : newline_idx + 1]
            frame_len = len(self._buffer) + len(segment)
            if frame_len > self._max_frame_bytes:
                self._buffer.clear()
                raise FrameTooLargeError(self.direction, frame_len, self._max_frame_bytes)

            if self._buffer:
                frame = bytes(self._buffer) + segment
                self._buffer.clear()
            else:
                frame = segment

            frames.append(frame)
            pos = newline_idx + 1

        return frames

    def flush_eof(self) -> bytes | None:
        """Drain any incomplete trailing bytes buffered when EOF is reached."""
        if not self._buffer:
            return None
        trailing = bytes(self._buffer)
        self._buffer.clear()
        return trailing
