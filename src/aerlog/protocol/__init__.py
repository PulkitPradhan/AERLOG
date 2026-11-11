"""Protocol framing and read-only JSON-RPC envelope inspection for AERLOG."""

from __future__ import annotations

from aerlog.protocol.framing import (
    DEFAULT_MAX_FRAME_BYTES,
    FrameAccumulator,
    FrameTooLargeError,
    LineEnding,
    detect_line_ending,
)
from aerlog.protocol.jsonrpc import FrameObservation, inspect_frame, redact_text

__all__ = [
    "DEFAULT_MAX_FRAME_BYTES",
    "FrameAccumulator",
    "FrameObservation",
    "FrameTooLargeError",
    "LineEnding",
    "detect_line_ending",
    "inspect_frame",
    "redact_text",
]
