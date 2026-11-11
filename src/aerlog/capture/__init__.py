"""AERLOG capture pipeline, redaction, normalizer, sinks, and proxy observer."""

from __future__ import annotations

from aerlog.capture.normalizer import (
    EventNormalizer,
    RawCaptureInput,
    RawCaptureWarningInput,
    RawChildShutdownEscalateInput,
    RawFrameTooLargeInput,
    RawIncompleteFrameInput,
    RawProcessExitedInput,
    RawProxySignalInput,
    RawStderrLineInput,
    RawTransportErrorInput,
    RawWireFrameInput,
)
from aerlog.capture.observer import CaptureProxyObserver
from aerlog.capture.pipeline import (
    CaptureConfig,
    CapturePipeline,
    estimate_raw_input_bytes,
)
from aerlog.capture.redaction import (
    REDACTED_KEY_BLOCK_MARKER,
    REDACTED_MARKER,
    REDACTION_FAILED_MARKER,
    EventRedactor,
    RedactedTextOutcome,
    RedactedValueOutcome,
    RedactionConfig,
    merge_redaction_summaries,
)
from aerlog.capture.sinks import (
    CaptureSink,
    InMemoryCaptureSink,
    RecoverySpool,
    default_spool_path,
)

__all__ = [
    "REDACTED_KEY_BLOCK_MARKER",
    "REDACTED_MARKER",
    "REDACTION_FAILED_MARKER",
    "CaptureConfig",
    "CapturePipeline",
    "CaptureProxyObserver",
    "CaptureSink",
    "EventNormalizer",
    "EventRedactor",
    "InMemoryCaptureSink",
    "RawCaptureInput",
    "RawCaptureWarningInput",
    "RawChildShutdownEscalateInput",
    "RawFrameTooLargeInput",
    "RawIncompleteFrameInput",
    "RawProcessExitedInput",
    "RawProxySignalInput",
    "RawStderrLineInput",
    "RawTransportErrorInput",
    "RawWireFrameInput",
    "RecoverySpool",
    "RedactedTextOutcome",
    "RedactedValueOutcome",
    "RedactionConfig",
    "default_spool_path",
    "estimate_raw_input_bytes",
    "merge_redaction_summaries",
]
