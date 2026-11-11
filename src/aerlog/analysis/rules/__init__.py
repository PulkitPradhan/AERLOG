"""Approved deterministic diagnostic rules for AERLOG Phase 7."""

from __future__ import annotations

from aerlog.analysis.diagnostics import DiagnosticRule
from aerlog.analysis.rules.behavioral_patterns import detect_repeated_identical_calls
from aerlog.analysis.rules.lifecycle_and_transport import (
    detect_capture_integrity,
    detect_cooperative_cancellations,
    detect_process_exit_and_signals,
    detect_wire_anomalies,
)
from aerlog.analysis.rules.missing_and_timeouts import (
    detect_configured_request_timeouts,
    detect_missing_responses,
    detect_observed_timeouts,
)
from aerlog.analysis.rules.protocol_errors import (
    detect_correlation_anomalies,
    detect_protocol_and_tool_errors,
)

ALL_DIAGNOSTIC_RULES: tuple[DiagnosticRule, ...] = (
    detect_protocol_and_tool_errors,
    detect_correlation_anomalies,
    detect_missing_responses,
    detect_observed_timeouts,
    detect_configured_request_timeouts,
    detect_process_exit_and_signals,
    detect_wire_anomalies,
    detect_cooperative_cancellations,
    detect_capture_integrity,
    detect_repeated_identical_calls,
)

__all__ = [
    "ALL_DIAGNOSTIC_RULES",
    "detect_capture_integrity",
    "detect_configured_request_timeouts",
    "detect_cooperative_cancellations",
    "detect_correlation_anomalies",
    "detect_missing_responses",
    "detect_observed_timeouts",
    "detect_process_exit_and_signals",
    "detect_protocol_and_tool_errors",
    "detect_repeated_identical_calls",
    "detect_wire_anomalies",
]
