"""Identifier generation and W3C Trace Context parsing helpers.

Note on identity semantics:
    ``execution_id`` and ``event_id`` use standard :func:`uuid.uuid4`. They are
    globally unique random UUIDv4 identifiers and are intentionally **not**
    time-sortable. Authoritative intra-execution ordering uses ``sequence`` and
    duration calculations use ``monotonic_time_ns``.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass

from aerlog.events.types import TraceSource

_TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace_id>[0-9a-f]{32})-"
    r"(?P<parent_id>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)


@dataclass(frozen=True, slots=True)
class W3CTraceparent:
    """Validated components of an observed W3C ``traceparent`` header."""

    version: str
    trace_id: str
    parent_span_id: str
    trace_flags: str
    raw: str


def new_execution_id() -> str:
    """Return a unique UUIDv4 execution identifier (unique, not time-sortable)."""
    return str(uuid.uuid4())


def new_event_id() -> str:
    """Return a unique UUIDv4 event identifier (unique, not time-sortable)."""
    return str(uuid.uuid4())


def synthetic_trace_id_for_execution(execution_id: str) -> str:
    """Derive a deterministic 32-hex synthetic trace identifier from ``execution_id``.

    This value is strictly an execution-scoped synthetic grouping key and must
    never be represented as an observed wire W3C ``traceparent`` trace ID.
    """
    parsed = uuid.UUID(execution_id)
    return parsed.hex


def parse_w3c_traceparent(value: object) -> W3CTraceparent | None:
    """Parse and validate a W3C ``traceparent`` string without mutating input.

    Returns ``None`` if ``value`` is not a valid W3C traceparent string (including
    all-zero trace/parent IDs or reserved version ``ff``).
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    match = _TRACEPARENT_RE.fullmatch(stripped)
    if match is None:
        return None

    version = match.group("version")
    trace_id = match.group("trace_id")
    parent_id = match.group("parent_id")
    flags = match.group("flags")

    if version == "ff":
        return None
    if trace_id == "0" * 32 or parent_id == "0" * 16:
        return None

    return W3CTraceparent(
        version=version,
        trace_id=trace_id,
        parent_span_id=parent_id,
        trace_flags=flags,
        raw=stripped,
    )


@dataclass(frozen=True, slots=True)
class ObservedTraceExtraction:
    """Result of read-only extraction from wire ``params._meta``."""

    trace_source: TraceSource
    observed_traceparent: W3CTraceparent | None
    observed_tracestate: str | None
    invalid_traceparent_present: bool
    synthetic_execution_trace_id: str | None


def extract_observed_trace_from_params(
    params: object,
    *,
    execution_id: str | None = None,
) -> ObservedTraceExtraction:
    """Inspect ``params._meta`` read-only for W3C ``traceparent`` / ``tracestate``.

    Wire messages are never modified, and parent/child relationships are never
    fabricated when wire trace headers are absent or invalid.
    """
    synthetic_id = (
        synthetic_trace_id_for_execution(execution_id) if execution_id is not None else None
    )

    if not isinstance(params, Mapping):
        return ObservedTraceExtraction(
            trace_source="synthetic_execution" if synthetic_id is not None else "none",
            observed_traceparent=None,
            observed_tracestate=None,
            invalid_traceparent_present=False,
            synthetic_execution_trace_id=synthetic_id,
        )

    meta = params.get("_meta")
    if not isinstance(meta, Mapping):
        return ObservedTraceExtraction(
            trace_source="synthetic_execution" if synthetic_id is not None else "none",
            observed_traceparent=None,
            observed_tracestate=None,
            invalid_traceparent_present=False,
            synthetic_execution_trace_id=synthetic_id,
        )

    raw_traceparent = meta.get("traceparent")
    raw_tracestate = meta.get("tracestate")
    tracestate = raw_tracestate if isinstance(raw_tracestate, str) and raw_tracestate else None

    if "traceparent" not in meta:
        return ObservedTraceExtraction(
            trace_source="synthetic_execution" if synthetic_id is not None else "none",
            observed_traceparent=None,
            observed_tracestate=tracestate,
            invalid_traceparent_present=False,
            synthetic_execution_trace_id=synthetic_id,
        )

    parsed = parse_w3c_traceparent(raw_traceparent)
    if parsed is None:
        return ObservedTraceExtraction(
            trace_source="synthetic_execution" if synthetic_id is not None else "none",
            observed_traceparent=None,
            observed_tracestate=tracestate,
            invalid_traceparent_present=True,
            synthetic_execution_trace_id=synthetic_id,
        )

    return ObservedTraceExtraction(
        trace_source="w3c_meta",
        observed_traceparent=parsed,
        observed_tracestate=tracestate,
        invalid_traceparent_present=False,
        synthetic_execution_trace_id=synthetic_id,
    )


__all__ = [
    "ObservedTraceExtraction",
    "W3CTraceparent",
    "extract_observed_trace_from_params",
    "new_event_id",
    "new_execution_id",
    "parse_w3c_traceparent",
    "synthetic_trace_id_for_execution",
]
