"""Read-only JSON-RPC envelope inspection and diagnostic secret redaction.

Nothing in this module mutates forwarded protocol bytes. Diagnostic helpers
redact obvious credentials on a best-effort basis and omit full payloads;
environments requiring zero payload previews should set ``include_previews=False``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from aerlog.protocol.framing import LineEnding, detect_line_ending

EventKind = Literal["protocol_frame", "non_object_json", "malformed_json", "malformed_utf8"]
MessageKind = Literal["request", "notification", "response", "error_response", "unknown_object"]

_AUTH_SCHEME_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}")
_TOKEN_PREFIX_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{16,})\b"
)
_QUOTED_SECRET_KV_RE = re.compile(
    r'(?i)(["\']?(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|'
    r'client[_-]?secret|private[_-]?key|password|passwd|secret|token)["\']?\s*[:=]\s*)'
    r'(?:"[^"]*"|\'[^\']*\')'
)
_UNQUOTED_SECRET_KV_RE = re.compile(
    r"(?i)(\b(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key|password|passwd|secret|token)\s*[:=]\s*)"
    r'(?:(?:bearer|basic)\s+)?([^\s,}&;"\']+)'
)


def redact_text(text: str) -> str:
    """Apply best-effort regex redaction for obvious tokens, keys, and passwords.

    Note:
        Best-effort redaction cannot guarantee removal of arbitrary unstructured
        secrets; diagnostic logs may still carry sensitive text unless payload
        previews are disabled via configuration.
    """
    redacted = _QUOTED_SECRET_KV_RE.sub(r'\1"[REDACTED]"', text)
    redacted = _UNQUOTED_SECRET_KV_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _AUTH_SCHEME_RE.sub(r"\1 [REDACTED]", redacted)
    return _TOKEN_PREFIX_RE.sub("[REDACTED]", redacted)


@dataclass(frozen=True, slots=True)
class FrameObservation:
    """Structured metadata derived read-only from one framed byte slice."""

    direction: str
    event_kind: EventKind
    byte_length: int
    line_ending: LineEnding
    message_kind: MessageKind | None = None
    request_id: int | str | None = None
    has_id: bool = False
    method: str | None = None
    keys: tuple[str, ...] = ()
    json_type: str | None = None
    error: str | None = None
    preview: str | None = None
    preview_hex: str | None = None

    def to_diagnostic_fields(self) -> dict[str, Any]:
        """Serialize only structural metadata (and bounded preview if enabled)."""
        fields: dict[str, Any] = {
            "direction": self.direction,
            "byte_length": self.byte_length,
            "line_ending": self.line_ending,
        }
        if self.event_kind == "protocol_frame":
            fields["kind"] = self.message_kind
            fields["id"] = self.request_id
            fields["has_id"] = self.has_id
            fields["method"] = self.method
            fields["keys"] = list(self.keys)
        elif self.event_kind == "non_object_json":
            fields["json_type"] = self.json_type
        elif self.event_kind == "malformed_json":
            fields["error"] = self.error
            if self.preview is not None:
                fields["preview"] = self.preview
        elif self.event_kind == "malformed_utf8":
            fields["error"] = self.error
            if self.preview_hex is not None:
                fields["preview_hex"] = self.preview_hex
        return fields


def _coerce_request_id(value: object) -> int | str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def inspect_frame(
    direction: str,
    raw_frame: bytes,
    *,
    include_previews: bool = True,
    preview_max_chars: int = 120,
    preview_max_hex_bytes: int = 32,
) -> FrameObservation:
    """Inspect a raw protocol frame without modifying its bytes or dropping fields.

    Args:
        direction: Stream direction label (``client_to_server`` or ``server_to_client``).
        raw_frame: Exact frame bytes read from the wire.
        include_previews: Whether bounded redacted previews may be recorded for
            malformed UTF-8/JSON diagnostics. Valid JSON payloads are never previewed.
        preview_max_chars: Maximum character length of malformed JSON previews.
        preview_max_hex_bytes: Maximum byte count hex-encoded for invalid UTF-8 previews.

    Returns:
        Read-only :class:`FrameObservation` summarizing the frame.
    """
    line_ending = detect_line_ending(raw_frame)
    payload = raw_frame[:-1] if raw_frame.endswith(b"\n") else raw_frame
    if payload.endswith(b"\r"):
        payload = payload[:-1]

    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        preview_hex = payload[:preview_max_hex_bytes].hex() if include_previews else None
        return FrameObservation(
            direction=direction,
            event_kind="malformed_utf8",
            byte_length=len(raw_frame),
            line_ending=line_ending,
            error=f"utf8_decode_error: {exc}",
            preview_hex=preview_hex,
        )

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        preview = redact_text(text)[:preview_max_chars] if include_previews else None
        return FrameObservation(
            direction=direction,
            event_kind="malformed_json",
            byte_length=len(raw_frame),
            line_ending=line_ending,
            error=f"json_decode_error: {exc}",
            preview=preview,
        )

    if not isinstance(parsed, dict):
        return FrameObservation(
            direction=direction,
            event_kind="non_object_json",
            byte_length=len(raw_frame),
            line_ending=line_ending,
            json_type=type(parsed).__name__,
        )

    has_id = "id" in parsed
    request_id = _coerce_request_id(parsed.get("id")) if has_id else None
    raw_method = parsed.get("method")
    method = raw_method if isinstance(raw_method, str) else None

    if "method" in parsed:
        message_kind: MessageKind = "request" if has_id else "notification"
    elif "result" in parsed:
        message_kind = "response"
    elif "error" in parsed:
        message_kind = "error_response"
    else:
        message_kind = "unknown_object"

    return FrameObservation(
        direction=direction,
        event_kind="protocol_frame",
        byte_length=len(raw_frame),
        line_ending=line_ending,
        message_kind=message_kind,
        request_id=request_id,
        has_id=has_id,
        method=method,
        keys=tuple(sorted(str(k) for k in parsed)),
    )
