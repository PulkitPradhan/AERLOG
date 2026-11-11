"""Pre-persistence redaction engine for AERLOG capture pipelines.

Redaction operates solely on copied/decoded capture structures before persistence
or recovery spooling and never mutates forwarded wire protocol bytes.
"""

from __future__ import annotations

import copy
import re
import warnings
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from aerlog.events.models import RedactionSummary
from aerlog.events.types import PayloadMode, RedactionMode
from aerlog.protocol.jsonrpc import redact_text as _protocol_redact_text

REDACTED_MARKER = "[REDACTED]"
REDACTED_KEY_BLOCK_MARKER = "[REDACTED_PRIVATE_KEY]"
REDACTION_FAILED_MARKER = "[REDACTION_FAILED_WITHHELD]"

_MAX_RECURSION_DEPTH = 64
_MAX_RECORDED_PATHS = 128

_PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z0-9 _-]{0,32}?PRIVATE KEY-----")
_PEM_END_RE = re.compile(r"-----END [A-Z0-9 _-]{0,32}?PRIVATE KEY-----")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
_URL_USERINFO_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]{0,31}+://)(?:[^/\s:@?#]+:[^/\s@?#]*|[^/\s:@?#]*:[^/\s@?#]+)@"
)

_SAFE_COMPACT_KEYS = frozenset(
    {
        "progresstoken",
        "nextcursor",
        "cursor",
        "tokencount",
        "maxtokens",
        "inputtokens",
        "outputtokens",
        "totaltokens",
        "cachecreationinputtokens",
        "cachereadinputtokens",
    }
)

_SENSITIVE_KEY_TOKENS = frozenset(
    {
        "authorization",
        "proxy_authorization",
        "api_key",
        "apikey",
        "x_api_key",
        "access_token",
        "refresh_token",
        "id_token",
        "auth_token",
        "session_token",
        "bearer_token",
        "client_secret",
        "private_key",
        "secret_key",
        "signing_key",
        "encryption_key",
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "credential",
        "credentials",
        "cookie",
        "set_cookie",
        "connection_string",
        "bearer",
        "secrets",
        "tokens",
        "passwords",
        "api_keys",
        "aws_secret_access_key",
    }
)

_SENSITIVE_CLI_FLAG_NAMES = frozenset(
    {
        "--api-key",
        "--apikey",
        "--token",
        "--access-token",
        "--refresh-token",
        "--client-secret",
        "--secret",
        "--secret-key",
        "--signing-key",
        "--password",
        "--passwd",
        "--passphrase",
        "--private-key",
        "--auth",
        "--authorization",
        "--bearer",
    }
)

_ACRONYM_SPLIT_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
_KEY_SPLIT_RE = re.compile(r"([a-z0-9])([A-Z])")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class RedactionConfig:
    """Configuration controlling pre-persistence capture redaction."""

    mode: RedactionMode = "standard"
    extra_sensitive_keys: tuple[str, ...] = ()
    extra_secret_patterns: tuple[str, ...] = ()
    max_text_chars: int = 65_536

    def __post_init__(self) -> None:
        if self.mode not in ("standard", "strict_hash_only", "explicit_unredacted"):
            raise ValueError(f"Unsupported redaction_mode: {self.mode!r}")
        if self.max_text_chars < 0:
            raise ValueError("max_text_chars must be non-negative")
        for pattern in self.extra_secret_patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Invalid extra_secret_patterns regex {pattern!r}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class RedactedTextOutcome:
    """Result of redacting a text value along with summary audit metadata."""

    text: str | None
    truncated: bool
    summary: RedactionSummary


@dataclass(frozen=True, slots=True)
class RedactedValueOutcome:
    """Result of redacting an arbitrary JSON-compatible value."""

    value: Any
    summary: RedactionSummary


def _normalize_key_snake(key: str) -> str:
    acronym_split = _ACRONYM_SPLIT_RE.sub(r"\1_\2", key)
    camel_split = _KEY_SPLIT_RE.sub(r"\1_\2", acronym_split)
    return _NON_ALNUM_RE.sub("_", camel_split.lower()).strip("_")


def _redact_pem_blocks(text: str) -> tuple[str, int]:
    """Scan linearly for bounded PEM private key blocks to prevent ReDoS."""
    if "-----BEGIN " not in text or "-----END " not in text:
        return text, 0
    out: list[str] = []
    pos = 0
    count = 0
    while True:
        begin_match = _PEM_BEGIN_RE.search(text, pos)
        if begin_match is None:
            break
        end_match = _PEM_END_RE.search(text, begin_match.end())
        if end_match is None:
            break
        out.append(text[pos : begin_match.start()])
        out.append(REDACTED_KEY_BLOCK_MARKER)
        pos = end_match.end()
        count += 1
    if count == 0:
        return text, 0
    out.append(text[pos:])
    return "".join(out), count


def _is_safe_key(key: str) -> bool:
    compact = _normalize_key_snake(key).replace("_", "")
    return compact in _SAFE_COMPACT_KEYS


class EventRedactor:
    """Recursive, fail-safe redactor applied before persistence or spooling."""

    def __init__(self, config: RedactionConfig | None = None) -> None:
        self._config = config or RedactionConfig()
        if self._config.mode == "explicit_unredacted":
            warnings.warn(
                "AERLOG capture initialized with redaction_mode='explicit_unredacted'; "
                "unredacted secrets may be written to capture output or recovery spool.",
                UserWarning,
                stacklevel=2,
            )
        self._extra_sensitive_snake = frozenset(
            _normalize_key_snake(k) for k in self._config.extra_sensitive_keys if k.strip()
        )
        self._extra_patterns = tuple(
            re.compile(pattern) for pattern in self._config.extra_secret_patterns
        )

    @property
    def config(self) -> RedactionConfig:
        """Return active redaction configuration."""
        return self._config

    def _is_sensitive_key(self, key: str) -> bool:
        if _is_safe_key(key):
            return False
        norm = _normalize_key_snake(key)
        compact = norm.replace("_", "")
        if norm in _SENSITIVE_KEY_TOKENS or compact in _SENSITIVE_KEY_TOKENS:
            return True
        if norm in self._extra_sensitive_snake:
            return True
        parts = norm.split("_") if norm else []
        if parts and parts[-1] in {
            "secret",
            "secrets",
            "password",
            "passwords",
            "passwd",
            "passphrase",
            "token",
            "tokens",
        }:
            return True
        return any(
            norm.endswith(suffix)
            for suffix in (
                "_api_key",
                "_private_key",
                "_secret_key",
                "_signing_key",
                "_access_key",
            )
        )

    def _redact_string_impl(self, text: str) -> tuple[str, int]:
        current, findings = _redact_pem_blocks(text)

        # Pre-check literal delimiters before running URL regex on multi-MiB strings.
        if "://" in current and "@" in current:
            current, count = _URL_USERINFO_RE.subn(rf"\1{REDACTED_MARKER}@", current)
            findings += count

        if "eyJ" in current:
            current, count = _JWT_RE.subn(REDACTED_MARKER, current)
            findings += count

        after_protocol = _protocol_redact_text(current)
        if after_protocol != current:
            findings += 1
            current = after_protocol

        for extra_re in self._extra_patterns:
            current, count = extra_re.subn(REDACTED_MARKER, current)
            findings += count

        return current, findings

    def _redact_nested(
        self,
        value: Any,
        path: str,
        paths: list[str],
        findings: list[int],
        depth: int,
    ) -> Any:
        if depth > _MAX_RECURSION_DEPTH:
            raise RecursionError(f"Redaction nesting exceeded {_MAX_RECURSION_DEPTH} levels")

        if isinstance(value, str):
            redacted, count = self._redact_string_impl(value)
            if count > 0:
                findings[0] += count
                if len(paths) < _MAX_RECORDED_PATHS:
                    paths.append(path or "$")
            return redacted

        if isinstance(value, Mapping):
            out: dict[str, Any] = {}
            for raw_k, raw_v in value.items():
                raw_key_str = str(raw_k)
                k, key_findings = self._redact_string_impl(raw_key_str)
                child_path = f"{path}.{k}" if path else k
                if key_findings > 0:
                    findings[0] += key_findings
                    if len(paths) < _MAX_RECORDED_PATHS:
                        paths.append(child_path or "$")
                if self._is_sensitive_key(raw_key_str):
                    out[k] = self._redact_sensitive_subtree(
                        raw_v, child_path, paths, findings, depth + 1
                    )
                else:
                    out[k] = self._redact_nested(raw_v, child_path, paths, findings, depth + 1)
            return out

        if isinstance(value, list | tuple):
            return [
                self._redact_nested(item, f"{path}[{idx}]", paths, findings, depth + 1)
                for idx, item in enumerate(value)
            ]

        return value

    def _redact_sensitive_subtree(
        self,
        value: Any,
        path: str,
        paths: list[str],
        findings: list[int],
        depth: int,
    ) -> Any:
        if depth > _MAX_RECURSION_DEPTH:
            raise RecursionError(f"Redaction nesting exceeded {_MAX_RECURSION_DEPTH} levels")
        if value is None:
            return None
        if isinstance(value, Mapping):
            return {
                str(k): self._redact_sensitive_subtree(v, f"{path}.{k}", paths, findings, depth + 1)
                for k, v in value.items()
            }
        if isinstance(value, list | tuple):
            return [
                self._redact_sensitive_subtree(item, f"{path}[{idx}]", paths, findings, depth + 1)
                for idx, item in enumerate(value)
            ]
        findings[0] += 1
        if len(paths) < _MAX_RECORDED_PATHS:
            paths.append(path or "$")
        return REDACTED_MARKER

    def redact_value(self, value: Any, *, root_path: str = "") -> RedactedValueOutcome:
        """Redact a JSON-compatible object according to ``self.config.mode``.

        On any internal redaction failure, returns a withheld placeholder and sets
        ``summary.degraded=True`` without returning raw sensitive data.
        """
        mode = self._config.mode
        if mode == "explicit_unredacted":
            return RedactedValueOutcome(
                value=copy.deepcopy(value),
                summary=RedactionSummary(
                    mode=mode,
                    payload_mode="full_unredacted",
                    applied=False,
                    degraded=False,
                    findings_count=0,
                    redacted_paths=(),
                ),
            )

        if mode == "strict_hash_only":
            return RedactedValueOutcome(
                value=None,
                summary=RedactionSummary(
                    mode=mode,
                    payload_mode="strict_hash_only",
                    applied=True,
                    degraded=False,
                    findings_count=0,
                    redacted_paths=(root_path,) if root_path else (),
                ),
            )

        paths: list[str] = []
        findings = [0]
        try:
            redacted = self._redact_nested(value, root_path, paths, findings, depth=0)
        except Exception as exc:
            return RedactedValueOutcome(
                value=None,
                summary=RedactionSummary(
                    mode=mode,
                    payload_mode="redaction_failed",
                    applied=False,
                    degraded=True,
                    findings_count=0,
                    redacted_paths=(root_path,) if root_path else (),
                    error=repr(exc),
                ),
            )

        return RedactedValueOutcome(
            value=redacted,
            summary=RedactionSummary(
                mode=mode,
                payload_mode="redacted",
                applied=True,
                degraded=False,
                findings_count=findings[0],
                redacted_paths=tuple(paths),
            ),
        )

    def redact_text_value(
        self,
        text: str,
        *,
        path_label: str = "text",
        max_chars: int | None = None,
    ) -> RedactedTextOutcome:
        """Redact an unstructured string (such as stderr, malformed JSON, or EOF bytes)."""
        limit = self._config.max_text_chars if max_chars is None else max_chars
        mode = self._config.mode

        if mode == "strict_hash_only":
            return RedactedTextOutcome(
                text=None,
                truncated=bool(text),
                summary=RedactionSummary(
                    mode=mode,
                    payload_mode="strict_hash_only",
                    applied=True,
                    degraded=False,
                    findings_count=0,
                    redacted_paths=(path_label,),
                ),
            )

        if mode == "explicit_unredacted":
            truncated = len(text) > limit if limit >= 0 else False
            bounded = text[:limit] if limit >= 0 else text
            return RedactedTextOutcome(
                text=bounded,
                truncated=truncated,
                summary=RedactionSummary(
                    mode=mode,
                    payload_mode="full_unredacted",
                    applied=False,
                    degraded=False,
                ),
            )

        try:
            redacted, count = self._redact_string_impl(text)
        except Exception as exc:
            return RedactedTextOutcome(
                text=REDACTION_FAILED_MARKER,
                truncated=False,
                summary=RedactionSummary(
                    mode=mode,
                    payload_mode="redaction_failed",
                    applied=False,
                    degraded=True,
                    redacted_paths=(path_label,),
                    error=repr(exc),
                ),
            )

        effective_limit = max(0, limit)
        truncated = len(redacted) > effective_limit
        bounded = redacted[:effective_limit]
        return RedactedTextOutcome(
            text=bounded,
            truncated=truncated,
            summary=RedactionSummary(
                mode=mode,
                payload_mode="redacted",
                applied=True,
                degraded=False,
                findings_count=count,
                redacted_paths=(path_label,) if count > 0 else (),
            ),
        )

    def redact_command(self, command: Sequence[str]) -> tuple[tuple[str, ...], RedactionSummary]:
        """Redact secrets in command-line flags and URL credentials safely."""
        mode = self._config.mode
        if mode == "explicit_unredacted":
            return tuple(command), RedactionSummary(
                mode=mode,
                payload_mode="full_unredacted",
                applied=False,
            )

        if mode == "strict_hash_only":
            head = (command[0],) if command else ()
            masked = head + ("[REDACTED_ARGS]",) * max(0, len(command) - 1)
            return masked, RedactionSummary(
                mode=mode,
                payload_mode="strict_hash_only",
                applied=True,
                redacted_paths=("command",) if len(command) > 1 else (),
            )

        paths: list[str] = []
        findings = 0
        out: list[str] = []
        redact_next_arg = False

        try:
            for idx, arg in enumerate(command):
                if redact_next_arg:
                    out.append(REDACTED_MARKER)
                    findings += 1
                    paths.append(f"command[{idx}]")
                    redact_next_arg = False
                    continue

                lowered = arg.lower()
                if lowered in _SENSITIVE_CLI_FLAG_NAMES:
                    out.append(arg)
                    redact_next_arg = True
                    continue

                eq_idx = arg.find("=")
                if eq_idx > 0 and arg[:eq_idx].lower() in _SENSITIVE_CLI_FLAG_NAMES:
                    out.append(f"{arg[:eq_idx]}={REDACTED_MARKER}")
                    findings += 1
                    paths.append(f"command[{idx}]")
                    continue

                redacted_arg, arg_count = self._redact_string_impl(arg)
                out.append(redacted_arg)
                if arg_count > 0:
                    findings += arg_count
                    if len(paths) < _MAX_RECORDED_PATHS:
                        paths.append(f"command[{idx}]")
        except Exception as exc:
            safe_head = (command[0],) if command else ()
            return (*safe_head, REDACTION_FAILED_MARKER), RedactionSummary(
                mode=mode,
                payload_mode="redaction_failed",
                applied=False,
                degraded=True,
                redacted_paths=("command",),
                error=repr(exc),
            )

        return tuple(out), RedactionSummary(
            mode=mode,
            payload_mode="redacted",
            applied=True,
            degraded=False,
            findings_count=findings,
            redacted_paths=tuple(paths),
        )

    def redact_env_overrides(
        self, env: Mapping[str, str] | None
    ) -> tuple[tuple[str, ...], dict[str, str], RedactionSummary]:
        """Return override key names and safe/redacted override values."""
        if not env:
            return (
                (),
                {},
                RedactionSummary(
                    mode=self._config.mode,
                    payload_mode=self.default_payload_mode,
                    applied=self._config.mode != "explicit_unredacted",
                ),
            )

        keys = tuple(sorted(env.keys()))
        outcome = self.redact_value(dict(env), root_path="env")
        if outcome.summary.degraded or not isinstance(outcome.value, dict):
            return keys, {}, outcome.summary
        sanitized = {k: str(v) for k, v in outcome.value.items()}
        return keys, sanitized, outcome.summary

    @property
    def default_payload_mode(self) -> PayloadMode:
        """Return default :type:`PayloadMode` corresponding to configured mode."""
        if self._config.mode == "explicit_unredacted":
            return "full_unredacted"
        if self._config.mode == "strict_hash_only":
            return "strict_hash_only"
        return "redacted"


def merge_redaction_summaries(
    mode: RedactionMode,
    summaries: Sequence[RedactionSummary],
) -> RedactionSummary:
    """Combine multiple field-level :class:`RedactionSummary` records into one envelope audit."""
    if not summaries:
        payload_mode: PayloadMode = (
            "full_unredacted"
            if mode == "explicit_unredacted"
            else "strict_hash_only"
            if mode == "strict_hash_only"
            else "redacted"
        )
        return RedactionSummary(
            mode=mode,
            payload_mode=payload_mode,
            applied=mode != "explicit_unredacted",
        )

    degraded = any(s.degraded for s in summaries)
    applied = all(s.applied for s in summaries) if not degraded else False
    findings_count = sum(s.findings_count for s in summaries)
    seen_paths: list[str] = []
    seen_set: set[str] = set()
    errors: list[str] = []
    for s in summaries:
        for p in s.redacted_paths:
            if p not in seen_set and len(seen_paths) < _MAX_RECORDED_PATHS:
                seen_set.add(p)
                seen_paths.append(p)
        if s.error:
            errors.append(s.error)

    if degraded:
        final_mode: PayloadMode = "redaction_failed"
    elif mode == "strict_hash_only":
        final_mode = "strict_hash_only"
    elif mode == "explicit_unredacted":
        final_mode = "full_unredacted"
    else:
        final_mode = "redacted"

    return RedactionSummary(
        mode=mode,
        payload_mode=final_mode,
        applied=applied,
        degraded=degraded,
        findings_count=findings_count,
        redacted_paths=tuple(seen_paths),
        error="; ".join(errors) if errors else None,
    )


def scrub_event_dict_withheld(
    raw_event: dict[str, Any],
    *,
    redactor: EventRedactor,
    failure_replacement: str | None = None,
) -> dict[str, Any]:
    """Fail-closed scrubbing of a serialized ``ExecutionEvent`` dictionary.

    Used by recovery spooling and spool import under ``strict_hash_only`` or
    when standard redaction fails so raw wire, error, and trace data cannot leak.
    """
    out = copy.deepcopy(raw_event)
    payload = out.get("payload")
    if isinstance(payload, dict):
        for key in (
            "params",
            "result",
            "error",
            "error_message",
            "error_data",
            "value",
            "text",
            "raw_bytes_b64",
            "redacted_lossy_text",
            "cwd",
        ):
            if key in payload:
                payload[key] = None
        for key in ("extra_fields", "details", "redacted_env_overrides"):
            if key in payload:
                payload[key] = {}
        for key in ("unanswered_request_ids", "env_override_keys"):
            if key in payload:
                payload[key] = []
        if "body" in payload:
            payload["body"] = {}
        if "command" in payload and isinstance(payload["command"], list):
            if failure_replacement is not None:
                payload["command"] = [failure_replacement]
            else:
                safe_cmd, _ = redactor.redact_command([str(c) for c in payload["command"]])
                payload["command"] = list(safe_cmd)
        if failure_replacement is not None:
            for req_str_key in ("error", "message"):
                if req_str_key in payload and isinstance(payload[req_str_key], str):
                    payload[req_str_key] = failure_replacement
            if payload.get("kind") == "child_shutdown_escalate":
                payload["error"] = None

    trace = out.get("trace")
    if isinstance(trace, dict) and "observed_tracestate" in trace:
        trace["observed_tracestate"] = None
    derived = out.get("derived")
    if isinstance(derived, dict) and "otel_attributes" in derived:
        derived["otel_attributes"] = {}
    return out


__all__ = [
    "REDACTED_KEY_BLOCK_MARKER",
    "REDACTED_MARKER",
    "REDACTION_FAILED_MARKER",
    "EventRedactor",
    "RedactedTextOutcome",
    "RedactedValueOutcome",
    "RedactionConfig",
    "merge_redaction_summaries",
]
