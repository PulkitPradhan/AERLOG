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

_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 _-]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 _-]*PRIVATE KEY-----"
)
_ESCAPED_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 _-]*PRIVATE KEY-----[^\"]*?-----END [A-Z0-9 _-]*PRIVATE KEY-----"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
_URL_USERINFO_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]{0,31}+://)([^/\s:@?#]+:[^/\s@?#]*)@")

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
        "--password",
        "--passwd",
        "--private-key",
        "--auth",
        "--authorization",
    }
)

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
    camel_split = _KEY_SPLIT_RE.sub(r"\1_\2", key)
    return _NON_ALNUM_RE.sub("_", camel_split.lower()).strip("_")


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
        if parts and parts[-1] in {"secret", "password", "passwd", "passphrase", "token"}:
            return True
        return any(
            norm.endswith(suffix)
            for suffix in ("_api_key", "_private_key", "_secret_key", "_signing_key")
        )

    def _redact_string_impl(self, text: str) -> tuple[str, int]:
        findings = 0
        current = text

        for regex, replacement in (
            (_PEM_PRIVATE_KEY_RE, REDACTED_KEY_BLOCK_MARKER),
            (_ESCAPED_PEM_PRIVATE_KEY_RE, REDACTED_KEY_BLOCK_MARKER),
        ):
            current, count = regex.subn(replacement, current)
            findings += count

        # Pre-check literal delimiters before running URL regex on multi-MiB strings.
        if "://" in current and "@" in current:
            current, count = _URL_USERINFO_RE.subn(rf"\1{REDACTED_MARKER}@", current)
            findings += count

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
                k = str(raw_k)
                child_path = f"{path}.{k}" if path else k
                if self._is_sensitive_key(k):
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

        truncated = len(redacted) > limit
        bounded = redacted[:limit]
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
