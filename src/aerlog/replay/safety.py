"""Replay safety policies, side-effect classification, and fail-closed live blocks."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict

from aerlog.capture.redaction import EventRedactor, RedactionConfig

SideEffectClass = Literal[
    "protocol_control",
    "read_only_hint",
    "potentially_mutating",
    "unknown_unsafe",
]
UnsafeToolPolicy = Literal["block", "warn"]
ReplayMode = Literal["cassette", "live"]

_PROTOCOL_CONTROL_METHODS: Final[frozenset[str]] = frozenset(
    {
        "completion/complete",
        "initialize",
        "logging/setLevel",
        "notifications/cancelled",
        "notifications/initialized",
        "notifications/progress",
        "ping",
        "server/discover",
    }
)

_DISCOVERY_READ_METHODS: Final[frozenset[str]] = frozenset(
    {
        "prompts/list",
        "resources/list",
        "resources/templates/list",
        "roots/list",
        "tools/list",
    }
)

_MUTATING_VERBS: Final[frozenset[str]] = frozenset(
    {
        "append",
        "chmod",
        "chown",
        "commit",
        "create",
        "delete",
        "deploy",
        "drop",
        "edit",
        "eval",
        "exec",
        "execute",
        "insert",
        "kill",
        "modify",
        "mutate",
        "mv",
        "patch",
        "pay",
        "post",
        "publish",
        "purge",
        "push",
        "put",
        "remove",
        "rename",
        "reset",
        "rm",
        "run",
        "save",
        "send",
        "set",
        "shell",
        "spawn",
        "transfer",
        "trigger",
        "truncate",
        "update",
        "upsert",
        "write",
    }
)

_ACRONYM_BOUNDARY_RE: Final[re.Pattern[str]] = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_BOUNDARY_RE: Final[re.Pattern[str]] = re.compile(r"([a-z0-9])([A-Z])")
_TOKEN_SPLIT_RE: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")


class ReplayError(Exception):
    """Base error raised by AERLOG cassette replay operations."""


class LiveReplayBlockedError(ReplayError):
    """Raised whenever live replay is requested; offline cassette replay only is permitted."""


class UnredactedCassetteRefusedError(ReplayError):
    """Raised when building a cassette from explicit_unredacted data without explicit opt-in."""


class CassetteValidationError(ReplayError):
    """Raised when loading or validating an untrusted cassette JSON artifact fails."""


class CassetteIntegrityError(CassetteValidationError):
    """Raised when a cassette SHA-256 digest does not match its contents."""


class CassetteSchemaVersionError(CassetteValidationError):
    """Raised when a cassette carries an unsupported or newer major schema version."""


class ReplayMissingCassetteError(ReplayError):
    """Raised when a requested cassette file or source execution cannot be located."""


class ReplayInterruptedError(ReplayError):
    """Raised when ``serve_cassette_stdio`` is interrupted cleanly by an OS signal."""

    def __init__(self, *, signal_num: int, signal_name: str) -> None:
        self.signal_num = signal_num
        self.signal_name = signal_name
        self.exit_code = 128 + signal_num
        super().__init__(f"Replay server interrupted by {signal_name} (exit_code={self.exit_code})")


class ToolSideEffectAssessment(BaseModel):
    """Conservative side-effect classification attached to a recorded interaction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    side_effect_class: SideEffectClass
    reason: str
    tool_name: str | None = None


class SafetyAuditNotice(BaseModel):
    """Explicit non-silent safety notice emitted during cassette replay."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    severity: Literal["info", "warning", "error"]
    method: str
    tool_name: str | None = None
    side_effect_class: SideEffectClass
    message: str


def _tokenize_name(raw_name: str) -> set[str]:
    acronym_split = _ACRONYM_BOUNDARY_RE.sub(r"\1_\2", raw_name)
    snake = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", acronym_split).lower()
    return {tok for tok in _TOKEN_SPLIT_RE.split(snake) if tok}


def ensure_replay_mode_allowed(mode: str) -> Literal["cassette"]:
    """Allow strictly offline cassette replay and fail closed on live replay requests."""
    normalized = mode.strip().lower()
    if normalized == "cassette":
        return "cassette"
    if normalized == "live":
        raise LiveReplayBlockedError(
            "Live replay mode is blocked to prevent executing real MCP tools, subprocesses, "
            "or external side effects. Re-run with '--mode cassette' for safe offline replay."
        )
    raise ValueError(f"Unsupported replay mode {mode!r}; expected 'cassette' or 'live'")


def classify_interaction_safety(
    method: str,
    *,
    tool_name: str | None = None,
    tool_annotations: Mapping[str, Any] | None = None,
) -> ToolSideEffectAssessment:
    """Conservatively classify an MCP method/tool call for offline replay gating."""
    if method in _PROTOCOL_CONTROL_METHODS:
        return ToolSideEffectAssessment(
            side_effect_class="protocol_control",
            reason="Standard MCP protocol handshake or control frame",
            tool_name=tool_name,
        )

    if method in _DISCOVERY_READ_METHODS:
        return ToolSideEffectAssessment(
            side_effect_class="read_only_hint",
            reason="Standard MCP discovery method; safe to serve from offline cassette",
            tool_name=tool_name,
        )

    if method == "tools/call":
        name_tokens = _tokenize_name(tool_name) if tool_name else set()
        if any(verb in _MUTATING_VERBS for verb in name_tokens):
            matched = sorted(verb for verb in name_tokens if verb in _MUTATING_VERBS)
            return ToolSideEffectAssessment(
                side_effect_class="potentially_mutating",
                reason=f"Tool name indicates potential side effects ({', '.join(matched)})",
                tool_name=tool_name,
            )

        if tool_annotations is not None:
            destructive_hint = tool_annotations.get("destructiveHint")
            read_only_hint = tool_annotations.get("readOnlyHint")
            if destructive_hint is True:
                return ToolSideEffectAssessment(
                    side_effect_class="potentially_mutating",
                    reason="tools/list annotation declared destructiveHint=true",
                    tool_name=tool_name,
                )
            if read_only_hint is False:
                return ToolSideEffectAssessment(
                    side_effect_class="potentially_mutating",
                    reason="tools/list annotation declared readOnlyHint=false",
                    tool_name=tool_name,
                )
            if read_only_hint is True:
                return ToolSideEffectAssessment(
                    side_effect_class="read_only_hint",
                    reason=(
                        "tools/list annotation declared readOnlyHint=true "
                        "(server hint only, not execution proof)"
                    ),
                    tool_name=tool_name,
                )

        return ToolSideEffectAssessment(
            side_effect_class="unknown_unsafe",
            reason="Tool has no verified readOnlyHint annotation; unknown tools default to unsafe",
            tool_name=tool_name,
        )

    method_tokens = _tokenize_name(method)
    if any(verb in _MUTATING_VERBS for verb in method_tokens):
        return ToolSideEffectAssessment(
            side_effect_class="potentially_mutating",
            reason=f"Method {method!r} contains potential mutation verb",
            tool_name=tool_name,
        )

    return ToolSideEffectAssessment(
        side_effect_class="unknown_unsafe",
        reason=f"Unclassified method {method!r} defaults to unknown_unsafe",
        tool_name=tool_name,
    )


def requires_unsafe_opt_in(side_effect_class: SideEffectClass) -> bool:
    """Return True if replaying ``side_effect_class`` requires explicit opt-in under 'block'."""
    return side_effect_class in ("potentially_mutating", "unknown_unsafe")


def sanitize_command_for_metadata(command: Sequence[str]) -> tuple[str, ...]:
    """Redact command-line arguments strictly for display metadata; never executed."""
    redactor = EventRedactor(RedactionConfig(mode="standard"))
    safe_cmd, _ = redactor.redact_command(command)
    return safe_cmd


__all__ = [
    "CassetteIntegrityError",
    "CassetteSchemaVersionError",
    "CassetteValidationError",
    "LiveReplayBlockedError",
    "ReplayError",
    "ReplayInterruptedError",
    "ReplayMissingCassetteError",
    "ReplayMode",
    "SafetyAuditNotice",
    "SideEffectClass",
    "ToolSideEffectAssessment",
    "UnredactedCassetteRefusedError",
    "UnsafeToolPolicy",
    "classify_interaction_safety",
    "ensure_replay_mode_allowed",
    "requires_unsafe_opt_in",
    "sanitize_command_for_metadata",
]
