"""Offline cassette replay runner, divergence tracker, and cassette-backed stdio mock server."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aerlog.events.models import classify_jsonrpc_id
from aerlog.protocol.framing import DEFAULT_MAX_FRAME_BYTES, FrameAccumulator, FrameTooLargeError
from aerlog.replay.cassette import Cassette, verify_cassette_integrity
from aerlog.replay.matcher import (
    CassetteMatcher,
    MatchOutcomeKind,
    MissingResponsePolicy,
    ReplayDivergence,
    ReplayMatchMode,
)
from aerlog.replay.safety import (
    CassetteValidationError,
    SafetyAuditNotice,
    SideEffectClass,
    UnsafeToolPolicy,
    ensure_replay_mode_allowed,
)
from aerlog.storage.event_log import validate_execution_id, write_atomic_private_json

REPLAY_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
REPLAYS_DIR_NAME: Final[str] = "replays"
REPLAY_REPORT_FILE_NAME: Final[str] = "report.json"

ReplayDriverMode = Literal["self_replay", "transcript_replay", "stdio_mock_server"]
ReplayOverallStatus = Literal["clean_match", "matched_with_warnings", "diverged"]

_DEFAULT_REPLAY_LIMITATIONS: Final[tuple[str, ...]] = (
    "Cassette replay serves stored wire responses offline without invoking the original MCP "
    "server process, tool handlers, or external network endpoints.",
    "Replay validates protocol sequence alignment against recorded interactions; it cannot "
    "prove whether a live server would behave identically today.",
    "If the source recording masked secrets via redaction, replayed fields contain redacted "
    "markers rather than original raw credentials.",
)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class ReplayStepOutcome(BaseModel):
    """Per-message outcome captured while executing an offline cassette replay."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_index: int = Field(ge=0)
    kind: Literal["request", "notification"]
    method: str
    tool_name: str | None = None
    incoming_request_id: Any = None
    matched_interaction_index: int | None = Field(default=None, ge=0)
    source_request_sequence: int | None = Field(default=None, ge=1)
    source_response_sequence: int | None = Field(default=None, ge=1)
    outcome_kind: MatchOutcomeKind
    side_effect_class: SideEffectClass | None = None
    recorded_outcome: str | None = None
    replayed_status: str
    id_rebound: bool = False
    diverged: bool = False
    divergence_message: str | None = None
    safety_notice: SafetyAuditNotice | None = None


class ReplayReport(BaseModel):
    """Immutable replay report persisted distinctly from original captured executions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    replay_schema_version: Literal["1.0.0"] = REPLAY_SCHEMA_VERSION
    is_replay: Literal[True] = True
    replay_id: str
    replayed_at: datetime
    replay_mode: Literal["cassette"] = "cassette"
    driver_mode: ReplayDriverMode
    source_execution_id: str
    cassette_id: str
    cassette_sha256: str | None = None
    contains_raw_secrets: bool = False
    contains_redacted_placeholders: bool = False
    match_mode: ReplayMatchMode
    unsafe_tool_policy: UnsafeToolPolicy
    missing_response_policy: MissingResponsePolicy
    overall_status: ReplayOverallStatus
    total_steps: int = Field(ge=0)
    matched_count: int = Field(ge=0)
    diverged_count: int = Field(ge=0)
    blocked_count: int = Field(ge=0)
    unmatched_count: int = Field(ge=0)
    missing_response_count: int = Field(ge=0)
    safety_warning_count: int = Field(ge=0)
    steps: tuple[ReplayStepOutcome, ...] = ()
    divergences: tuple[ReplayDivergence, ...] = ()
    safety_notices: tuple[SafetyAuditNotice, ...] = ()
    limitations: tuple[str, ...] = _DEFAULT_REPLAY_LIMITATIONS

    @field_validator("replayed_at")
    @classmethod
    def _normalize_replayed_at(cls, value: datetime) -> datetime:
        return _ensure_utc(value)


def resolve_replay_report_path(data_dir: Path, replay_id: str) -> Path:
    """Resolve ``<data_dir>/replays/<replay_id>/report.json`` with strict path containment."""
    clean_id = validate_execution_id(replay_id)
    replays_root = (data_dir / REPLAYS_DIR_NAME).resolve()
    target = (replays_root / clean_id / REPLAY_REPORT_FILE_NAME).resolve()
    if not target.is_relative_to(replays_root) or target.parent == replays_root:
        raise CassetteValidationError(f"Path containment violation for replay_id {clean_id!r}")
    return target


def save_replay_report(report: ReplayReport, *, data_dir: Path) -> Path:
    """Persist ``report`` cleanly under ``<data_dir>/replays/<replay_id>/report.json``."""
    target = resolve_replay_report_path(data_dir, report.replay_id)
    write_atomic_private_json(target, report.model_dump(mode="json"), fsync=True)
    return target


def load_replay_report(replay_id: str, *, data_dir: Path) -> ReplayReport:
    """Load and strictly validate a previously saved :class:`ReplayReport`."""
    target = resolve_replay_report_path(data_dir, replay_id)
    if target.is_symlink():
        raise CassetteValidationError(f"Refusing symlink replay report: {target}")
    try:
        decoded = json.loads(target.read_text(encoding="utf-8"))
        return ReplayReport.model_validate(decoded)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CassetteValidationError(f"Failed loading replay report {target}: {exc}") from exc


class CassetteReplaySession:
    """Shared replay state machine driving matcher decisions into a :class:`ReplayReport`."""

    def __init__(
        self,
        cassette: Cassette,
        *,
        driver_mode: ReplayDriverMode,
        match_mode: ReplayMatchMode = "strict",
        unsafe_tool_policy: UnsafeToolPolicy = "block",
        missing_response_policy: MissingResponsePolicy = "error",
        require_exact_id: bool = False,
        replay_id: str | None = None,
    ) -> None:
        verify_cassette_integrity(cassette)
        self._cassette = cassette
        self._driver_mode: ReplayDriverMode = driver_mode
        self._match_mode: ReplayMatchMode = match_mode
        self._unsafe_tool_policy: UnsafeToolPolicy = unsafe_tool_policy
        self._missing_response_policy: MissingResponsePolicy = missing_response_policy
        self._replay_id = (
            validate_execution_id(replay_id) if replay_id is not None else str(uuid.uuid4())
        )
        self._matcher = CassetteMatcher(
            cassette,
            match_mode=match_mode,
            unsafe_tool_policy=unsafe_tool_policy,
            missing_response_policy=missing_response_policy,
            require_exact_id=require_exact_id,
        )
        self._steps: list[ReplayStepOutcome] = []
        self._divergences: list[ReplayDivergence] = []
        self._safety_notices: list[SafetyAuditNotice] = []
        self._matched_count = 0
        self._diverged_count = 0
        self._blocked_count = 0
        self._unmatched_count = 0
        self._missing_response_count = 0

    def process_incoming_object(
        self,
        raw_obj: Mapping[str, Any],
    ) -> tuple[tuple[dict[str, Any], ...], dict[str, Any] | None]:
        """Match one JSON-RPC request/notification and return outgoing notification/reply frames."""
        step_index = len(self._steps)
        method_raw = raw_obj.get("method")
        method = str(method_raw) if isinstance(method_raw, str) else "<missing-method>"
        has_params = "params" in raw_obj
        params = raw_obj.get("params")

        is_request = "id" in raw_obj and raw_obj.get("id") is not None and "method" in raw_obj
        if is_request:
            id_type, id_val = classify_jsonrpc_id(raw_obj)
            decision = self._matcher.match_request(
                method=method,
                params=params,
                has_params=has_params,
                request_id=id_val,
                id_type=id_type,
            )
            step_kind: Literal["request", "notification"] = "request"
            incoming_req_id: Any = id_val
        else:
            decision = self._matcher.match_notification(method=method, params=params)
            step_kind = "notification"
            incoming_req_id = None

        if decision.safety_notice is not None:
            self._safety_notices.append(decision.safety_notice)
        if decision.divergence is not None:
            self._divergences.append(decision.divergence)

        if decision.outcome_kind == "blocked_unsafe_tool":
            self._blocked_count += 1
        elif decision.outcome_kind == "missing_recorded_response":
            self._missing_response_count += 1
        elif decision.outcome_kind in {
            "unmatched_request",
            "out_of_order_request",
            "repeated_request_exhausted",
        }:
            self._unmatched_count += 1
        elif decision.matched and step_kind == "request":
            self._matched_count += 1

        if decision.diverged:
            self._diverged_count += 1

        slot = decision.interaction
        replayed_status = (
            "served_from_cassette"
            if decision.response_frame_obj is not None and not decision.diverged
            else decision.outcome_kind
        )
        self._steps.append(
            ReplayStepOutcome(
                step_index=step_index,
                kind=step_kind,
                method=method,
                tool_name=slot.tool_name if slot is not None else None,
                incoming_request_id=incoming_req_id,
                matched_interaction_index=slot.interaction_index if slot is not None else None,
                source_request_sequence=slot.request_sequence if slot is not None else None,
                source_response_sequence=slot.response_sequence if slot is not None else None,
                outcome_kind=decision.outcome_kind,
                side_effect_class=decision.side_effect_class,
                recorded_outcome=slot.outcome if slot is not None else None,
                replayed_status=replayed_status,
                id_rebound=decision.id_rebound,
                diverged=decision.diverged,
                divergence_message=decision.divergence.message if decision.divergence else None,
                safety_notice=decision.safety_notice,
            )
        )
        return decision.emitted_notifications, decision.response_frame_obj

    def finalize(self) -> ReplayReport:
        """Finalize counters, record unconsumed cassette slots, and build :class:`ReplayReport`."""
        unconsumed = self._matcher.unconsumed_client_interactions()
        if unconsumed:
            self._divergences.append(
                ReplayDivergence(
                    kind="unconsumed_recorded_interactions",
                    severity="warning",
                    step_index=None,
                    method=None,
                    message=(
                        f"{len(unconsumed)} recorded client interaction(s) were not replayed."
                    ),
                    details={
                        "unconsumed_indices": [s.interaction_index for s in unconsumed],
                        "methods": [s.method for s in unconsumed],
                    },
                )
            )
            self._diverged_count += 1

        safety_warning_count = len(self._safety_notices)
        overall_status: ReplayOverallStatus
        if self._diverged_count > 0 or self._blocked_count > 0 or self._unmatched_count > 0:
            overall_status = "diverged"
        elif safety_warning_count > 0:
            overall_status = "matched_with_warnings"
        else:
            overall_status = "clean_match"

        return ReplayReport(
            replay_id=self._replay_id,
            replayed_at=datetime.now(UTC),
            driver_mode=self._driver_mode,
            source_execution_id=self._cassette.source_execution_id,
            cassette_id=self._cassette.cassette_id,
            cassette_sha256=self._cassette.cassette_sha256,
            contains_raw_secrets=self._cassette.contains_raw_secrets,
            contains_redacted_placeholders=self._cassette.contains_redacted_placeholders,
            match_mode=self._match_mode,
            unsafe_tool_policy=self._unsafe_tool_policy,
            missing_response_policy=self._missing_response_policy,
            overall_status=overall_status,
            total_steps=len(self._steps),
            matched_count=self._matched_count,
            diverged_count=self._diverged_count,
            blocked_count=self._blocked_count,
            unmatched_count=self._unmatched_count,
            missing_response_count=self._missing_response_count,
            safety_warning_count=safety_warning_count,
            steps=tuple(self._steps),
            divergences=tuple(self._divergences),
            safety_notices=tuple(self._safety_notices),
        )


def _self_replay_messages(cassette: Cassette) -> list[dict[str, Any]]:
    """Construct chronological client-originated JSON-RPC objects for self-replay."""
    timed_items: list[tuple[int, dict[str, Any]]] = []

    for slot in cassette.interactions:
        if slot.origin_direction != "client_to_server":
            continue
        obj: dict[str, Any] = dict(slot.extra_fields)
        obj["jsonrpc"] = "2.0"
        obj["method"] = slot.method
        if slot.request_id_type != "missing":
            obj["id"] = slot.request_id
        if slot.has_params:
            obj["params"] = slot.params
        timed_items.append((slot.request_sequence, obj))

    for notif in (*cassette.standalone_notifications, *cassette.cancellations):
        if notif.direction != "client_to_server":
            continue
        n_obj: dict[str, Any] = dict(notif.extra_fields)
        n_obj["jsonrpc"] = "2.0"
        n_obj["method"] = notif.method
        if notif.has_params:
            n_obj["params"] = notif.params
        timed_items.append((notif.sequence, n_obj))

    timed_items.sort(key=lambda pair: pair[0])
    return [item for _, item in timed_items]


def replay_cassette(
    cassette: Cassette,
    *,
    mode: str = "cassette",
    match_mode: ReplayMatchMode = "strict",
    unsafe_tool_policy: UnsafeToolPolicy = "block",
    missing_response_policy: MissingResponsePolicy = "error",
    require_exact_id: bool = False,
    incoming_messages: Sequence[Mapping[str, Any]] | None = None,
    replay_id: str | None = None,
) -> ReplayReport:
    """Execute deterministic offline cassette replay and return a :class:`ReplayReport`.

    Live mode (``mode='live'``) is rejected fail-closed by :func:`ensure_replay_mode_allowed`.
    """
    ensure_replay_mode_allowed(mode)
    driver_mode: ReplayDriverMode = (
        "self_replay" if incoming_messages is None else "transcript_replay"
    )
    session = CassetteReplaySession(
        cassette,
        driver_mode=driver_mode,
        match_mode=match_mode,
        unsafe_tool_policy=unsafe_tool_policy,
        missing_response_policy=missing_response_policy,
        require_exact_id=require_exact_id,
        replay_id=replay_id,
    )
    messages = _self_replay_messages(cassette) if incoming_messages is None else incoming_messages
    for msg in messages:
        session.process_incoming_object(msg)
    return session.finalize()


def _encode_json_frame(obj: Mapping[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


async def serve_cassette_stdio(
    cassette: Cassette,
    *,
    mode: str = "cassette",
    match_mode: ReplayMatchMode = "strict",
    unsafe_tool_policy: UnsafeToolPolicy = "block",
    missing_response_policy: MissingResponsePolicy = "error",
    require_exact_id: bool = False,
    read_chunk: Callable[[], bytes] | None = None,
    write_frame: Callable[[bytes], None] | None = None,
    replay_id: str | None = None,
) -> ReplayReport:
    """Run an offline cassette-backed MCP stdio mock server over newline JSON-RPC frames.

    Reads client JSON-RPC requests/notifications from stdin (never spawning any server
    process or making network calls) and writes matching recorded notifications and
    responses to stdout cleanly until EOF.
    """
    ensure_replay_mode_allowed(mode)
    session = CassetteReplaySession(
        cassette,
        driver_mode="stdio_mock_server",
        match_mode=match_mode,
        unsafe_tool_policy=unsafe_tool_policy,
        missing_response_policy=missing_response_policy,
        require_exact_id=require_exact_id,
        replay_id=replay_id,
    )

    stdin_fd = sys.stdin.buffer.fileno() if read_chunk is None else -1
    stdout_fd = sys.stdout.buffer.fileno() if write_frame is None else -1

    def _default_read() -> bytes:
        return os.read(stdin_fd, 65_536)

    def _default_write(data: bytes) -> None:
        view = memoryview(data)
        sent = 0
        while sent < len(data):
            sent += os.write(stdout_fd, view[sent:])

    reader = _default_read if read_chunk is None else read_chunk
    writer = _default_write if write_frame is None else write_frame
    accumulator = FrameAccumulator("client_to_server", DEFAULT_MAX_FRAME_BYTES)

    while True:
        chunk = await asyncio.to_thread(reader)
        if not chunk:
            break
        try:
            frames = accumulator.feed(chunk)
        except FrameTooLargeError as exc:
            err_reply = _encode_json_frame(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": str(exc)},
                }
            )
            await asyncio.to_thread(writer, err_reply)
            break

        for frame in frames:
            try:
                decoded = json.loads(frame.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                err_reply = _encode_json_frame(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Invalid JSON frame: {exc}"},
                    }
                )
                await asyncio.to_thread(writer, err_reply)
                continue

            if not isinstance(decoded, Mapping):
                err_reply = _encode_json_frame(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32600, "message": "Expected JSON-RPC object frame"},
                    }
                )
                await asyncio.to_thread(writer, err_reply)
                continue

            emitted_notifs, reply_obj = session.process_incoming_object(decoded)
            for notif_obj in emitted_notifs:
                await asyncio.to_thread(writer, _encode_json_frame(notif_obj))
            if reply_obj is not None:
                await asyncio.to_thread(writer, _encode_json_frame(reply_obj))

    return session.finalize()


__all__ = [
    "REPLAYS_DIR_NAME",
    "REPLAY_REPORT_FILE_NAME",
    "REPLAY_SCHEMA_VERSION",
    "CassetteReplaySession",
    "ReplayDriverMode",
    "ReplayOverallStatus",
    "ReplayReport",
    "ReplayStepOutcome",
    "load_replay_report",
    "replay_cassette",
    "resolve_replay_report_path",
    "save_replay_report",
    "serve_cassette_stdio",
]
