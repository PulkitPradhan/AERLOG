"""Versioned, integrity-hashed replay cassette schema, builder, and safe persistence."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aerlog.analysis.timeline import reconstruct_timeline
from aerlog.events.models import (
    ExecutionEvent,
    JsonRpcErrorPayload,
    JsonRpcIdValue,
    JsonRpcNotificationPayload,
    JsonRpcRequestPayload,
    JsonRpcResponsePayload,
)
from aerlog.events.types import JsonRpcIdType, WireDirection
from aerlog.replay.safety import (
    CassetteIntegrityError,
    CassetteSchemaVersionError,
    CassetteValidationError,
    ReplayMissingCassetteError,
    SideEffectClass,
    UnredactedCassetteRefusedError,
    classify_interaction_safety,
    sanitize_command_for_metadata,
)
from aerlog.storage.event_log import (
    JsonlReadResult,
    canonical_event_sha256,
    validate_execution_id,
    write_atomic_private_json,
)
from aerlog.storage.exceptions import StorageCorruptionError
from aerlog.storage.repositories import RecordingRepository

CASSETTE_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
CASSETTES_DIR_NAME: Final[str] = "cassettes"
CASSETTE_FILE_SUFFIX: Final[str] = ".cassette.json"


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def compute_params_hashes(params: Any, *, has_params: bool = True) -> tuple[str, str]:
    """Return ``(exact_params_sha256, normalized_params_sha256)`` digests.

    ``normalized_params_sha256`` strips volatile top-level ``_meta`` metadata
    (e.g., ``progressToken``, ``traceparent``) while keeping functional inputs
    such as tool ``name``, ``arguments``, and pagination ``cursor`` intact.
    """
    raw_repr: Any = params if has_params else "__AERLOG_NO_PARAMS__"
    if has_params and isinstance(params, Mapping):
        norm_repr: Any = {k: v for k, v in params.items() if k != "_meta"}
    else:
        norm_repr = raw_repr

    def _digest(value: Any) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    return _digest(raw_repr), _digest(norm_repr)


class CassetteNotification(BaseModel):
    """Recorded JSON-RPC notification stored safely inside a replay cassette."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    sequence: int = Field(ge=1)
    direction: WireDirection
    method: str
    params: Any = None
    has_params: bool = False
    extra_fields: dict[str, Any] = Field(default_factory=dict)
    target_interaction_index: int | None = Field(default=None, ge=0)
    target_request_sequence: int | None = Field(default=None, ge=1)


class CassetteInteraction(BaseModel):
    """Single chronological recorded request exchange paired with its response & safety tag."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    interaction_index: int = Field(ge=0)
    request_event_id: str
    request_sequence: int = Field(ge=1)
    origin_direction: WireDirection
    method: str
    request_id: JsonRpcIdValue = None
    request_id_type: JsonRpcIdType
    params: Any = None
    has_params: bool = False
    extra_fields: dict[str, Any] = Field(default_factory=dict)
    exact_params_sha256: str
    normalized_params_sha256: str
    tool_name: str | None = None
    side_effect_class: SideEffectClass
    side_effect_reason: str
    outcome: str
    response_event_id: str | None = None
    response_sequence: int | None = Field(default=None, ge=1)
    response_kind: Literal["jsonrpc_response", "jsonrpc_error"] | None = None
    response_result: Any = None
    response_error: Any = None
    response_error_code: int | None = None
    response_error_message: str | None = None
    response_error_data: Any = None
    response_extra_fields: dict[str, Any] = Field(default_factory=dict)
    emitted_notifications: tuple[CassetteNotification, ...] = ()
    recorded_duration_ns: int | None = Field(default=None, ge=0)
    cancel_notified: bool = False
    replayable: bool = True
    non_replayable_reason: str | None = None


class Cassette(BaseModel):
    """Self-contained, hashed, immutable offline replay cassette artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cassette_schema_version: Literal["1.0.0"] = CASSETTE_SCHEMA_VERSION
    cassette_id: str
    created_at: datetime
    source_execution_id: str
    source_timeline_version: str
    source_capture_completeness: str
    source_redaction_mode: str
    source_unclean_shutdown: bool = False
    source_has_corruptions: bool = False
    contains_raw_secrets: bool = False
    contains_redacted_placeholders: bool = False
    command_summary: tuple[str, ...] = ()
    observed_mcp_protocol_versions: tuple[str, ...] = ()
    interactions: tuple[CassetteInteraction, ...] = ()
    standalone_notifications: tuple[CassetteNotification, ...] = ()
    cancellations: tuple[CassetteNotification, ...] = ()
    cassette_sha256: str | None = None

    @field_validator("created_at")
    @classmethod
    def _normalize_created_at(cls, value: datetime) -> datetime:
        return _ensure_utc(value)


def compute_cassette_sha256(cassette: Cassette) -> str:
    """Compute canonical SHA-256 digest over ``cassette`` excluding ``cassette_sha256``."""
    payload = cassette.model_dump(mode="json", exclude={"cassette_sha256"})
    return canonical_event_sha256(payload)


def seal_cassette_digest(cassette: Cassette) -> Cassette:
    """Attach canonical ``cassette_sha256`` to an unsigned :class:`Cassette`."""
    digest = compute_cassette_sha256(cassette)
    return cassette.model_copy(update={"cassette_sha256": digest})


def verify_cassette_integrity(cassette: Cassette) -> None:
    """Verify major schema version and exact SHA-256 match for ``cassette``."""
    version_parts = cassette.cassette_schema_version.split(".", 1)
    if version_parts[0] != "1":
        raise CassetteSchemaVersionError(
            f"Unsupported cassette_schema_version {cassette.cassette_schema_version!r}"
        )
    if not cassette.cassette_sha256:
        raise CassetteIntegrityError("Cassette is missing required cassette_sha256 integrity hash")
    expected = compute_cassette_sha256(cassette)
    if expected != cassette.cassette_sha256:
        raise CassetteIntegrityError(
            f"Cassette integrity mismatch: expected {expected}, recorded {cassette.cassette_sha256}"
        )


def parse_untrusted_cassette_dict(raw_data: object) -> Cassette:
    """Strictly parse and integrity-verify an untrusted JSON dict into :class:`Cassette`."""
    if not isinstance(raw_data, dict):
        raise CassetteValidationError("Untrusted cassette root JSON value must be an object")

    raw_version = raw_data.get("cassette_schema_version")
    if not isinstance(raw_version, str) or "." not in raw_version:
        raise CassetteSchemaVersionError(
            f"Invalid or missing cassette_schema_version: {raw_version!r}"
        )
    major = raw_version.split(".", 1)[0]
    expected_major = CASSETTE_SCHEMA_VERSION.split(".", 1)[0]
    if major != expected_major:
        raise CassetteSchemaVersionError(
            f"Unsupported cassette_schema_version {raw_version!r}; expected {expected_major}.x"
        )

    try:
        cassette = Cassette.model_validate(raw_data)
    except ValidationError as exc:
        raise CassetteValidationError(f"Cassette schema validation failed: {exc}") from exc

    verify_cassette_integrity(cassette)
    return cassette


def _extract_tool_annotations(events: Sequence[ExecutionEvent]) -> dict[str, dict[str, Any]]:
    """Collect tool annotations advertised in ``tools/list`` responses."""
    annotations_by_name: dict[str, dict[str, Any]] = {}
    for ev in events:
        if not isinstance(ev.payload, JsonRpcResponsePayload):
            continue
        res = ev.payload.result
        if not isinstance(res, Mapping):
            continue
        tools = res.get("tools")
        if not isinstance(tools, list):
            continue
        for tool in tools:
            if not isinstance(tool, Mapping):
                continue
            name = tool.get("name")
            ann = tool.get("annotations")
            if isinstance(name, str) and name and isinstance(ann, Mapping):
                annotations_by_name[name] = dict(ann)
    return annotations_by_name


def _contains_redacted_placeholders(events: Sequence[ExecutionEvent]) -> bool:
    for ev in events:
        if ev.redaction.findings_count > 0 or ev.redaction.payload_mode == "strict_hash_only":
            return True
    return False


def build_cassette_from_read_result(
    read_result: JsonlReadResult,
    *,
    strict_integrity: bool = False,
    allow_unredacted_cassette: bool = False,
    cassette_id: str | None = None,
) -> Cassette:
    """Build a sealed :class:`Cassette` from a Phase 5 :class:`JsonlReadResult`."""
    if strict_integrity and read_result.has_corruptions:
        first = read_result.corruptions[0]
        raise StorageCorruptionError(
            f"Refusing cassette build under strict integrity: {first.details}"
        )
    timeline = reconstruct_timeline(read_result)
    redaction_mode = timeline.redaction_mode
    if redaction_mode == "explicit_unredacted" and not allow_unredacted_cassette:
        raise UnredactedCassetteRefusedError(
            f"Recording {read_result.execution_id!r} uses redaction_mode='explicit_unredacted'; "
            "pass '--allow-unredacted-cassette' (allow_unredacted_cassette=True) to confirm "
            "exporting unredacted payloads into a replay cassette."
        )

    events = sorted((item.event for item in read_result.events), key=lambda item: item.sequence)
    events_by_id = {ev.event_id: ev for ev in events}
    annotations_by_name = _extract_tool_annotations(events)

    interactions: list[CassetteInteraction] = []
    span_index_by_req_eid: dict[str, int] = {}
    linked_notif_eids: set[str] = set()

    for span in timeline.spans:
        if span.span_kind != "request_exchange" or span.request_event_id is None:
            continue
        req_ev = events_by_id.get(span.request_event_id)
        if req_ev is None or not isinstance(req_ev.payload, JsonRpcRequestPayload):
            continue
        req = req_ev.payload
        if not req.method:
            continue

        wire_dir: WireDirection = (
            "server_to_client" if req_ev.direction == "server_to_client" else "client_to_server"
        )
        tool_name: str | None = None
        if req.method == "tools/call" and isinstance(req.params, Mapping):
            raw_tool = req.params.get("name")
            if isinstance(raw_tool, str) and raw_tool:
                tool_name = raw_tool

        safety = classify_interaction_safety(
            req.method,
            tool_name=tool_name,
            tool_annotations=annotations_by_name.get(tool_name) if tool_name else None,
        )
        exact_hash, norm_hash = compute_params_hashes(req.params, has_params=req.has_params)

        resp_ev = (
            events_by_id.get(span.response_event_id) if span.response_event_id is not None else None
        )
        resp_kind: Literal["jsonrpc_response", "jsonrpc_error"] | None = None
        resp_result: Any = None
        resp_error: Any = None
        resp_error_code: int | None = None
        resp_error_message: str | None = None
        resp_error_data: Any = None
        resp_extra: dict[str, Any] = {}

        if resp_ev is not None and isinstance(resp_ev.payload, JsonRpcResponsePayload):
            resp_kind = "jsonrpc_response"
            resp_result = resp_ev.payload.result
            resp_extra = dict(resp_ev.payload.extra_fields)
        elif resp_ev is not None and isinstance(resp_ev.payload, JsonRpcErrorPayload):
            resp_kind = "jsonrpc_error"
            resp_error = resp_ev.payload.error
            resp_error_code = resp_ev.payload.error_code
            resp_error_message = resp_ev.payload.error_message
            resp_error_data = resp_ev.payload.error_data
            resp_extra = dict(resp_ev.payload.extra_fields)

        emitted_notifs: list[CassetteNotification] = []
        idx = len(interactions)
        for rel_eid in span.related_event_ids:
            rel_ev = events_by_id.get(rel_eid)
            if rel_ev is None or not isinstance(rel_ev.payload, JsonRpcNotificationPayload):
                continue
            if rel_ev.payload.method == "notifications/cancelled":
                continue
            if not rel_ev.payload.method:
                continue
            rel_dir: WireDirection = (
                "client_to_server" if rel_ev.direction == "client_to_server" else "server_to_client"
            )
            linked_notif_eids.add(rel_ev.event_id)
            emitted_notifs.append(
                CassetteNotification(
                    event_id=rel_ev.event_id,
                    sequence=rel_ev.sequence,
                    direction=rel_dir,
                    method=rel_ev.payload.method,
                    params=rel_ev.payload.params,
                    has_params=rel_ev.payload.has_params,
                    extra_fields=dict(rel_ev.payload.extra_fields),
                    target_interaction_index=idx,
                    target_request_sequence=req_ev.sequence,
                )
            )

        unreplayable_reason: str | None = None
        replayable = True
        if resp_kind is None or span.outcome in {
            "missing_response",
            "cancelled_no_response",
            "uncompleted_recording",
            "ambiguous_correlation",
            "invalid_id",
        }:
            replayable = False
            unreplayable_reason = span.outcome

        interactions.append(
            CassetteInteraction(
                interaction_index=idx,
                request_event_id=req_ev.event_id,
                request_sequence=req_ev.sequence,
                origin_direction=wire_dir,
                method=req.method,
                request_id=req.id,
                request_id_type=req.id_type,
                params=req.params,
                has_params=req.has_params,
                extra_fields=dict(req.extra_fields),
                exact_params_sha256=exact_hash,
                normalized_params_sha256=norm_hash,
                tool_name=tool_name,
                side_effect_class=safety.side_effect_class,
                side_effect_reason=safety.reason,
                outcome=span.outcome,
                response_event_id=resp_ev.event_id if resp_ev else None,
                response_sequence=resp_ev.sequence if resp_ev else None,
                response_kind=resp_kind,
                response_result=resp_result,
                response_error=resp_error,
                response_error_code=resp_error_code,
                response_error_message=resp_error_message,
                response_error_data=resp_error_data,
                response_extra_fields=resp_extra,
                emitted_notifications=tuple(emitted_notifs),
                recorded_duration_ns=span.duration_ns,
                cancel_notified=span.cancel_notified,
                replayable=replayable,
                non_replayable_reason=unreplayable_reason,
            )
        )
        span_index_by_req_eid[req_ev.event_id] = idx

    standalone_notifs: list[CassetteNotification] = []
    cancellations: list[CassetteNotification] = []
    for ev in events:
        if ev.event_id in linked_notif_eids or not isinstance(
            ev.payload, JsonRpcNotificationPayload
        ):
            continue
        if not ev.payload.method:
            continue
        notif_dir: WireDirection = (
            "server_to_client" if ev.direction == "server_to_client" else "client_to_server"
        )
        target_eid = ev.correlation.matched_request_event_id if ev.correlation else None
        target_idx = span_index_by_req_eid.get(target_eid) if target_eid else None
        target_seq = interactions[target_idx].request_sequence if target_idx is not None else None
        notif_obj = CassetteNotification(
            event_id=ev.event_id,
            sequence=ev.sequence,
            direction=notif_dir,
            method=ev.payload.method,
            params=ev.payload.params,
            has_params=ev.payload.has_params,
            extra_fields=dict(ev.payload.extra_fields),
            target_interaction_index=target_idx,
            target_request_sequence=target_seq,
        )
        if ev.payload.method == "notifications/cancelled":
            cancellations.append(notif_obj)
        else:
            standalone_notifs.append(notif_obj)

    versions = (
        tuple(read_result.summary.observed_mcp_protocol_versions)
        if read_result.summary is not None
        else ()
    )
    resolved_id = (
        validate_execution_id(cassette_id) if cassette_id is not None else str(uuid.uuid4())
    )
    unsigned = Cassette(
        cassette_id=resolved_id,
        created_at=datetime.now(UTC),
        source_execution_id=read_result.execution_id,
        source_timeline_version=timeline.timeline_version,
        source_capture_completeness=timeline.capture_completeness,
        source_redaction_mode=redaction_mode,
        source_unclean_shutdown=timeline.unclean_shutdown,
        source_has_corruptions=timeline.has_corruptions,
        contains_raw_secrets=(redaction_mode == "explicit_unredacted"),
        contains_redacted_placeholders=_contains_redacted_placeholders(events),
        command_summary=sanitize_command_for_metadata(timeline.command),
        observed_mcp_protocol_versions=versions,
        interactions=tuple(interactions),
        standalone_notifications=tuple(standalone_notifs),
        cancellations=tuple(cancellations),
    )
    return seal_cassette_digest(unsigned)


def build_cassette_from_execution(
    repo: RecordingRepository,
    execution_id: str,
    *,
    strict_integrity: bool = False,
    verify_checksums: bool = True,
    allow_unredacted_cassette: bool = False,
    cassette_id: str | None = None,
) -> Cassette:
    """Build a :class:`Cassette` directly from an immutable execution via ``repo``."""
    repo.get_execution(execution_id)
    read_result = repo.get_execution_events(
        execution_id,
        strict_integrity=strict_integrity,
        verify_checksums=verify_checksums,
        mark_missing=False,
    )
    return build_cassette_from_read_result(
        read_result,
        strict_integrity=strict_integrity,
        allow_unredacted_cassette=allow_unredacted_cassette,
        cassette_id=cassette_id,
    )


def resolve_cassette_path(data_dir: Path, cassette_id: str) -> Path:
    """Resolve ``<data_dir>/cassettes/<cassette_id>.cassette.json`` with containment checks."""
    clean_id = validate_execution_id(cassette_id)
    cassettes_root = (data_dir / CASSETTES_DIR_NAME).resolve()
    target = (cassettes_root / f"{clean_id}{CASSETTE_FILE_SUFFIX}").resolve()
    if not target.is_relative_to(cassettes_root) or target.parent != cassettes_root:
        raise CassetteValidationError(f"Path containment violation for cassette_id {clean_id!r}")
    return target


def save_cassette(
    cassette: Cassette,
    *,
    data_dir: Path | None = None,
    output_path: Path | None = None,
) -> Path:
    """Persist ``cassette`` atomically with ``0o600`` file permissions and return path."""
    if output_path is not None:
        target = output_path.expanduser().resolve()
    elif data_dir is not None:
        target = resolve_cassette_path(data_dir, cassette.cassette_id)
    else:
        raise ValueError("Either data_dir or output_path must be supplied to save_cassette()")

    sealed = (
        cassette
        if cassette.cassette_sha256 == compute_cassette_sha256(cassette)
        else seal_cassette_digest(cassette)
    )
    write_atomic_private_json(target, sealed.model_dump(mode="json"), fsync=True)
    return target


def load_cassette(
    target: str | Path,
    *,
    data_dir: Path | None = None,
) -> tuple[Cassette, Path]:
    """Load, strictly validate, and SHA-256 verify a cassette by ID or file path.

    Read-only: never creates XDG directories or storage files.
    """
    raw_str = str(target)
    if isinstance(target, Path) or "/" in raw_str or "\\" in raw_str or raw_str.endswith(".json"):
        candidate = Path(target).expanduser()
        if not candidate.is_file():
            raise ReplayMissingCassetteError(f"Cassette file not found: {candidate}")
        resolved_path = candidate.resolve()
    else:
        if data_dir is None:
            raise ValueError("data_dir is required when loading a cassette by UUID")
        candidate = resolve_cassette_path(data_dir, raw_str)
        if not candidate.is_file():
            raise ReplayMissingCassetteError(f"Cassette {raw_str!r} not found at {candidate}")
        resolved_path = candidate

    try:
        text = resolved_path.read_text(encoding="utf-8")
        decoded = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CassetteValidationError(f"Failed reading cassette {resolved_path}: {exc}") from exc

    return parse_untrusted_cassette_dict(decoded), resolved_path


__all__ = [
    "CASSETTES_DIR_NAME",
    "CASSETTE_FILE_SUFFIX",
    "CASSETTE_SCHEMA_VERSION",
    "Cassette",
    "CassetteInteraction",
    "CassetteNotification",
    "build_cassette_from_execution",
    "build_cassette_from_read_result",
    "compute_cassette_sha256",
    "compute_params_hashes",
    "load_cassette",
    "parse_untrusted_cassette_dict",
    "resolve_cassette_path",
    "save_cassette",
    "seal_cassette_digest",
    "verify_cassette_integrity",
]
