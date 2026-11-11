"""Deterministic request/notification cassette matching for strict and tolerant replay."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aerlog.capture.redaction import REDACTION_FAILED_MARKER, EventRedactor, RedactionConfig
from aerlog.events.models import JsonRpcIdValue, classify_jsonrpc_id
from aerlog.events.types import JsonRpcIdType
from aerlog.replay.cassette import (
    Cassette,
    CassetteInteraction,
    CassetteNotification,
    compute_params_hashes,
)
from aerlog.replay.safety import (
    SafetyAuditNotice,
    SideEffectClass,
    UnsafeToolPolicy,
    classify_interaction_safety,
    requires_unsafe_opt_in,
)

ReplayMatchMode = Literal["strict", "tolerant"]
MissingResponsePolicy = Literal["error", "omit"]

MatchOutcomeKind = Literal[
    "matched_ok",
    "matched_error",
    "matched_tool_error",
    "normalized_match",
    "out_of_order_match",
    "blocked_unsafe_tool",
    "missing_recorded_response",
    "out_of_order_request",
    "unmatched_request",
    "repeated_request_exhausted",
    "cancellation_matched",
    "cancellation_target_missing",
    "notification_ignored",
]

ERR_CASSETTE_UNMATCHED = -32004
ERR_CASSETTE_MISSING_RESPONSE = -32005
ERR_CASSETTE_UNSAFE_BLOCKED = -32010


class ReplayDivergence(BaseModel):
    """Structured mismatch or divergence detected during cassette replay."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal[
        "unmatched_request",
        "out_of_order_request",
        "repeated_request_exhausted",
        "missing_recorded_response",
        "blocked_unsafe_tool",
        "cancellation_target_missing",
        "id_mismatch",
        "unconsumed_recorded_interactions",
    ]
    severity: Literal["info", "warning", "error"]
    step_index: int | None = Field(default=None, ge=0)
    method: str | None = None
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class MatchDecision(BaseModel):
    """Result returned by :class:`CassetteMatcher` for one incoming JSON-RPC message."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    matched: bool
    outcome_kind: MatchOutcomeKind
    interaction: CassetteInteraction | None = None
    response_frame_obj: dict[str, Any] | None = None
    emitted_notifications: tuple[dict[str, Any], ...] = ()
    side_effect_class: SideEffectClass | None = None
    id_rebound: bool = False
    diverged: bool = False
    divergence: ReplayDivergence | None = None
    safety_notice: SafetyAuditNotice | None = None


def _jsonrpc_error_frame(
    *,
    request_id: JsonRpcIdValue,
    id_type: JsonRpcIdType,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    err_obj: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err_obj["data"] = data
    frame: dict[str, Any] = {"jsonrpc": "2.0", "error": err_obj}
    if id_type != "missing":
        frame["id"] = request_id
    return frame


def _build_recorded_response_frame(
    slot: CassetteInteraction,
    *,
    incoming_id: JsonRpcIdValue,
    incoming_id_type: JsonRpcIdType,
) -> dict[str, Any]:
    frame: dict[str, Any] = dict(slot.response_extra_fields)
    frame["jsonrpc"] = "2.0"
    if incoming_id_type != "missing":
        frame["id"] = incoming_id
    else:
        frame.pop("id", None)

    if slot.response_kind == "jsonrpc_error":
        err_val = slot.response_error
        if not isinstance(err_val, dict):
            err_val = {
                "code": slot.response_error_code
                if slot.response_error_code is not None
                else -32603,
                "message": slot.response_error_message or "Recorded JSON-RPC error",
            }
            if slot.response_error_data is not None:
                err_val["data"] = slot.response_error_data
        frame["error"] = err_val
    else:
        frame["result"] = slot.response_result
    return frame


def _build_emitted_notifications(
    slot: CassetteInteraction,
    *,
    incoming_params: Any,
) -> tuple[dict[str, Any], ...]:
    incoming_progress_token: Any = None
    has_incoming_token = False
    if isinstance(incoming_params, Mapping):
        meta = incoming_params.get("_meta")
        if isinstance(meta, Mapping) and "progressToken" in meta:
            incoming_progress_token = meta["progressToken"]
            has_incoming_token = True

    frames: list[dict[str, Any]] = []
    for notif in slot.emitted_notifications:
        obj: dict[str, Any] = dict(notif.extra_fields)
        obj["jsonrpc"] = "2.0"
        obj["method"] = notif.method
        if notif.has_params:
            params_val = notif.params
            if (
                notif.method == "notifications/progress"
                and has_incoming_token
                and isinstance(params_val, Mapping)
            ):
                rebound_params = dict(params_val)
                rebound_params["progressToken"] = incoming_progress_token
                params_val = rebound_params
            obj["params"] = params_val
        frames.append(obj)
    return tuple(frames)


class CassetteMatcher:
    """Stateful sequential/tolerant matcher tracking 1-use cassette interaction slots."""

    def __init__(
        self,
        cassette: Cassette,
        *,
        match_mode: ReplayMatchMode = "strict",
        unsafe_tool_policy: UnsafeToolPolicy = "block",
        missing_response_policy: MissingResponsePolicy = "error",
        require_exact_id: bool = False,
    ) -> None:
        self._cassette = cassette
        self._match_mode: ReplayMatchMode = match_mode
        self._unsafe_tool_policy: UnsafeToolPolicy = unsafe_tool_policy
        self._missing_response_policy: MissingResponsePolicy = missing_response_policy
        self._require_exact_id = require_exact_id

        self._client_slots: tuple[CassetteInteraction, ...] = tuple(
            item for item in cassette.interactions if item.origin_direction == "client_to_server"
        )
        self._tool_annotations: dict[str, dict[str, Any]] = {}
        for item in cassette.interactions:
            if item.method != "tools/list" or not isinstance(item.response_result, Mapping):
                continue
            tools = item.response_result.get("tools")
            if not isinstance(tools, list):
                continue
            for tool in tools:
                if not isinstance(tool, Mapping):
                    continue
                name = tool.get("name")
                ann = tool.get("annotations")
                if isinstance(name, str) and name and isinstance(ann, Mapping):
                    self._tool_annotations[name] = dict(ann)
        self._redactor = EventRedactor(RedactionConfig(mode="standard"))
        self._consumed_indices: set[int] = set()
        self._step_counter = 0
        self._seen_request_keys: dict[tuple[str, str], int] = {}

    def _safe_text(self, value: str) -> str:
        out = self._redactor.redact_text_value(value, path_label="replay.divergence")
        if out.summary.degraded or out.text is None:
            return REDACTION_FAILED_MARKER
        return out.text

    def _safe_value(self, value: Any) -> Any:
        out = self._redactor.redact_value(value, root_path="replay.divergence")
        if out.summary.degraded:
            return REDACTION_FAILED_MARKER
        return out.value

    @property
    def consumed_indices(self) -> frozenset[int]:
        """Set of ``interaction_index`` slots already consumed in this replay session."""
        return frozenset(self._consumed_indices)

    def unconsumed_client_interactions(self) -> tuple[CassetteInteraction, ...]:
        """Return client-to-server cassette interactions not yet replayed."""
        return tuple(
            slot
            for slot in self._client_slots
            if slot.interaction_index not in self._consumed_indices
        )

    def _next_unconsumed_slot(self) -> CassetteInteraction | None:
        for slot in self._client_slots:
            if slot.interaction_index not in self._consumed_indices:
                return slot
        return None

    def _slot_matches_id(
        self,
        slot: CassetteInteraction,
        *,
        incoming_id: JsonRpcIdValue,
        id_type: JsonRpcIdType,
    ) -> bool:
        if not self._require_exact_id:
            return True
        return slot.request_id_type == id_type and slot.request_id == incoming_id

    def _apply_safety_and_build(
        self,
        slot: CassetteInteraction,
        *,
        incoming_id: JsonRpcIdValue,
        id_type: JsonRpcIdType,
        incoming_params: Any,
        step_index: int,
        normalized_used: bool,
        out_of_order_used: bool,
    ) -> MatchDecision:
        id_rebound = slot.request_id_type != id_type or slot.request_id != incoming_id
        safety_notice: SafetyAuditNotice | None = None

        # Always re-compute safety dynamically from slot method, extracted tool name, and
        # verified tools/list annotations rather than trusting stored side_effect_class.
        effective_tool_name: str | None = slot.tool_name
        if slot.method == "tools/call" and isinstance(slot.params, Mapping):
            raw_tool_name = slot.params.get("name")
            if isinstance(raw_tool_name, str) and raw_tool_name:
                effective_tool_name = raw_tool_name
        recomputed = classify_interaction_safety(
            slot.method,
            tool_name=effective_tool_name,
            tool_annotations=(
                self._tool_annotations.get(effective_tool_name) if effective_tool_name else None
            ),
        )
        effective_class = recomputed.side_effect_class
        effective_reason = recomputed.reason
        safe_method = self._safe_text(slot.method)
        safe_tool = self._safe_text(effective_tool_name) if effective_tool_name else None

        if requires_unsafe_opt_in(effective_class):
            if self._unsafe_tool_policy == "block":
                tool_desc = f" tool={safe_tool!r}" if safe_tool else ""
                notice = SafetyAuditNotice(
                    code="BLOCKED_UNSAFE_TOOL",
                    severity="error",
                    method=safe_method,
                    tool_name=safe_tool,
                    side_effect_class=effective_class,
                    message=(
                        f"Blocked replay of {safe_method}{tool_desc} "
                        f"({effective_class}: {effective_reason}); pass "
                        "'--allow-mutating' to serve recorded offline response."
                    ),
                )
                div = ReplayDivergence(
                    kind="blocked_unsafe_tool",
                    severity="error",
                    step_index=step_index,
                    method=safe_method,
                    message=notice.message,
                    details={
                        "interaction_index": slot.interaction_index,
                        "tool_name": safe_tool,
                        "side_effect_class": effective_class,
                    },
                )
                err_frame = _jsonrpc_error_frame(
                    request_id=incoming_id,
                    id_type=id_type,
                    code=ERR_CASSETTE_UNSAFE_BLOCKED,
                    message=notice.message,
                    data={
                        "aerlog_divergence": div.kind,
                        "side_effect_class": effective_class,
                    },
                )
                return MatchDecision(
                    matched=True,
                    outcome_kind="blocked_unsafe_tool",
                    interaction=slot,
                    response_frame_obj=err_frame,
                    side_effect_class=effective_class,
                    id_rebound=id_rebound,
                    diverged=True,
                    divergence=div,
                    safety_notice=notice,
                )

            safety_notice = SafetyAuditNotice(
                code="MUTATING_OPERATION_REPLAYED_OFFLINE",
                severity="warning",
                method=safe_method,
                tool_name=safe_tool,
                side_effect_class=effective_class,
                message=(
                    f"Served offline cassette response for {effective_class} call "
                    f"{safe_method}"
                    + (f" ({safe_tool})" if safe_tool else "")
                    + " under explicit opt-in; no real tool handler executed."
                ),
            )

        if not slot.replayable:
            div = ReplayDivergence(
                kind="missing_recorded_response",
                severity="warning",
                step_index=step_index,
                method=safe_method,
                message=(
                    f"Recorded request #{slot.interaction_index} ({safe_method}) ended with "
                    f"{slot.non_replayable_reason or 'no_response'}; no cached reply exists."
                ),
                details={
                    "interaction_index": slot.interaction_index,
                    "recorded_outcome": slot.outcome,
                    "missing_response_policy": self._missing_response_policy,
                },
            )
            missing_err_frame: dict[str, Any] | None = (
                _jsonrpc_error_frame(
                    request_id=incoming_id,
                    id_type=id_type,
                    code=ERR_CASSETTE_MISSING_RESPONSE,
                    message=div.message,
                    data={"aerlog_divergence": div.kind, "recorded_outcome": slot.outcome},
                )
                if self._missing_response_policy == "error"
                else None
            )
            return MatchDecision(
                matched=True,
                outcome_kind="missing_recorded_response",
                interaction=slot,
                response_frame_obj=missing_err_frame,
                side_effect_class=effective_class,
                id_rebound=id_rebound,
                diverged=True,
                divergence=div,
                safety_notice=safety_notice,
            )

        response_frame = _build_recorded_response_frame(
            slot, incoming_id=incoming_id, incoming_id_type=id_type
        )
        emitted = _build_emitted_notifications(slot, incoming_params=incoming_params)

        div_out: ReplayDivergence | None = None
        outcome_kind: MatchOutcomeKind
        if out_of_order_used:
            outcome_kind = "out_of_order_match"
            div_out = ReplayDivergence(
                kind="out_of_order_request",
                severity="warning",
                step_index=step_index,
                method=safe_method,
                message=(
                    f"Tolerant replay matched slot #{slot.interaction_index} ({safe_method}) "
                    "out of recorded chronological order."
                ),
                details={"matched_interaction_index": slot.interaction_index},
            )
        elif normalized_used:
            outcome_kind = "normalized_match"
        elif slot.outcome == "tool_error":
            outcome_kind = "matched_tool_error"
        elif slot.response_kind == "jsonrpc_error":
            outcome_kind = "matched_error"
        else:
            outcome_kind = "matched_ok"

        return MatchDecision(
            matched=True,
            outcome_kind=outcome_kind,
            interaction=slot,
            response_frame_obj=response_frame,
            emitted_notifications=emitted,
            side_effect_class=effective_class,
            id_rebound=id_rebound,
            diverged=out_of_order_used,
            divergence=div_out,
            safety_notice=safety_notice,
        )

    def match_request(
        self,
        *,
        method: str,
        params: Any,
        has_params: bool,
        request_id: JsonRpcIdValue,
        id_type: JsonRpcIdType,
    ) -> MatchDecision:
        """Match an incoming client JSON-RPC request deterministically against the cassette."""
        step_index = self._step_counter
        self._step_counter += 1
        exact_hash, norm_hash = compute_params_hashes(params, has_params=has_params)

        next_slot = self._next_unconsumed_slot()

        if self._match_mode == "strict":
            if (
                next_slot is not None
                and next_slot.method == method
                and next_slot.exact_params_sha256 == exact_hash
                and self._slot_matches_id(next_slot, incoming_id=request_id, id_type=id_type)
            ):
                self._consumed_indices.add(next_slot.interaction_index)
                self._seen_request_keys[(id_type, repr(request_id))] = next_slot.interaction_index
                return self._apply_safety_and_build(
                    next_slot,
                    incoming_id=request_id,
                    id_type=id_type,
                    incoming_params=params,
                    step_index=step_index,
                    normalized_used=False,
                    out_of_order_used=False,
                )

            if (
                next_slot is not None
                and next_slot.method == method
                and next_slot.exact_params_sha256 == exact_hash
                and not self._slot_matches_id(next_slot, incoming_id=request_id, id_type=id_type)
            ):
                div = ReplayDivergence(
                    kind="id_mismatch",
                    severity="error",
                    step_index=step_index,
                    method=self._safe_text(method),
                    message=(
                        f"Strict exact-ID mismatch for {self._safe_text(method)}: expected "
                        f"{next_slot.request_id_type}:{self._safe_value(next_slot.request_id)!r}, "
                        f"got {id_type}:{self._safe_value(request_id)!r}."
                    ),
                    details={"expected_index": next_slot.interaction_index},
                )
                return MatchDecision(
                    matched=False,
                    outcome_kind="unmatched_request",
                    response_frame_obj=_jsonrpc_error_frame(
                        request_id=request_id,
                        id_type=id_type,
                        code=ERR_CASSETTE_UNMATCHED,
                        message=div.message,
                        data={"aerlog_divergence": div.kind},
                    ),
                    diverged=True,
                    divergence=div,
                )

            later_match = next(
                (
                    slot
                    for slot in self._client_slots
                    if slot.interaction_index not in self._consumed_indices
                    and slot.method == method
                    and slot.exact_params_sha256 == exact_hash
                    and self._slot_matches_id(slot, incoming_id=request_id, id_type=id_type)
                ),
                None,
            )
            if later_match is not None:
                expected_desc = (
                    f"{next_slot.method} (slot #{next_slot.interaction_index})"
                    if next_slot is not None
                    else "<exhausted>"
                )
                div = ReplayDivergence(
                    kind="out_of_order_request",
                    severity="error",
                    step_index=step_index,
                    method=method,
                    message=(
                        f"Out-of-order request {method} matches future slot "
                        f"#{later_match.interaction_index} instead of {expected_desc}."
                    ),
                    details={
                        "matched_future_index": later_match.interaction_index,
                        "expected_index": next_slot.interaction_index if next_slot else None,
                    },
                )
                return MatchDecision(
                    matched=False,
                    outcome_kind="out_of_order_request",
                    response_frame_obj=_jsonrpc_error_frame(
                        request_id=request_id,
                        id_type=id_type,
                        code=ERR_CASSETTE_UNMATCHED,
                        message=div.message,
                        data={"aerlog_divergence": div.kind},
                    ),
                    diverged=True,
                    divergence=div,
                )

            consumed_match = next(
                (
                    slot
                    for slot in self._client_slots
                    if slot.interaction_index in self._consumed_indices
                    and slot.method == method
                    and slot.exact_params_sha256 == exact_hash
                ),
                None,
            )
            if consumed_match is not None:
                div = ReplayDivergence(
                    kind="repeated_request_exhausted",
                    severity="error",
                    step_index=step_index,
                    method=method,
                    message=(
                        f"No unconsumed cassette slot left for repeated {method} request "
                        f"(previously consumed slot #{consumed_match.interaction_index})."
                    ),
                    details={"prior_interaction_index": consumed_match.interaction_index},
                )
                return MatchDecision(
                    matched=False,
                    outcome_kind="repeated_request_exhausted",
                    response_frame_obj=_jsonrpc_error_frame(
                        request_id=request_id,
                        id_type=id_type,
                        code=ERR_CASSETTE_UNMATCHED,
                        message=div.message,
                        data={"aerlog_divergence": div.kind},
                    ),
                    diverged=True,
                    divergence=div,
                )

            div = ReplayDivergence(
                kind="unmatched_request",
                severity="error",
                step_index=step_index,
                method=method,
                message=f"No matching recorded interaction in cassette for {method}.",
                details={"expected_index": next_slot.interaction_index if next_slot else None},
            )
            return MatchDecision(
                matched=False,
                outcome_kind="unmatched_request",
                response_frame_obj=_jsonrpc_error_frame(
                    request_id=request_id,
                    id_type=id_type,
                    code=ERR_CASSETTE_UNMATCHED,
                    message=div.message,
                    data={"aerlog_divergence": div.kind},
                ),
                diverged=True,
                divergence=div,
            )

        # Tolerant mode: head exact -> head normalized -> unconsumed exact -> unconsumed normalized.
        if (
            next_slot is not None
            and next_slot.method == method
            and self._slot_matches_id(next_slot, incoming_id=request_id, id_type=id_type)
        ):
            if next_slot.exact_params_sha256 == exact_hash:
                self._consumed_indices.add(next_slot.interaction_index)
                self._seen_request_keys[(id_type, repr(request_id))] = next_slot.interaction_index
                return self._apply_safety_and_build(
                    next_slot,
                    incoming_id=request_id,
                    id_type=id_type,
                    incoming_params=params,
                    step_index=step_index,
                    normalized_used=False,
                    out_of_order_used=False,
                )
            if next_slot.normalized_params_sha256 == norm_hash:
                self._consumed_indices.add(next_slot.interaction_index)
                self._seen_request_keys[(id_type, repr(request_id))] = next_slot.interaction_index
                return self._apply_safety_and_build(
                    next_slot,
                    incoming_id=request_id,
                    id_type=id_type,
                    incoming_params=params,
                    step_index=step_index,
                    normalized_used=True,
                    out_of_order_used=False,
                )

        unconsumed_exact = next(
            (
                slot
                for slot in self._client_slots
                if slot.interaction_index not in self._consumed_indices
                and slot.method == method
                and slot.exact_params_sha256 == exact_hash
                and self._slot_matches_id(slot, incoming_id=request_id, id_type=id_type)
            ),
            None,
        )
        if unconsumed_exact is not None:
            self._consumed_indices.add(unconsumed_exact.interaction_index)
            self._seen_request_keys[(id_type, repr(request_id))] = (
                unconsumed_exact.interaction_index
            )
            return self._apply_safety_and_build(
                unconsumed_exact,
                incoming_id=request_id,
                id_type=id_type,
                incoming_params=params,
                step_index=step_index,
                normalized_used=False,
                out_of_order_used=(
                    next_slot is not None
                    and unconsumed_exact.interaction_index != next_slot.interaction_index
                ),
            )

        unconsumed_norm = next(
            (
                slot
                for slot in self._client_slots
                if slot.interaction_index not in self._consumed_indices
                and slot.method == method
                and slot.normalized_params_sha256 == norm_hash
                and self._slot_matches_id(slot, incoming_id=request_id, id_type=id_type)
            ),
            None,
        )
        if unconsumed_norm is not None:
            self._consumed_indices.add(unconsumed_norm.interaction_index)
            self._seen_request_keys[(id_type, repr(request_id))] = unconsumed_norm.interaction_index
            return self._apply_safety_and_build(
                unconsumed_norm,
                incoming_id=request_id,
                id_type=id_type,
                incoming_params=params,
                step_index=step_index,
                normalized_used=True,
                out_of_order_used=(
                    next_slot is not None
                    and unconsumed_norm.interaction_index != next_slot.interaction_index
                ),
            )

        consumed_norm = next(
            (
                slot
                for slot in self._client_slots
                if slot.interaction_index in self._consumed_indices
                and slot.method == method
                and slot.normalized_params_sha256 == norm_hash
            ),
            None,
        )
        if consumed_norm is not None:
            div = ReplayDivergence(
                kind="repeated_request_exhausted",
                severity="error",
                step_index=step_index,
                method=method,
                message=(
                    f"All recorded {method} slots are exhausted (last matched slot "
                    f"#{consumed_norm.interaction_index})."
                ),
                details={"prior_interaction_index": consumed_norm.interaction_index},
            )
            return MatchDecision(
                matched=False,
                outcome_kind="repeated_request_exhausted",
                response_frame_obj=_jsonrpc_error_frame(
                    request_id=request_id,
                    id_type=id_type,
                    code=ERR_CASSETTE_UNMATCHED,
                    message=div.message,
                    data={"aerlog_divergence": div.kind},
                ),
                diverged=True,
                divergence=div,
            )

        div = ReplayDivergence(
            kind="unmatched_request",
            severity="error",
            step_index=step_index,
            method=method,
            message=f"No matching interaction found in cassette (even normalized) for {method}.",
            details={},
        )
        return MatchDecision(
            matched=False,
            outcome_kind="unmatched_request",
            response_frame_obj=_jsonrpc_error_frame(
                request_id=request_id,
                id_type=id_type,
                code=ERR_CASSETTE_UNMATCHED,
                message=div.message,
                data={"aerlog_divergence": div.kind},
            ),
            diverged=True,
            divergence=div,
        )

    def match_notification(
        self,
        *,
        method: str,
        params: Any,
    ) -> MatchDecision:
        """Process an incoming client notification (especially ``notifications/cancelled``)."""
        step_index = self._step_counter
        self._step_counter += 1

        if method == "notifications/cancelled":
            raw_target = params.get("requestId") if isinstance(params, Mapping) else None
            target_type, target_val = classify_jsonrpc_id({"id": raw_target})
            seen_idx = self._seen_request_keys.get((target_type, repr(target_val)))
            if seen_idx is not None:
                target_slot = next(
                    (s for s in self._client_slots if s.interaction_index == seen_idx),
                    None,
                )
                return MatchDecision(
                    matched=True,
                    outcome_kind="cancellation_matched",
                    interaction=target_slot,
                    diverged=False,
                )

            # In self-replay or recorded cancellations, also match recorded cancellation entries.
            rec_cancel: CassetteNotification | None = next(
                (
                    c
                    for c in self._cassette.cancellations
                    if c.target_interaction_index is not None
                    and isinstance(c.params, Mapping)
                    and c.params.get("requestId") == raw_target
                ),
                None,
            )
            if rec_cancel is not None and rec_cancel.target_interaction_index is not None:
                target_slot = next(
                    (
                        s
                        for s in self._client_slots
                        if s.interaction_index == rec_cancel.target_interaction_index
                    ),
                    None,
                )
                return MatchDecision(
                    matched=True,
                    outcome_kind="cancellation_matched",
                    interaction=target_slot,
                    diverged=False,
                )

            safe_target = self._safe_value(raw_target)
            div = ReplayDivergence(
                kind="cancellation_target_missing",
                severity="warning",
                step_index=step_index,
                method=self._safe_text(method),
                message=(
                    f"Cancellation notification targeted unknown/unseen requestId={safe_target!r}."
                ),
                details={"target_request_id": safe_target},
            )
            return MatchDecision(
                matched=False,
                outcome_kind="cancellation_target_missing",
                diverged=True,
                divergence=div,
            )

        return MatchDecision(
            matched=True,
            outcome_kind="notification_ignored",
            diverged=False,
        )


__all__ = [
    "ERR_CASSETTE_MISSING_RESPONSE",
    "ERR_CASSETTE_UNMATCHED",
    "ERR_CASSETTE_UNSAFE_BLOCKED",
    "CassetteMatcher",
    "MatchDecision",
    "MatchOutcomeKind",
    "MissingResponsePolicy",
    "ReplayDivergence",
    "ReplayMatchMode",
]
