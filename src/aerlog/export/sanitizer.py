"""Deterministic pre-export secret sanitization and volatile field normalization."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from aerlog.capture.redaction import (
    REDACTED_KEY_BLOCK_MARKER,
    REDACTED_MARKER,
    REDACTION_FAILED_MARKER,
    EventRedactor,
    RedactionConfig,
)
from aerlog.replay.cassette import (
    Cassette,
    CassetteInteraction,
    CassetteNotification,
    compute_params_hashes,
    seal_cassette_digest,
)

TMP_PATH_PLACEHOLDER: Final[str] = "<TMP_PATH>"
HOME_PATH_PLACEHOLDER: Final[str] = "<HOME_PATH>"
TIMESTAMP_PLACEHOLDER: Final[str] = "<TIMESTAMP>"
UUID_PLACEHOLDER: Final[str] = "<UUID>"
TRACEPARENT_PLACEHOLDER: Final[str] = "<NORMALIZED_TRACEPARENT>"
TRACESTATE_PLACEHOLDER: Final[str] = "<NORMALIZED_TRACESTATE>"

_PROTECTED_MARKERS: Final[frozenset[str]] = frozenset(
    {
        REDACTED_MARKER,
        REDACTED_KEY_BLOCK_MARKER,
        REDACTION_FAILED_MARKER,
        TMP_PATH_PLACEHOLDER,
        HOME_PATH_PLACEHOLDER,
        TIMESTAMP_PLACEHOLDER,
        UUID_PLACEHOLDER,
        TRACEPARENT_PLACEHOLDER,
        TRACESTATE_PLACEHOLDER,
    }
)

_TMP_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:/private)?/(?:tmp|var/folders)/[^\s\"'`,;)}\]]+"
)
_HOME_PATH_RE: Final[re.Pattern[str]] = re.compile(r"/(?:home|Users)/[^\s\"'`,;)}\]]+")
_ISO_TIMESTAMP_RE: Final[re.Pattern[str]] = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
)
_UUID_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class SanitizedValueResult:
    """Output from sanitizing and normalizing a JSON value."""

    value: Any
    variable_fields: tuple[str, ...]
    redaction_findings: int
    normalized_categories: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SanitizedCassetteResult:
    """Output from sanitizing and deterministically re-sealing a :class:`Cassette`."""

    cassette: Cassette
    variable_fields: tuple[str, ...]
    redaction_findings: int
    normalized_categories: tuple[str, ...]


def normalize_text_volatiles(
    text: str,
    *,
    path: str,
    variable_fields: list[str],
    categories: set[str],
) -> str:
    """Replace ephemeral host paths, ISO timestamps, and random UUIDs cleanly."""
    if text in _PROTECTED_MARKERS:
        return text

    current = text
    changed = False

    for pattern, placeholder, cat in (
        (_TMP_PATH_RE, TMP_PATH_PLACEHOLDER, "host_temp_paths"),
        (_HOME_PATH_RE, HOME_PATH_PLACEHOLDER, "host_home_paths"),
        (_ISO_TIMESTAMP_RE, TIMESTAMP_PLACEHOLDER, "timestamps"),
        (_UUID_RE, UUID_PLACEHOLDER, "random_uuids"),
    ):
        updated, count = pattern.subn(placeholder, current)
        if count > 0:
            current = updated
            changed = True
            categories.add(cat)

    if changed:
        variable_fields.append(path)
    return current


def _normalize_nested(
    value: Any,
    *,
    path: str,
    progress_token_label: str | None,
    variable_fields: list[str],
    categories: set[str],
    inside_meta: bool = False,
) -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value

    if isinstance(value, str):
        return normalize_text_volatiles(
            value,
            path=path,
            variable_fields=variable_fields,
            categories=categories,
        )

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k_raw, v in value.items():
            k = str(k_raw)
            child_path = f"{path}.{k}" if path else k
            if inside_meta and k == "traceparent":
                out[k] = TRACEPARENT_PLACEHOLDER
                variable_fields.append(child_path)
                categories.add("meta_headers")
            elif inside_meta and k == "tracestate":
                out[k] = TRACESTATE_PLACEHOLDER
                variable_fields.append(child_path)
                categories.add("meta_headers")
            elif (inside_meta or path.endswith("notifications/progress.params")) and (
                k == "progressToken"
            ):
                if progress_token_label is not None:
                    out[k] = progress_token_label
                    variable_fields.append(child_path)
                    categories.add("meta_headers")
                else:
                    out[k] = v
            else:
                out[k] = _normalize_nested(
                    v,
                    path=child_path,
                    progress_token_label=progress_token_label,
                    variable_fields=variable_fields,
                    categories=categories,
                    inside_meta=(inside_meta or k == "_meta"),
                )
        return out

    if isinstance(value, Sequence):
        return [
            _normalize_nested(
                item,
                path=f"{path}[{idx}]",
                progress_token_label=progress_token_label,
                variable_fields=variable_fields,
                categories=categories,
                inside_meta=inside_meta,
            )
            for idx, item in enumerate(value)
        ]

    return value


def sanitize_and_normalize_value(
    value: Any,
    *,
    root_path: str,
    sanitize: bool = True,
    normalize_volatile: bool = True,
    progress_token_label: str | None = None,
) -> SanitizedValueResult:
    """Apply standard secret redaction and optional volatile normalization to ``value``."""
    variable_fields: list[str] = []
    categories: set[str] = set()
    findings = 0

    current = copy.deepcopy(value)
    if sanitize:
        redactor = EventRedactor(RedactionConfig(mode="standard"))
        red_out = redactor.redact_value(current, root_path=root_path)
        current = red_out.value
        findings += red_out.summary.findings_count
        if red_out.summary.findings_count > 0:
            categories.add("redacted_secrets")
        for rpath in red_out.summary.redacted_paths:
            variable_fields.append(rpath)

    if normalize_volatile:
        current = _normalize_nested(
            current,
            path=root_path,
            progress_token_label=progress_token_label,
            variable_fields=variable_fields,
            categories=categories,
        )

    return SanitizedValueResult(
        value=current,
        variable_fields=tuple(dict.fromkeys(variable_fields)),
        redaction_findings=findings,
        normalized_categories=tuple(sorted(categories)),
    )


def _sanitize_notification(
    notif: CassetteNotification,
    *,
    prefix: str,
    sanitize: bool,
    normalize_volatile: bool,
    progress_token_label: str | None,
    all_vars: list[str],
    all_cats: set[str],
) -> tuple[CassetteNotification, int]:
    findings = 0
    if notif.has_params:
        hint_path = (
            f"{prefix}.notifications/progress.params"
            if notif.method == "notifications/progress"
            else f"{prefix}.params"
        )
        p_res = sanitize_and_normalize_value(
            notif.params,
            root_path=hint_path,
            sanitize=sanitize,
            normalize_volatile=normalize_volatile,
            progress_token_label=progress_token_label,
        )
        clean_params = p_res.value
        findings += p_res.redaction_findings
        all_vars.extend(p_res.variable_fields)
        all_cats.update(p_res.normalized_categories)
    else:
        clean_params = None

    ex_res = sanitize_and_normalize_value(
        notif.extra_fields,
        root_path=f"{prefix}.extra_fields",
        sanitize=sanitize,
        normalize_volatile=normalize_volatile,
    )
    findings += ex_res.redaction_findings
    all_vars.extend(ex_res.variable_fields)
    all_cats.update(ex_res.normalized_categories)

    return (
        notif.model_copy(
            update={
                "params": clean_params,
                "extra_fields": ex_res.value if isinstance(ex_res.value, dict) else {},
            }
        ),
        findings,
    )


def sanitize_cassette_for_export(
    cassette: Cassette,
    *,
    deterministic_cassette_id: str,
    anchored_created_at: datetime,
    sanitize: bool = True,
    normalize_volatile: bool = True,
) -> SanitizedCassetteResult:
    """Sanitize and normalize a :class:`Cassette`, recomputing matching and seal digests."""
    all_vars: list[str] = []
    all_cats: set[str] = set()
    total_findings = 0
    if normalize_volatile:
        all_cats.add("wire_request_ids")

    new_interactions: list[CassetteInteraction] = []
    for slot in cassette.interactions:
        prefix = f"interactions[{slot.interaction_index}]"
        prog_label = f"norm_progress_{slot.interaction_index}"

        if slot.has_params:
            p_res = sanitize_and_normalize_value(
                slot.params,
                root_path=f"{prefix}.params",
                sanitize=sanitize,
                normalize_volatile=normalize_volatile,
                progress_token_label=prog_label,
            )
            clean_params = p_res.value
            total_findings += p_res.redaction_findings
            all_vars.extend(p_res.variable_fields)
            all_cats.update(p_res.normalized_categories)
        else:
            clean_params = None

        req_ex_res = sanitize_and_normalize_value(
            slot.extra_fields,
            root_path=f"{prefix}.extra_fields",
            sanitize=sanitize,
            normalize_volatile=normalize_volatile,
        )
        total_findings += req_ex_res.redaction_findings
        all_vars.extend(req_ex_res.variable_fields)
        all_cats.update(req_ex_res.normalized_categories)

        clean_result = None
        if slot.response_kind == "jsonrpc_response":
            r_res = sanitize_and_normalize_value(
                slot.response_result,
                root_path=f"{prefix}.response_result",
                sanitize=sanitize,
                normalize_volatile=normalize_volatile,
            )
            clean_result = r_res.value
            total_findings += r_res.redaction_findings
            all_vars.extend(r_res.variable_fields)
            all_cats.update(r_res.normalized_categories)

        clean_error = None
        clean_err_msg = slot.response_error_message
        clean_err_data = None
        if slot.response_kind == "jsonrpc_error":
            err_res = sanitize_and_normalize_value(
                slot.response_error,
                root_path=f"{prefix}.response_error",
                sanitize=sanitize,
                normalize_volatile=normalize_volatile,
            )
            clean_error = err_res.value
            total_findings += err_res.redaction_findings
            all_vars.extend(err_res.variable_fields)
            all_cats.update(err_res.normalized_categories)

            if clean_err_msg is not None:
                m_res = sanitize_and_normalize_value(
                    clean_err_msg,
                    root_path=f"{prefix}.response_error_message",
                    sanitize=sanitize,
                    normalize_volatile=normalize_volatile,
                )
                clean_err_msg = str(m_res.value)
                total_findings += m_res.redaction_findings
                all_vars.extend(m_res.variable_fields)
                all_cats.update(m_res.normalized_categories)

            if slot.response_error_data is not None:
                d_res = sanitize_and_normalize_value(
                    slot.response_error_data,
                    root_path=f"{prefix}.response_error_data",
                    sanitize=sanitize,
                    normalize_volatile=normalize_volatile,
                )
                clean_err_data = d_res.value
                total_findings += d_res.redaction_findings
                all_vars.extend(d_res.variable_fields)
                all_cats.update(d_res.normalized_categories)

        resp_ex_res = sanitize_and_normalize_value(
            slot.response_extra_fields,
            root_path=f"{prefix}.response_extra_fields",
            sanitize=sanitize,
            normalize_volatile=normalize_volatile,
        )
        total_findings += resp_ex_res.redaction_findings
        all_vars.extend(resp_ex_res.variable_fields)
        all_cats.update(resp_ex_res.normalized_categories)

        clean_emitted: list[CassetteNotification] = []
        for n_idx, notif in enumerate(slot.emitted_notifications):
            clean_n, n_find = _sanitize_notification(
                notif,
                prefix=f"{prefix}.emitted_notifications[{n_idx}]",
                sanitize=sanitize,
                normalize_volatile=normalize_volatile,
                progress_token_label=prog_label,
                all_vars=all_vars,
                all_cats=all_cats,
            )
            total_findings += n_find
            clean_emitted.append(clean_n)

        exact_hash, norm_hash = compute_params_hashes(clean_params, has_params=slot.has_params)
        new_interactions.append(
            slot.model_copy(
                update={
                    "params": clean_params,
                    "extra_fields": (
                        req_ex_res.value if isinstance(req_ex_res.value, dict) else {}
                    ),
                    "exact_params_sha256": exact_hash,
                    "normalized_params_sha256": norm_hash,
                    "response_result": clean_result,
                    "response_error": clean_error,
                    "response_error_message": clean_err_msg,
                    "response_error_data": clean_err_data,
                    "response_extra_fields": (
                        resp_ex_res.value if isinstance(resp_ex_res.value, dict) else {}
                    ),
                    "emitted_notifications": tuple(clean_emitted),
                }
            )
        )

    clean_standalone: list[CassetteNotification] = []
    for n_idx, notif in enumerate(cassette.standalone_notifications):
        clean_n, n_find = _sanitize_notification(
            notif,
            prefix=f"standalone_notifications[{n_idx}]",
            sanitize=sanitize,
            normalize_volatile=normalize_volatile,
            progress_token_label=None,
            all_vars=all_vars,
            all_cats=all_cats,
        )
        total_findings += n_find
        clean_standalone.append(clean_n)

    clean_cancels: list[CassetteNotification] = []
    for n_idx, notif in enumerate(cassette.cancellations):
        clean_n, n_find = _sanitize_notification(
            notif,
            prefix=f"cancellations[{n_idx}]",
            sanitize=sanitize,
            normalize_volatile=normalize_volatile,
            progress_token_label=None,
            all_vars=all_vars,
            all_cats=all_cats,
        )
        total_findings += n_find
        clean_cancels.append(clean_n)

    clean_cmd: list[str] = []
    for c_idx, part in enumerate(cassette.command_summary):
        c_res = sanitize_and_normalize_value(
            part,
            root_path=f"command_summary[{c_idx}]",
            sanitize=sanitize,
            normalize_volatile=normalize_volatile,
        )
        clean_cmd.append(str(c_res.value))
        total_findings += c_res.redaction_findings
        all_vars.extend(c_res.variable_fields)
        all_cats.update(c_res.normalized_categories)

    contains_raw = False if sanitize else cassette.contains_raw_secrets
    contains_redacted = cassette.contains_redacted_placeholders or (sanitize and total_findings > 0)
    updated_cassette = cassette.model_copy(
        update={
            "cassette_id": deterministic_cassette_id,
            "created_at": anchored_created_at,
            "contains_raw_secrets": contains_raw,
            "contains_redacted_placeholders": contains_redacted,
            "command_summary": tuple(clean_cmd),
            "interactions": tuple(new_interactions),
            "standalone_notifications": tuple(clean_standalone),
            "cancellations": tuple(clean_cancels),
        }
    )
    sealed = seal_cassette_digest(updated_cassette)
    return SanitizedCassetteResult(
        cassette=sealed,
        variable_fields=tuple(dict.fromkeys(all_vars)),
        redaction_findings=total_findings,
        normalized_categories=tuple(sorted(all_cats)),
    )


__all__ = [
    "HOME_PATH_PLACEHOLDER",
    "TIMESTAMP_PLACEHOLDER",
    "TMP_PATH_PLACEHOLDER",
    "TRACEPARENT_PLACEHOLDER",
    "TRACESTATE_PLACEHOLDER",
    "UUID_PLACEHOLDER",
    "SanitizedCassetteResult",
    "SanitizedValueResult",
    "normalize_text_volatiles",
    "sanitize_and_normalize_value",
    "sanitize_cassette_for_export",
]
