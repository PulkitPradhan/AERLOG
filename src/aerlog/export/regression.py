"""Deterministic offline MCP regression fixture builder, pytest generator, and verifier."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aerlog.analysis.diagnostics import diagnose_jsonl_result
from aerlog.events.models import classify_jsonrpc_id
from aerlog.export.sanitizer import (
    SanitizedCassetteResult,
    sanitize_and_normalize_value,
    sanitize_cassette_for_export,
)
from aerlog.replay.cassette import (
    Cassette,
    build_cassette_from_read_result,
    verify_cassette_integrity,
)
from aerlog.replay.matcher import (
    CassetteMatcher,
    MatchOutcomeKind,
    MissingResponsePolicy,
    ReplayMatchMode,
)
from aerlog.replay.runner import ReplayOverallStatus
from aerlog.replay.safety import (
    CassetteIntegrityError,
    ReplayError,
    SideEffectClass,
    UnsafeToolPolicy,
    ensure_replay_mode_allowed,
)
from aerlog.storage.event_log import JsonlReadResult, canonical_event_sha256, validate_execution_id
from aerlog.storage.repositories import RecordingRepository

REGRESSION_FIXTURE_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
EPOCH_ANCHOR_TIMESTAMP: Final[datetime] = datetime(1970, 1, 1, 0, 0, 0, tzinfo=UTC)

ExportFormat = Literal["both", "json"]
TimestampAnchorBasis = Literal["ended_at", "started_at", "epoch_fallback"]

_FIXTURE_UUID_NS: Final[uuid.UUID] = uuid.UUID("72a4f4a0-6e87-4c36-9f6e-91c2a0c7f901")
_CASSETTE_UUID_NS: Final[uuid.UUID] = uuid.UUID("a32e101c-78f1-4625-a64f-e38b876a9402")
_VALID_SLUG_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9_]+$")

_CONSTANT_EXPORT_FIELDS: Final[tuple[str, ...]] = (
    "method",
    "tool_name",
    "ordered_interaction_indices",
    "response_kind",
    "error_code",
    "tool_is_error",
    "normalized_result_sha256",
)

_DEFAULT_EXPORT_LIMITATIONS: Final[tuple[str, ...]] = (
    "Exported regression fixtures replay strictly offline via embedded sealed cassettes and "
    "never execute live MCP servers, tool handlers, or network requests.",
    "Fields marked in normalization.variable_fields were redacted or normalized deterministically "
    "before export; verbatim secret strings are intentionally absent unless '--raw' opt-in ran.",
    "Passing offline regression verifies protocol and cassette response compatibility; it cannot "
    "prove upstream third-party API health on a live server.",
)


class ExportError(ReplayError):
    """Base error raised by AERLOG regression test export and verification."""


class UnredactedExportRefusedError(ExportError):
    """Raised when ``--raw`` export is requested without explicit opt-in confirmation."""


class RegressionFixtureValidationError(ExportError):
    """Raised when an exported fixture JSON file is invalid, tampered, or incompatible."""


class RegressionFixtureIntegrityError(RegressionFixtureValidationError):
    """Raised when a fixture SHA-256 digest does not match its canonical payload."""


class RegressionFixtureSchemaError(RegressionFixtureValidationError):
    """Raised when a fixture carries an unsupported major schema version."""


class NormalizationSummary(BaseModel):
    """Explicit contract separating normalized variable fields from asserted constants."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sanitize_applied: bool = True
    normalize_volatile: bool = True
    normalized_categories: tuple[str, ...] = ()
    variable_fields: tuple[str, ...] = ()
    constant_fields: tuple[str, ...] = _CONSTANT_EXPORT_FIELDS


class RegressionExpectedOutcome(BaseModel):
    """Expected deterministic outcome asserted for one exported step."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_matched: bool
    expected_outcome_kind: MatchOutcomeKind
    expected_response_kind: Literal["jsonrpc_response", "jsonrpc_error"] | None = None
    expected_error_code: int | None = None
    expected_tool_is_error: bool | None = None
    expected_result_keys: tuple[str, ...] = ()
    expected_normalized_result_sha256: str | None = None


class RegressionStepSpec(BaseModel):
    """One deterministic replay step inside an exported :class:`RegressionFixture`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_index: int = Field(ge=0)
    source_sequence: int = Field(ge=1)
    kind: Literal["request", "notification"]
    method: str
    tool_name: str | None = None
    incoming_request_id: Any = None
    params: Any = None
    has_params: bool = False
    extra_fields: dict[str, Any] = Field(default_factory=dict)
    side_effect_class: SideEffectClass | None = None
    variable_fields: tuple[str, ...] = ()
    constant_fields: tuple[str, ...] = ("method", "tool_name")
    expected: RegressionExpectedOutcome


class RegressionFixture(BaseModel):
    """Portable, SHA-256-sealed offline regression fixture built from one recording."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_schema_version: Literal["1.0.0"] = REGRESSION_FIXTURE_SCHEMA_VERSION
    fixture_id: str
    source_execution_id: str
    anchored_at: datetime
    timestamp_anchor_basis: TimestampAnchorBasis
    source_capture_completeness: str
    source_redaction_mode: str
    source_unclean_shutdown: bool = False
    source_has_corruptions: bool = False
    source_diagnostic_codes: tuple[str, ...] = ()
    sanitized_for_export: bool = True
    contains_raw_secrets: bool = False
    contains_redacted_placeholders: bool = False
    redaction_findings_count: int = Field(default=0, ge=0)
    match_mode: ReplayMatchMode = "strict"
    unsafe_tool_policy: UnsafeToolPolicy = "block"
    missing_response_policy: MissingResponsePolicy = "error"
    normalization: NormalizationSummary
    cassette: Cassette
    steps: tuple[RegressionStepSpec, ...] = ()
    expected_overall_status: ReplayOverallStatus
    expected_matched_count: int = Field(ge=0)
    expected_diverged_count: int = Field(ge=0)
    expected_blocked_count: int = Field(ge=0)
    expected_unmatched_count: int = Field(ge=0)
    expected_missing_response_count: int = Field(ge=0)
    limitations: tuple[str, ...] = _DEFAULT_EXPORT_LIMITATIONS
    fixture_sha256: str | None = None

    @field_validator("anchored_at")
    @classmethod
    def _ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class StepVerificationFailure(BaseModel):
    """Actionable failure record identifying where an exported test assertion drifted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_index: int | None = None
    source_sequence: int | None = None
    method: str | None = None
    tool_name: str | None = None
    field: str
    expected: Any = None
    actual: Any = None
    message: str


class RegressionRunResult(BaseModel):
    """Verification outcome produced by executing a :class:`RegressionFixture` offline."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: str
    source_execution_id: str
    replay_cassette_id: str
    passed: bool
    total_steps: int = Field(ge=0)
    passed_steps: int = Field(ge=0)
    failed_steps: int = Field(ge=0)
    matched_count: int = Field(ge=0)
    diverged_count: int = Field(ge=0)
    blocked_count: int = Field(ge=0)
    unmatched_count: int = Field(ge=0)
    missing_response_count: int = Field(ge=0)
    failures: tuple[StepVerificationFailure, ...] = ()
    contains_raw_secrets: bool = False


class RegressionExportBundleResult(BaseModel):
    """Metadata returned by exporting a regression fixture and optional pytest file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture: RegressionFixture
    slug: str
    output_dir: Path
    fixture_path: Path
    pytest_path: Path | None = None
    export_format: ExportFormat
    sanitized_from_unredacted_source: bool = False
    overwritten_files: tuple[Path, ...] = ()


def validate_export_slug(slug: str) -> str:
    """Strictly validate a filename slug against ``^[a-z0-9_]+$`` and path-traversal rules."""
    if not isinstance(slug, str) or not slug:
        raise ValueError("Export name must be a non-empty string matching ^[a-z0-9_]+$")
    if ".." in slug or "/" in slug or "\\" in slug or Path(slug).is_absolute():
        raise ValueError(f"Unsafe path characters in export name {slug!r}")
    if not _VALID_SLUG_RE.fullmatch(slug):
        raise ValueError(
            f"Invalid export name {slug!r}; must match ^[a-z0-9_]+$ "
            "(lowercase alphanumeric and underscores only)"
        )
    return slug


def resolve_export_paths(
    output_dir: Path,
    slug: str,
    *,
    export_format: ExportFormat = "both",
) -> tuple[Path, Path | None]:
    """Resolve contained ``(fixture_path, pytest_path)`` strictly inside ``output_dir``."""
    clean_slug = validate_export_slug(slug)
    root = output_dir.expanduser().resolve()
    fixture_path = (root / f"{clean_slug}.fixture.json").resolve()
    if not fixture_path.is_relative_to(root) or fixture_path.parent != root:
        raise ValueError(f"Path containment violation for fixture path {fixture_path}")

    pytest_path: Path | None = None
    if export_format == "both":
        pytest_path = (root / f"test_{clean_slug}.py").resolve()
        if not pytest_path.is_relative_to(root) or pytest_path.parent != root:
            raise ValueError(f"Path containment violation for pytest path {pytest_path}")

    return fixture_path, pytest_path


def _resolve_timestamp_anchor(
    read_result: JsonlReadResult,
) -> tuple[datetime, TimestampAnchorBasis]:
    """Anchor deterministic metadata timestamps purely from immutable source facts."""
    if read_result.summary is not None:
        return read_result.summary.ended_at, "ended_at"
    if read_result.header is not None:
        return read_result.header.started_at, "started_at"
    if read_result.events:
        return read_result.events[0].event.timestamp, "started_at"
    return EPOCH_ANCHOR_TIMESTAMP, "epoch_fallback"


def _compute_result_shape_and_digest(
    result_val: Any,
    *,
    sanitize: bool,
    normalize_volatile: bool,
) -> tuple[tuple[str, ...], str]:
    clean = sanitize_and_normalize_value(
        result_val,
        root_path="result",
        sanitize=sanitize,
        normalize_volatile=normalize_volatile,
    ).value
    keys: tuple[str, ...] = (
        tuple(sorted(str(k) for k in clean)) if isinstance(clean, Mapping) else ()
    )
    encoded = json.dumps(
        clean,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return keys, hashlib.sha256(encoded).hexdigest()


def compute_fixture_sha256(fixture: RegressionFixture) -> str:
    """Compute canonical SHA-256 over ``fixture`` excluding ``fixture_sha256``."""
    payload = fixture.model_dump(mode="json", exclude={"fixture_sha256"})
    return canonical_event_sha256(payload)


def seal_regression_fixture(fixture: RegressionFixture) -> RegressionFixture:
    """Attach canonical ``fixture_sha256`` digest to a :class:`RegressionFixture`."""
    return fixture.model_copy(update={"fixture_sha256": compute_fixture_sha256(fixture)})


def verify_regression_fixture_integrity(fixture: RegressionFixture) -> None:
    """Validate fixture schema version, SHA-256 digest, and embedded cassette integrity."""
    major = fixture.fixture_schema_version.split(".", 1)[0]
    expected_major = REGRESSION_FIXTURE_SCHEMA_VERSION.split(".", 1)[0]
    if major != expected_major:
        raise RegressionFixtureSchemaError(
            f"Unsupported fixture_schema_version {fixture.fixture_schema_version!r}"
        )
    if not fixture.fixture_sha256:
        raise RegressionFixtureIntegrityError(
            "Regression fixture is missing required fixture_sha256 digest"
        )
    expected = compute_fixture_sha256(fixture)
    if expected != fixture.fixture_sha256:
        raise RegressionFixtureIntegrityError(
            f"Regression fixture integrity mismatch: expected {expected}, recorded "
            f"{fixture.fixture_sha256}"
        )
    try:
        verify_cassette_integrity(fixture.cassette)
    except CassetteIntegrityError as exc:
        raise RegressionFixtureIntegrityError(str(exc)) from exc


def parse_regression_fixture_dict(raw_data: object) -> RegressionFixture:
    """Strictly parse and integrity-verify an untrusted regression fixture JSON dict."""
    if not isinstance(raw_data, dict):
        raise RegressionFixtureValidationError(
            "Regression fixture root JSON value must be an object"
        )

    raw_ver = raw_data.get("fixture_schema_version")
    if not isinstance(raw_ver, str) or "." not in raw_ver:
        raise RegressionFixtureSchemaError(
            f"Invalid or missing fixture_schema_version: {raw_ver!r}"
        )
    major = raw_ver.split(".", 1)[0]
    expected_major = REGRESSION_FIXTURE_SCHEMA_VERSION.split(".", 1)[0]
    if major != expected_major:
        raise RegressionFixtureSchemaError(
            f"Unsupported fixture_schema_version {raw_ver!r}; expected {expected_major}.x"
        )

    try:
        fixture = RegressionFixture.model_validate(raw_data)
    except ValidationError as exc:
        raise RegressionFixtureValidationError(
            f"Regression fixture validation failed: {exc}"
        ) from exc

    verify_regression_fixture_integrity(fixture)
    return fixture


def load_regression_fixture(fixture_path: str | Path) -> RegressionFixture:
    """Read, validate, and SHA-256 verify a ``.fixture.json`` file read-only."""
    resolved = Path(fixture_path).expanduser()
    if not resolved.is_file():
        raise RegressionFixtureValidationError(f"Regression fixture file not found: {resolved}")
    try:
        decoded = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegressionFixtureValidationError(
            f"Failed reading regression fixture {resolved}: {exc}"
        ) from exc
    return parse_regression_fixture_dict(decoded)


def _step_variable_paths(
    step_idx: int,
    interaction_idx: int | None,
    all_vars: tuple[str, ...],
    *,
    is_request: bool,
) -> tuple[str, ...]:
    paths: list[str] = []
    if is_request:
        paths.append("incoming_request_id")
    if interaction_idx is not None:
        prefix = f"interactions[{interaction_idx}]."
        for v in all_vars:
            if v.startswith(prefix):
                paths.append(v[len(prefix) :])
    else:
        c_prefix = f"cancellations[{step_idx}]"
        for v in all_vars:
            if c_prefix in v:
                paths.append(v)
    return tuple(dict.fromkeys(paths))


def build_regression_fixture_from_read_result(
    read_result: JsonlReadResult,
    *,
    match_mode: ReplayMatchMode = "strict",
    unsafe_tool_policy: UnsafeToolPolicy = "block",
    missing_response_policy: MissingResponsePolicy = "error",
    sanitize: bool = True,
    normalize_volatile: bool = True,
    raw: bool = False,
    allow_unredacted_export: bool = False,
    strict_integrity: bool = False,
) -> tuple[RegressionFixture, bool]:
    """Deterministically build a sealed :class:`RegressionFixture` from one recording.

    Returns ``(fixture, sanitized_from_unredacted_source)``.
    """
    effective_sanitize = sanitize and not raw
    if raw and not allow_unredacted_export:
        raise UnredactedExportRefusedError(
            "Unredacted '--raw' regression export is refused by default; pass "
            "'--allow-unredacted-export' explicitly or omit '--raw' to sanitize safely."
        )

    clean_exec_id = validate_execution_id(read_result.execution_id)
    anchor_ts, anchor_basis = _resolve_timestamp_anchor(read_result)

    seed_key = (
        f"{clean_exec_id}:{match_mode}:{unsafe_tool_policy}:{missing_response_policy}:"
        f"san={effective_sanitize}:norm={normalize_volatile}"
    )
    det_cassette_id = str(uuid.uuid5(_CASSETTE_UUID_NS, seed_key))
    det_fixture_id = str(uuid.uuid5(_FIXTURE_UUID_NS, seed_key))

    # Build cassette with allow_unredacted_cassette=True so sanitizer can clean payloads cleanly.
    raw_cassette = build_cassette_from_read_result(
        read_result,
        strict_integrity=strict_integrity,
        allow_unredacted_cassette=True,
        cassette_id=det_cassette_id,
    )
    sanitized_from_unredacted = (
        effective_sanitize and raw_cassette.source_redaction_mode == "explicit_unredacted"
    )
    if (
        not effective_sanitize
        and raw_cassette.source_redaction_mode == "explicit_unredacted"
        and not allow_unredacted_export
    ):
        raise UnredactedExportRefusedError(
            "Explicit unredacted export requires '--allow-unredacted-export'."
        )

    san_res: SanitizedCassetteResult = sanitize_cassette_for_export(
        raw_cassette,
        deterministic_cassette_id=det_cassette_id,
        anchored_created_at=anchor_ts,
        sanitize=effective_sanitize,
        normalize_volatile=normalize_volatile,
    )
    cassette = san_res.cassette

    diag_report = diagnose_jsonl_result(read_result)
    diag_codes = tuple(dict.fromkeys(item.code for item in diag_report.diagnostics))

    # Collect chronological client requests & client cancellation notifications.
    raw_sequence_items: list[tuple[int, str, Any]] = []
    for slot in cassette.interactions:
        if slot.origin_direction == "client_to_server":
            raw_sequence_items.append((slot.request_sequence, "request", slot))
    for notif in (*cassette.cancellations, *cassette.standalone_notifications):
        if notif.direction == "client_to_server":
            raw_sequence_items.append((notif.sequence, "notification", notif))
    raw_sequence_items.sort(key=lambda entry: entry[0])

    matcher = CassetteMatcher(
        cassette,
        match_mode=match_mode,
        unsafe_tool_policy=unsafe_tool_policy,
        missing_response_policy=missing_response_policy,
        require_exact_id=False,
    )

    # Track normalized sequential request IDs so notifications/cancelled points accurately.
    seq_to_norm_id: dict[int, int] = {}
    next_norm_id = 1
    for src_seq, item_kind, _ in raw_sequence_items:
        if item_kind == "request":
            seq_to_norm_id[src_seq] = next_norm_id
            next_norm_id += 1

    steps: list[RegressionStepSpec] = []
    matched_count = 0
    diverged_count = 0
    blocked_count = 0
    unmatched_count = 0
    missing_response_count = 0

    for step_idx, (src_seq, item_kind, item_obj) in enumerate(raw_sequence_items):
        if item_kind == "request":
            norm_id = seq_to_norm_id[src_seq]
            decision = matcher.match_request(
                method=item_obj.method,
                params=item_obj.params,
                has_params=item_obj.has_params,
                request_id=norm_id,
                id_type="int",
            )
            if decision.outcome_kind == "blocked_unsafe_tool":
                blocked_count += 1
            elif decision.outcome_kind == "missing_recorded_response":
                missing_response_count += 1
            elif decision.outcome_kind in {
                "unmatched_request",
                "out_of_order_request",
                "repeated_request_exhausted",
            }:
                unmatched_count += 1
            elif decision.matched:
                matched_count += 1
            if decision.diverged:
                diverged_count += 1

            reply = decision.response_frame_obj
            resp_kind: Literal["jsonrpc_response", "jsonrpc_error"] | None = None
            err_code: int | None = None
            tool_is_err: bool | None = None
            res_keys: tuple[str, ...] = ()
            res_sha: str | None = None

            if isinstance(reply, Mapping):
                if "error" in reply and isinstance(reply["error"], Mapping):
                    resp_kind = "jsonrpc_error"
                    raw_code = reply["error"].get("code")
                    err_code = raw_code if isinstance(raw_code, int) else None
                elif "result" in reply:
                    resp_kind = "jsonrpc_response"
                    r_val = reply["result"]
                    if isinstance(r_val, Mapping) and isinstance(r_val.get("isError"), bool):
                        tool_is_err = r_val["isError"]
                    res_keys, res_sha = _compute_result_shape_and_digest(
                        r_val,
                        sanitize=effective_sanitize,
                        normalize_volatile=normalize_volatile,
                    )

            var_fields = _step_variable_paths(
                step_idx,
                item_obj.interaction_index,
                san_res.variable_fields,
                is_request=True,
            )
            steps.append(
                RegressionStepSpec(
                    step_index=step_idx,
                    source_sequence=src_seq,
                    kind="request",
                    method=item_obj.method,
                    tool_name=item_obj.tool_name,
                    incoming_request_id=norm_id,
                    params=item_obj.params,
                    has_params=item_obj.has_params,
                    extra_fields=dict(item_obj.extra_fields),
                    side_effect_class=item_obj.side_effect_class,
                    variable_fields=var_fields,
                    constant_fields=("method", "tool_name", "response_kind", "error_code"),
                    expected=RegressionExpectedOutcome(
                        expected_matched=decision.matched,
                        expected_outcome_kind=decision.outcome_kind,
                        expected_response_kind=resp_kind,
                        expected_error_code=err_code,
                        expected_tool_is_error=tool_is_err,
                        expected_result_keys=res_keys,
                        expected_normalized_result_sha256=res_sha,
                    ),
                )
            )
        else:
            notif_params = item_obj.params
            if (
                item_obj.method == "notifications/cancelled"
                and isinstance(notif_params, Mapping)
                and item_obj.target_request_sequence in seq_to_norm_id
            ):
                rebound_cancel = dict(notif_params)
                rebound_cancel["requestId"] = seq_to_norm_id[item_obj.target_request_sequence]
                notif_params = rebound_cancel

            decision = matcher.match_notification(
                method=item_obj.method,
                params=notif_params,
            )
            if decision.diverged:
                diverged_count += 1
            var_fields = _step_variable_paths(
                step_idx,
                None,
                san_res.variable_fields,
                is_request=False,
            )
            steps.append(
                RegressionStepSpec(
                    step_index=step_idx,
                    source_sequence=src_seq,
                    kind="notification",
                    method=item_obj.method,
                    tool_name=None,
                    incoming_request_id=None,
                    params=notif_params,
                    has_params=item_obj.has_params,
                    extra_fields=dict(item_obj.extra_fields),
                    side_effect_class=None,
                    variable_fields=var_fields,
                    constant_fields=("method",),
                    expected=RegressionExpectedOutcome(
                        expected_matched=decision.matched,
                        expected_outcome_kind=decision.outcome_kind,
                    ),
                )
            )

    overall_status: ReplayOverallStatus
    if diverged_count > 0 or blocked_count > 0 or unmatched_count > 0:
        overall_status = "diverged"
    elif unsafe_tool_policy == "warn" and any(
        s.side_effect_class in ("potentially_mutating", "unknown_unsafe")
        for s in steps
        if s.kind == "request"
    ):
        overall_status = "matched_with_warnings"
    else:
        overall_status = "clean_match"

    unsigned = RegressionFixture(
        fixture_id=det_fixture_id,
        source_execution_id=clean_exec_id,
        anchored_at=anchor_ts,
        timestamp_anchor_basis=anchor_basis,
        source_capture_completeness=cassette.source_capture_completeness,
        source_redaction_mode=cassette.source_redaction_mode,
        source_unclean_shutdown=cassette.source_unclean_shutdown,
        source_has_corruptions=cassette.source_has_corruptions,
        source_diagnostic_codes=diag_codes,
        sanitized_for_export=effective_sanitize,
        contains_raw_secrets=cassette.contains_raw_secrets,
        contains_redacted_placeholders=cassette.contains_redacted_placeholders,
        redaction_findings_count=san_res.redaction_findings,
        match_mode=match_mode,
        unsafe_tool_policy=unsafe_tool_policy,
        missing_response_policy=missing_response_policy,
        normalization=NormalizationSummary(
            sanitize_applied=effective_sanitize,
            normalize_volatile=normalize_volatile,
            normalized_categories=san_res.normalized_categories,
            variable_fields=san_res.variable_fields,
        ),
        cassette=cassette,
        steps=tuple(steps),
        expected_overall_status=overall_status,
        expected_matched_count=matched_count,
        expected_diverged_count=diverged_count,
        expected_blocked_count=blocked_count,
        expected_unmatched_count=unmatched_count,
        expected_missing_response_count=missing_response_count,
    )
    return seal_regression_fixture(unsigned), sanitized_from_unredacted


def generate_pytest_source(*, slug: str, fixture_filename: str, source_execution_id: str) -> str:
    """Render deterministic, non-eval pytest module code loading ``fixture_filename``."""
    clean_slug = validate_export_slug(slug)
    validate_export_slug(fixture_filename.removesuffix(".fixture.json"))
    clean_exec_id = validate_execution_id(source_execution_id)

    lines = [
        '"""Offline MCP regression test exported deterministically by AERLOG."""',
        "",
        "from __future__ import annotations",
        "",
        "from pathlib import Path",
        "",
        "from aerlog.export.regression import (",
        "    format_regression_failure,",
        "    load_regression_fixture,",
        "    run_regression_fixture,",
        ")",
        "",
        f'_FIXTURE_PATH = Path(__file__).with_name("{fixture_filename}")',
        f'_SOURCE_EXECUTION_ID = "{clean_exec_id}"',
        "",
        "",
        f"def test_aerlog_regression_{clean_slug}() -> None:",
        '    """Replay exported MCP cassette strictly offline without contacting live servers."""',
        "    fixture = load_regression_fixture(_FIXTURE_PATH)",
        "    assert fixture.source_execution_id == _SOURCE_EXECUTION_ID",
        "    result = run_regression_fixture(fixture)",
        "    assert result.passed, format_regression_failure(result)",
        "",
    ]
    return "\n".join(lines)


def _write_atomic_bytes(target_path: Path, data: bytes, *, mode: int) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = f".{target_path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    tmp_path = target_path.parent / tmp_name
    fd = -1
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        os.chmod(fd, mode)
        view = memoryview(data)
        written = 0
        while written < len(data):
            n = os.write(fd, view[written:])
            if n <= 0:
                raise ExportError(f"Zero-byte write while exporting {target_path}")
            written += n
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp_path, target_path)
        os.chmod(target_path, mode)
    except OSError as exc:
        if fd >= 0:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise ExportError(f"Failed writing export artifact {target_path}: {exc}") from exc


def export_execution_regression_test(
    repo: RecordingRepository,
    execution_id: str,
    *,
    output_dir: Path,
    slug: str | None = None,
    export_format: ExportFormat = "both",
    match_mode: ReplayMatchMode = "strict",
    unsafe_tool_policy: UnsafeToolPolicy = "block",
    missing_response_policy: MissingResponsePolicy = "error",
    sanitize: bool = True,
    normalize_volatile: bool = True,
    raw: bool = False,
    allow_unredacted_export: bool = False,
    strict_integrity: bool = False,
) -> RegressionExportBundleResult:
    """Export a deterministic ``.fixture.json`` (+ optional ``test_*.py``) from ``repo``."""
    if raw and not allow_unredacted_export:
        raise UnredactedExportRefusedError(
            "Unredacted '--raw' export refused without explicit '--allow-unredacted-export'."
        )

    repo.get_execution(execution_id)
    read_result = repo.get_execution_events(
        execution_id,
        strict_integrity=strict_integrity,
        verify_checksums=True,
        mark_missing=False,
    )
    resolved_slug = (
        validate_export_slug(slug)
        if slug is not None
        else validate_export_slug(f"exec_{read_result.execution_id.replace('-', '_')}")
    )
    fixture_path, pytest_path = resolve_export_paths(
        output_dir, resolved_slug, export_format=export_format
    )

    fixture, sanitized_from_unredacted = build_regression_fixture_from_read_result(
        read_result,
        match_mode=match_mode,
        unsafe_tool_policy=unsafe_tool_policy,
        missing_response_policy=missing_response_policy,
        sanitize=sanitize,
        normalize_volatile=normalize_volatile,
        raw=raw,
        allow_unredacted_export=allow_unredacted_export,
        strict_integrity=strict_integrity,
    )

    overwritten: list[Path] = []
    if fixture_path.exists():
        overwritten.append(fixture_path)
    if pytest_path is not None and pytest_path.exists():
        overwritten.append(pytest_path)

    fixture_mode = 0o600 if fixture.contains_raw_secrets else 0o644
    fixture_bytes = (fixture.model_dump_json(indent=2) + "\n").encode("utf-8")
    _write_atomic_bytes(fixture_path, fixture_bytes, mode=fixture_mode)

    if pytest_path is not None:
        pytest_src = generate_pytest_source(
            slug=resolved_slug,
            fixture_filename=fixture_path.name,
            source_execution_id=fixture.source_execution_id,
        )
        _write_atomic_bytes(pytest_path, pytest_src.encode("utf-8"), mode=0o644)

    return RegressionExportBundleResult(
        fixture=fixture,
        slug=resolved_slug,
        output_dir=output_dir.expanduser().resolve(),
        fixture_path=fixture_path,
        pytest_path=pytest_path,
        export_format=export_format,
        sanitized_from_unredacted_source=sanitized_from_unredacted,
        overwritten_files=tuple(overwritten),
    )


def run_regression_fixture(
    fixture: RegressionFixture,
    *,
    override_cassette: Cassette | None = None,
) -> RegressionRunResult:
    """Verify ``fixture`` offline against its embedded cassette or ``override_cassette``."""
    verify_regression_fixture_integrity(fixture)
    ensure_replay_mode_allowed("cassette")

    target_cassette = fixture.cassette if override_cassette is None else override_cassette
    verify_cassette_integrity(target_cassette)

    matcher = CassetteMatcher(
        target_cassette,
        match_mode=fixture.match_mode,
        unsafe_tool_policy=fixture.unsafe_tool_policy,
        missing_response_policy=fixture.missing_response_policy,
        require_exact_id=False,
    )

    failures: list[StepVerificationFailure] = []
    passed_steps = 0
    matched_count = 0
    diverged_count = 0
    blocked_count = 0
    unmatched_count = 0
    missing_response_count = 0

    for step in fixture.steps:
        step_failed = False
        if step.kind == "request":
            _, norm_id_val = classify_jsonrpc_id({"id": step.incoming_request_id})
            id_type, _ = classify_jsonrpc_id({"id": step.incoming_request_id})
            decision = matcher.match_request(
                method=step.method,
                params=step.params,
                has_params=step.has_params,
                request_id=norm_id_val,
                id_type=id_type,
            )
            if decision.outcome_kind == "blocked_unsafe_tool":
                blocked_count += 1
            elif decision.outcome_kind == "missing_recorded_response":
                missing_response_count += 1
            elif decision.outcome_kind in {
                "unmatched_request",
                "out_of_order_request",
                "repeated_request_exhausted",
            }:
                unmatched_count += 1
            elif decision.matched:
                matched_count += 1
            if decision.diverged:
                diverged_count += 1

            exp = step.expected
            actual_outcome = decision.outcome_kind
            # In tolerant override checks, normalized_match satisfies expected ok/error outcomes
            # while still checking exact response_kind, error_code, and result digest below.
            outcome_matches = actual_outcome == exp.expected_outcome_kind or (
                fixture.match_mode == "tolerant"
                and actual_outcome == "normalized_match"
                and exp.expected_outcome_kind
                in {"matched_ok", "matched_error", "matched_tool_error"}
            )
            if not outcome_matches:
                step_failed = True
                failures.append(
                    StepVerificationFailure(
                        step_index=step.step_index,
                        source_sequence=step.source_sequence,
                        method=step.method,
                        tool_name=step.tool_name,
                        field="outcome_kind",
                        expected=exp.expected_outcome_kind,
                        actual=actual_outcome,
                        message=(
                            f"Step #{step.step_index} ({step.method}) expected outcome "
                            f"{exp.expected_outcome_kind!r}, got {actual_outcome!r}."
                        ),
                    )
                )

            reply = decision.response_frame_obj
            actual_resp_kind: Literal["jsonrpc_response", "jsonrpc_error"] | None = None
            actual_err_code: int | None = None
            actual_tool_is_err: bool | None = None
            actual_res_keys: tuple[str, ...] = ()
            actual_res_sha: str | None = None

            if isinstance(reply, Mapping):
                if "error" in reply and isinstance(reply["error"], Mapping):
                    actual_resp_kind = "jsonrpc_error"
                    raw_c = reply["error"].get("code")
                    actual_err_code = raw_c if isinstance(raw_c, int) else None
                elif "result" in reply:
                    actual_resp_kind = "jsonrpc_response"
                    r_val = reply["result"]
                    if isinstance(r_val, Mapping) and isinstance(r_val.get("isError"), bool):
                        actual_tool_is_err = r_val["isError"]
                    actual_res_keys, actual_res_sha = _compute_result_shape_and_digest(
                        r_val,
                        sanitize=fixture.sanitized_for_export,
                        normalize_volatile=fixture.normalization.normalize_volatile,
                    )

            if actual_resp_kind != exp.expected_response_kind:
                step_failed = True
                failures.append(
                    StepVerificationFailure(
                        step_index=step.step_index,
                        source_sequence=step.source_sequence,
                        method=step.method,
                        tool_name=step.tool_name,
                        field="response_kind",
                        expected=exp.expected_response_kind,
                        actual=actual_resp_kind,
                        message=(
                            f"Step #{step.step_index} ({step.method}) expected response_kind="
                            f"{exp.expected_response_kind!r}, got {actual_resp_kind!r}."
                        ),
                    )
                )

            if actual_err_code != exp.expected_error_code:
                step_failed = True
                failures.append(
                    StepVerificationFailure(
                        step_index=step.step_index,
                        source_sequence=step.source_sequence,
                        method=step.method,
                        tool_name=step.tool_name,
                        field="error_code",
                        expected=exp.expected_error_code,
                        actual=actual_err_code,
                        message=(
                            f"Step #{step.step_index} ({step.method}) expected error_code="
                            f"{exp.expected_error_code!r}, got {actual_err_code!r}."
                        ),
                    )
                )

            if (
                exp.expected_tool_is_error is not None
                and actual_tool_is_err != exp.expected_tool_is_error
            ):
                step_failed = True
                failures.append(
                    StepVerificationFailure(
                        step_index=step.step_index,
                        source_sequence=step.source_sequence,
                        method=step.method,
                        tool_name=step.tool_name,
                        field="tool_is_error",
                        expected=exp.expected_tool_is_error,
                        actual=actual_tool_is_err,
                        message=(
                            f"Step #{step.step_index} ({step.method}) expected isError="
                            f"{exp.expected_tool_is_error!r}, got {actual_tool_is_err!r}."
                        ),
                    )
                )

            if (
                exp.expected_normalized_result_sha256 is not None
                and actual_res_sha != exp.expected_normalized_result_sha256
            ):
                step_failed = True
                failures.append(
                    StepVerificationFailure(
                        step_index=step.step_index,
                        source_sequence=step.source_sequence,
                        method=step.method,
                        tool_name=step.tool_name,
                        field="normalized_result_sha256",
                        expected={
                            "keys": list(exp.expected_result_keys),
                            "sha256": exp.expected_normalized_result_sha256[:16],
                        },
                        actual={
                            "keys": list(actual_res_keys),
                            "sha256": actual_res_sha[:16] if actual_res_sha else None,
                        },
                        message=(
                            f"Step #{step.step_index} ({step.method}) result changed: expected "
                            f"keys={list(exp.expected_result_keys)} "
                            f"hash={exp.expected_normalized_result_sha256[:12]}, got "
                            f"keys={list(actual_res_keys)} "
                            f"hash={actual_res_sha[:12] if actual_res_sha else None}."
                        ),
                    )
                )
        else:
            decision = matcher.match_notification(method=step.method, params=step.params)
            if decision.diverged:
                diverged_count += 1
            if decision.outcome_kind != step.expected.expected_outcome_kind:
                step_failed = True
                failures.append(
                    StepVerificationFailure(
                        step_index=step.step_index,
                        source_sequence=step.source_sequence,
                        method=step.method,
                        tool_name=None,
                        field="outcome_kind",
                        expected=step.expected.expected_outcome_kind,
                        actual=decision.outcome_kind,
                        message=(
                            f"Notification step #{step.step_index} ({step.method}) expected "
                            f"{step.expected.expected_outcome_kind!r}, "
                            f"got {decision.outcome_kind!r}."
                        ),
                    )
                )

        if not step_failed:
            passed_steps += 1

    unconsumed = matcher.unconsumed_client_interactions()
    if unconsumed and override_cassette is not None:
        failures.append(
            StepVerificationFailure(
                step_index=None,
                source_sequence=None,
                method=None,
                tool_name=None,
                field="unconsumed_override_interactions",
                expected=0,
                actual=len(unconsumed),
                message=(
                    f"Override cassette still has {len(unconsumed)} extra interaction(s) not "
                    "covered by exported fixture steps."
                ),
            )
        )

    total = len(fixture.steps)
    failed_steps = total - passed_steps
    passed = not failures and failed_steps == 0
    return RegressionRunResult(
        fixture_id=fixture.fixture_id,
        source_execution_id=fixture.source_execution_id,
        replay_cassette_id=target_cassette.cassette_id,
        passed=passed,
        total_steps=total,
        passed_steps=passed_steps,
        failed_steps=failed_steps,
        matched_count=matched_count,
        diverged_count=diverged_count,
        blocked_count=blocked_count,
        unmatched_count=unmatched_count,
        missing_response_count=missing_response_count,
        failures=tuple(failures),
        contains_raw_secrets=target_cassette.contains_raw_secrets or fixture.contains_raw_secrets,
    )


def format_regression_failure(result: RegressionRunResult) -> str:
    """Format actionable expected-vs-actual diagnostics when a regression test fails."""
    if result.passed:
        return (
            f"AERLOG regression fixture {result.fixture_id} passed cleanly "
            f"({result.passed_steps}/{result.total_steps} steps)."
        )
    lines = [
        f"AERLOG REGRESSION FAILURE (fixture={result.fixture_id}, "
        f"source_execution={result.source_execution_id})",
        f"Passed: {result.passed_steps}/{result.total_steps} step(s); "
        f"Failures: {len(result.failures)}",
    ]
    for fail in result.failures:
        step_lbl = f"step #{fail.step_index}" if fail.step_index is not None else "session"
        seq_lbl = f"seq #{fail.source_sequence}" if fail.source_sequence is not None else "-"
        target_lbl = fail.method or "-"
        if fail.tool_name:
            target_lbl += f" (tool={fail.tool_name})"
        lines.append(f"  [FAIL] {step_lbl} ({seq_lbl}) {target_lbl} [{fail.field}]")
        lines.append(f"    Expected: {fail.expected!r}")
        lines.append(f"    Actual:   {fail.actual!r}")
        lines.append(f"    Reason:   {fail.message}")
    return "\n".join(lines)


__all__ = [
    "EPOCH_ANCHOR_TIMESTAMP",
    "REGRESSION_FIXTURE_SCHEMA_VERSION",
    "ExportError",
    "ExportFormat",
    "NormalizationSummary",
    "RegressionExpectedOutcome",
    "RegressionExportBundleResult",
    "RegressionFixture",
    "RegressionFixtureIntegrityError",
    "RegressionFixtureSchemaError",
    "RegressionFixtureValidationError",
    "RegressionRunResult",
    "RegressionStepSpec",
    "StepVerificationFailure",
    "TimestampAnchorBasis",
    "UnredactedExportRefusedError",
    "build_regression_fixture_from_read_result",
    "compute_fixture_sha256",
    "export_execution_regression_test",
    "format_regression_failure",
    "generate_pytest_source",
    "load_regression_fixture",
    "parse_regression_fixture_dict",
    "resolve_export_paths",
    "run_regression_fixture",
    "seal_regression_fixture",
    "validate_export_slug",
    "verify_regression_fixture_integrity",
]
