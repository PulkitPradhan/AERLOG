"""Unit tests for pre-persistence AERLOG redaction engine."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aerlog.capture.redaction import (
    REDACTED_KEY_BLOCK_MARKER,
    REDACTED_MARKER,
    REDACTION_FAILED_MARKER,
    EventRedactor,
    RedactionConfig,
    merge_redaction_summaries,
)
from aerlog.events.models import RedactionSummary


def test_default_redaction_mode_is_standard_and_off_rejected() -> None:
    """Default redaction_mode is 'standard' and invalid legacy 'off' is rejected."""
    cfg = RedactionConfig()
    assert cfg.mode == "standard"

    with pytest.raises(ValidationError):
        RedactionSummary.model_validate({"mode": "off"})


def test_redaction_config_rejects_off() -> None:
    """RedactionConfig rejects 'off' explicitly."""
    with pytest.raises(ValueError, match="Unsupported redaction_mode"):
        RedactionConfig(mode="off")  # type: ignore[arg-type]


def test_nested_secrets_and_tokens_are_redacted_while_preserving_progress_and_pagination() -> None:
    """Nested credentials redact cleanly while progressToken and cursors remain intact."""
    redactor = EventRedactor()
    sample_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature_part_xyz"
    sample_pem = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA123\n-----END RSA PRIVATE KEY-----"
    )
    payload = {
        "_meta": {
            "progressToken": "prog-token-42",
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        },
        "nextCursor": "cursor-page-2",
        "tokenCount": 512,
        "arguments": {
            "apiKey": "sk-live-secret-9876543210",
            "nested": {
                "authHeader": "Bearer supersecret.bearer.value",
                "repoUrl": "https://deploy_user:topsecretpass@git.example.com/org/repo.git",
                "jwt": sample_jwt,
                "pem": sample_pem,
                "password": "hunter2_password",
                "publicLabel": "safe-value",
            },
        },
    }

    outcome = redactor.redact_value(payload, root_path="params")

    assert outcome.summary.mode == "standard"
    assert outcome.summary.payload_mode == "redacted"
    assert outcome.summary.applied is True
    assert outcome.summary.degraded is False
    assert outcome.summary.findings_count >= 6

    res = outcome.value
    assert res["_meta"]["progressToken"] == "prog-token-42"
    assert res["nextCursor"] == "cursor-page-2"
    assert res["tokenCount"] == 512
    assert res["arguments"]["apiKey"] == REDACTED_MARKER
    assert "supersecret.bearer.value" not in res["arguments"]["nested"]["authHeader"]
    assert (
        res["arguments"]["nested"]["repoUrl"]
        == f"https://{REDACTED_MARKER}@git.example.com/org/repo.git"
    )
    assert res["arguments"]["nested"]["jwt"] == REDACTED_MARKER
    assert res["arguments"]["nested"]["pem"] == REDACTED_KEY_BLOCK_MARKER
    assert res["arguments"]["nested"]["password"] == REDACTED_MARKER
    assert res["arguments"]["nested"]["publicLabel"] == "safe-value"

    assert "params.arguments.apiKey" in outcome.summary.redacted_paths
    assert "params.arguments.nested.password" in outcome.summary.redacted_paths


def test_text_redaction_covers_stderr_api_keys_github_tokens_and_urls() -> None:
    """Unstructured stderr and malformed text redact credentials and preserve progressToken text."""
    redactor = EventRedactor()
    raw_stderr = (
        "Connecting to postgres://svc:pgsecret123@db.local:5432/app "
        "Authorization: Bearer abc.def.ghi "
        "token=ghp_1234567890abcdef progressToken=keep-99 "
        "api_key=sk-test1234567890ab"
    )
    outcome = redactor.redact_text_value(raw_stderr, path_label="stderr")

    assert outcome.text is not None
    assert "pgsecret123" not in outcome.text
    assert "abc.def.ghi" not in outcome.text
    assert "ghp_1234567890abcdef" not in outcome.text
    assert "sk-test1234567890ab" not in outcome.text
    assert "progressToken=keep-99" in outcome.text
    assert outcome.summary.redacted_paths == ("stderr",)


def test_command_arguments_and_env_overrides_are_redacted() -> None:
    """Command arguments and env overrides redact secrets cleanly."""
    redactor = EventRedactor()
    cmd = [
        "my-mcp-server",
        "--api-key",
        "secret_flag_value",
        "--token=inline_secret_value",
        "--endpoint",
        "https://user:pass123@api.internal/v1",
        "--port",
        "8080",
    ]
    redacted_cmd, cmd_summary = redactor.redact_command(cmd)
    assert redacted_cmd == (
        "my-mcp-server",
        "--api-key",
        REDACTED_MARKER,
        f"--token={REDACTED_MARKER}",
        "--endpoint",
        f"https://{REDACTED_MARKER}@api.internal/v1",
        "--port",
        "8080",
    )
    assert cmd_summary.findings_count == 3

    env_keys, redacted_env, env_summary = redactor.redact_env_overrides(
        {"OPENAI_API_KEY": "sk-secret99999999", "MCP_LOG_LEVEL": "debug"}
    )
    assert env_keys == ("MCP_LOG_LEVEL", "OPENAI_API_KEY")
    assert redacted_env["OPENAI_API_KEY"] == REDACTED_MARKER
    assert redacted_env["MCP_LOG_LEVEL"] == "debug"
    assert env_summary.findings_count == 1


def test_strict_hash_only_withholds_payloads() -> None:
    """strict_hash_only removes payload bodies and text cleanly."""
    redactor = EventRedactor(RedactionConfig(mode="strict_hash_only"))
    val_out = redactor.redact_value({"query": "anything"}, root_path="params")
    txt_out = redactor.redact_text_value("secret stderr", path_label="stderr")

    assert val_out.value is None
    assert val_out.summary.payload_mode == "strict_hash_only"
    assert txt_out.text is None
    assert txt_out.summary.payload_mode == "strict_hash_only"


def test_explicit_unredacted_must_be_explicit_and_never_mutates_data() -> None:
    """explicit_unredacted preserves raw values only when explicitly constructed and warns."""
    with pytest.warns(UserWarning, match="explicit_unredacted"):
        redactor = EventRedactor(RedactionConfig(mode="explicit_unredacted"))
    raw = {"api_key": "sk-raw-1234567890"}
    out = redactor.redact_value(raw, root_path="params")

    assert out.value == raw
    assert out.summary.mode == "explicit_unredacted"
    assert out.summary.payload_mode == "full_unredacted"
    assert out.summary.applied is False


def test_redaction_failure_degrades_safely_without_leaking_or_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Internal errors during redaction withhold data and mark summary degraded."""
    redactor = EventRedactor()

    def _boom(_value: object) -> tuple[str, int]:
        raise RuntimeError("regex failure")

    monkeypatch.setattr(redactor, "_redact_string_impl", _boom)

    val_out = redactor.redact_value({"text": "Bearer topsecret123456"}, root_path="params")
    assert val_out.value is None
    assert val_out.summary.degraded is True
    assert val_out.summary.applied is False
    assert val_out.summary.payload_mode == "redaction_failed"
    assert "RuntimeError" in (val_out.summary.error or "")

    txt_out = redactor.redact_text_value("Bearer topsecret123456", path_label="stderr")
    assert txt_out.text == REDACTION_FAILED_MARKER
    assert txt_out.summary.degraded is True
    assert txt_out.summary.payload_mode == "redaction_failed"

    merged = merge_redaction_summaries("standard", [val_out.summary, txt_out.summary])
    assert merged.degraded is True
    assert merged.payload_mode == "redaction_failed"
