"""Regression tests for redaction engine O(N^2) ReDoS protection."""

from __future__ import annotations

import pytest

from aerlog.capture.redaction import (
    REDACTED_KEY_BLOCK_MARKER,
    REDACTED_MARKER,
    EventRedactor,
    RedactionConfig,
)
from aerlog.protocol.jsonrpc import redact_text as protocol_redact_text


def test_large_ascii_payload_without_url_delimiters_completes_cleanly() -> None:
    """A 2 MiB ASCII string lacking ``://`` or ``@`` passes without backtracking stalls."""
    redactor = EventRedactor()
    payload = "B" * (2 * 1024 * 1024)

    value_outcome = redactor.redact_value({"data": payload}, root_path="result")
    assert value_outcome.summary.applied is True
    assert value_outcome.summary.degraded is False
    assert value_outcome.summary.findings_count == 0
    assert value_outcome.value["data"] == payload

    text_outcome = redactor.redact_text_value(
        payload,
        path_label="raw",
        max_chars=len(payload),
    )
    assert text_outcome.summary.applied is True
    assert text_outcome.summary.degraded is False
    assert text_outcome.summary.findings_count == 0
    assert text_outcome.text == payload


def test_url_userinfo_redaction_preserved_across_small_and_large_payloads() -> None:
    """URL userinfo credentials still redact after adding pre-checks and scheme bounds."""
    redactor = EventRedactor()

    samples = [
        (
            "postgresql://alice:s3cr3t@db.internal:5432/app",
            f"postgresql://{REDACTED_MARKER}@db.internal:5432/app",
        ),
        (
            "url=https://user:pass@example.com/path",
            f"url=https://{REDACTED_MARKER}@example.com/path",
        ),
        (
            "foo+bar://u:p@host",
            f"foo+bar://{REDACTED_MARKER}@host",
        ),
    ]
    for raw, expected in samples:
        outcome = redactor.redact_value({"text": raw})
        assert outcome.summary.findings_count == 1
        assert outcome.value["text"] == expected

    # Both delimiters exist alongside a 1 MiB unbroken ASCII prefix: must finish and redact.
    large_with_url = ("B" * (1024 * 1024)) + " https://deploy:topsecret@git.example.com/org/repo"
    large_outcome = redactor.redact_value({"blob": large_with_url})
    assert large_outcome.summary.degraded is False
    assert large_outcome.summary.findings_count == 1
    assert "topsecret" not in large_outcome.value["blob"]
    assert f"https://{REDACTED_MARKER}@git.example.com/org/repo" in large_outcome.value["blob"]


def test_url_userinfo_precheck_preserves_non_matching_delimiters() -> None:
    """Strings with partial URL delimiters or userinfo without password keep prior semantics."""
    redactor = EventRedactor(RedactionConfig(max_text_chars=256_000))
    non_secret_cases = [
        "https://example.com/no-credentials/" * 1000,
        "alice@example.com " * 1000,
        "http://alice_only@example.com/resource",
    ]
    for sample in non_secret_cases:
        outcome = redactor.redact_value({"msg": sample})
        assert outcome.summary.findings_count == 0
        assert outcome.value["msg"] == sample


def test_pem_redos_repeated_begin_markers_completes_linearly() -> None:
    """Pathological 27 KB PEM header repetitions complete cleanly without O(N^3) backtracking."""
    redactor = EventRedactor()
    repeated_begin = "-----BEGIN PRIVATE KEY-----" * 1000  # ~27 KB
    end_then_begins = "-----END PRIVATE KEY----- " + ("-----BEGIN PRIVATE KEY-----" * 1000)

    out1 = redactor.redact_value({"pem_spam": repeated_begin})
    assert out1.summary.degraded is False
    assert out1.summary.findings_count == 0
    assert out1.value["pem_spam"] == repeated_begin

    out2 = redactor.redact_value({"pem_spam": end_then_begins})
    assert out2.summary.degraded is False
    assert out2.summary.findings_count == 0
    assert out2.value["pem_spam"] == end_then_begins

    real_multi = (
        '{"a":"-----BEGIN RSA PRIVATE KEY-----\\nSECRET1\\n-----END RSA PRIVATE KEY-----",'
        '"b":"-----BEGIN EC PRIVATE KEY-----\\nSECRET2\\n-----END EC PRIVATE KEY-----"}'
    )
    out3 = redactor.redact_value({"json": real_multi})
    assert out3.summary.findings_count == 2
    assert "SECRET1" not in out3.value["json"]
    assert "SECRET2" not in out3.value["json"]
    assert out3.value["json"].count(REDACTED_KEY_BLOCK_MARKER) == 2


def test_jsonrpc_redact_text_closes_bypass_cases_while_preserving_progress_tokens() -> None:
    """Protocol redact_text handles escaped/unclosed quotes, unquoted JSON values, and tokens."""
    cases = [
        ('{"password": "abc\\"real_secret"}', "real_secret"),
        ('{"password": "unclosed_secret', "unclosed_secret"),
        ('password="unclosed_secret', "unclosed_secret"),
        ('{"password": unquoted_secret}', "unquoted_secret"),
        ("slack=xoxb-1234567890_secret", "1234567890_secret"),
        ("aws=AKIAIOSFODNN7EXAMPLE gh=github_pat_1234567890abcdef", "AKIAIOSFODNN7EXAMPLE"),
    ]
    for raw, leaked in cases:
        redacted = protocol_redact_text(raw)
        assert leaked not in redacted, f"Expected {leaked!r} redacted in {redacted!r}"
        assert REDACTED_MARKER in redacted

    preserved = protocol_redact_text('progressToken=keep-99 {"progressToken": "tok-1"}')
    assert "keep-99" in preserved
    assert "tok-1" in preserved


def test_acronym_keys_password_only_url_and_config_validation() -> None:
    """Acronym keys, password-only URLs, dict keys, negative max_chars, and bad regex fail safe."""
    redactor = EventRedactor(RedactionConfig(max_text_chars=65_536))
    payload = {
        "APIToken": "raw_api_tok",
        "DBPassword": "raw_db_pw",
        "aws_secret_access_key": "raw_aws_sec",
        "tokens": ["tok1", "tok2"],
        "url": "redis://:redispass99@cache.internal:6379/0",
        "https://keyuser:keypass@bad.key.example/path": "benign",
    }
    outcome = redactor.redact_value(payload, root_path="root")
    dumped = str(outcome.value)
    for secret in ("raw_api_tok", "raw_db_pw", "raw_aws_sec", "tok1", "redispass99", "keypass"):
        assert secret not in dumped
    assert f"redis://{REDACTED_MARKER}@cache.internal:6379/0" == outcome.value["url"]

    neg_out = redactor.redact_text_value("hello", path_label="x", max_chars=-5)
    assert neg_out.text == ""
    assert neg_out.truncated is True

    with pytest.raises(ValueError, match="extra_secret_patterns"):
        RedactionConfig(extra_secret_patterns=("[unclosed",))
