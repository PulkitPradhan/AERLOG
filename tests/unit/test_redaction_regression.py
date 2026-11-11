"""Regression tests for redaction engine O(N^2) ReDoS protection."""

from __future__ import annotations

from aerlog.capture.redaction import REDACTED_MARKER, EventRedactor, RedactionConfig


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
