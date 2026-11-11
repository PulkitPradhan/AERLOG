"""Unit tests for read-only JSON-RPC frame inspection and secret redaction."""

from __future__ import annotations

from aerlog.protocol.framing import FrameAccumulator
from aerlog.protocol.jsonrpc import inspect_frame, redact_text


def test_classifies_request_notification_response_and_error() -> None:
    req = inspect_frame(
        "client_to_server",
        b'{"jsonrpc":"2.0","id":42,"method":"vendor/custom","params":{"x":1},"extra_top":true}\n',
    )
    assert req.event_kind == "protocol_frame"
    assert req.message_kind == "request"
    assert req.request_id == 42
    assert req.has_id is True
    assert req.method == "vendor/custom"
    assert "extra_top" in req.keys
    # Valid payloads must never appear in diagnostic fields.
    diag = req.to_diagnostic_fields()
    assert "params" not in diag

    notif = inspect_frame(
        "client_to_server",
        b'{"jsonrpc":"2.0","method":"notifications/custom"}\r\n',
    )
    assert notif.message_kind == "notification"
    assert notif.has_id is False
    assert notif.line_ending == "crlf"

    resp = inspect_frame(
        "server_to_client",
        b'{"jsonrpc":"2.0","id":"req-1","result":{"ok":true}}\n',
    )
    assert resp.message_kind == "response"
    assert resp.request_id == "req-1"

    err = inspect_frame(
        "server_to_client",
        b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}\n',
    )
    assert err.message_kind == "error_response"
    assert err.has_id is True
    assert err.request_id is None


def test_boolean_request_id_not_treated_as_int() -> None:
    obs = inspect_frame("client_to_server", b'{"jsonrpc":"2.0","id":true,"method":"ping"}\n')
    assert obs.has_id is True
    assert obs.request_id is None


def test_multibyte_utf8_split_across_chunks() -> None:
    raw = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"msg":"🚀é"}}\n'.encode()
    # Split right inside the 4-byte emoji (🚀 is bytes 64..67).
    split_idx = raw.index("🚀".encode()) + 2
    acc = FrameAccumulator("client_to_server")
    assert acc.feed(raw[:split_idx]) == []
    frames = acc.feed(raw[split_idx:])
    assert frames == [raw]

    obs = inspect_frame("client_to_server", frames[0])
    assert obs.event_kind == "protocol_frame"
    assert obs.method == "tools/call"


def test_invalid_utf8_and_preview_toggle() -> None:
    bad_bytes = b'{"bad":"\xff\xfe"}\n'
    obs_with = inspect_frame("server_to_client", bad_bytes, include_previews=True)
    assert obs_with.event_kind == "malformed_utf8"
    assert obs_with.preview_hex == bad_bytes[:-1][:32].hex()

    obs_without = inspect_frame("server_to_client", bad_bytes, include_previews=False)
    assert obs_without.event_kind == "malformed_utf8"
    assert obs_without.preview_hex is None
    assert "preview_hex" not in obs_without.to_diagnostic_fields()


def test_malformed_json_redacts_secrets_and_respects_preview_toggle() -> None:
    bad_json = b'{broken "api_key": "sk-secret1234567890", Authorization: Bearer topsecret999\n'
    obs = inspect_frame("client_to_server", bad_json, include_previews=True, preview_max_chars=120)
    assert obs.event_kind == "malformed_json"
    assert obs.preview is not None
    assert "sk-secret1234567890" not in obs.preview
    assert "topsecret999" not in obs.preview
    assert "[REDACTED]" in obs.preview

    obs_no_preview = inspect_frame("client_to_server", bad_json, include_previews=False)
    assert obs_no_preview.preview is None
    assert "preview" not in obs_no_preview.to_diagnostic_fields()


def test_non_object_json_classified() -> None:
    obs = inspect_frame("client_to_server", b'[{"jsonrpc":"2.0"}]\n')
    assert obs.event_kind == "non_object_json"
    assert obs.json_type == "list"


def test_redact_text_covers_common_secret_patterns() -> None:
    sample = (
        "Authorization: Bearer abc.def.ghi "
        "token=my-secret-token "
        '"password": "hunter2" '
        "ghp_1234567890abcdef"
    )
    redacted = redact_text(sample)
    assert "abc.def.ghi" not in redacted
    assert "my-secret-token" not in redacted
    assert "hunter2" not in redacted
    assert "ghp_1234567890abcdef" not in redacted
    assert redacted.count("[REDACTED]") >= 4
