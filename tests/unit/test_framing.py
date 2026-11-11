"""Unit tests for byte-exact newline framing and frame size limits."""

from __future__ import annotations

import pytest

from aerlog.protocol.framing import (
    DEFAULT_MAX_FRAME_BYTES,
    FrameAccumulator,
    FrameTooLargeError,
    detect_line_ending,
)


def test_single_and_multiple_sequential_frames() -> None:
    acc = FrameAccumulator("client_to_server")
    frames = acc.feed(b'{"id":1}\n{"id":2}\n')

    assert frames == [b'{"id":1}\n', b'{"id":2}\n']
    assert acc.buffered_bytes == 0
    assert acc.flush_eof() is None


def test_partial_one_byte_chunks_and_trailing_eof() -> None:
    acc = FrameAccumulator("server_to_client")
    message = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'

    collected: list[bytes] = []
    for i in range(len(message)):
        collected.extend(acc.feed(message[i : i + 1]))

    assert collected == [message]
    assert acc.feed(b'{"partial": ') == []
    assert acc.buffered_bytes == 12
    assert acc.flush_eof() == b'{"partial": '
    assert acc.flush_eof() is None


def test_crlf_preserved_and_trailing_cr_without_lf() -> None:
    acc = FrameAccumulator("client_to_server")
    crlf_frame = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\r\n'
    lf_frame = b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'

    frames = acc.feed(crlf_frame + lf_frame + b'{"trailing":1}\r')
    assert frames == [crlf_frame, lf_frame]
    assert detect_line_ending(frames[0]) == "crlf"
    assert detect_line_ending(frames[1]) == "lf"

    trailing = acc.flush_eof()
    assert trailing == b'{"trailing":1}\r'
    assert detect_line_ending(trailing) == "none"


def test_exact_max_frame_bytes_boundary() -> None:
    limit = 32
    acc = FrameAccumulator("client_to_server", max_frame_bytes=limit)

    exact_frame = (b"a" * (limit - 1)) + b"\n"
    assert len(exact_frame) == limit
    # Two adjacent frames at the exact limit arriving in one chunk must both succeed.
    assert acc.feed(exact_frame + exact_frame) == [exact_frame, exact_frame]

    oversized_frame = (b"b" * limit) + b"\n"
    assert len(oversized_frame) == limit + 1
    with pytest.raises(FrameTooLargeError) as exc_info:
        acc.feed(oversized_frame)
    assert exc_info.value.observed_bytes == limit + 1
    assert exc_info.value.max_frame_bytes == limit


def test_unterminated_oversized_chunk_fails_closed() -> None:
    limit = 16
    acc = FrameAccumulator("server_to_client", max_frame_bytes=limit)
    assert acc.feed(b"1234567890") == []

    with pytest.raises(FrameTooLargeError) as exc_info:
        acc.feed(b"1234567")  # 10 + 7 = 17 > 16 without newline
    assert exc_info.value.observed_bytes == 17
    assert acc.buffered_bytes == 0


def test_frame_larger_than_64kib_accepted_under_default_limit() -> None:
    acc = FrameAccumulator("server_to_client")
    big_frame = (b"x" * 200_000) + b"\n"
    assert DEFAULT_MAX_FRAME_BYTES > len(big_frame) > 65_536
    assert acc.feed(big_frame) == [big_frame]


def test_non_positive_limit_rejected() -> None:
    with pytest.raises(ValueError):
        FrameAccumulator("client_to_server", max_frame_bytes=0)
