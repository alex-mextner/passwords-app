# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
from __future__ import annotations

import io
import json
import struct
from typing import BinaryIO, cast

import pytest

from passwords_app.browser.framing import (
    DISCARD_CHUNK,
    MAX_PAYLOAD,
    MalformedError,
    Oversize,
    TooLargeError,
    decode_message,
    encode_frame,
    read_frame,
    write_frame,
)


def frame(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


class TrickleReader:
    """A pipe that hands out at most `step` bytes per read, like a slow browser."""

    def __init__(self, data: bytes, step: int) -> None:
        self._data = data
        self._step = step
        self.largest_read = 0

    def read(self, size: int) -> bytes:
        self.largest_read = max(self.largest_read, size)
        n = min(size, self._step)
        chunk, self._data = self._data[:n], self._data[n:]
        return chunk

    def stream(self) -> BinaryIO:
        # read_frame only ever calls read(n); the rest of BinaryIO is never touched.
        return cast("BinaryIO", self)


# ---------------------------------------------------------------------- encoding


def test_round_trip() -> None:
    message = {"id": 7, "cmd": "match", "url": "https://accounts.example.com/login"}
    stream = io.BytesIO(encode_frame(message))
    payload = read_frame(stream)
    assert isinstance(payload, bytes)
    assert decode_message(payload) == message


def test_length_prefix_is_little_endian_uint32() -> None:
    data = encode_frame({"a": "b"})
    payload = b'{"a":"b"}'
    assert data[:4] == len(payload).to_bytes(4, "little")
    assert data[4:] == payload


def test_non_ascii_round_trips_through_escapes() -> None:
    message = {"title": "Почта Пример ☕", "lone": "\ud800"}
    data = encode_frame(message)
    assert data[4:].isascii()
    payload = read_frame(io.BytesIO(data))
    assert isinstance(payload, bytes)
    assert decode_message(payload) == message


def test_encode_exactly_at_cap() -> None:
    overhead = len(encode_frame({"p": ""})) - 4
    data = encode_frame({"p": "x" * (MAX_PAYLOAD - overhead)})
    assert len(data) == 4 + MAX_PAYLOAD


def test_encode_one_over_cap_raises() -> None:
    overhead = len(encode_frame({"p": ""})) - 4
    with pytest.raises(TooLargeError):
        encode_frame({"p": "x" * (MAX_PAYLOAD - overhead + 1)})


def test_encode_rejects_nan() -> None:
    with pytest.raises(ValueError, match="JSON"):
        encode_frame({"x": float("nan")})


def test_write_frame_flushes() -> None:
    raw = io.BytesIO()
    buffered = io.BufferedWriter(raw)
    write_frame(buffered, encode_frame({"ok": True}))
    assert raw.getvalue() == frame(b'{"ok":true}')


# ---------------------------------------------------------------------- reading


def test_two_frames_in_order() -> None:
    stream = io.BytesIO(frame(b'{"n":1}') + frame(b'{"n":2}'))
    assert read_frame(stream) == b'{"n":1}'
    assert read_frame(stream) == b'{"n":2}'
    assert read_frame(stream) is None


def test_eof_before_any_frame() -> None:
    assert read_frame(io.BytesIO(b"")) is None


@pytest.mark.parametrize("prefix", [b"\x05", b"\x05\x00", b"\x05\x00\x00"])
def test_truncated_prefix_is_eof(prefix: bytes) -> None:
    assert read_frame(io.BytesIO(prefix)) is None


def test_truncated_payload_is_eof() -> None:
    assert read_frame(io.BytesIO(struct.pack("<I", 10) + b"12345")) is None


def test_zero_length_frame_is_empty_payload() -> None:
    stream = io.BytesIO(frame(b"") + frame(b"{}"))
    assert read_frame(stream) == b""
    assert read_frame(stream) == b"{}"


def test_short_reads_are_reassembled() -> None:
    payload = json.dumps({"url": "https://example.com/" + "a" * 5000}).encode()
    stream = TrickleReader(frame(payload) * 2, step=7).stream()
    assert read_frame(stream) == payload
    assert read_frame(stream) == payload


def test_payload_exactly_at_cap_is_read() -> None:
    payload = b"x" * MAX_PAYLOAD
    assert read_frame(io.BytesIO(frame(payload))) == payload


def test_payload_one_under_cap_is_read() -> None:
    payload = b"x" * (MAX_PAYLOAD - 1)
    assert read_frame(io.BytesIO(frame(payload))) == payload


def test_payload_one_over_cap_is_skipped() -> None:
    stream = io.BytesIO(frame(b"x" * (MAX_PAYLOAD + 1)) + frame(b'{"next":1}'))
    assert read_frame(stream) == Oversize(MAX_PAYLOAD + 1)
    assert read_frame(stream) == b'{"next":1}'


def test_oversize_discard_keeps_stream_in_sync_and_reads_in_bounded_chunks() -> None:
    length = 3 * MAX_PAYLOAD + 123
    raw = TrickleReader(frame(b"y" * length) + frame(b'{"after":true}'), step=1 << 30)
    assert read_frame(raw.stream()) == Oversize(length)
    assert raw.largest_read <= DISCARD_CHUNK
    assert read_frame(raw.stream()) == b'{"after":true}'


def test_oversize_with_huge_declared_length_ending_early_is_eof() -> None:
    stream = io.BytesIO(struct.pack("<I", 0xFFFFFFFF) + b"z" * 1000)
    assert read_frame(stream) is None


# ---------------------------------------------------------------------- decoding


def test_decode_object() -> None:
    assert decode_message(b'{"id":1,"cmd":"status"}') == {"id": 1, "cmd": "status"}


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b"", "empty"),
        (b"\xff\xfe{}", "UTF-8"),
        (b'{"a":"\xc3"}', "UTF-8"),
        (b"\xed\xa0\x80", "UTF-8"),  # an encoded surrogate is not UTF-8
        (b"{", "JSON"),
        (b"{}garbage", "JSON"),
        (b"\xef\xbb\xbf{}", "JSON"),  # BOM
        (b'{"a":NaN}', "JSON"),
        (b'{"a":Infinity}', "JSON"),
        (b'{"a":1' + b"0" * 5000 + b"}", "JSON"),  # beyond int digit limit
        (b"[" * 100_000 + b"]" * 100_000, "JSON"),  # nesting deeper than the parser allows
        (b"[]", "object"),
        (b'"text"', "object"),
        (b"42", "object"),
        (b"null", "object"),
        (b"true", "object"),
    ],
)
def test_malformed_payloads(payload: bytes, reason: str) -> None:
    with pytest.raises(MalformedError, match=reason):
        decode_message(payload)


def test_duplicate_keys_keep_the_last_value() -> None:
    assert decode_message(b'{"cmd":"match","cmd":"status"}') == {"cmd": "status"}
