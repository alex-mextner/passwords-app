# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Native messaging framing: a uint32 little-endian length, then that many bytes of UTF-8 JSON.

Browsers use the platform byte order; every platform this project supports is little endian, and
pinning it keeps the wire format independent of where the tests run.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO, Final, NoReturn, cast

if TYPE_CHECKING:
    from collections.abc import Mapping

MAX_PAYLOAD: Final = 1024 * 1024
# Oversize frames are skipped in pieces this big so a hostile length never sizes a buffer.
DISCARD_CHUNK: Final = 64 * 1024
_HEADER: Final = struct.Struct("<I")


class MalformedError(ValueError):
    """The frame payload is not a UTF-8 JSON object."""


class TooLargeError(ValueError):
    """An outgoing message does not fit in one frame."""


@dataclass(frozen=True, slots=True)
class Oversize:
    """An incoming frame over the cap; its payload has already been skipped."""

    length: int


def _read_exact(stream: BinaryIO, size: int) -> bytes | None:
    """Read exactly `size` bytes, or None when the stream ends first."""
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(stream: BinaryIO) -> bytes | Oversize | None:
    """Next frame's payload, `Oversize` for a skipped frame, None at (possibly mid-frame) EOF."""
    header = _read_exact(stream, _HEADER.size)
    if header is None:
        return None
    (length,) = _HEADER.unpack(header)
    if length <= MAX_PAYLOAD:
        return _read_exact(stream, length)
    remaining = length
    while remaining:
        chunk = stream.read(min(remaining, DISCARD_CHUNK))
        if not chunk:
            return None
        remaining -= len(chunk)
    return Oversize(length)


def _reject_constant(name: str) -> NoReturn:
    # NaN and Infinity are Python extensions, not JSON; the browser never sends them.
    msg = f"{name} is not JSON"
    raise ValueError(msg)


def decode_message(payload: bytes) -> dict[str, object]:
    """Parse one payload into a JSON object or raise `MalformedError`."""
    if not payload:
        msg = "empty frame"
        raise MalformedError(msg)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        msg = "frame is not UTF-8"
        raise MalformedError(msg) from None
    try:
        value = json.loads(text, parse_constant=_reject_constant)
    # RecursionError: deeply nested arrays fit easily in 1 MiB.
    except (ValueError, RecursionError):
        msg = "frame is not JSON"
        raise MalformedError(msg) from None
    if not isinstance(value, dict):
        msg = "frame is not a JSON object"
        raise MalformedError(msg)
    return cast("dict[str, object]", value)


def encode_frame(message: Mapping[str, object]) -> bytes:
    """Length prefix + JSON for `message`; raises `TooLargeError` over the cap."""
    # ASCII escapes keep lone surrogates (valid in a JSON string, not in UTF-8) encodable.
    payload = json.dumps(message, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode(
        "ascii"
    )
    if len(payload) > MAX_PAYLOAD:
        msg = f"message of {len(payload)} bytes is over the {MAX_PAYLOAD}-byte cap"
        raise TooLargeError(msg)
    return _HEADER.pack(len(payload)) + payload


def write_frame(stream: BinaryIO, frame: bytes) -> None:
    stream.write(frame)
    stream.flush()
