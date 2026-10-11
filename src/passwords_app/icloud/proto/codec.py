# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Minimal protobuf wire codec for the Cuttlefish and CloudKit messages.

Hand-rolled to keep byte-exact control over field ordering: Apple signs some of these blobs,
and a generated encoder would be free to reorder or re-encode them.
"""

from __future__ import annotations

import struct
from typing import Self, overload

WT_VARINT = 0
WT_I64 = 1
WT_LEN = 2
WT_I32 = 5

_U64 = (1 << 64) - 1
_FIXED_WIDTH = {WT_I64: 8, WT_I32: 4}

Fields = dict[int, list[int | bytes]]


class ProtoError(ValueError):
    pass


def encode_varint(v: int) -> bytes:
    if v < 0:
        v &= _U64  # two's complement for negative ints (proto int64)
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return encode_varint((field << 3) | wire)


_Bytes = bytes  # inside Writer, `bytes` names the method below


class Writer:
    """Accumulates fields in call order.

    Call fields in ascending field-number order when the output is going to be signed (matches
    Apple's generated `writeTo:` canonical ordering). A `None` value writes nothing, so optional
    fields chain without branches.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def uint64(self, field: int, value: int | None) -> Self:
        if value is not None:
            self._buf += _tag(field, WT_VARINT) + encode_varint(value)
        return self

    def bool(self, field: int, value: bool | None) -> Self:
        if value is not None:
            self._buf += _tag(field, WT_VARINT) + encode_varint(1 if value else 0)
        return self

    def double(self, field: int, value: float | None) -> Self:
        if value is not None:
            self._buf += _tag(field, WT_I64) + struct.pack("<d", value)
        return self

    def bytes(self, field: int, value: bytes | None) -> Self:
        if value is not None:
            self._buf += _tag(field, WT_LEN) + encode_varint(len(value)) + value
        return self

    def string(self, field: int, value: str | None) -> Self:
        if value is not None:
            return self.bytes(field, value.encode("utf-8"))
        return self

    def message(self, field: int, value: Writer | _Bytes | None) -> Self:
        if value is None:
            return self
        return self.bytes(field, value if isinstance(value, _Bytes) else value.finish())

    def finish(self) -> _Bytes:
        return _Bytes(self._buf)


_MAX_VARINT_BITS = 70  # 10 bytes x 7 bits, the longest uint64 encoding


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Decode the base-128 varint at `pos`; return (value, position after it)."""
    shift = val = 0
    n = len(data)
    while True:
        if pos >= n:
            msg = "truncated varint"
            raise ProtoError(msg)
        b = data[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, pos
        shift += 7
        if shift >= _MAX_VARINT_BITS:
            # A uint64 needs at most 10 bytes; longer runs are damage and would cost
            # quadratic big-int work on an adversarial body.
            msg = "varint longer than 10 bytes"
            raise ProtoError(msg)


def decode_fields(data: bytes) -> Fields:
    """Parse raw wire data into {field_number: [values...]}, preserving repeats.

    Values are: int for varint/i32/i64, bytes for length-delimited. Callers interpret bytes as
    string/sub-message as needed. Unknown fields are kept (so round-trips don't silently drop).
    Any truncated value raises `ProtoError` rather than yielding a short slice.
    """
    pos, n = 0, len(data)
    out: Fields = {}
    while pos < n:
        tag, pos = read_varint(data, pos)
        field, wire = tag >> 3, tag & 7
        val: int | bytes
        if wire == WT_VARINT:
            val, pos = read_varint(data, pos)
        elif wire == WT_LEN:
            ln, pos = read_varint(data, pos)
            val = bytes(data[pos : pos + ln])
            pos += ln
            if len(val) != ln:
                msg = "truncated length-delimited field"
                raise ProtoError(msg)
        elif wire in _FIXED_WIDTH:
            width = _FIXED_WIDTH[wire]
            if pos + width > n:
                msg = f"truncated fixed-width field {field}"
                raise ProtoError(msg)
            val = int.from_bytes(data[pos : pos + width], "little")
            pos += width
        else:
            msg = f"unsupported wire type {wire} (field {field})"
            raise ProtoError(msg)
        out.setdefault(field, []).append(val)
    return out


@overload
def first(fields: Fields, field: int) -> int | bytes | None: ...
@overload
def first[T](fields: Fields, field: int, default: T) -> int | bytes | T: ...
def first(fields: Fields, field: int, default: object = None) -> object:
    vals = fields.get(field)
    return vals[0] if vals else default


def first_bytes(fields: Fields, field: int) -> bytes | None:
    """Return the first value of a length-delimited field (bytes, string or sub-message)."""
    v = first(fields, field)
    return v if isinstance(v, bytes) else None


def first_int(fields: Fields, field: int) -> int | None:
    """Return the first value of a varint or fixed-width field."""
    v = first(fields, field)
    return v if isinstance(v, int) else None


@overload
def first_str(fields: Fields, field: int) -> str | None: ...
@overload
def first_str(fields: Fields, field: int, default: str) -> str: ...
def first_str(fields: Fields, field: int, default: str | None = None) -> str | None:
    v = first_bytes(fields, field)
    if v is None:
        return default
    try:
        return v.decode("utf-8")
    except UnicodeDecodeError as e:
        msg = f"field {field} is not UTF-8"
        raise ProtoError(msg) from e


def first_message(fields: Fields, field: int) -> Fields | None:
    """Return the first value of a sub-message field, decoded."""
    v = first_bytes(fields, field)
    return decode_fields(v) if v is not None else None


def all_bytes(fields: Fields, field: int) -> list[bytes]:
    """Every value of a repeated length-delimited field, in wire order."""
    return [v for v in fields.get(field, []) if isinstance(v, bytes)]


def as_double(bits: int) -> float:
    """Reinterpret a fixed64 field as the IEEE-754 double it encodes."""
    value: float = struct.unpack("<d", (bits & _U64).to_bytes(8, "little"))[0]
    return value


def as_int64(value: int) -> int:
    """Reinterpret a varint as the signed int64 it encodes (negatives arrive as 2^64 - n)."""
    value &= _U64
    return value - (1 << 64) if value >> 63 else value
