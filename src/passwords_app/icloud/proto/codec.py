"""Minimal protobuf wire codec - enough to build/parse the Cuttlefish + CloudKit messages,
hand-rolled to keep byte-exact control over field ordering (Apple signs some of these blobs)."""

from __future__ import annotations

WT_VARINT = 0
WT_LEN = 2
WT_I64 = 1
WT_I32 = 5


class ProtoError(ValueError):
    pass


def encode_varint(v: int) -> bytes:
    if v < 0:
        v &= (1 << 64) - 1  # two's complement for negative ints (proto int64)
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return encode_varint((field << 3) | wire)


class Writer:
    """Accumulates fields in call order. Call fields in ascending field-number order when the
    output is going to be signed (matches Apple's generated `writeTo:` canonical ordering)."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def uint64(self, field: int, value: int | None) -> "Writer":
        if value is not None:
            self._buf += _tag(field, WT_VARINT) + encode_varint(value)
        return self

    def bool(self, field: int, value: bool | None) -> "Writer":
        if value is not None:
            self._buf += _tag(field, WT_VARINT) + encode_varint(1 if value else 0)
        return self

    def bytes(self, field: int, value: bytes | None) -> "Writer":
        if value is not None:
            self._buf += _tag(field, WT_LEN) + encode_varint(len(value)) + value
        return self

    def string(self, field: int, value: str | None) -> "Writer":
        if value is not None:
            return self.bytes(field, value.encode("utf-8"))
        return self

    def message(self, field: int, value: "Writer | bytes | None") -> "Writer":
        if value is None:
            return self
        raw = value.finish() if isinstance(value, Writer) else value
        return self.bytes(field, raw)

    def finish(self) -> bytes:
        return bytes(self._buf)


def decode_fields(data: bytes) -> dict:
    """Parse raw wire data into {field_number: [values...]}, preserving repeats.

    Values are: int for varint/i32/i64, bytes for length-delimited. Callers interpret bytes as
    string/sub-message as needed. Unknown fields are kept (so round-trips don't silently drop).
    """
    pos, n = 0, len(data)
    out: dict[int, list] = {}

    def read_varint(p):
        shift, val = 0, 0
        while True:
            if p >= n:
                raise ProtoError("truncated varint")
            b = data[p]
            p += 1
            val |= (b & 0x7F) << shift
            if not (b & 0x80):
                return val, p
            shift += 7

    while pos < n:
        tag, pos = read_varint(pos)
        field, wire = tag >> 3, tag & 7
        if wire == WT_VARINT:
            val, pos = read_varint(pos)
        elif wire == WT_LEN:
            ln, pos = read_varint(pos)
            val = data[pos:pos + ln]
            pos += ln
            if len(val) != ln:
                raise ProtoError("truncated length-delimited field")
        elif wire == WT_I64:
            val = int.from_bytes(data[pos:pos + 8], "little")
            pos += 8
        elif wire == WT_I32:
            val = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4
        else:
            raise ProtoError(f"unsupported wire type {wire} (field {field})")
        out.setdefault(field, []).append(val)
    return out


def first(fields: dict, field: int, default=None):
    vals = fields.get(field)
    return vals[0] if vals else default


def first_str(fields: dict, field: int, default=None):
    v = first(fields, field)
    return v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else default
