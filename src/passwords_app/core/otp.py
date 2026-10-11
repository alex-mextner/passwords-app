# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""TOTP (RFC 6238) from `otpauth://totp/...` URIs, the form Apple stores for verification codes.

The shared secret is a long-lived credential: it is kept out of `repr` and never quoted in error
messages, since both routinely end up in logs.
"""

from __future__ import annotations

import base64
import hmac
import math
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal
from urllib.parse import SplitResult, parse_qsl, unquote, urlsplit

if TYPE_CHECKING:
    from datetime import datetime

type Algorithm = Literal["SHA1", "SHA256", "SHA512"]

_ALGORITHMS: tuple[Algorithm, ...] = ("SHA1", "SHA256", "SHA512")
_DIGITS_RANGE = range(6, 9)
_PERIOD_RANGE = range(1, 3601)
_INT = re.compile(r"[0-9]{1,10}")
# Base32 groups encode 5 bytes in 8 chars; these residues cannot end a valid encoding.
_BAD_B32_LENGTHS = frozenset({1, 3, 6})


class OtpError(ValueError):
    """The otpauth URI or its parameters are not a usable TOTP configuration."""


@dataclass(frozen=True, slots=True)
class OtpParams:
    secret: bytes = field(repr=False)
    digits: int
    period: int
    algorithm: Algorithm
    issuer: str | None
    account: str | None

    def __post_init__(self) -> None:
        if not self.secret:
            msg = "secret must be non-empty"
            raise OtpError(msg)
        if self.digits not in _DIGITS_RANGE:
            msg = "digits must be 6..8"
            raise OtpError(msg)
        if self.period not in _PERIOD_RANGE:
            msg = "period must be 1..3600 seconds"
            raise OtpError(msg)
        if self.algorithm not in _ALGORITHMS:
            msg = "algorithm must be SHA1, SHA256 or SHA512"
            raise OtpError(msg)


def _decode_secret(raw: str) -> bytes:
    text = raw.replace(" ", "").upper().rstrip("=")
    if not text or len(text) % 8 in _BAD_B32_LENGTHS:
        msg = "secret is not valid base32"
        raise OtpError(msg)
    try:
        secret = base64.b32decode(text + "=" * (-len(text) % 8))
    except ValueError:  # binascii.Error, or plain ValueError for non-ASCII input
        # Deliberately not chained: the underlying message can quote the offending input.
        msg = "secret is not valid base32"
        raise OtpError(msg) from None
    return secret


def _int_param(params: dict[str, str], name: str, default: int, allowed: range) -> int:
    raw = params.get(name)
    if raw is None:
        return default
    # int() would also take signs, spaces, underscores and non-ASCII digits.
    if not _INT.fullmatch(raw) or int(raw) not in allowed:
        msg = f"{name} must be an integer in {allowed.start}..{allowed.stop - 1}"
        raise OtpError(msg)
    return int(raw)


def _algorithm(params: dict[str, str]) -> Algorithm:
    raw = params.get("algorithm", "SHA1").upper()
    if raw in _ALGORITHMS:
        return raw
    msg = "algorithm must be SHA1, SHA256 or SHA512"
    raise OtpError(msg)


def _split_totp_uri(uri: str) -> SplitResult:
    try:
        parts = urlsplit(uri)
    except ValueError:
        msg = "not a URI"
        raise OtpError(msg) from None
    if parts.scheme.lower() != "otpauth":
        msg = "scheme must be otpauth"
        raise OtpError(msg)
    if parts.netloc.lower() != "totp":
        msg = "only totp is supported"
        raise OtpError(msg)
    return parts


def _query_params(query: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for key, value in parse_qsl(query, keep_blank_values=True):
        name = key.lower()
        if name in params:
            msg = f"duplicate parameter {name!r}"
            raise OtpError(msg)
        params[name] = value
    if "secret" not in params:
        msg = "secret is missing"
        raise OtpError(msg)
    return params


def parse_otpauth(uri: str) -> OtpParams:
    """Parse `otpauth://totp/[Issuer:]account?secret=...`; raises OtpError on anything else."""
    parts = _split_totp_uri(uri)
    params = _query_params(parts.query)

    label = unquote(parts.path.removeprefix("/"))
    label_issuer, sep, account = label.partition(":")
    if not sep:
        label_issuer, account = "", label_issuer
    account = account.strip()
    issuer = params.get("issuer") or label_issuer.strip()

    return OtpParams(
        secret=_decode_secret(params["secret"]),
        digits=_int_param(params, "digits", 6, _DIGITS_RANGE),
        period=_int_param(params, "period", 30, _PERIOD_RANGE),
        algorithm=_algorithm(params),
        issuer=issuer or None,
        account=account or None,
    )


def code_at(p: OtpParams, at: datetime) -> tuple[str, int]:
    """Return (zero-padded code, seconds left in the current period, 1..period) at `at`."""
    if at.tzinfo is None or at.utcoffset() is None:
        msg = "at must be timezone-aware"
        raise ValueError(msg)
    now = math.floor(at.timestamp())
    if now < 0:
        msg = "TOTP is undefined before the Unix epoch"
        raise ValueError(msg)
    counter, elapsed = divmod(now, p.period)
    digest = hmac.digest(p.secret, counter.to_bytes(8, "big"), p.algorithm.lower())
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    code = str(binary % 10**p.digits).zfill(p.digits)
    return code, p.period - elapsed
