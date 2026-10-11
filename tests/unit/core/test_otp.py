# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""otpauth:// parsing and TOTP code generation against the RFC 4226/6238 test vectors."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta, timezone
from typing import Literal

import pytest

from passwords_app.core.otp import OtpError, OtpParams, code_at, parse_otpauth

type Algorithm = Literal["SHA1", "SHA256", "SHA512"]

SEEDS: dict[Algorithm, bytes] = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}

# RFC 6238 Appendix B.
RFC6238: list[tuple[int, Algorithm, str]] = [
    (59, "SHA1", "94287082"),
    (59, "SHA256", "46119246"),
    (59, "SHA512", "90693936"),
    (1111111109, "SHA1", "07081804"),
    (1111111109, "SHA256", "68084774"),
    (1111111109, "SHA512", "25091201"),
    (1111111111, "SHA1", "14050471"),
    (1111111111, "SHA256", "67062674"),
    (1111111111, "SHA512", "99943326"),
    (1234567890, "SHA1", "89005924"),
    (1234567890, "SHA256", "91819424"),
    (1234567890, "SHA512", "93441116"),
    (2000000000, "SHA1", "69279037"),
    (2000000000, "SHA256", "90698825"),
    (2000000000, "SHA512", "38618901"),
    (20000000000, "SHA1", "65353130"),
    (20000000000, "SHA256", "77737706"),
    (20000000000, "SHA512", "47863826"),
]

# RFC 4226 Appendix D: HOTP(counter) for the SHA1 seed, 6 digits.
RFC4226 = ["755224", "287082", "359152", "969429", "338314"]
RFC4226 += ["254676", "287922", "162583", "399871", "520489"]


def _params(alg: Algorithm = "SHA1", digits: int = 8, period: int = 30) -> OtpParams:
    return OtpParams(
        secret=SEEDS[alg], digits=digits, period=period, algorithm=alg, issuer=None, account=None
    )


def _at(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=UTC)


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode()


@pytest.mark.parametrize(("ts", "alg", "expected"), RFC6238)
def test_rfc6238_vectors(ts: int, alg: Algorithm, expected: str) -> None:
    code, _ = code_at(_params(alg), _at(ts))
    assert code == expected


@pytest.mark.parametrize(("ts", "alg", "expected"), RFC6238)
def test_rfc6238_six_digits_is_suffix(ts: int, alg: Algorithm, expected: str) -> None:
    # Truncation is mod 10^digits, so the 6-digit code is the 8-digit code's last six.
    code, _ = code_at(_params(alg, digits=6), _at(ts))
    assert code == expected[-6:]


@pytest.mark.parametrize(("ts", "alg", "expected"), RFC6238)
def test_rfc6238_vectors_through_uri(ts: int, alg: Algorithm, expected: str) -> None:
    uri = f"otpauth://totp/X?secret={_b32(SEEDS[alg])}&digits=8&algorithm={alg}"
    assert code_at(parse_otpauth(uri), _at(ts))[0] == expected


@pytest.mark.parametrize(("counter", "expected"), list(enumerate(RFC4226)))
def test_period_60_uses_counter_t_div_60(counter: int, expected: str) -> None:
    p = _params(digits=6, period=60)
    assert code_at(p, _at(counter * 60))[0] == expected
    assert code_at(p, _at(counter * 60 + 59))[0] == expected


@pytest.mark.parametrize(("counter", "expected"), list(enumerate(RFC4226)))
def test_period_30_counter_vectors(counter: int, expected: str) -> None:
    assert code_at(_params(digits=6), _at(counter * 30 + 15))[0] == expected


def test_seven_digits() -> None:
    code, _ = code_at(_params(digits=7), _at(59))
    assert code == "4287082"


def test_code_is_zero_padded() -> None:
    code, _ = code_at(_params(), _at(1111111109))
    assert code == "07081804"
    assert len(code) == 8


@pytest.mark.parametrize(
    ("ts", "period", "left"),
    [
        (0, 30, 30),
        (1, 30, 29),
        (29, 30, 1),
        (30, 30, 30),
        (59, 30, 1),
        (60, 30, 30),
        (59, 60, 1),
        (60, 60, 60),
        (61, 60, 59),
        (1111111109, 30, 1),
        (1111111110, 30, 30),
        (0, 1, 1),
        (12345, 1, 1),
        (3599, 3600, 1),
        (3600, 3600, 3600),
        (29.999, 30, 1),
        (30.5, 30, 30),
    ],
)
def test_seconds_left(ts: float, period: int, left: int) -> None:
    _, remaining = code_at(_params(period=period), _at(ts))
    assert remaining == left


def test_code_changes_exactly_at_period_boundary() -> None:
    p = _params(digits=6)
    before, _ = code_at(p, _at(29.999))
    at, _ = code_at(p, _at(30))
    assert before == RFC4226[0]
    assert at == RFC4226[1]


def test_non_utc_timezone_gives_same_code() -> None:
    plus5 = timezone(timedelta(hours=5))
    local = datetime.fromtimestamp(1234567890, tz=plus5)
    assert code_at(_params(), local) == code_at(_params(), _at(1234567890))


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        code_at(_params(), datetime(2026, 1, 1))  # noqa: DTZ001 - the naive value is the point


def test_pre_epoch_rejected() -> None:
    with pytest.raises(ValueError, match="epoch"):
        code_at(_params(), datetime(1969, 12, 31, 23, 59, tzinfo=UTC))


# ------------------------------------------------------------------ parsing

SECRET = _b32(SEEDS["SHA1"])  # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ


def test_parse_defaults() -> None:
    p = parse_otpauth(f"otpauth://totp/alice?secret={SECRET}")
    assert p.secret == SEEDS["SHA1"]
    assert (p.digits, p.period, p.algorithm) == (6, 30, "SHA1")
    assert p.issuer is None
    assert p.account == "alice"


def test_parse_all_params() -> None:
    p = parse_otpauth(
        f"otpauth://totp/ACME%20Co:john.doe%40email.com?secret={SECRET}"
        "&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60"
    )
    assert (p.issuer, p.account) == ("ACME Co", "john.doe@email.com")
    assert (p.algorithm, p.digits, p.period) == ("SHA256", 8, 60)


@pytest.mark.parametrize(
    ("label", "query_issuer", "issuer", "account"),
    [
        ("Example:alice@example.com", "", "Example", "alice@example.com"),
        ("Example:%20alice", "", "Example", "alice"),
        ("Example%3Aalice", "", "Example", "alice"),
        ("alice", "&issuer=Example", "Example", "alice"),
        ("Label:alice", "&issuer=Param", "Param", "alice"),
        ("", "&issuer=Example", "Example", None),
        ("", "", None, None),
        ("%D0%9F%D1%80%D0%B8%D0%BC%D0%B5%D1%80:%D1%8F", "", "Пример", "я"),
        ("A:b:c", "", "A", "b:c"),
        ("Example:", "", "Example", None),
        ("Big%20Corp:a%2Bb%40x.io", "", "Big Corp", "a+b@x.io"),
    ],
)
def test_parse_label(
    label: str, query_issuer: str, issuer: str | None, account: str | None
) -> None:
    p = parse_otpauth(f"otpauth://totp/{label}?secret={SECRET}{query_issuer}")
    assert (p.issuer, p.account) == (issuer, account)


@pytest.mark.parametrize(
    "secret",
    [
        SECRET,
        SECRET.lower(),
        "gezdgnbvgy3tqojqGEZDGNBVGY3TQOJQ",
        "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
        "GEZD%20GNBV%20GY3T%20QOJQ%20GEZD%20GNBV%20GY3T%20QOJQ",
    ],
)
def test_secret_normalization(secret: str) -> None:
    assert parse_otpauth(f"otpauth://totp/x?secret={secret}").secret == SEEDS["SHA1"]


@pytest.mark.parametrize(
    ("unpadded", "raw"),
    [
        ("MY", b"f"),
        ("MZXQ", b"fo"),  # codespell:ignore
        ("MZXW6", b"foo"),
        ("MZXW6YQ", b"foob"),
        ("MZXW6YQ=", b"foob"),
        ("MZXW6YTB", b"fooba"),
        ("MZXW6YTBOI", b"foobar"),
        ("MZXW6YTBOI======", b"foobar"),
    ],
)
def test_secret_padding_optional(unpadded: str, raw: bytes) -> None:
    assert parse_otpauth(f"otpauth://totp/x?secret={unpadded}").secret == raw


@pytest.mark.parametrize(
    ("value", "expected"), [("sha1", "SHA1"), ("Sha256", "SHA256"), ("SHA512", "SHA512")]
)
def test_algorithm_case_insensitive(value: str, expected: Algorithm) -> None:
    p = parse_otpauth(f"otpauth://totp/x?secret={SECRET}&algorithm={value}")
    assert p.algorithm == expected


@pytest.mark.parametrize("digits", [6, 7, 8])
def test_digits_range(digits: int) -> None:
    assert parse_otpauth(f"otpauth://totp/x?secret={SECRET}&digits={digits}").digits == digits


@pytest.mark.parametrize("period", [1, 15, 30, 60, 3600])
def test_period_range(period: int) -> None:
    assert parse_otpauth(f"otpauth://totp/x?secret={SECRET}&period={period}").period == period


def test_scheme_and_type_case_insensitive() -> None:
    assert parse_otpauth(f"OTPAUTH://TOTP/x?secret={SECRET}").secret == SEEDS["SHA1"]


def test_unknown_parameters_ignored() -> None:
    p = parse_otpauth(f"otpauth://totp/x?secret={SECRET}&image=https://x/y.png&foo=bar")
    assert p.secret == SEEDS["SHA1"]


MALFORMED = [
    "otpauth://totp/x?secret=%FF%FF",
    "otpauth://totp/x?secret=ÄÄÄÄÄÄÄÄ",
    "otpauth://totp/x?secret=GEZDGNBV%C3%A9",
    "",
    "not a uri",
    f"https://totp/x?secret={SECRET}",
    f"otpauth-migration://totp/x?secret={SECRET}",
    f"otpauth:totp/x?secret={SECRET}",
    f"otpauth://hotp/x?secret={SECRET}&counter=0",
    f"otpauth://steam/x?secret={SECRET}",
    f"otpauth:///x?secret={SECRET}",
    "otpauth://totp/x",
    "otpauth://totp/x?issuer=Example",
    "otpauth://totp/x?secret=",
    "otpauth://totp/x?secret=%20%20",
    "otpauth://totp/x?secret==",
    "otpauth://totp/x?secret=GEZDGNB1",
    "otpauth://totp/x?secret=GEZDGNB8",
    "otpauth://totp/x?secret=GEZ!GNBV",
    "otpauth://totp/x?secret=A",
    "otpauth://totp/x?secret=ABC",
    "otpauth://totp/x?secret=ABCDEF",
    "otpauth://totp/x?secret=MY=MY",
    f"otpauth://totp/x?secret={SECRET}&secret={SECRET}",
    f"otpauth://totp/x?secret={SECRET}&algorithm=MD5",
    f"otpauth://totp/x?secret={SECRET}&algorithm=SHA-1",
    f"otpauth://totp/x?secret={SECRET}&algorithm=",
    f"otpauth://totp/x?secret={SECRET}&digits=5",
    f"otpauth://totp/x?secret={SECRET}&digits=9",
    f"otpauth://totp/x?secret={SECRET}&digits=0",
    f"otpauth://totp/x?secret={SECRET}&digits=six",
    f"otpauth://totp/x?secret={SECRET}&digits=6.0",
    f"otpauth://totp/x?secret={SECRET}&digits=-6",
    f"otpauth://totp/x?secret={SECRET}&digits=+6",
    f"otpauth://totp/x?secret={SECRET}&digits=",
    f"otpauth://totp/x?secret={SECRET}&digits=%206",
    f"otpauth://totp/x?secret={SECRET}&digits=6&digits=8",
    f"otpauth://totp/x?secret={SECRET}&period=0",
    f"otpauth://totp/x?secret={SECRET}&period=3601",
    f"otpauth://totp/x?secret={SECRET}&period=-30",
    f"otpauth://totp/x?secret={SECRET}&period=30s",
    f"otpauth://totp/x?secret={SECRET}&period=1e2",
    f"otpauth://totp/x?secret={SECRET}&period=٣٠",
    f"otpauth://totp/x?secret={SECRET}&period=99999999999999999999",
]


@pytest.mark.parametrize("uri", MALFORMED)
def test_malformed_uri_rejected(uri: str) -> None:
    with pytest.raises(OtpError):
        parse_otpauth(uri)


def test_otp_error_is_value_error() -> None:
    with pytest.raises(ValueError, match=r"."):
        parse_otpauth("otpauth://hotp/x?secret=GEZDGNBV")


def test_error_message_does_not_echo_secret() -> None:
    bad = "SUPERSECRETVALUE1"  # '1' is outside the base32 alphabet
    with pytest.raises(OtpError) as info:
        parse_otpauth(f"otpauth://totp/x?secret={bad}")
    assert bad not in str(info.value)
    assert bad.lower() not in str(info.value).lower()


def test_secret_not_in_repr_or_str() -> None:
    p = parse_otpauth(f"otpauth://totp/Issuer:acct?secret={SECRET}")
    for text in (repr(p), str(p)):
        assert SECRET not in text
        assert SEEDS["SHA1"].decode() not in text
        assert repr(SEEDS["SHA1"]) not in text
        assert "acct" in text  # repr still useful for debugging


@pytest.mark.parametrize(
    "kwargs",
    [
        {"digits": 5},
        {"digits": 9},
        {"period": 0},
        {"period": 3601},
        {"secret": b""},
    ],
)
def test_params_validated_on_construction(kwargs: dict[str, object]) -> None:
    base: dict[str, object] = {
        "secret": b"x",
        "digits": 6,
        "period": 30,
        "algorithm": "SHA1",
        "issuer": None,
        "account": None,
    }
    with pytest.raises(OtpError):
        OtpParams(**(base | kwargs))  # type: ignore[arg-type]


def test_params_reject_unknown_algorithm() -> None:
    with pytest.raises(OtpError):
        OtpParams(
            secret=b"x",
            digits=6,
            period=30,
            algorithm="MD5",  # type: ignore[arg-type]
            issuer=None,
            account=None,
        )
