# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Password strength (zxcvbn) and reuse detection."""

from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from passwords_app.core.model import Credential
from passwords_app.core.strength import Strength, assess, reused

_T = datetime(2026, 1, 1, tzinfo=UTC)


def _cred(cid: str, password: str) -> Credential:
    return Credential(
        id=cid, url="https://example.com", username="u", password=password, created=_T, modified=_T
    )


def _key(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@pytest.mark.parametrize(
    "password",
    [
        "",
        "password",
        "123456",
        "qwerty",
        "aaaaaaaaaaaa",
        "letmein",
        "iloveyou",
        "Password1",
        "Tr0ub4dour&3",
        "пароль",
        "abc123",
        "11111111",
    ],
)
def test_weak_passwords(password: str) -> None:
    s = assess(password)
    assert s.weak
    assert s.score < 3


@pytest.mark.parametrize(
    "password",
    [
        "correct horse battery staple",
        "xkQ9-mzt4-Pq2w-R8vn",
        "kqzbtw-vfmh7J-pxrnsa",
        "cxndk-Rvp4b-ahbki",
        "кошкасобакажираф9Щ",  # noqa: RUF001 - Cyrillic on purpose
        "zorblaxquentin",
    ],
)
def test_strong_passwords(password: str) -> None:
    s = assess(password)
    assert not s.weak
    assert s.score >= 3


def test_empty_password_is_score_zero() -> None:
    assert assess("") == Strength(score=0, weak=True)


@pytest.mark.parametrize(
    "password",
    ["", "a", "password", "correct horse battery staple", "🔑" * 40, "x" * 300],
    ids=["empty", "one-char", "common", "passphrase", "emoji-40", "x-300"],
)
def test_score_in_range_and_weak_consistent(password: str) -> None:
    s = assess(password)
    assert 0 <= s.score <= 4
    assert s.weak is (s.score < 3)


def test_password_equal_to_user_input_is_weak() -> None:
    assert not assess("zorblaxquentin").weak
    assert assess("zorblaxquentin", user_inputs=["zorblaxquentin"]).weak


def test_user_inputs_lower_the_score() -> None:
    plain = assess("mextnerQuasar77")
    informed = assess("mextnerQuasar77", user_inputs=("mextner", "quasar"))
    assert informed.score < plain.score


def test_user_inputs_do_not_leak_between_calls() -> None:
    # zxcvbn keeps user inputs in module-global state; a later call must not inherit them.
    assess("zorblaxquentin", user_inputs=["zorblaxquentin"])
    assert not assess("zorblaxquentin").weak


def test_user_inputs_accepts_any_sequence() -> None:
    assert assess("zorblaxquentin", user_inputs=("zorblaxquentin",)).weak


@pytest.mark.parametrize("password", ["🔑🔒🗝️🔐", "пароль", "密码密码", "ÄÖÜäöüß"])
def test_unicode_passwords_are_assessed(password: str) -> None:
    assert isinstance(assess(password).score, int)


def test_long_input_is_truncated_to_256() -> None:
    head = "Zq7!mK2@vB9#xL4$" * 16  # exactly 256 characters
    assert len(head) == 256
    assert assess(head + "a" * 10_000) == assess(head)


def test_input_beyond_zxcvbn_default_limit_accepted() -> None:
    # zxcvbn raises above 72 characters by default; long passphrases must still be scored.
    assert not assess("correct horse battery staple " * 4).weak


def test_strength_is_frozen() -> None:
    s = assess("password")
    with pytest.raises(FrozenInstanceError):
        s.score = 4  # type: ignore[misc]


# ------------------------------------------------------------------ reused


def test_reused_groups_shared_passwords() -> None:
    creds = [
        _cred("b", "hunter2"),
        _cred("a", "hunter2"),
        _cred("c", "unique"),
        _cred("d", "s3cret"),
        _cred("e", "s3cret"),
        _cred("f", "s3cret"),
    ]
    assert reused(creds) == {_key("hunter2"): ["a", "b"], _key("s3cret"): ["d", "e", "f"]}


def test_reused_ids_sorted() -> None:
    creds = [_cred(cid, "same") for cid in ("z", "m", "a", "k")]
    assert reused(creds) == {_key("same"): ["a", "k", "m", "z"]}


def test_reused_single_use_excluded() -> None:
    assert reused([_cred("a", "one"), _cred("b", "two")]) == {}


def test_reused_empty_passwords_ignored() -> None:
    assert reused([_cred("a", ""), _cred("b", ""), _cred("c", "")]) == {}


def test_reused_empty_input() -> None:
    assert reused([]) == {}


def test_reused_accepts_iterator() -> None:
    assert reused(iter([_cred("a", "x1"), _cred("b", "x1")])) == {_key("x1"): ["a", "b"]}


def test_reused_is_case_sensitive() -> None:
    assert reused([_cred("a", "Hunter2"), _cred("b", "hunter2")]) == {}


def test_reused_whitespace_matters() -> None:
    assert reused([_cred("a", "pw"), _cred("b", "pw ")]) == {}


def test_reused_unicode_key_is_utf8_sha256() -> None:
    assert reused([_cred("a", "пароль"), _cred("b", "пароль")]) == {_key("пароль"): ["a", "b"]}


def test_reused_key_never_contains_password() -> None:
    password = "correct horse battery staple"
    result = reused([_cred("a", password), _cred("b", password)])
    (key,) = result
    assert password not in key
    assert key == _key(password)
    assert len(key) == 64
    assert all(c in "0123456789abcdef" for c in key)


def test_reused_duplicate_id_counted_once() -> None:
    # The same credential observed twice (e.g. from two listings) is not "reuse".
    assert reused([_cred("a", "dup"), _cred("a", "dup")]) == {}
