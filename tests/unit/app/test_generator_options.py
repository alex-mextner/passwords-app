# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Generator settings: Apple's format by default, a clamped custom mode with class guarantees."""

from __future__ import annotations

import re
import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from passwords_app.app.generator_options import (
    MAX_CUSTOM_LENGTH,
    MIN_CUSTOM_LENGTH,
    GeneratorOptions,
    Mode,
    make_password,
)

APPLE = re.compile(r"[A-Za-z0-9]{6}-[A-Za-z0-9]{6}-[A-Za-z0-9]{6}")


def test_default_is_apple_format() -> None:
    assert GeneratorOptions().mode is Mode.APPLE
    for _ in range(50):
        pw = make_password(GeneratorOptions())
        assert APPLE.fullmatch(pw)
        assert sum(c.isupper() for c in pw) == 1
        assert sum(c.isdigit() for c in pw) == 1


def test_apple_mode_ignores_custom_options() -> None:
    options = GeneratorOptions(Mode.APPLE, length=8, uppercase=False, digits=False)
    assert APPLE.fullmatch(make_password(options))


@pytest.mark.parametrize(
    ("requested", "clamped"),
    [
        (-5, MIN_CUSTOM_LENGTH),
        (0, MIN_CUSTOM_LENGTH),
        (MIN_CUSTOM_LENGTH - 1, MIN_CUSTOM_LENGTH),
        (MIN_CUSTOM_LENGTH, MIN_CUSTOM_LENGTH),
        (20, 20),
        (MAX_CUSTOM_LENGTH, MAX_CUSTOM_LENGTH),
        (MAX_CUSTOM_LENGTH + 1, MAX_CUSTOM_LENGTH),
        (10_000, MAX_CUSTOM_LENGTH),
    ],
)
def test_clamped_length(requested: int, clamped: int) -> None:
    options = GeneratorOptions(Mode.CUSTOM, requested, uppercase=False, digits=True, symbols=False)
    result = options.clamped()
    assert result == GeneratorOptions(Mode.CUSTOM, clamped, uppercase=False, symbols=False)
    assert len(make_password(options)) == clamped


@settings(max_examples=60)
@given(
    length=st.integers(min_value=-10, max_value=200),
    uppercase=st.booleans(),
    digits=st.booleans(),
    symbols=st.booleans(),
)
def test_custom_password_has_exactly_the_enabled_classes(
    length: int, *, uppercase: bool, digits: bool, symbols: bool
) -> None:
    pw = make_password(GeneratorOptions(Mode.CUSTOM, length, uppercase, digits, symbols))
    assert MIN_CUSTOM_LENGTH <= len(pw) <= MAX_CUSTOM_LENGTH
    assert any(c in string.ascii_lowercase for c in pw)
    assert any(c in string.ascii_uppercase for c in pw) is uppercase
    assert any(c in string.digits for c in pw) is digits
    assert any(c in string.punctuation for c in pw) is symbols
    allowed = set(string.ascii_lowercase)
    allowed |= set(string.ascii_uppercase) if uppercase else set()
    allowed |= set(string.digits) if digits else set()
    allowed |= set(string.punctuation) if symbols else set()
    assert set(pw) <= allowed


def test_lowercase_only_when_every_option_is_off() -> None:
    options = GeneratorOptions(Mode.CUSTOM, 12, uppercase=False, digits=False, symbols=False)
    pw = make_password(options)
    assert len(pw) == 12
    assert set(pw) <= set(string.ascii_lowercase)


def test_passwords_differ_between_calls() -> None:
    options = GeneratorOptions(Mode.CUSTOM, 20)
    assert len({make_password(options) for _ in range(20)}) == 20
