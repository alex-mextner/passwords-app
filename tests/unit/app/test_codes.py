# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Verification-code display helpers and the paste-aware six-box sign-in code entry."""

from __future__ import annotations

from urllib.parse import urlencode

import pytest
from hypothesis import given
from hypothesis import strategies as st

from passwords_app.app.codes import (
    DEFAULT_PERIOD,
    SIGNIN_CODE_LENGTH,
    Boxes,
    grouped,
    period_of,
    ring_fraction,
    urgent,
)

KEY_B32 = "JBSWY3DPEHPK3PXP"


def _uri(**params: str) -> str:
    return "otpauth://totp/Example:jane@example.com?" + urlencode({"secret": KEY_B32, **params})


@pytest.mark.parametrize(
    ("code", "shown"),
    [
        ("", ""),
        ("12345", "12345"),
        ("123456", "123 456"),
        ("1234567", "123 4567"),
        ("12345678", "1234 5678"),
    ],
)
def test_grouped(code: str, shown: str) -> None:
    assert grouped(code) == shown


@pytest.mark.parametrize(
    ("otpauth", "period"),
    [
        (None, DEFAULT_PERIOD),
        ("", DEFAULT_PERIOD),
        (_uri(), 30),
        (_uri(period="60"), 60),
        (_uri(period="0"), DEFAULT_PERIOD),
        (_uri(period="abc"), DEFAULT_PERIOD),
        ("otpauth://hotp/x?" + urlencode({"secret": KEY_B32}), DEFAULT_PERIOD),
        ("not a uri", DEFAULT_PERIOD),
    ],
)
def test_period_of(otpauth: str | None, period: int) -> None:
    assert period_of(otpauth) == period


@pytest.mark.parametrize(
    ("left", "period", "fraction"),
    [
        (30, 30, 1.0),
        (15, 30, 0.5),
        (0, 30, 0.0),
        (-3, 30, 0.0),
        (45, 30, 1.0),
        (10, 0, 0.0),
        (10, -30, 0.0),
    ],
)
def test_ring_fraction(left: float, period: int, fraction: float) -> None:
    assert ring_fraction(left, period) == pytest.approx(fraction)


@given(st.floats(allow_nan=False), st.integers(min_value=-100, max_value=3600))
def test_ring_fraction_always_in_unit_interval(left: float, period: int) -> None:
    assert 0.0 <= ring_fraction(left, period) <= 1.0


@pytest.mark.parametrize(
    ("left", "is_urgent"), [(0, True), (5, True), (5.0001, False), (6, False), (30, False)]
)
def test_urgent_is_last_five_seconds(left: float, *, is_urgent: bool) -> None:
    assert urgent(left) is is_urgent


# ---------------------------------------------------------------- Boxes


def _boxes(code: str, focus: int = 0) -> Boxes:
    digits = tuple(code.ljust(SIGNIN_CODE_LENGTH))
    return Boxes(tuple(d.strip() for d in digits), focus)


def test_new_boxes_are_empty() -> None:
    boxes = Boxes()
    assert boxes.code == ""
    assert not boxes.complete
    assert boxes.focus == 0


def test_typing_one_digit_advances_focus() -> None:
    boxes = Boxes().typed(0, "4")
    assert boxes.digits[0] == "4"
    assert boxes.focus == 1


def test_typing_into_last_box_keeps_focus_there() -> None:
    boxes = _boxes("12345", focus=5).typed(5, "6")
    assert boxes.code == "123456"
    assert boxes.complete
    assert boxes.focus == 5


def test_typing_overwrites_a_filled_box() -> None:
    assert _boxes("123456").typed(2, "9").code == "129456"


@pytest.mark.parametrize("text", ["a", " ", "-", "", "٣"])
def test_non_digits_are_ignored_but_focus_moves_to_the_box(text: str) -> None:
    before = _boxes("12")
    after = before.typed(4, text)
    assert after.digits == before.digits
    assert after.focus == 4


@pytest.mark.parametrize(
    "pasted",
    [
        "123456",
        "123 456",
        "123-456",
        "Your Apple Account code is: 123456. Don't share it with anyone.",
        "Your Apple Account code is: 123 456.\n\n@apple.com #123456",
    ],
)
@pytest.mark.parametrize("index", [0, 3, 5])
def test_pasting_a_whole_code_fills_every_box_from_the_start(pasted: str, index: int) -> None:
    boxes = _boxes("9", focus=index).typed(index, pasted)
    assert boxes.code == "123456"
    assert boxes.complete
    assert boxes.focus == SIGNIN_CODE_LENGTH - 1


def test_a_seven_digit_run_is_not_a_whole_code() -> None:
    boxes = Boxes().typed(2, "1234567")
    assert boxes.digits == ("", "", "1", "2", "3", "4")
    assert boxes.focus == 5


def test_short_paste_spreads_from_the_box() -> None:
    boxes = Boxes().typed(2, "1a2")
    assert boxes.digits == ("", "", "1", "2", "", "")
    assert boxes.focus == 4


def test_backspace_clears_a_filled_box_and_keeps_focus() -> None:
    boxes = _boxes("123").backspace(2)
    assert boxes.digits == ("1", "2", "", "", "", "")
    assert boxes.focus == 2


def test_backspace_on_empty_box_clears_the_previous_one() -> None:
    boxes = _boxes("123").backspace(3)
    assert boxes.digits == ("1", "2", "", "", "", "")
    assert boxes.focus == 2


def test_backspace_on_empty_first_box_stays_put() -> None:
    boxes = Boxes().backspace(0)
    assert boxes == Boxes()


def test_cleared_resets_everything() -> None:
    assert _boxes("123456", focus=5).cleared() == Boxes()


def test_boxes_are_immutable_values() -> None:
    boxes = Boxes()
    boxes.typed(0, "1")
    assert boxes == Boxes()


_ops = st.lists(
    st.tuples(
        st.sampled_from(["type", "backspace", "clear"]),
        st.integers(min_value=0, max_value=SIGNIN_CODE_LENGTH - 1),
        st.text(alphabet="0123456789 -a\n", max_size=12),
    ),
    max_size=20,
)


@given(_ops)
def test_boxes_never_exceed_six_single_digits(ops: list[tuple[str, int, str]]) -> None:
    boxes = Boxes()
    for op, index, text in ops:
        if op == "type":
            boxes = boxes.typed(index, text)
        elif op == "backspace":
            boxes = boxes.backspace(index)
        else:
            boxes = boxes.cleared()
        assert len(boxes.digits) == SIGNIN_CODE_LENGTH
        assert all(d == "" or (len(d) == 1 and d in "0123456789") for d in boxes.digits)
        assert len(boxes.code) <= SIGNIN_CODE_LENGTH
        assert 0 <= boxes.focus < SIGNIN_CODE_LENGTH
