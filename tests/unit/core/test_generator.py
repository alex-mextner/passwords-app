# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Password generator: format invariants, class guarantees, and distribution sanity.

Statistical tolerances sit beyond 6 standard deviations of the expected binomial counts, so a
correct generator fails them with probability far below 1e-8 per assertion.
"""

from __future__ import annotations

import itertools
import math
import re
import string
from collections import Counter
from functools import cache

import pytest

from passwords_app.core.generator import apple_style, generate

LOWER = set(string.ascii_lowercase)
UPPER = set(string.ascii_uppercase)
DIGITS = set(string.digits)
SYMBOLS = set(string.punctuation)
APPLE_RE = re.compile(r"[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}")
N = 20_000


def _within(observed: int, expected: float, sigmas: float, p: float) -> bool:
    # Binomial standard deviation for `expected = n * p`.
    sd = math.sqrt(expected * (1 - p))
    return abs(observed - expected) <= sigmas * sd


@cache
def _apple_samples() -> tuple[str, ...]:
    return tuple(apple_style() for _ in range(N))


# ------------------------------------------------------------------ apple_style


def test_apple_style_format() -> None:
    for pw in _apple_samples():
        assert APPLE_RE.fullmatch(pw), pw


def test_apple_style_exactly_one_upper_and_one_digit() -> None:
    for pw in _apple_samples():
        body = pw.replace("-", "")
        assert sum(c in UPPER for c in body) == 1
        assert sum(c in DIGITS for c in body) == 1
        assert sum(c in LOWER for c in body) == 16


def test_apple_style_samples_unique() -> None:
    assert len(set(_apple_samples())) == N


def _body_positions(cls: set[str]) -> Counter[int]:
    counts: Counter[int] = Counter()
    for pw in _apple_samples():
        body = pw.replace("-", "")
        counts.update(i for i, c in enumerate(body) if c in cls)
    return counts


@pytest.mark.parametrize("cls", [UPPER, DIGITS], ids=["upper", "digit"])
def test_apple_style_special_position_uniform(cls: set[str]) -> None:
    counts = _body_positions(cls)
    assert set(counts) == set(range(18))
    for pos in range(18):
        assert _within(counts[pos], N / 18, 6.5, 1 / 18), (pos, counts[pos])


def test_apple_style_upper_and_digit_never_share_position() -> None:
    # Implied by the exact counts, but asserts the "distinct positions" rule directly.
    for pw in _apple_samples():
        body = pw.replace("-", "")
        up = next(i for i, c in enumerate(body) if c in UPPER)
        dg = next(i for i, c in enumerate(body) if c in DIGITS)
        assert up != dg


@pytest.mark.parametrize(
    ("cls", "per_password"),
    [(LOWER, 16), (UPPER, 1), (DIGITS, 1)],
    ids=["lower", "upper", "digit"],
)
def test_apple_style_char_frequency_uniform(cls: set[str], per_password: int) -> None:
    counts = Counter(c for pw in _apple_samples() for c in pw if c in cls)
    assert set(counts) == cls
    total = N * per_password
    p = 1 / len(cls)
    for ch in cls:
        assert _within(counts[ch], total * p, 6.5, p), (ch, counts[ch])


# ------------------------------------------------------------------ generate

FLAGS = ("upper", "lower", "digits", "symbols")
CLASS_OF = {"upper": UPPER, "lower": LOWER, "digits": DIGITS, "symbols": SYMBOLS}
COMBOS = [
    combo for r in range(1, 5) for combo in itertools.combinations(FLAGS, r)
]  # all 15 non-empty combinations


def _kwargs(enabled: tuple[str, ...]) -> dict[str, bool]:
    return {f: f in enabled for f in FLAGS}


@pytest.mark.parametrize("enabled", COMBOS, ids=["+".join(c) for c in COMBOS])
def test_generate_class_guarantee(enabled: tuple[str, ...]) -> None:
    allowed = set().union(*(CLASS_OF[f] for f in enabled))
    for length in (len(enabled), len(enabled) + 1, 12, 64):
        for _ in range(200):
            pw = generate(length, **_kwargs(enabled))
            assert len(pw) == length
            assert set(pw) <= allowed
            for f in enabled:
                assert set(pw) & CLASS_OF[f], (f, pw)


@pytest.mark.parametrize("enabled", COMBOS, ids=["+".join(c) for c in COMBOS])
def test_generate_minimum_length_contains_each_class_once(enabled: tuple[str, ...]) -> None:
    for _ in range(100):
        pw = generate(len(enabled), **_kwargs(enabled))
        assert sorted(next(f for f in enabled if c in CLASS_OF[f]) for c in pw) == sorted(enabled)


def test_generate_defaults_exclude_symbols() -> None:
    pw = "".join(generate(64) for _ in range(200))
    assert set(pw) <= UPPER | LOWER | DIGITS
    assert set(pw) & UPPER
    assert set(pw) & LOWER
    assert set(pw) & DIGITS


@pytest.mark.parametrize("length", [1, 2, 3, 128, 255, 256])
def test_generate_boundary_lengths(length: int) -> None:
    assert len(generate(length, upper=False, digits=False)) == length


def test_generate_max_length_all_classes() -> None:
    pw = generate(256, symbols=True)
    assert len(pw) == 256


@pytest.mark.parametrize(
    ("length", "kwargs"),
    [
        (0, {}),
        (-1, {}),
        (257, {}),
        (10_000, {}),
        (2, {}),  # three classes enabled by default
        (3, {"symbols": True}),
        (1, {"upper": True, "lower": True, "digits": False}),
        (16, {"upper": False, "lower": False, "digits": False, "symbols": False}),
        (0, {"upper": False, "lower": False, "digits": False}),
    ],
)
def test_generate_rejects(length: int, kwargs: dict[str, bool]) -> None:
    with pytest.raises(ValueError, match=r"."):
        generate(length, **kwargs)


def test_generate_samples_unique() -> None:
    samples = {generate(16) for _ in range(5_000)}
    assert len(samples) == 5_000


def test_generate_single_class_frequency_uniform() -> None:
    length = 32
    counts = Counter(
        c for _ in range(N) for c in generate(length, upper=False, digits=False, symbols=False)
    )
    total = N * length
    p = 1 / 26
    assert set(counts) == LOWER
    for ch in LOWER:
        assert _within(counts[ch], total * p, 6.5, p), (ch, counts[ch])


def test_generate_symbol_frequency_uniform() -> None:
    length = 16
    counts = Counter(
        c
        for _ in range(N // 2)
        for c in generate(length, upper=False, lower=False, digits=False, symbols=True)
    )
    total = (N // 2) * length
    p = 1 / len(SYMBOLS)
    assert set(counts) == SYMBOLS
    for ch in SYMBOLS:
        assert _within(counts[ch], total * p, 6.5, p), (ch, counts[ch])


def test_generate_union_class_proportions() -> None:
    # One guaranteed char per class, the remaining L-4 drawn uniformly from the 94-char union.
    length = 20
    sizes = {f: len(CLASS_OF[f]) for f in FLAGS}
    union = sum(sizes.values())
    counts: Counter[str] = Counter()
    for _ in range(N):
        for c in generate(length, symbols=True):
            counts[next(f for f in FLAGS if c in CLASS_OF[f])] += 1
    for f in FLAGS:
        p = sizes[f] / union
        free = N * (length - 4)
        expected = N + free * p
        assert abs(counts[f] - expected) <= 6.5 * math.sqrt(free * p * (1 - p)), (f, counts[f])


def test_generate_shuffle_spreads_guaranteed_chars() -> None:
    # With length == number of classes every position holds one class; without the shuffle the
    # guaranteed characters would sit at fixed indexes.
    counts: Counter[tuple[int, str]] = Counter()
    for _ in range(N):
        pw = generate(4, symbols=True)
        for i, c in enumerate(pw):
            counts[i, next(f for f in FLAGS if c in CLASS_OF[f])] += 1
    for i in range(4):
        for f in FLAGS:
            assert _within(counts[i, f], N / 4, 6.5, 1 / 4), (i, f, counts[i, f])
