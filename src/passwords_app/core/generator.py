# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Password generation from the OS CSPRNG (`secrets`), never `random`."""

from __future__ import annotations

import secrets
import string

MAX_LENGTH = 256

_GROUPS = 3
_GROUP_LEN = 6
_SYSRAND = secrets.SystemRandom()


def apple_style() -> str:
    """Apple's strong-password format: `abcdef-ghijkl-mnopqr` with one uppercase and one digit.

    The uppercase letter and the digit sit at distinct, uniformly chosen positions among the 18
    letters; every other position is a uniform lowercase letter.
    """
    size = _GROUPS * _GROUP_LEN
    chars = [_SYSRAND.choice(string.ascii_lowercase) for _ in range(size)]
    upper_at, digit_at = _SYSRAND.sample(range(size), 2)
    chars[upper_at] = _SYSRAND.choice(string.ascii_uppercase)
    chars[digit_at] = _SYSRAND.choice(string.digits)
    return "-".join("".join(chars[i : i + _GROUP_LEN]) for i in range(0, size, _GROUP_LEN))


def generate(
    length: int,
    *,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = False,
) -> str:
    """Random password of `length` (1..256) with at least one character of each enabled class.

    Symbols are ASCII punctuation (`string.punctuation`).
    """
    classes = [
        alphabet
        for enabled, alphabet in (
            (upper, string.ascii_uppercase),
            (lower, string.ascii_lowercase),
            (digits, string.digits),
            (symbols, string.punctuation),
        )
        if enabled
    ]
    if not classes:
        msg = "at least one character class must be enabled"
        raise ValueError(msg)
    if not len(classes) <= length <= MAX_LENGTH:
        msg = f"length must be between {len(classes)} and {MAX_LENGTH}"
        raise ValueError(msg)
    union = "".join(classes)
    chars = [_SYSRAND.choice(alphabet) for alphabet in classes]
    chars += [_SYSRAND.choice(union) for _ in range(length - len(classes))]
    # The guaranteed characters were placed first; shuffle so their positions carry no signal.
    _SYSRAND.shuffle(chars)
    return "".join(chars)
