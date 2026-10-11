# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Verification-code presentation and the paste-aware six-box code entry."""

from __future__ import annotations

import re
from dataclasses import dataclass

from passwords_app.core.otp import OtpError, parse_otpauth

DEFAULT_PERIOD = 30
SIGNIN_CODE_LENGTH = 6
# A standalone six-digit run, optionally split in halves, as Apple prints and texts it.
_WHOLE_CODE = re.compile(r"(?<![0-9])[0-9]{3}[ \-]?[0-9]{3}(?![0-9])")


def grouped(code: str) -> str:
    """`123456` -> `123 456`, `12345678` -> `1234 5678`: halves are easier to read aloud."""
    if len(code) < 6:  # noqa: PLR2004 - shorter codes are not split
        return code
    middle = len(code) // 2
    return f"{code[:middle]} {code[middle:]}"


def period_of(otpauth: str | None) -> int:
    if not otpauth:
        return DEFAULT_PERIOD
    try:
        return parse_otpauth(otpauth).period
    except OtpError:
        return DEFAULT_PERIOD


def ring_fraction(seconds_left: float, period: int) -> float:
    """Share of the period still remaining, clamped to 0..1, for the countdown ring."""
    if period <= 0:
        return 0.0
    return min(1.0, max(0.0, seconds_left / period))


def urgent(seconds_left: float) -> bool:
    """Tell whether the code is in its last five seconds (the ring turns red, as in Apple's)."""
    return seconds_left <= 5  # noqa: PLR2004


@dataclass(frozen=True, slots=True)
class Boxes:
    """State of the six single-digit boxes; `focus` is the box that should hold the cursor."""

    digits: tuple[str, ...] = ("",) * SIGNIN_CODE_LENGTH
    focus: int = 0

    @property
    def code(self) -> str:
        return "".join(self.digits)

    @property
    def complete(self) -> bool:
        return all(self.digits)

    def typed(self, index: int, text: str) -> Boxes:
        """Apply text typed or pasted into box `index`.

        Several digits at once are a paste: a whole code (`123456`, `123 456`, or an SMS
        text containing one) fills every box from the start; a shorter run spreads from
        `index`. Non-digits are ignored.
        """
        whole = _WHOLE_CODE.search(text)
        if whole:
            index, digits = 0, [c for c in whole.group() if c.isdigit()]
        else:
            digits = [c for c in text if c.isascii() and c.isdigit()]
        if not digits:
            return Boxes(self.digits, index)
        values = list(self.digits)
        position = index
        for d in digits:
            if position >= SIGNIN_CODE_LENGTH:
                break
            values[position] = d
            position += 1
        return Boxes(tuple(values), min(position, SIGNIN_CODE_LENGTH - 1))

    def backspace(self, index: int) -> Boxes:
        """Clear box `index`, or the previous one when it is already empty."""
        values = list(self.digits)
        if values[index]:
            values[index] = ""
            return Boxes(tuple(values), index)
        target = max(0, index - 1)
        values[target] = ""
        return Boxes(tuple(values), target)

    def cleared(self) -> Boxes:
        return Boxes()
