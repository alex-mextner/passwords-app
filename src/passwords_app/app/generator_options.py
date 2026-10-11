# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Password generator choices as stored in GSettings (`generator-*` keys)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from passwords_app.core.generator import MAX_LENGTH, apple_style, generate

MIN_CUSTOM_LENGTH = 8
MAX_CUSTOM_LENGTH = 64


class Mode(StrEnum):
    APPLE = "apple"
    CUSTOM = "custom"


@dataclass(frozen=True, slots=True)
class GeneratorOptions:
    mode: Mode = Mode.APPLE
    length: int = 20
    uppercase: bool = True
    digits: bool = True
    symbols: bool = True

    def clamped(self) -> GeneratorOptions:
        length = min(MAX_CUSTOM_LENGTH, MAX_LENGTH, max(MIN_CUSTOM_LENGTH, self.length))
        return GeneratorOptions(self.mode, length, self.uppercase, self.digits, self.symbols)


def make_password(options: GeneratorOptions) -> str:
    """Apple's `xxxxxx-xxxxxx-xxxxxx`, or a custom one; lowercase letters are always in."""
    if options.mode is Mode.APPLE:
        return apple_style()
    o = options.clamped()
    return generate(o.length, upper=o.uppercase, lower=True, digits=o.digits, symbols=o.symbols)
