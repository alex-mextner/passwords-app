# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Instant search: accent- and case-insensitive substring matching over precomputed text.

Every keystroke re-filters the whole list (5 000 items within one 16 ms frame), so all string
normalization happens once per item when it is loaded, and a query is normalized once.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from passwords_app.app.records import display_host

if TYPE_CHECKING:
    from passwords_app.app.records import Item

# Letters that NFKD does not decompose but users type without the stroke or ligature.
_FOLDS = str.maketrans({"ø": "o", "æ": "ae", "œ": "oe", "ł": "l", "đ": "d"})


def fold(text: str) -> str:
    """Lowercase, strip diacritics and compatibility forms: `Café` (fullwidth too) -> `cafe`."""
    # Casefold after NFKD too: compatibility forms (mathematical bold letters) decompose to
    # uppercase ASCII, which a single casefold before decomposition would leave uppercase.
    decomposed = unicodedata.normalize("NFKD", unicodedata.normalize("NFKD", text).casefold())
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return stripped.translate(_FOLDS)


def haystack(item: Item) -> str:
    """Everything a user may search by; NUL-separated so a token never spans two fields."""
    alt_hosts = (display_host(u) for u in item.alt_urls)
    parts = (
        item.display_title,
        item.host,
        item.url,
        item.username,
        item.notes,
        *item.alt_urls,
        *alt_hosts,
    )
    return "\0".join(fold(p) for p in parts if p)


@dataclass(frozen=True, slots=True)
class Query:
    tokens: tuple[str, ...]

    @classmethod
    def parse(cls, text: str) -> Query:
        return cls(tuple(dict.fromkeys(fold(text).split())))

    @property
    def empty(self) -> bool:
        return not self.tokens

    def matches(self, hay: str) -> bool:
        """All tokens must occur (in any order), like Apple's search field."""
        return all(t in hay for t in self.tokens)


class Change(Enum):
    """How a new query relates to the previous one; lets GTK re-check only what can change."""

    DIFFERENT = auto()
    MORE_STRICT = auto()
    LESS_STRICT = auto()
    SAME = auto()


def change_between(old: Query, new: Query) -> Change:
    if old == new:
        return Change.SAME
    if old.empty:
        return Change.MORE_STRICT
    if new.empty:
        return Change.LESS_STRICT
    if _implies(new, old):
        return Change.MORE_STRICT
    if _implies(old, new):
        return Change.LESS_STRICT
    return Change.DIFFERENT


def _implies(stricter: Query, looser: Query) -> bool:
    """Tell whether every haystack matching `stricter` also matches `looser`."""
    return all(any(loose in strict for strict in stricter.tokens) for loose in looser.tokens)
