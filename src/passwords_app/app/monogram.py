# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Monogram tiles: one letter plus a color that never changes between runs or machines.

The color is keyed by the site, not the title, so every login for one website shares a tile
color; it uses SHA-256 because Python's `hash()` is salted per process.
"""

from __future__ import annotations

import hashlib
import unicodedata
from typing import TYPE_CHECKING, Final

from passwords_app.core.urls import link_host, registrable_domain

if TYPE_CHECKING:
    from passwords_app.app.records import Item

# (top, bottom) gradient stops from the GNOME HIG palette, dark enough for white text.
PALETTE: Final[tuple[tuple[str, str], ...]] = (
    ("#62a0ea", "#1c71d8"),  # blue
    ("#33c7de", "#0f8a9e"),  # teal
    ("#57e389", "#26a269"),  # green
    ("#f8c94c", "#e5a50a"),  # yellow
    ("#ffa348", "#e66100"),  # orange
    ("#f66151", "#c01c28"),  # red
    ("#f68ad0", "#c4307f"),  # pink
    ("#c061cb", "#813d9c"),  # purple
    ("#cdab8f", "#865e3c"),  # brown
    ("#9a9996", "#5e5c64"),  # slate
)


def site_key(item: Item) -> str:
    """Return the registrable domain, so `mail.x.example` and `x.example` share a color."""
    host = link_host(item.url)
    if not host:
        return item.display_title.casefold()
    try:
        return registrable_domain(host)
    except ValueError:
        return host


def color_index(key: str) -> int:
    digest = hashlib.sha256(key.encode()).digest()
    return int.from_bytes(digest[:4], "big") % len(PALETTE)


def _strip_site_prefix(text: str) -> str:
    lowered = text.casefold()
    for prefix in ("https://", "http://", "www."):
        if lowered.startswith(prefix):
            text, lowered = text[len(prefix) :], lowered[len(prefix) :]
    return text


def letter(item: Item) -> str:
    """First letter or digit of the title (or site), uppercased; `?` when there is none."""
    for char in _strip_site_prefix(item.display_title.strip()):
        category = unicodedata.category(char)
        if category[0] in {"L", "N"}:
            # `ß`.upper() is `SS`: a tile shows one glyph.
            return char.upper()[0]
        if category == "So":  # an emoji title still deserves its emoji
            return char
    return "?"
