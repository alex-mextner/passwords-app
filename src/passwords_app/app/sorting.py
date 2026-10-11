# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""List orderings offered by the sort menu."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from passwords_app.app.search import fold

if TYPE_CHECKING:
    from passwords_app.app.records import Item


class SortOrder(StrEnum):
    """Values double as the GSettings `sort-order` choices."""

    TITLE = "title"
    WEBSITE = "website"
    MODIFIED = "modified"


type SortKey = tuple[object, ...]


def sort_key(item: Item, order: SortOrder) -> SortKey:
    """Total order: ties fall through to username and id so the list never reshuffles."""
    title = fold(item.display_title)
    host = fold(item.host)
    user = fold(item.username)
    if order is SortOrder.WEBSITE:
        return (host, title, user, item.id)
    if order is SortOrder.MODIFIED:
        # Newest first; negating the timestamp keeps a single ascending key.
        return (-item.modified.timestamp(), title, user, item.id)
    return (title, host, user, item.id)


def sorted_items(items: list[Item], order: SortOrder) -> list[Item]:
    return sorted(items, key=lambda i: sort_key(i, order))
