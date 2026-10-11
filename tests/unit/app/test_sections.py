# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Sidebar sections: which items each one lists, and what the sidebar row shows."""

from __future__ import annotations

import pytest

from passwords_app.app import i18n
from passwords_app.app.records import Item
from passwords_app.app.sections import ALL, CODES, DELETED, FIXED, SECURITY, Kind, Section
from passwords_app.app.security import Issue

PLAIN = Item(id="p", url="https://example.com")
WITH_CODE = Item(id="c", url="https://example.com", has_code=True)
FAMILY = Item(id="f", url="https://example.com", group="Family")
NO_ISSUES: frozenset[Issue] = frozenset()
WEAK = frozenset({Issue.WEAK})


@pytest.fixture(autouse=True)
def _english() -> None:
    i18n.setup(["en"])


@pytest.mark.parametrize(
    ("section", "item", "issues", "included"),
    [
        (ALL, PLAIN, NO_ISSUES, True),
        (ALL, FAMILY, WEAK, True),
        (CODES, WITH_CODE, NO_ISSUES, True),
        (CODES, PLAIN, NO_ISSUES, False),
        (SECURITY, PLAIN, WEAK, True),
        (SECURITY, PLAIN, NO_ISSUES, False),
        (SECURITY, WITH_CODE, frozenset({Issue.REUSED, Issue.COMPROMISED}), True),
        (DELETED, PLAIN, NO_ISSUES, False),
        (DELETED, FAMILY, WEAK, False),
        (Section(Kind.GROUP, "Family"), FAMILY, NO_ISSUES, True),
        (Section(Kind.GROUP, "Family"), PLAIN, NO_ISSUES, False),
        (Section(Kind.GROUP, "family"), FAMILY, NO_ISSUES, False),
    ],
)
def test_includes(
    section: Section, item: Item, issues: frozenset[Issue], *, included: bool
) -> None:
    assert section.includes(item, issues) is included


@pytest.mark.parametrize(
    ("section", "title"),
    [(ALL, "All"), (CODES, "Codes"), (SECURITY, "Security"), (DELETED, "Deleted")],
)
def test_fixed_section_titles(section: Section, title: str) -> None:
    assert section.title == title


def test_group_section_is_titled_by_its_group() -> None:
    assert Section(Kind.GROUP, "Family Sharing").title == "Family Sharing"


def test_every_kind_has_an_icon_and_icons_are_distinct() -> None:
    icons = [Section(kind, "g").icon for kind in Kind]
    assert all(icon.endswith("-symbolic") for icon in icons)
    assert len(set(icons)) == len(icons)


def test_fixed_sections_order_and_equality() -> None:
    assert [s.kind for s in FIXED] == [Kind.ALL, Kind.CODES, Kind.SECURITY, Kind.DELETED]
    assert Section(Kind.GROUP, "A") != Section(Kind.GROUP, "B")
    assert Section(Kind.CODES) == CODES
