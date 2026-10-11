# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Monogram tiles: the letter shown and a color that is stable and shared per site."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from passwords_app.app.monogram import PALETTE, color_index, letter, site_key
from passwords_app.app.records import Item


def _item(url: str = "", title: str = "") -> Item:
    return Item(id="x", url=url, title=title)


@pytest.mark.parametrize(
    ("url", "title", "expected"),
    [
        ("https://example.com", "mail", "M"),
        ("https://example.com", "  éclair", "É"),
        ("https://www.github.example", "", "G"),
        ("", "www.shop.example", "S"),
        ("", "HTTPS://WWW.Bank.example", "B"),
        ("", "http://news.example", "N"),
        ("", "1Password Club", "1"),
        ("", "  --  _bank", "B"),
        ("", "straße", "S"),
        ("", "ßeta", "S"),
        ("", "яндекс", "Я"),
        ("", "🔑 Vault", "🔑"),
        ("", "!!!", "?"),
        ("", "", "?"),
        ("", "   ", "?"),
    ],
)
def test_letter(url: str, title: str, expected: str) -> None:
    assert letter(_item(url, title)) == expected


@given(st.text())
def test_letter_is_always_one_glyph(title: str) -> None:
    assert len(letter(_item(title=title))) == 1


@pytest.mark.parametrize(
    ("url", "title", "key"),
    [
        ("https://mail.example.com/inbox", "", "example.com"),
        ("https://www.example.com", "", "example.com"),
        ("https://shop.example.co.uk", "", "example.co.uk"),
        ("", "My Router", "my router"),
    ],
)
def test_site_key(url: str, title: str, key: str) -> None:
    assert site_key(_item(url, title)) == key


def test_subdomains_share_a_color_regardless_of_title() -> None:
    a = _item("https://mail.example.com", "Mail")
    b = _item("https://www.example.com/login", "Zzz")
    assert color_index(site_key(a)) == color_index(site_key(b))


@given(st.text())
def test_color_index_in_palette_range(key: str) -> None:
    assert 0 <= color_index(key) < len(PALETTE)


def test_color_index_is_pinned_across_processes_and_releases() -> None:
    # SHA-256 is deterministic, unlike the salted builtin hash(): a site keeps its color.
    assert [color_index(k) for k in ("example.com", "example.org", "")] == [6, 8, 0]


def test_color_index_uses_the_whole_palette() -> None:
    assert {color_index(f"site{n}.example") for n in range(200)} == set(range(len(PALETTE)))
