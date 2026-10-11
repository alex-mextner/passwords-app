# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Instant search: folding, haystacks, multi-token queries and incremental-filter hints."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from passwords_app.app.records import Item
from passwords_app.app.search import Change, Query, change_between, fold, haystack
from passwords_app.core.urls import normalize_url


def _item(**fields: object) -> Item:
    values: dict[str, object] = {"id": "x", "url": "https://example.com"}
    values.update(fields)
    return Item(**values)  # type: ignore[arg-type]


# ---------------------------------------------------------------- fold


@pytest.mark.parametrize(
    ("text", "folded"),
    [
        ("Café", "cafe"),
        ("ÉCOLE", "ecole"),
        ("\uff25\uff58\uff41\uff4d\uff50\uff4c\uff45", "example"),
        ("Straße", "strasse"),
        ("Øresund", "oresund"),
        ("Æble", "aeble"),
        ("Œuvre", "oeuvre"),
        ("Łódź", "lodz"),
        ("Đakovo", "dakovo"),
        ("ﬁle", "file"),
        ("Ёлка", "елка"),
        ("ПРИВЕТ", "привет"),
        ("Ñandú", "nandu"),
        ("\U0001d401\U0001d41a\U0001d427\U0001d424", "bank"),
        ("", ""),
    ],
)
def test_fold(text: str, folded: str) -> None:
    assert fold(text) == folded


@given(st.text())
def test_fold_is_idempotent(text: str) -> None:
    once = fold(text)
    assert fold(once) == once


@given(st.text())
def test_fold_ignores_case(text: str) -> None:
    assert fold(text.casefold()) == fold(text)


# ---------------------------------------------------------------- haystack


def test_haystack_contains_every_searchable_field() -> None:
    hay = haystack(
        _item(
            url="https://www.Exämple.com/login",
            title="Mon Café",
            username="Jane@Example.com",
            notes="Zürich Hauptbahnhof",
            alt_urls=("https://Other.example.org",),
        )
    )
    for needle in ("mon cafe", "jane@example.com", "zurich", "other.example.org", "/login"):
        assert needle in hay


def test_haystack_includes_host_when_title_is_set() -> None:
    hay = haystack(_item(url="https://www.shop.example", title="Groceries"))
    assert "shop.example" in hay


def test_haystack_never_lets_a_token_span_two_fields() -> None:
    hay = haystack(_item(url="https://ab.example", title="Title", username="jane", notes="doe"))
    assert not Query.parse("janedoe").matches(hay)
    assert Query.parse("jane doe").matches(hay)


def test_haystack_skips_empty_fields() -> None:
    hay = haystack(_item(url="", title="Only"))
    assert hay == "only"


# ---------------------------------------------------------------- Query


@pytest.mark.parametrize(
    ("text", "tokens"),
    [
        ("", ()),
        ("   ", ()),
        ("Mail", ("mail",)),
        ("  jane   EXAMPLE ", ("jane", "example")),
        ("mail Mail MAIL", ("mail",)),
        ("café cafe", ("cafe",)),
    ],
)
def test_query_parse(text: str, tokens: tuple[str, ...]) -> None:
    assert Query.parse(text).tokens == tokens


def test_query_empty() -> None:
    assert Query.parse(" ").empty
    assert not Query.parse("x").empty


def test_empty_query_matches_everything() -> None:
    assert Query.parse("").matches("")
    assert Query.parse("").matches("anything")


@pytest.mark.parametrize(
    ("query", "matches"),
    [
        ("example", True),
        ("EXAMPLE", True),
        ("exämple", True),
        ("jane example", True),
        ("example jane", True),
        ("jane bank", False),
        ("xample", True),
        ("zzz", False),
    ],
)
def test_query_matches_all_tokens_in_any_order(query: str, *, matches: bool) -> None:
    hay = haystack(_item(url="https://example.com", username="jane"))
    assert Query.parse(query).matches(hay) is matches


# ---------------------------------------------------------------- change_between


@pytest.mark.parametrize(
    ("old", "new", "change"),
    [
        ("", "", Change.SAME),
        ("mail", "mail", Change.SAME),
        ("mail jane", "mail jane", Change.SAME),
        ("", "m", Change.MORE_STRICT),
        ("m", "", Change.LESS_STRICT),
        ("ma", "mai", Change.MORE_STRICT),
        ("mai", "ma", Change.LESS_STRICT),
        ("mail", "mail jane", Change.MORE_STRICT),
        ("mail jane", "mail", Change.LESS_STRICT),
        ("mail", "bank", Change.DIFFERENT),
        ("mail", "ail", Change.LESS_STRICT),
        ("mail jane", "mail bank", Change.DIFFERENT),
    ],
)
def test_change_between(old: str, new: str, change: Change) -> None:
    assert change_between(Query.parse(old), Query.parse(new)) is change


_words = st.lists(st.sampled_from(["a", "ab", "abc", "b", "bc", "mail", "ma"]), max_size=3)
_hays = st.lists(st.sampled_from(["a", "ab", "abc", "bc", "mail", "x"]), max_size=4)


@given(_words, _words, _hays)
def test_change_hint_is_sound(old_words: list[str], new_words: list[str], hay: list[str]) -> None:
    """MORE_STRICT never re-admits a hidden row; LESS_STRICT never hides a shown one."""
    old, new = Query.parse(" ".join(old_words)), Query.parse(" ".join(new_words))
    text = "\0".join(hay)
    change = change_between(old, new)
    if change is Change.MORE_STRICT and new.matches(text):
        assert old.matches(text)
    if change is Change.LESS_STRICT and old.matches(text):
        assert new.matches(text)
    if change is Change.SAME:
        assert old.matches(text) == new.matches(text)


def test_a_normalized_idn_host_is_found_by_its_unicode_name() -> None:
    item = Item(id="1", url=normalize_url("https://faß.de"))
    assert Query.parse("faß").matches(haystack(item))


def test_an_alternate_idn_website_is_found_by_its_unicode_name() -> None:
    item = Item(id="1", url="https://example.com", alt_urls=(normalize_url("https://пример.рф"),))
    assert Query.parse("пример").matches(haystack(item))
