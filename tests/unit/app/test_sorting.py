# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Sort orders are total and stable, so the list never reshuffles between refreshes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from hypothesis import given
from hypothesis import strategies as st

from passwords_app.app.records import Item
from passwords_app.app.sorting import SortOrder, sort_key, sorted_items

if TYPE_CHECKING:
    import random

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _item(item_id: str, **fields: object) -> Item:
    values: dict[str, object] = {"id": item_id, "url": "https://example.com"}
    values.update(fields)
    return Item(**values)  # type: ignore[arg-type]


def _ids(items: list[Item]) -> list[str]:
    return [i.id for i in items]


def test_title_order_is_accent_and_case_insensitive() -> None:
    items = [
        _item("z", title="zebra"),
        _item("e", title="Éclair"),
        _item("a", title="apple"),
        _item("d", title="Delta"),
    ]
    assert _ids(sorted_items(items, SortOrder.TITLE)) == ["a", "d", "e", "z"]


def test_title_order_uses_website_when_title_is_empty() -> None:
    items = [_item("t", title="Mail"), _item("u", url="https://www.bank.example")]
    assert _ids(sorted_items(items, SortOrder.TITLE)) == ["u", "t"]


def test_website_order_groups_by_host_then_title() -> None:
    items = [
        _item("2", url="https://b.example", title="Alpha"),
        _item("1", url="https://www.a.example", title="Zulu"),
        _item("3", url="https://b.example", title="Beta"),
    ]
    assert _ids(sorted_items(items, SortOrder.WEBSITE)) == ["1", "2", "3"]


def test_modified_order_is_newest_first() -> None:
    items = [
        _item("old", modified=T0),
        _item("new", modified=T0 + timedelta(days=2)),
        _item("mid", modified=T0 + timedelta(days=1)),
    ]
    assert _ids(sorted_items(items, SortOrder.MODIFIED)) == ["new", "mid", "old"]


def test_modified_ties_fall_back_to_title() -> None:
    items = [_item("b", title="Beta", modified=T0), _item("a", title="Alpha", modified=T0)]
    assert _ids(sorted_items(items, SortOrder.MODIFIED)) == ["a", "b"]


@pytest.mark.parametrize("order", list(SortOrder))
def test_ties_fall_through_to_username_then_id(order: SortOrder) -> None:
    items = [
        _item("2", title="Mail", username="bob"),
        _item("3", title="Mail", username="alice"),
        _item("1", title="Mail", username="bob"),
    ]
    assert _ids(sorted_items(items, order)) == ["3", "1", "2"]


def test_sorted_items_does_not_mutate_input() -> None:
    items = [_item("b", title="B"), _item("a", title="A")]
    sorted_items(items, SortOrder.TITLE)
    assert _ids(items) == ["b", "a"]


def test_sort_order_values_are_gsettings_choices() -> None:
    assert SortOrder("modified") is SortOrder.MODIFIED
    with pytest.raises(ValueError, match="bogus"):
        SortOrder("bogus")


_items = st.lists(
    st.builds(
        Item,
        id=st.text(alphabet="abc123", min_size=1, max_size=3),
        url=st.sampled_from(["https://a.example", "https://www.b.example", "", "c.example"]),
        title=st.sampled_from(["", "Mail", "mail", "Mäil", "Bank"]),
        username=st.sampled_from(["", "jane", "Jane", "bob"]),
        modified=st.sampled_from([T0, T0 + timedelta(hours=1)]),
    ),
    max_size=8,
    unique_by=lambda i: i.id,
)


@given(_items, st.sampled_from(list(SortOrder)), st.randoms(use_true_random=False))
def test_order_is_total_and_independent_of_input_order(
    items: list[Item], order: SortOrder, rng: random.Random
) -> None:
    shuffled = list(items)
    rng.shuffle(shuffled)
    assert _ids(sorted_items(items, order)) == _ids(sorted_items(shuffled, order))
    keys = [sort_key(i, order) for i in items]
    assert len(set(keys)) == len(keys)
