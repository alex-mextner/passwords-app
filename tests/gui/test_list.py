# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Sidebar sections, instant search, sorting and live list updates on the real widgets."""

from __future__ import annotations

from typing import Any

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)


def _section(app: support.AppUnderTest, name: str) -> None:
    app.window.activate_action("win.section", _variant(name))
    support.pump(0.1)


def _variant(text: str) -> Any:
    from gi.repository import GLib  # noqa: PLC0415

    return GLib.Variant("s", text)


def _search(app: support.AppUnderTest, text: str) -> None:
    app.window.list_page.search.set_text(text)
    support.wait_until(
        lambda: app.window.list_page.query.tokens == tuple(text.casefold().split()),
        what="search applied",
    )


def test_all_lists_every_item_sorted_by_title(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    titles = app.titles()
    assert len(titles) == 60
    assert titles == sorted(titles, key=str.casefold)


def test_sidebar_counts_match_the_daemon(app: support.AppUnderTest) -> None:
    from passwords_app.app import sections  # noqa: PLC0415

    app.wait_scanned()
    support.pump(0.1)
    rows = app.window.sidebar.rows
    daemon_items = app.call(lambda d: list(d.items.values()))
    assert rows[sections.ALL].shown_count == str(len(daemon_items))
    assert rows[sections.CODES].shown_count == str(sum(1 for c in daemon_items if c.otpauth))
    assert rows[sections.DELETED].shown_count == str(app.call(lambda d: len(d.trash)))
    assert rows[sections.SECURITY].badge.get_visible()
    assert int(rows[sections.SECURITY].shown_count) == len(app.vault.report.flagged)


def test_codes_section_shows_only_items_with_codes(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _section(app, "codes")
    page = app.window.list_page
    objs = [page.filtered.get_item(i) for i in range(page.filtered.get_n_items())]
    assert objs
    assert all(o.item.has_code for o in objs)
    assert page.get_title() == "Codes"


def test_codes_rows_show_a_live_code(app: support.AppUnderTest) -> None:
    from gi.repository import Gtk  # noqa: PLC0415

    from passwords_app.app.ui.item_list import ItemRow  # noqa: PLC0415

    app.wait_loaded()
    _section(app, "codes")

    def codes_shown() -> list[str]:
        return [
            w.code.get_text()
            for w in support.walk(app.window.list_page.list_view)
            if isinstance(w, ItemRow) and w.get_mapped() and w.code.get_text()
        ]

    shown = support.wait_until(codes_shown, what="codes in rows")
    assert all(len(c.replace(" ", "")) in {6, 7, 8} for c in shown)
    assert isinstance(app.window.list_page.list_view, Gtk.ListView)


def test_security_section_lists_only_flagged_items(app: support.AppUnderTest) -> None:
    app.wait_scanned()
    _section(app, "security")
    page = app.window.list_page
    flagged = set(app.vault.report.flagged)
    shown = {page.filtered.get_item(i).item.id for i in range(page.filtered.get_n_items())}
    assert shown == flagged
    assert page.security_header.get_visible()


def test_shared_group_section(app: support.AppUnderTest) -> None:
    from passwords_app.app.sections import Kind, Section  # noqa: PLC0415

    app.wait_loaded()
    section = Section(Kind.GROUP, "Family")
    assert section in app.window.sidebar.rows
    app.window.sidebar.select(section)
    support.pump(0.1)
    page = app.window.list_page
    groups = {page.filtered.get_item(i).item.group for i in range(page.filtered.get_n_items())}
    assert groups == {"Family"}
    assert page.get_title() == "Family"


def test_deleted_section_lists_trash_with_days_left(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _section(app, "deleted")
    page = app.window.list_page
    assert page.stack.get_visible_child_name() == "trash"
    texts = support.visible_texts(page.trash_view)
    assert any("days left" in t or "day left" in t for t in texts)
    entries = [
        page.trash_filtered.get_item(i).entry for i in range(page.trash_filtered.get_n_items())
    ]
    assert [e.deleted_at for e in entries] == sorted((e.deleted_at for e in entries), reverse=True)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("northwind", "Northwind Mail"),
        ("NORTHWIND", "Northwind Mail"),
        ("cafe", "Café Lumière"),
        ("почта", "Почта Пример"),
    ],
)
def test_search_is_case_and_accent_insensitive(
    app: support.AppUnderTest, query: str, expected: str
) -> None:
    app.wait_loaded()
    _search(app, query)
    assert expected in app.titles()
    assert len(app.titles()) < 60


def test_search_matches_username_and_requires_every_word(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _search(app, "alex.doe@example.com")
    by_user = app.titles()
    assert by_user
    assert all("alex.doe@example.com" in app.vault.find(_id).item.username for _id in _ids(app))
    _search(app, "alex.doe@example.com northwind")
    narrowed = app.titles()
    assert set(narrowed) < set(by_user)


def _ids(app: support.AppUnderTest) -> list[str]:
    page = app.window.list_page
    return [page.filtered.get_item(i).item.id for i in range(page.filtered.get_n_items())]


def test_search_without_results_shows_empty_state(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _search(app, "zzzz-no-such-site")
    page = app.window.list_page
    assert page.stack.get_visible_child_name() == "empty"
    assert page.empty.get_title() == "No Results"
    _search(app, "")
    assert page.stack.get_visible_child_name() == "items"
    assert len(app.titles()) == 60


def test_search_applies_to_deleted_items(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _section(app, "deleted")
    page = app.window.list_page
    total = page.trash_filtered.get_n_items()
    first = page.trash_filtered.get_item(0).entry.item.display_title
    _search(app, first)
    assert 0 < page.trash_filtered.get_n_items() < total


def test_typing_anywhere_starts_a_search(app: support.AppUnderTest, shell: Any) -> None:
    app.wait_loaded()
    app.window.list_page.list_view.grab_focus()
    support.pump(0.1)
    support.type_text(shell, "north")
    support.wait_until(
        lambda: app.window.list_page.search.get_text() == "north", what="captured typing"
    )
    support.wait_until(lambda: "Northwind Mail" in app.titles(), what="filtered list")


@pytest.mark.parametrize("order", ["website", "modified", "title"])
def test_sort_order_changes_list_and_is_remembered(app: support.AppUnderTest, order: str) -> None:
    app.wait_loaded()
    app.window.activate_action("win.sort-order", _variant(order))
    support.pump(0.1)
    items = [app.vault.find(i).item for i in _ids(app)]
    if order == "modified":
        stamps = [i.modified for i in items]
        assert stamps == sorted(stamps, reverse=True)
    elif order == "website":
        hosts = [i.host.casefold() for i in items]
        assert hosts == sorted(hosts)
    else:
        titles = [i.display_title.casefold() for i in items]
        assert titles == sorted(titles)
    assert app.settings.get_string("sort-order") == order


def test_new_item_from_another_device_appears_without_reload(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.call(
        lambda d: d.add_item(
            "https://new.example.org", "fresh.user", "Strong-Passw0rd-2026", title="Fresh Site"
        )
    )
    support.wait_until(lambda: "Fresh Site" in app.titles(), what="pushed item")
    assert len(app.titles()) == 61


def test_selection_survives_an_unrelated_change(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = app.select("Northwind Mail")
    app.call(
        lambda d: d.add_item("https://other.example.net", "x", "Another-Passw0rd-1", title="Other")
    )
    support.wait_until(lambda: "Other" in app.titles(), what="pushed item")
    support.pump(0.2)
    selected = app.window.list_page.selected_item()
    assert selected is not None
    assert selected.item.id == item.id
