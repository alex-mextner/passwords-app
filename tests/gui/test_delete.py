# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Delete with Undo, the Deleted view, Restore and Delete Now."""

from __future__ import annotations

from typing import Any

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)


def _variant(text: str) -> Any:
    from gi.repository import GLib  # noqa: PLC0415

    return GLib.Variant("s", text)


def _delete(app: support.AppUnderTest, title: str) -> Any:
    item = app.select(title)
    app.window.activate_action("win.delete", None)
    support.wait_until(lambda: title not in app.titles(), what="item gone")
    return item


def test_delete_moves_the_item_to_trash_and_offers_undo(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = _delete(app, "Northwind Mail")
    assert item.id not in app.call(lambda d: d.items)
    trashed = app.call(lambda d: [e.credential.id for e in d.trash.values()])
    assert item.id in trashed
    toast = app.window.last_toast
    assert toast.get_title() == "Deleted “Northwind Mail”"
    assert toast.get_button_label() == "Undo"
    assert app.window.lookup_action("undo").get_enabled()


def test_undo_restores_the_same_item(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = _delete(app, "Northwind Mail")
    app.window.activate_action("win.undo", None)
    support.wait_until(lambda: "Northwind Mail" in app.titles(), what="restored")
    # The copy comes back under a fresh id (the old one may be tombstoned in iCloud).
    (restored,) = app.call(lambda d: [c for c in d.items.values() if c.title == "Northwind Mail"])
    assert restored.id != item.id
    assert restored.password == item.password
    assert not app.window.lookup_action("undo").get_enabled()
    support.wait_until(
        lambda: (
            app.window.list_page.selected_item() is not None
            and app.window.list_page.selected_item().item.id == restored.id
        ),
        what="restored item selected",
    )


def test_undo_from_the_toast_button(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _delete(app, "Contoso ID")
    toast = app.window.last_toast
    app.window.activate_action(toast.get_action_name(), None)
    support.wait_until(lambda: "Contoso ID" in app.titles(), what="restored")


def test_delete_counts_update(app: support.AppUnderTest) -> None:
    from passwords_app.app import sections  # noqa: PLC0415

    app.wait_loaded()
    rows = app.window.sidebar.rows
    before = int(rows[sections.DELETED].shown_count)
    _delete(app, "Northwind Mail")
    support.wait_until(
        lambda: rows[sections.DELETED].shown_count == str(before + 1), what="trash count"
    )
    assert rows[sections.ALL].shown_count == "59"


def test_deleted_item_detail_shows_days_left_and_reason(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _delete(app, "Northwind Mail")
    app.window.activate_action("win.section", _variant("deleted"))
    support.pump(0.1)
    page = app.window.list_page
    position = next(
        i
        for i in range(page.trash_filtered.get_n_items())
        if page.trash_filtered.get_item(i).entry.item.display_title == "Northwind Mail"
    )
    page.trash_selection.set_selected(position)
    detail = app.window.detail
    assert detail.stack.get_visible_child_name() == "trash"
    assert detail.trash_left.get_text() == "90 days left"
    assert detail.trash_reason.get_subtitle() == "Deleted on this computer"
    assert not app.window.lookup_action("copy-password").get_enabled()


def _open_trash_entry(app: support.AppUnderTest, index: int = 0) -> Any:
    app.window.activate_action("win.section", _variant("deleted"))
    support.pump(0.1)
    page = app.window.list_page
    page.trash_selection.set_selected(index)
    return page.trash_filtered.get_item(index).entry


def test_restore_brings_the_item_back(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    entry = _open_trash_entry(app)
    trashed = app.call(lambda d: d.trash[entry.trash_id].credential)
    support.find_button(app.window.detail, "Restore").emit("clicked")
    support.wait_until(lambda: entry.trash_id not in app.call(lambda d: d.trash), what="restored")
    support.wait_toast(app, "Restored")
    # The copy comes back under a fresh id (the old one may be tombstoned in iCloud).
    items = app.call(lambda d: list(d.items.values()))
    back = [c for c in items if c.password == trashed.password and c.url == trashed.url]
    assert len(back) == 1
    assert back[0].id != trashed.id
    support.wait_until(
        lambda: all(
            app.window.list_page.trash_filtered.get_item(i).entry.trash_id != entry.trash_id
            for i in range(app.window.list_page.trash_filtered.get_n_items())
        ),
        what="gone from Deleted",
    )


def test_delete_now_asks_first_and_then_purges(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    entry = _open_trash_entry(app)
    support.find_button(app.window.detail, "Delete Now").emit("clicked")
    dialog = support.wait_until(lambda: getattr(app.window, "purge_dialog", None), what="dialog")
    assert dialog.get_heading() == "Delete Permanently?"
    assert entry.trash_id in app.call(lambda d: d.trash)  # nothing happens before confirming
    dialog.emit("response", "purge")
    support.wait_until(lambda: entry.trash_id not in app.call(lambda d: d.trash), what="purged")
    assert entry.item.id not in app.call(lambda d: d.items)


def test_delete_now_cancelled_keeps_the_entry(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    entry = _open_trash_entry(app)
    support.find_button(app.window.detail, "Delete Now").emit("clicked")
    dialog = support.wait_until(lambda: getattr(app.window, "purge_dialog", None), what="dialog")
    dialog.emit("response", "cancel")
    support.pump(0.3)
    assert entry.trash_id in app.call(lambda d: d.trash)


def test_entries_close_to_expiry_say_so(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.window.activate_action("win.section", _variant("deleted"))
    support.pump(0.2)
    texts = support.visible_texts(app.window.list_page.trash_view)
    # The demo trash holds an entry deleted 88 days ago: 2 days left of 90.
    assert "2 days left" in texts


def test_a_new_window_shows_the_loaded_trash_and_groups(app: support.AppUnderTest) -> None:
    from passwords_app.app.sections import Kind, Section  # noqa: PLC0415

    app.wait_loaded()
    _delete(app, "Northwind Mail")
    support.wait_until(lambda: app.vault.trash.get_n_items() > 0, what="trash loaded")
    groups = app.vault.groups()
    assert groups
    app.window.destroy()
    app.application.window = None  # what the destroy handler does once GTK drops it
    support.pump(0.3)
    window = app.application.ensure_window()
    assert window is not app.window
    try:
        assert window.list_page.trash_filtered.get_n_items() == app.vault.trash.get_n_items()
        for group in groups:
            assert Section(Kind.GROUP, group) in window.sidebar.rows, group
    finally:
        window.destroy()
        support.pump(0.1)


def test_an_entry_purged_after_90_days_leaves_the_deleted_view(app: support.AppUnderTest) -> None:
    # The daemon's retention purge announces itself only through StatusChanged (#69).
    from passwords_app.app import sections  # noqa: PLC0415

    app.wait_loaded()
    page = app.window.list_page
    before = page.trash_filtered.get_n_items()
    oldest = _open_trash_entry(app, before - 1)  # newest first: the last one expires first
    kept = _open_trash_entry(app, 0)
    page.trash_selection.set_selected(before - 1)
    assert app.window.detail.entry == oldest
    app.call(lambda d: d.expire_trash(oldest.trash_id))
    support.wait_until(
        lambda: page.trash_filtered.get_n_items() == before - 1, what="entry gone from Deleted"
    )
    shown = [page.trash_filtered.get_item(i).entry.trash_id for i in range(before - 1)]
    assert oldest.trash_id not in shown
    assert app.window.sidebar.rows[sections.DELETED].shown_count == str(before - 1)
    # Its detail goes too: Restore would only fail with "No deleted password with this id."
    assert _detail_entry(app) is None
    assert page.selected_trash() is None
    # Another selected entry stays selected through the reload.
    page.trash_selection.set_selected(0)
    app.call(lambda d: d.expire_trash(page.trash_filtered.get_item(before - 2).entry.trash_id))
    support.wait_until(lambda: page.trash_filtered.get_n_items() == before - 2, what="reload")
    assert page.selected_trash().entry.trash_id == kept.trash_id
    assert _detail_entry(app).trash_id == kept.trash_id


def _detail_entry(app: support.AppUnderTest) -> Any:
    return app.window.detail.entry
