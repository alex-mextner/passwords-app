# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Every control a screen reader can reach has a name (GTK's test accessibility backend)."""

from __future__ import annotations

from typing import Any

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)


def _named(widget: Any) -> bool:  # noqa: PLR0911 - one early return per way GTK names a control
    from gi.repository import Adw, Gtk  # noqa: PLC0415

    if Gtk.test_accessible_has_property(widget, Gtk.AccessibleProperty.LABEL):
        return True
    if Gtk.test_accessible_has_relation(widget, Gtk.AccessibleRelation.LABELLED_BY):
        return True
    if isinstance(widget, Gtk.Button | Gtk.MenuButton) and widget.get_label():
        return True
    child = widget.get_first_child() if isinstance(widget, Gtk.Widget) else None
    if isinstance(child, Gtk.Label) and child.get_text():
        return True
    if isinstance(child, Adw.ButtonContent) and child.get_label():
        return True
    parent = widget.get_parent()
    # GtkMenuButton's focusable part is an internal toggle; the menu button carries the name.
    if isinstance(parent, Gtk.MenuButton):
        return _named(parent)
    # libadwaita's own helpers (the password row's peek button) are named by their tooltip.
    if (
        isinstance(widget, Gtk.Button)
        and widget.get_tooltip_text()
        and _inside(widget, Adw.EntryRow)
    ):
        return True
    # Inside a titled row, the row names its embedded controls (libadwaita sets this up).
    while parent is not None:
        if isinstance(parent, Adw.PreferencesRow) and parent.get_title():
            return isinstance(widget, Gtk.Switch | Gtk.CheckButton | Gtk.Text | Gtk.SpinButton)
        parent = parent.get_parent()
    return False


def _inside(widget: Any, kind: type) -> bool:
    parent = widget.get_parent()
    while parent is not None:
        if isinstance(parent, kind):
            return True
        parent = parent.get_parent()
    return False


def _controls(root: Any) -> list[Any]:
    from gi.repository import Gtk  # noqa: PLC0415

    kinds = (
        Gtk.Button,
        Gtk.MenuButton,
        Gtk.ToggleButton,
        Gtk.Switch,
        Gtk.CheckButton,
        Gtk.Entry,
        Gtk.SearchEntry,
        Gtk.Text,
        Gtk.SpinButton,
        Gtk.ListView,
        Gtk.ListBox,
        Gtk.TextView,
    )
    return [
        w
        for w in support.walk(root)
        if isinstance(w, kinds)
        and w.get_mapped()
        and w.get_can_focus()
        and w.get_focusable()
        # A boxed list only groups rows; the rows are what gets focus and a name.
        and not (isinstance(w, Gtk.ListBox) and w.has_css_class("boxed-list"))
    ]


def _unnamed(root: Any) -> list[str]:
    return [
        f"{type(w).__name__}({getattr(w, 'get_icon_name', lambda: '')() or ''})"
        for w in _controls(root)
        if not _named(w)
    ]


def test_main_window_controls_are_named(app: support.AppUnderTest) -> None:
    app.wait_scanned()
    app.select("Northwind Mail")
    support.pump(0.2)
    assert _controls(app.window)
    assert _unnamed(app.window) == []


def test_edit_form_controls_are_named(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.select("Contoso ID")
    app.window.activate_action("win.edit", None)
    support.wait_until(lambda: app.window.detail.editing, what="edit")
    support.pump(0.2)
    assert _unnamed(app.window.detail) == []


def test_new_password_dialog_controls_are_named(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.window.activate_action("win.new-password", None)
    dialog = support.wait_until(lambda: getattr(app.window, "new_dialog", None), what="dialog")
    support.wait_until(dialog.get_mapped, what="mapped")
    support.pump(0.3)
    assert _unnamed(dialog) == []


def test_preferences_controls_are_named(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.application.activate_action("preferences", None)
    prefs = support.wait_until(lambda: getattr(app.application, "preferences", None), what="prefs")
    support.wait_until(prefs.get_mapped, what="mapped")
    support.pump(0.3)
    assert _unnamed(prefs) == []


def test_sign_in_pages_are_named(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.call(lambda d: d.sign_out())
    app.window.activate_action("win.sign-in", None)
    dialog = support.wait_until(lambda: app.window.sign_in_dialog, what="wizard")
    support.wait_until(dialog.get_mapped, what="mapped")
    support.pump(0.3)
    assert _unnamed(dialog) == []
    dialog.apple_id.set_text("alex.doe@example.com")
    dialog.password.set_text("correct-horse")
    dialog.start()
    support.wait_until(lambda: dialog.page_tag == "code", what="code page")
    support.pump(0.5)
    assert _unnamed(dialog) == []
    dialog.code_boxes.entries[0].set_text("123456")
    support.wait_until(lambda: dialog.page_tag == "device", what="device page")
    support.pump(0.5)
    assert _unnamed(dialog) == []


def test_deleted_view_controls_are_named(app: support.AppUnderTest) -> None:
    from gi.repository import GLib  # noqa: PLC0415

    app.wait_loaded()
    app.window.activate_action("win.section", GLib.Variant("s", "deleted"))
    app.window.list_page.trash_selection.set_selected(0)
    support.pump(0.3)
    assert _unnamed(app.window) == []


def test_list_rows_have_names(app: support.AppUnderTest) -> None:
    from gi.repository import Gtk  # noqa: PLC0415

    app.wait_loaded()
    support.pump(0.2)
    rows = [
        w
        for w in support.walk(app.window.list_page.list_view)
        if type(w).__name__ == "GtkListItemWidget"
    ]
    named = [
        r
        for r in rows
        if r.get_mapped() and Gtk.test_accessible_has_property(r, Gtk.AccessibleProperty.LABEL)
    ]
    assert len(named) >= 10
