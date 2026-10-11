# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Keyboard-only operation: real key events injected through the compositor."""

from __future__ import annotations

from typing import Any

import pytest
from tests.fakes.fake_daemon import FakeDaemon
from tests.gui import support

pytestmark = pytest.mark.timeout(120)


def _ready(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    support.wait_until(app.window.is_active, what="window has keyboard focus")


def _focus_in(widget: Any, window: Any) -> bool:
    focus = window.get_focus()
    return focus is not None and (focus is widget or focus.is_ancestor(widget))


def test_search_select_open_and_copy_without_a_mouse(app: support.AppUnderTest, shell: Any) -> None:
    _ready(app)
    support.press(shell, "ctrl+f")
    support.wait_until(lambda: _focus_in(app.window.list_page.search, app.window), what="search")
    support.type_text(shell, "northwind mail")
    support.wait_until(lambda: len(app.titles()) < 60, what="filtered")
    assert "Northwind Mail" in app.titles()
    assert len(app.titles()) < 5
    first = app.titles()[0]
    support.press(shell, "Down")
    item = support.wait_until(lambda: app.window.detail.item, what="detail shown")
    assert item.display_title == first
    support.wait_until(lambda: _focus_in(app.window.list_page.list_view, app.window), what="list")
    support.press(shell, "ctrl+c")
    support.wait_until(
        lambda: support.clipboard_text(app.window) == item.password, what="password copied"
    )


def test_copy_username_and_code_shortcuts(app: support.AppUnderTest, shell: Any) -> None:
    _ready(app)
    page = app.window.list_page
    title = next(
        page.filtered.get_item(i).item.display_title
        for i in range(page.filtered.get_n_items())
        if page.filtered.get_item(i).item.has_code
    )
    item = app.select(title)
    app.window.list_page.focus_list()
    support.press(shell, "ctrl+shift+c")
    support.wait_until(lambda: support.clipboard_text(app.window) == item.username, what="user")
    support.press(shell, "ctrl+alt+c")
    support.wait_until(
        lambda: support.clipboard_text(app.window) == app.code_now(item.id), what="code"
    )


def test_ctrl_c_in_a_text_field_copies_the_text_not_the_password(
    app: support.AppUnderTest, shell: Any
) -> None:
    _ready(app)
    item = app.select("Northwind Mail")
    support.press(shell, "ctrl+f")
    support.type_text(shell, "north")
    support.wait_until(lambda: app.window.list_page.search.get_text() == "north", what="typed")
    app.window.list_page.search.select_region(0, -1)
    support.press(shell, "ctrl+c")
    support.wait_until(lambda: support.clipboard_text(app.window) == "north", what="text copied")
    assert support.clipboard_text(app.window) != item.password


def test_delete_key_and_ctrl_z(app: support.AppUnderTest, shell: Any) -> None:
    _ready(app)
    app.select("Northwind Mail")
    app.window.list_page.focus_list()
    support.press(shell, "Delete")
    support.wait_until(lambda: "Northwind Mail" not in app.titles(), what="deleted")
    support.press(shell, "ctrl+z")
    support.wait_until(lambda: "Northwind Mail" in app.titles(), what="restored")


def test_edit_save_with_keys(app: support.AppUnderTest, shell: Any) -> None:
    _ready(app)
    item = app.select("Northwind Mail")
    app.window.list_page.focus_list()
    support.press(shell, "ctrl+e")
    support.wait_until(lambda: app.window.detail.editing, what="edit mode")
    support.wait_until(lambda: _focus_in(app.window.detail.form.title, app.window), what="title")
    support.press(shell, "ctrl+a")
    support.type_text(shell, "Mail at Northwind")
    support.press(shell, "ctrl+s")
    support.wait_until(lambda: not app.window.detail.editing, what="saved")
    support.wait_until(
        lambda: app.call(lambda d: d.items[item.id].title) == "Mail at Northwind", what="stored"
    )


def test_escape_cancels_editing(app: support.AppUnderTest, shell: Any) -> None:
    _ready(app)
    app.select("Northwind Mail")
    app.window.list_page.focus_list()
    support.press(shell, "ctrl+e")
    support.wait_until(lambda: app.window.detail.editing, what="edit mode")
    support.type_text(shell, "xyz")
    support.press(shell, "Escape")
    support.wait_until(lambda: not app.window.detail.editing, what="cancelled")
    assert app.window.detail.title_label.get_text() == "Northwind Mail"


def test_ctrl_n_opens_and_escape_closes_the_new_password_dialog(
    app: support.AppUnderTest, shell: Any
) -> None:
    _ready(app)
    support.press(shell, "ctrl+n")
    dialog = support.wait_until(lambda: getattr(app.window, "new_dialog", None), what="dialog")
    support.wait_until(lambda: _focus_in(dialog.form.url, app.window), what="website field")
    support.type_text(shell, "keyboard.example.com")
    support.press(shell, "Tab")
    support.type_text(shell, "kb.user")
    support.press(shell, "Return")
    support.wait_until(lambda: "keyboard.example.com" in app.titles(), what="saved by Enter")
    app.window.new_dialog = None
    support.press(shell, "ctrl+n")
    dialog = support.wait_until(lambda: getattr(app.window, "new_dialog", None), what="dialog 2")
    support.wait_until(lambda: _focus_in(dialog, app.window), what="dialog focused")
    support.press(shell, "Escape")
    support.wait_until(lambda: dialog.get_parent() is None, what="closed")


@pytest.mark.parametrize(
    ("key", "section"),
    [("ctrl+2", "Codes"), ("ctrl+3", "Security"), ("ctrl+4", "Deleted"), ("ctrl+1", "All")],
)
def test_section_shortcuts(app: support.AppUnderTest, shell: Any, key: str, section: str) -> None:
    _ready(app)
    if section == "All":
        support.press(shell, "ctrl+4")
        support.wait_until(lambda: app.window.list_page.get_title() == "Deleted", what="away")
    support.press(shell, key)
    support.wait_until(lambda: app.window.list_page.get_title() == section, what=section)


def test_preferences_and_shortcuts_dialogs(app: support.AppUnderTest, shell: Any) -> None:
    _ready(app)
    support.press(shell, "ctrl+comma")
    prefs = support.wait_until(lambda: getattr(app.application, "preferences", None), what="prefs")
    support.wait_until(lambda: _focus_in(prefs, app.window), what="prefs focused")
    support.press(shell, "Escape")
    support.wait_until(lambda: prefs.get_parent() is None, what="prefs closed")
    support.press(shell, "ctrl+question")
    support.wait_until(
        lambda: getattr(app.application, "shortcuts_dialog", None), what="shortcuts dialog"
    )


def test_tab_reaches_every_pane(app: support.AppUnderTest, shell: Any) -> None:
    _ready(app)
    app.select("Northwind Mail")
    app.window.sidebar.list.get_selected_row().grab_focus()
    visited: set[str] = set()
    for _ in range(40):
        support.press(shell, "Tab")
        support.pump(0.03)
        focus = app.window.get_focus()
        for name, pane in (
            ("sidebar", app.window.sidebar),
            ("list", app.window.list_page),
            ("detail", app.window.detail),
        ):
            if focus is not None and focus.is_ancestor(pane):
                visited.add(name)
        if visited == {"sidebar", "list", "detail"}:
            break
    assert visited == {"sidebar", "list", "detail"}


@pytest.fixture
def daemon_factory() -> Any:
    return FakeDaemon.demo


def test_code_boxes_by_keyboard(app: support.AppUnderTest, shell: Any) -> None:
    _ready(app)
    app.call(lambda d: d.sign_out())
    app.window.activate_action("win.sign-in", None)
    dialog = support.wait_until(lambda: app.window.sign_in_dialog, what="wizard")
    assert dialog.apple_id.get_text() == "alex.doe@example.com"
    support.wait_until(lambda: _focus_in(dialog.password, app.window), what="password focused")
    support.type_text(shell, "correct-horse")
    support.press(shell, "Return")
    support.wait_until(lambda: dialog.page_tag == "code", what="code page")
    support.wait_until(lambda: _focus_in(dialog.code_boxes.entries[0], app.window), what="box 1")
    support.type_text(shell, "129")
    support.wait_until(lambda: dialog.code_boxes.code == "129", what="three digits")
    support.press(shell, "BackSpace", "BackSpace")
    support.wait_until(lambda: dialog.code_boxes.code == "1", what="two erased")
    support.type_text(shell, "23456")
    support.wait_until(lambda: dialog.page_tag == "device", what="submitted")
