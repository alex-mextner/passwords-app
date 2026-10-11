# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Copy buttons and the clipboard auto-clear, read back through the compositor."""

from __future__ import annotations

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)


def test_copy_password_puts_it_on_the_clipboard(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = app.select("Northwind Mail")
    app.window.activate_action("win.copy-password", None)
    assert support.clipboard_text(app.window) == item.password
    assert app.window.last_toast.get_title() == "Password copied · clears in 45 s"


def test_copied_password_is_cleared_after_the_delay(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.settings.set_uint("clipboard-clear-seconds", 1)
    item = app.select("Northwind Mail")
    app.window.activate_action("win.copy-password", None)
    assert support.clipboard_text(app.window) == item.password
    support.wait_until(
        lambda: support.clipboard_text(app.window) in {None, ""}, timeout=4, what="cleared"
    )


def test_clear_leaves_text_copied_later_alone(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.settings.set_uint("clipboard-clear-seconds", 1)
    app.select("Northwind Mail")
    app.window.activate_action("win.copy-password", None)
    app.window.get_clipboard().set("something the user copied")
    support.pump(1.6)
    assert support.clipboard_text(app.window) == "something the user copied"


def test_zero_seconds_never_clears(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.settings.set_uint("clipboard-clear-seconds", 0)
    item = app.select("Northwind Mail")
    app.window.activate_action("win.copy-password", None)
    assert not app.window.clipboard.pending
    assert app.window.last_toast.get_title() == "Password copied"
    assert support.clipboard_text(app.window) == item.password


def test_username_copy_is_not_treated_as_secret(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = app.select("Northwind Mail")
    app.window.activate_action("win.copy-username", None)
    assert support.clipboard_text(app.window) == item.username
    assert not app.window.clipboard.pending
    formats = app.window.get_clipboard().get_formats()
    assert not formats.contain_mime_type("x-kde-passwordManagerHint")


def test_password_copy_carries_the_password_manager_hint(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.select("Northwind Mail")
    app.window.activate_action("win.copy-password", None)
    formats = app.window.get_clipboard().get_formats()
    assert formats.contain_mime_type("x-kde-passwordManagerHint")


def test_copy_code_copies_the_current_code(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    page = app.window.list_page
    title = next(
        page.filtered.get_item(i).item.display_title
        for i in range(page.filtered.get_n_items())
        if page.filtered.get_item(i).item.has_code
    )
    item = app.select(title)
    app.window.activate_action("win.copy-code", None)
    support.wait_until(
        lambda: support.clipboard_text(app.window) == app.code_now(item.id), what="code copied"
    )
    assert app.window.clipboard.pending


def test_copy_buttons_in_the_detail_pane(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = app.select("Northwind Mail")
    buttons = [
        w
        for w in support.walk(app.window.detail.username_row)
        if w.__class__.__name__ == "Button" and w.get_tooltip_text() == "Copy User Name"
    ]
    buttons[0].emit("clicked")
    support.wait_until(
        lambda: support.clipboard_text(app.window) == item.username, what="username copied"
    )
