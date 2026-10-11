# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""New Password dialog: generated default, validation, save → selected in the list."""

from __future__ import annotations

import re
from typing import Any

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)
APPLE = re.compile(r"[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}")


def _open(app: support.AppUnderTest) -> Any:
    app.window.activate_action("win.new-password", None)
    return support.wait_until(lambda: getattr(app.window, "new_dialog", None), what="dialog")


def test_dialog_starts_with_an_apple_style_password(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    dialog = _open(app)
    password = dialog.form.password.get_text()
    assert APPLE.fullmatch(password)
    assert any(c.isupper() for c in password)
    assert any(c.isdigit() for c in password)


def test_each_dialog_gets_a_fresh_password(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    first = _open(app)
    one = first.form.password.get_text()
    first.close()
    support.pump(0.3)
    app.window.new_dialog = None
    two = _open(app).form.password.get_text()
    assert one != two


def test_save_creates_the_item_and_selects_it(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    dialog = _open(app)
    dialog.form.url.set_text("tickets.example.net")
    dialog.form.username.set_text("alex.doe@example.com")
    password = dialog.form.password.get_text()
    dialog.save_button.emit("clicked")
    support.wait_until(lambda: "tickets.example.net" in app.titles(), what="new item listed")
    created = app.call(
        lambda d: next(c for c in d.items.values() if c.url == "https://tickets.example.net")
    )
    assert created.password == password
    assert created.username == "alex.doe@example.com"
    support.wait_until(
        lambda: (
            app.window.list_page.selected_item() is not None
            and app.window.list_page.selected_item().item.id == created.id
        ),
        what="selected",
    )
    assert app.window.last_toast.get_title() == "Password saved"


def test_a_second_save_while_the_first_is_pending_is_ignored(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    dialog = _open(app)
    dialog.form.url.set_text("tickets.example.net")
    # Enter in the username field calls save() even while the button is insensitive.
    dialog.save()
    dialog.save()
    support.wait_until(lambda: "tickets.example.net" in app.titles(), what="new item listed")
    support.pump(0.3)
    assert app.call(lambda d: d.calls).count("Save") == 1


def test_missing_website_keeps_the_dialog_open(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    dialog = _open(app)
    dialog.save_button.emit("clicked")
    support.pump(0.3)
    assert dialog.form.url.has_css_class("error")
    assert "Enter a website" in dialog.form.error_label.get_text()
    assert dialog.get_parent() is not None  # still presented
    assert "Save" not in app.call(lambda d: d.calls)


def test_new_password_inside_a_group_belongs_to_that_group(app: support.AppUnderTest) -> None:
    from passwords_app.app.sections import Kind, Section  # noqa: PLC0415

    app.wait_loaded()
    app.window.sidebar.select(Section(Kind.GROUP, "Family"))
    support.pump(0.1)
    dialog = _open(app)
    dialog.form.url.set_text("streaming.example.com")
    dialog.save_button.emit("clicked")
    support.wait_until(lambda: "streaming.example.com" in app.titles(), what="listed in group")
    created = app.call(
        lambda d: next(c for c in d.items.values() if "streaming.example.com" in c.url)
    )
    assert created.group == "Family"


def test_new_password_with_a_setup_key(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    dialog = _open(app)
    dialog.form.url.set_text("vpn.example.org")
    dialog.form.username.set_text("jdoe")
    dialog.form.otpauth.set_text("JBSWY3DPEHPK3PXP")
    dialog.save_button.emit("clicked")
    support.wait_until(lambda: "vpn.example.org" in app.titles(), what="listed")
    created = app.call(lambda d: next(c for c in d.items.values() if "vpn.example.org" in c.url))
    assert created.otpauth.startswith("otpauth://totp/vpn.example.org:jdoe?")


def test_regenerate_changes_the_preview(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    gen = _open(app).form.generator
    before = gen.preview.get_text()
    gen.regenerate.emit("clicked")
    assert gen.preview.get_text() != before
    assert APPLE.fullmatch(gen.preview.get_text())
