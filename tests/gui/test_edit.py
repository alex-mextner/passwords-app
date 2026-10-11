# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""In-place editing: save reaches the daemon, validation blocks bad input, cancel discards."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest
from tests.gui import support

if TYPE_CHECKING:
    from passwords_app.app.records import Item

pytestmark = pytest.mark.timeout(120)

TOTP_KEY = "JBSWY3DPEHPK3PXP"


def _edit(app: support.AppUnderTest, title: str) -> Item:
    item: Item = app.select(title)
    app.window.activate_action("win.edit", None)
    support.wait_until(lambda: app.window.detail.editing, what="edit mode")
    return item


def _save(app: support.AppUnderTest) -> None:
    app.window.activate_action("win.save-edit", None)


def test_edit_loads_every_field(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = _edit(app, "Northwind Mail")
    form = app.window.detail.form
    assert form.title.get_text() == "Northwind Mail"
    assert form.url.get_text() == item.url
    assert form.username.get_text() == item.username
    assert form.password.get_text() == item.password
    assert app.window.detail.save_button.get_visible()
    assert app.window.detail.cancel_button.get_visible()
    assert not app.window.lookup_action("delete").get_enabled()


def test_save_updates_the_daemon_and_the_view(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = _edit(app, "Northwind Mail")
    form = app.window.detail.form
    form.title.set_text("Northwind Webmail")
    form.username.set_text("a.doe@example.com")
    form.password.set_text("brand-New-passw0rd-2026")
    _save(app)
    support.wait_until(lambda: not app.window.detail.editing, what="saved")
    stored = app.call(lambda d: d.items[item.id])
    assert stored.title == "Northwind Webmail"
    assert stored.username == "a.doe@example.com"
    assert stored.password == "brand-New-passw0rd-2026"
    support.wait_until(lambda: "Northwind Webmail" in app.titles(), what="renamed in list")
    support.wait_until(
        lambda: app.window.detail.title_label.get_text() == "Northwind Webmail",
        what="renamed detail",
    )
    assert app.window.last_toast.get_title() == "Saved"


def test_save_keeps_the_item_selected(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = _edit(app, "Northwind Mail")
    app.window.detail.form.title.set_text("ZZ Northwind")
    _save(app)
    support.wait_until(lambda: "ZZ Northwind" in app.titles(), what="renamed")
    support.pump(0.2)
    assert app.window.list_page.selected_item().item.id == item.id


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("url", "", "Enter a website"),
        ("url", "ftp://files.example.com", "Use a web address such as example.com"),
        ("password", "", "Enter a password"),
        ("otpauth", "not a key!", "A setup key contains only letters"),
        ("otpauth", "otpauth://hotp/x?secret=JBSWY3DP", "This verification code link is not valid"),
    ],
)
def test_invalid_input_is_not_saved(
    app: support.AppUnderTest, field: str, value: str, message: str
) -> None:
    app.wait_loaded()
    item = _edit(app, "Northwind Mail")
    form = app.window.detail.form
    getattr(form, field).set_text(value)
    _save(app)
    support.pump(0.3)
    assert app.window.detail.editing
    assert form.error_label.get_visible()
    assert message in form.error_label.get_text()
    assert getattr(form, field).has_css_class("error")
    assert "Save" not in app.call(lambda d: d.calls)
    assert app.call(lambda d: d.items[item.id]).url == item.url


def test_fixing_the_error_clears_the_highlight(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _edit(app, "Northwind Mail")
    form = app.window.detail.form
    form.url.set_text("")
    _save(app)
    support.pump(0.1)
    form.url.set_text("mail.northwind.example")
    _save(app)
    support.wait_until(lambda: not app.window.detail.editing, what="saved")
    assert not form.url.has_css_class("error")


def test_bare_host_is_normalized_to_https(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = _edit(app, "Northwind Mail")
    app.window.detail.form.url.set_text("Mail.Northwind.Example/inbox")
    _save(app)
    support.wait_until(lambda: not app.window.detail.editing, what="saved")
    assert app.call(lambda d: d.items[item.id]).url == "https://mail.northwind.example/inbox"


def test_adding_a_setup_key_creates_a_live_code(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    title = next(t for t in app.titles() if not app.vault.find(_id_of(app, t)).item.has_code)
    item = _edit(app, title)
    app.window.detail.form.otpauth.set_text("jbsw y3dp ehpk 3pxp")
    _save(app)
    support.wait_until(lambda: not app.window.detail.editing, what="saved")
    stored = app.call(lambda d: d.items[item.id])
    assert stored.otpauth.startswith("otpauth://totp/")
    assert f"secret={TOTP_KEY}" in stored.otpauth
    support.wait_until(lambda: re.fullmatch(r"\d{6}", app.window.detail.code), what="code")
    assert app.window.detail.code_row.get_visible()


def _id_of(app: support.AppUnderTest, title: str) -> str:
    page = app.window.list_page
    for i in range(page.filtered.get_n_items()):
        if page.filtered.get_item(i).item.display_title == title:
            item_id: str = page.filtered.get_item(i).item.id
            return item_id
    raise AssertionError(title)


def test_alt_websites_can_be_added_and_removed(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = _edit(app, "Northwind Mail")
    form = app.window.detail.form
    form.add_alt_url("webmail.northwind.example")
    _save(app)
    support.wait_until(lambda: not app.window.detail.editing, what="saved")
    assert app.call(lambda d: d.items[item.id]).alt_urls[-1] == "https://webmail.northwind.example"
    _edit(app, "Northwind Mail")
    form._remove_alt(form.alt_rows[-1])
    _save(app)
    support.wait_until(lambda: not app.window.detail.editing, what="saved again")
    assert "https://webmail.northwind.example" not in app.call(lambda d: d.items[item.id]).alt_urls


def test_notes_are_saved(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = _edit(app, "Northwind Mail")
    app.window.detail.form.notes.get_buffer().set_text("Recovery codes are in the safe.")
    _save(app)
    support.wait_until(lambda: not app.window.detail.editing, what="saved")
    assert app.call(lambda d: d.items[item.id]).notes == "Recovery codes are in the safe."
    support.wait_until(
        lambda: app.window.detail.notes_label.get_text() == "Recovery codes are in the safe.",
        what="notes shown",
    )


def test_cancel_discards_changes(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = _edit(app, "Northwind Mail")
    app.window.detail.form.title.set_text("Should not stick")
    app.window.activate_action("win.cancel-edit", None)
    assert not app.window.detail.editing
    assert app.window.detail.title_label.get_text() == "Northwind Mail"
    assert app.call(lambda d: d.items[item.id]).title == "Northwind Mail"
    # Leaving edit mode wipes the form so no password lingers in hidden widgets.
    assert app.window.detail.form.password.get_text() == ""


def test_daemon_rejection_is_shown_and_keeps_edit_mode(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _edit(app, "Northwind Mail")
    app.call(lambda d: d.fail_next("Save", "Locked", "The keyring is locked"))
    _save(app)
    support.wait_until(
        lambda: "The keyring is locked" in app.window.detail.form.error_label.get_text(),
        what="daemon error",
    )
    assert app.window.detail.editing


def test_generator_fills_an_apple_style_password(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _edit(app, "Northwind Mail")
    form = app.window.detail.form
    form.generator.modes.set_active_name("apple")
    form.generator.use.emit("clicked")
    assert re.fullmatch(r"[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}", form.password.get_text())


def test_custom_generator_options_apply_and_persist(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _edit(app, "Northwind Mail")
    gen = app.window.detail.form.generator
    gen.modes.set_active_name("custom")
    gen.length.set_value(32)
    gen.symbols.set_active(False)
    gen.digits.set_active(True)
    gen.use.emit("clicked")
    password = app.window.detail.form.password.get_text()
    assert len(password) == 32
    assert password.isalnum()
    assert app.settings.get_string("generator-mode") == "custom"
    assert app.settings.get_uint("generator-length") == 32
    assert not app.settings.get_boolean("generator-symbols")


def test_a_late_save_reply_leaves_the_next_edit_alone(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    _edit(app, "Northwind Mail")
    app.window.detail.form.title.set_text("Northwind Webmail")
    app.call(lambda d: setattr(d, "latency", 0.6))
    _save(app)
    app.call(lambda d: setattr(d, "latency", 0.0))  # only the save is slow
    other = _edit(app, "Contoso ID")  # select and edit B while A's save is in flight
    support.wait_toast(app, "Saved")
    support.pump(0.3)
    detail = app.window.detail
    assert detail.editing
    assert detail.item is not None
    assert detail.item.id == other.id
    assert detail.form.title.get_text() == "Contoso ID"
    assert detail.save_button.get_sensitive()
    assert app.call(lambda d: [c.title for c in d.items.values()]).count("Northwind Webmail") == 1
