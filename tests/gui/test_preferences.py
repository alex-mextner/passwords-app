# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Preferences dialog, About, Shortcuts, and the optional app lock."""

from __future__ import annotations

from typing import Any

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)


def _preferences(app: support.AppUnderTest) -> Any:
    app.application.activate_action("preferences", None)
    return support.wait_until(lambda: getattr(app.application, "preferences", None), what="prefs")


def test_defaults_are_private(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    prefs = _preferences(app)
    assert prefs.choices[prefs.clear_row.get_selected()] == 45
    assert not prefs.hibp_row.get_active()
    assert not prefs.favicons_row.get_active()
    assert not prefs.lock_row.get_active()


def test_clipboard_choice_is_stored(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    prefs = _preferences(app)
    prefs.clear_row.set_selected(prefs.choices.index(120))
    assert app.settings.get_uint("clipboard-clear-seconds") == 120
    prefs.clear_row.set_selected(prefs.choices.index(0))
    assert app.settings.get_uint("clipboard-clear-seconds") == 0


def test_retention_and_account_are_shown(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    prefs = _preferences(app)
    support.wait_until(lambda: "90 days" in support.visible_texts(prefs), what="retention")
    assert prefs.account_row.get_subtitle() == "alex.doe@example.com"
    assert prefs.account_button.get_label() == "Sign Out…"


def test_sign_out_asks_then_signs_out(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    prefs = _preferences(app)
    prefs.account_button.emit("clicked")
    support.pump(0.2)
    assert app.call(lambda d: d.state) == "idle"  # nothing before confirming
    dialogs = [w for w in support.walk(app.window) if w.__class__.__name__ == "AlertDialog"]
    assert dialogs
    dialogs[-1].emit("response", "sign-out")
    support.wait_until(lambda: app.call(lambda d: d.state) == "signed-out", what="signed out")
    support.wait_until(
        lambda: app.window.status_button.content.get_label() == "Not Signed In", what="status"
    )


def test_hibp_toggle_in_security_view_is_the_same_setting(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.window.hibp_switch.set_active(True)
    assert app.settings.get_boolean("hibp-enabled")
    assert app.vault.hibp_enabled
    prefs = _preferences(app)
    assert prefs.hibp_row.get_active()


def test_hibp_results_mark_compromised_passwords(
    app: support.AppUnderTest, monkeypatch: pytest.MonkeyPatch
) -> None:
    from passwords_app.app.security import Issue  # noqa: PLC0415

    app.wait_scanned()
    target = app.select("Northwind Mail")
    seen: list[dict[str, str]] = []

    class FakeHibp:
        def compromised(self, passwords: dict[str, str]) -> set[str]:
            seen.append(dict.fromkeys(passwords, "?"))
            return {target.id}

    monkeypatch.setattr(app.vault, "_hibp_factory", FakeHibp)
    app.settings.set_boolean("hibp-enabled", True)  # noqa: FBT003 - Gio.Settings takes the value positionally
    support.wait_until(
        lambda: Issue.COMPROMISED in app.vault.report.of(target.id), what="compromised verdict"
    )
    assert seen
    assert target.id in seen[0]
    support.wait_until(
        lambda: any("data leak" in r.get_title() for r in app.window.detail.warning_rows),
        what="warning row",
    )


def test_hibp_off_never_calls_the_service(
    app: support.AppUnderTest, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []

    class Spy:
        def compromised(self, passwords: dict[str, str]) -> set[str]:
            calls.append(len(passwords))
            return set()

    monkeypatch.setattr(app.vault, "_hibp_factory", Spy)
    app.wait_loaded()
    app.vault.scan()
    support.wait_until(lambda: not app.vault.scanning, what="scan")
    assert calls == []


def test_about_dialog(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.application.activate_action("about", None)
    about = support.wait_until(lambda: getattr(app.application, "about_dialog", None), what="about")
    assert about.get_application_name() == "Passwords"
    assert about.get_version() == "0.1.0"


def test_shortcuts_dialog_lists_every_spec_shortcut(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.application.activate_action("shortcuts", None)
    dialog = support.wait_until(
        lambda: getattr(app.application, "shortcuts_dialog", None), what="shortcuts"
    )
    from passwords_app.app.ui.shortcuts import accelerators  # noqa: PLC0415

    assert dialog.get_parent() is not None
    accels = accelerators(app.application.shortcut_sections)
    for accel in (
        "<Control>n",
        "<Control>f",
        "<Control>c",
        "<Control><Shift>c",
        "<Control><Alt>c",
        "<Control>e",
        "Delete",
        "<Control>z",
        "<Control>comma",
        "<Control>question",
    ):
        assert accel in accels


# ---------------------------------------------------------------------- app lock
def test_lock_is_unavailable_without_polkit(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.window.lock_available = False
    prefs = _preferences(app)
    # The fixture injects an authorizer; production probes polkit. Rebuild without it.
    prefs.close()
    support.pump(0.2)
    app.application.preferences = None
    window_auth, app.window._authorizer = app.window._authorizer, None
    try:
        prefs = _preferences(app)
        assert not prefs.lock_row.get_sensitive()
        assert "not installed" in prefs.lock_row.get_subtitle()
    finally:
        app.window._authorizer = window_auth


def test_lock_hides_secrets_and_unlock_needs_authorization(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.select("Northwind Mail")
    app.window.detail.reveal_button.set_active(True)
    app.settings.set_boolean("lock-enabled", True)  # noqa: FBT003 - Gio.Settings takes the value positionally
    app.window.lock()
    assert app.window.locked
    assert app.window.detail.item is None  # the shown password was dropped
    app.authorizations.append(False)
    support.find_button(app.window, "Unlock").emit("clicked")
    assert app.window.locked
    assert app.window.lock_page.get_description() == "Not unlocked. Try again."
    app.authorizations.append(True)
    support.find_button(app.window, "Unlock").emit("clicked")
    assert not app.window.locked
    support.wait_until(lambda: app.window.detail.item is not None, what="detail back")
    assert not app.window.detail.reveal_button.get_active()


def test_idle_timer_locks_only_when_enabled(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    assert not app.window.idle.armed
    app.settings.set_boolean("lock-enabled", True)  # noqa: FBT003 - Gio.Settings takes the value positionally
    assert app.window.idle.armed
    app.window.idle._fire()
    assert app.window.locked
    app.settings.set_boolean("lock-enabled", False)  # noqa: FBT003 - Gio.Settings takes the value positionally
    assert not app.window.idle.armed


def test_new_password_is_blocked_while_locked(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.settings.set_boolean("lock-enabled", True)  # noqa: FBT003 - Gio.Settings takes the value positionally
    app.window.lock()
    app.window.activate_action("win.new-password", None)
    support.pump(0.2)
    assert getattr(app.window, "new_dialog", None) is None


def test_nothing_secret_is_copied_while_locked(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    item = app.select("Northwind Mail")
    app.settings.set_boolean("lock-enabled", True)  # noqa: FBT003 - Gio.Settings takes the value positionally
    app.window.lock()
    app.window.get_clipboard().set("untouched")
    toast = app.window.last_toast
    # A GNOME Shell result activated while locked, and the copy shortcuts.
    app.application.activate_result(item.id)
    for action in ("win.copy-password", "win.copy-username", "win.copy-code"):
        app.window.activate_action(action, None)
    support.pump(0.5)
    assert app.window.locked
    assert support.clipboard_text(app.window) == "untouched"
    assert app.window.last_toast is toast  # no "copied" toast either


def test_nothing_is_deleted_while_locked(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.select("Northwind Mail")
    app.settings.set_boolean("lock-enabled", True)  # noqa: FBT003 - Gio.Settings takes the value positionally
    app.window.lock()
    app.window.delete_selected()
    support.pump(0.5)
    assert "Northwind Mail" in app.titles()
    assert app.window.last_deleted is None


def test_item_actions_are_disabled_while_locked_and_back_after_unlock(
    app: support.AppUnderTest,
) -> None:
    app.wait_loaded()
    app.select("Northwind Mail")
    item_actions = ("copy-password", "copy-username", "delete", "reveal", "edit")
    app.settings.set_boolean("lock-enabled", True)  # noqa: FBT003 - Gio.Settings takes the value positionally
    app.window.lock()
    for name in item_actions:
        assert not app.window.lookup_action(name).get_enabled(), name
    app.authorizations.append(True)
    app.window.unlock()
    assert not app.window.locked
    for name in item_actions:
        assert app.window.lookup_action(name).get_enabled(), name


def test_lock_closes_an_open_new_password_dialog(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.window.activate_action("win.new-password", None)
    dialog = support.wait_until(lambda: getattr(app.window, "new_dialog", None), what="dialog")
    dialog.form.url.set_text("tickets.example.net")
    app.settings.set_boolean("lock-enabled", True)  # noqa: FBT003 - Gio.Settings takes the value positionally
    app.window.lock()
    support.pump(0.3)
    assert app.window.get_visible_dialog() is None
    dialog.save()
    support.pump(0.3)
    assert "Save" not in app.call(lambda d: d.calls)
