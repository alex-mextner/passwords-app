# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Preferences: clipboard clearing, privacy, app lock, deleted-item retention, account."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gi.repository import Adw, Gio, GObject, Gtk

from passwords_app.app.constants import TRASH_RETENTION_DAYS
from passwords_app.app.i18n import _, ngettext
from passwords_app.app.ui.lock import idle_lock_hint

if TYPE_CHECKING:
    from collections.abc import Callable

# Offered clipboard delays in seconds; 0 keeps copies until the user replaces them.
CLEAR_CHOICES = (15, 30, 45, 60, 90, 120, 300, 0)


def clear_choice_text(seconds: int) -> str:
    if seconds == 0:
        return _("Never")
    if seconds % 60 == 0:
        minutes = seconds // 60
        return ngettext("After {n} minute", "After {n} minutes", minutes).format(n=minutes)
    return ngettext("After {n} second", "After {n} seconds", seconds).format(n=seconds)


class PreferencesDialog(Adw.PreferencesDialog):
    __gtype_name__ = "PasswordsPreferencesDialog"

    def __init__(  # noqa: PLR0913, PLR0915 - builds every preference group; splitting scatters one layout
        self,
        settings: Gio.Settings,
        *,
        lock_available: bool,
        fingerprint_available: bool,
        apple_id: str,
        on_sign_in: Callable[[], None],
        on_sign_out: Callable[[], None],
    ) -> None:
        super().__init__(title=_("Preferences"), search_enabled=False)
        self.settings = settings
        page = Adw.PreferencesPage(title=_("General"), icon_name="preferences-system-symbolic")

        clipboard = Adw.PreferencesGroup(
            title=_("Clipboard"),
            description=_("Copied passwords and codes are removed from the clipboard."),
        )
        seconds = settings.get_uint("clipboard-clear-seconds")
        self.choices: list[int] = list(CLEAR_CHOICES)
        if seconds not in self.choices:
            self.choices.insert(0, seconds)
        self.clear_row = Adw.ComboRow(
            title=_("Clear Clipboard"),
            model=Gtk.StringList.new([clear_choice_text(s) for s in self.choices]),
            selected=self.choices.index(seconds),
        )
        self.clear_row.connect("notify::selected", self._on_clear_changed)
        clipboard.add(self.clear_row)
        page.add(clipboard)

        privacy = Adw.PreferencesGroup(title=_("Privacy"))
        self.hibp_row = Adw.SwitchRow(
            title=_("Detect Compromised Passwords"),
            subtitle=_(
                "Checks passwords against known data leaks. Only the first 5 characters of "
                "each password’s fingerprint leave this computer."  # noqa: RUF001 - typographic punctuation in UI text
            ),
        )
        settings.bind("hibp-enabled", self.hibp_row, "active", Gio.SettingsBindFlags.DEFAULT)
        self.favicons_row = Adw.SwitchRow(
            title=_("Show Website Icons"),
            subtitle=_(
                "Downloads each website’s icon. When off, nothing is fetched and letters are shown."  # noqa: RUF001 - typographic punctuation in UI text
            ),
        )
        settings.bind(
            "favicons-enabled", self.favicons_row, "active", Gio.SettingsBindFlags.DEFAULT
        )
        privacy.add(self.hibp_row)
        privacy.add(self.favicons_row)
        page.add(privacy)

        lock = Adw.PreferencesGroup(title=_("App Lock"))
        self.lock_row = Adw.SwitchRow(
            title=_("Lock When Idle"),
            subtitle=idle_lock_hint(fingerprint=fingerprint_available)
            if lock_available
            else _("Unavailable: the Passwords polkit policy is not installed."),
            sensitive=lock_available,
        )
        # NO_SENSITIVITY: availability, not key writability, decides whether the row works.
        manual = Gio.SettingsBindFlags.DEFAULT | Gio.SettingsBindFlags.NO_SENSITIVITY
        settings.bind("lock-enabled", self.lock_row, "active", manual)
        self.lock_minutes = Adw.SpinRow.new_with_range(1, 120, 1)
        self.lock_minutes.set_title(_("Lock After (Minutes)"))
        settings.bind("lock-idle-minutes", self.lock_minutes, "value", manual)
        self.lock_row.bind_property(
            "active",
            self.lock_minutes,
            "sensitive",
            GObject.BindingFlags.SYNC_CREATE,
        )
        if not lock_available:
            self.lock_row.set_active(False)
            self.lock_minutes.set_sensitive(False)
        lock.add(self.lock_row)
        lock.add(self.lock_minutes)
        page.add(lock)

        deleted = Adw.PreferencesGroup(title=_("Deleted Passwords"))
        retention = Adw.ActionRow(
            title=_("Keep Deleted Passwords"),
            subtitle=_("Passwords deleted here or on another device can be restored."),
        )
        days = Gtk.Label(
            label=ngettext("{n} day", "{n} days", TRASH_RETENTION_DAYS).format(
                n=TRASH_RETENTION_DAYS
            )
        )
        days.add_css_class("dim-label")
        retention.add_suffix(days)
        deleted.add(retention)
        page.add(deleted)

        account = Adw.PreferencesGroup(title=_("Account"))
        self.account_row = Adw.ActionRow(
            title=_("Apple Account"), subtitle=apple_id or _("Not signed in")
        )
        self.account_row.add_css_class("property")
        if apple_id:
            button = Gtk.Button(label=_("Sign Out…"), valign=Gtk.Align.CENTER)
            button.add_css_class("destructive-action")
            button.connect("clicked", lambda *_a: on_sign_out())
        else:
            button = Gtk.Button(label=_("Sign In…"), valign=Gtk.Align.CENTER)
            button.add_css_class("suggested-action")
            button.connect("clicked", self._sign_in_clicked, on_sign_in)
        self.account_button = button
        self.account_row.add_suffix(button)
        account.add(self.account_row)
        page.add(account)
        self.add(page)

    def _sign_in_clicked(self, _button: Gtk.Button, on_sign_in: Callable[[], None]) -> None:
        self.close()
        on_sign_in()

    def _on_clear_changed(self, row: Adw.ComboRow, _pspec: object) -> None:
        self.settings.set_uint("clipboard-clear-seconds", self.choices[row.get_selected()])
