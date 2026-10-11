# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The Adw.Application: settings, styling, actions, single instance, search provider."""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess  # nosec B404 - runs glib-compile-schemas on our own files only
import time
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, override

from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from passwords_app.app.client import DaemonClient
from passwords_app.app.constants import APP_ID
from passwords_app.app.dbus_export import (
    AppExports,
    claim_app_name,
    forward_to_primary,
    release_app_name,
)
from passwords_app.app.i18n import _, ngettext
from passwords_app.app.ui.lock import PolkitAuthorizer
from passwords_app.app.ui.preferences import PreferencesDialog
from passwords_app.app.ui.shortcuts import build_dialog, shortcuts
from passwords_app.app.ui.widgets import on_activate
from passwords_app.app.ui.window import MainWindow
from passwords_app.app.vault import Vault

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from passwords_app.app.records import Item
    from passwords_app.app.ui.lock import Authorizer

_HERE = Path(__file__).resolve().parent
_SOURCE_DATA = _HERE.parents[3] / "data"
SCHEMA_DIR_ENV = "PASSWORDS_APP_SCHEMA_DIR"
# Set by the startup benchmark: a file that receives the time of the first painted frame.
FIRST_FRAME_ENV = "PASSWORDS_APP_FIRST_FRAME_FILE"
# How long a search-provider-only instance stays alive without a window.
_SERVICE_IDLE_MS = 60_000


def settings_schema_source() -> Gio.SettingsSchemaSource | None:
    """Installed schema, else one compiled from a source checkout (development runs)."""
    default = Gio.SettingsSchemaSource.get_default()
    if default is not None and default.lookup(APP_ID, True) is not None:  # noqa: FBT003
        return default
    directory = os.environ.get(SCHEMA_DIR_ENV)
    if not directory:
        source = _SOURCE_DATA / "glib-2.0" / "schemas"
        compiler = shutil.which("glib-compile-schemas")
        if not source.is_dir() or compiler is None:
            return None
        target = Path(GLib.get_user_cache_dir()) / "passwords-app" / "schemas"
        target.mkdir(parents=True, exist_ok=True)
        subprocess.run(  # noqa: S603  # nosec B603 - fixed tool, our own files
            [compiler, "--strict", f"--targetdir={target}", str(source)], check=True
        )
        directory = str(target)
    return Gio.SettingsSchemaSource.new_from_directory(directory, default, False)  # noqa: FBT003


def _report_first_frame(window: Gtk.Window, marker: Path) -> None:
    """Write CLOCK_MONOTONIC at the window's first painted frame (startup benchmark)."""

    def mapped(_window: Gtk.Window) -> None:
        clock = window.get_frame_clock()
        if clock is None:
            return
        handler = 0

        def painted(_clock: Gdk.FrameClock) -> None:
            clock.disconnect(handler)
            # Renamed into place: the benchmark reads the marker as soon as it exists.
            staged = marker.with_name(f"{marker.name}.tmp")
            staged.write_text(f"{time.monotonic():.6f}\n", encoding="ascii")
            staged.replace(marker)

        handler = clock.connect("after-paint", painted)

    window.connect("map", mapped)


def make_settings() -> Gio.Settings:
    source = settings_schema_source()
    schema = source.lookup(APP_ID, True) if source is not None else None  # noqa: FBT003
    if schema is None:
        msg = f"GSettings schema {APP_ID} is not installed"
        raise RuntimeError(msg)
    return Gio.Settings.new_full(schema, None, None)


class PasswordsApplication(Adw.Application):
    __gtype_name__ = "PasswordsApplication"
    instances: ClassVar[int] = 0

    def __init__(
        self,
        *,
        connection: Gio.DBusConnection | None = None,
        settings: Gio.Settings | None = None,
        authorizer: Authorizer | None = None,
        lock_probe: bool = True,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.NON_UNIQUE,
        )
        self._connection = connection
        self._settings = settings
        self._authorizer = authorizer
        self._lock_probe = lock_probe and authorizer is None
        self._now = now
        self.window: MainWindow | None = None
        self.vault: Vault | None = None
        self.exports: AppExports | None = None
        self.service_mode = False
        self.open_new = False
        self._skip_activation = False
        self.primary = True
        self.add_main_option(
            "search-provider",
            0,
            GLib.OptionFlags.NONE,
            GLib.OptionArg.NONE,
            _("Run only as the GNOME Shell search provider"),
            None,
        )
        self.add_main_option(
            "new", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE, _("Create a new password"), None
        )

    # ---------------------------------------------------------------- startup
    @property
    def connection(self) -> Gio.DBusConnection:
        if self._connection is None:
            self._connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        return self._connection

    @property
    def settings(self) -> Gio.Settings:
        if self._settings is None:
            self._settings = make_settings()
        return self._settings

    @override
    def do_handle_local_options(self, options: GLib.VariantDict) -> int:
        self.service_mode = options.contains("search-provider")
        # GApplication activates once after startup; a search-provider start must stay
        # windowless until the Shell actually asks for the app.
        self._skip_activation = self.service_mode
        self.open_new = options.contains("new")
        try:
            self.primary = claim_app_name(self.connection)
        except GLib.Error:
            self.primary = True  # no bus to coordinate on: run on our own
        if not self.primary:
            forward_to_primary(self.connection, "new-password" if self.open_new else None)
            return 0
        return -1

    @override
    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        display = Gdk.Display.get_default()
        if display is not None:
            theme = Gtk.IconTheme.get_for_display(display)
            theme.add_search_path(str(_HERE / "icons"))
            if (_SOURCE_DATA / "icons").is_dir():
                theme.add_search_path(str(_SOURCE_DATA / "icons"))
            css = Gtk.CssProvider()
            css.load_from_path(str(_HERE / "style.css"))
            Gtk.StyleContext.add_provider_for_display(
                display, css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
        Gtk.Window.set_default_icon_name(APP_ID)
        self._install_actions()
        self.attach()
        if self.service_mode:
            self.hold()
            GLib.timeout_add(_SERVICE_IDLE_MS, self._service_timeout)

    def attach(self) -> None:
        """Connect to the daemon and export our interfaces on `self.connection`."""
        client = DaemonClient(self.connection)
        self.vault = Vault(client)
        self.vault.hibp_enabled = self.settings.get_boolean("hibp-enabled")
        self.vault.start()
        self.exports = AppExports(
            self.connection,
            items=self._search_items,
            lookup=self._lookup,
            on_activate=self.activate,
            on_action=self._remote_action,
            on_result=self.activate_result,
            on_launch_search=self.launch_search,
        )
        if self._lock_probe:
            probe = PolkitAuthorizer()
            probe.check_available(lambda ok: self._lock_ready(probe if ok else None))

    def _service_timeout(self) -> bool:
        if self.service_mode:
            self.service_mode = False
            self.release()
        return GLib.SOURCE_REMOVE

    def _lock_ready(self, authorizer: Authorizer | None) -> None:
        self._authorizer = authorizer
        if self.window is not None:
            self.window.set_authorizer(authorizer)

    @override
    def do_activate(self) -> None:
        if self._skip_activation:
            self._skip_activation = False
            return
        window = self.ensure_window()
        marker = os.environ.get(FIRST_FRAME_ENV)
        if marker:
            _report_first_frame(window, Path(marker))
        window.present()
        if self.open_new:
            self.open_new = False
            window.new_password()

    def detach(self) -> None:
        """Close the window and drop the daemon connection state (inverse of `attach`)."""
        if self.window is not None:
            self.window.destroy()
            self.window = None
        if self.exports is not None:
            self.exports.close()
            self.exports = None
        if self.vault is not None:
            self.vault.stop()
            self.vault = None

    @override
    def do_shutdown(self) -> None:
        self.detach()
        if self.primary:
            with contextlib.suppress(GLib.Error):
                release_app_name(self.connection)
        Adw.Application.do_shutdown(self)

    def ensure_window(self) -> MainWindow:
        if self.window is None:
            if self.vault is None:
                msg = "ensure_window() called before startup created the vault"
                raise RuntimeError(msg)
            kwargs = {} if self._now is None else {"now": self._now}
            self.window = MainWindow(
                self, self.vault, self.settings, authorizer=self._authorizer, **kwargs
            )
            self.window.connect("destroy", lambda *_a: setattr(self, "window", None))
            if self.service_mode:
                self.service_mode = False
                self.release()
        return self.window

    # ---------------------------------------------------------------- actions
    def _install_actions(self) -> None:
        for name, callback in (
            ("preferences", self.show_preferences),
            ("shortcuts", self.show_shortcuts),
            ("about", self.show_about),
            ("quit", self.quit),
        ):
            action = Gio.SimpleAction.new(name, None)
            on_activate(action, callback)
            self.add_action(action)
        for entry in shortcuts():
            if not entry.bubble:
                self.set_accels_for_action(entry.action, list(entry.accels))

    def _remote_action(self, name: str) -> None:
        window = self.ensure_window()
        window.present()
        if name == "new-password":
            window.new_password()

    def show_preferences(self) -> None:
        window = self.ensure_window()
        status = self.vault.status if self.vault is not None else None
        dialog = PreferencesDialog(
            self.settings,
            lock_available=window.lock_available,
            apple_id=status.apple_id if status is not None else "",
            on_sign_in=window.show_sign_in,
            on_sign_out=self.confirm_sign_out,
        )
        self.preferences = dialog
        dialog.present(window)

    def confirm_sign_out(self) -> None:
        window = self.ensure_window()
        dialog = Adw.AlertDialog(
            heading=_("Sign Out of iCloud?"),
            body=_(
                "Syncing stops. Passwords already on this computer stay in GNOME Keyring and "
                "in this app."
            ),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("sign-out", _("Sign Out"))
        dialog.set_response_appearance("sign-out", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_close_response("cancel")

        def chosen(_d: Adw.AlertDialog, response: str) -> None:
            if response == "sign-out" and self.vault is not None:
                self.vault.client.sign_out(self._signed_out)
                if getattr(self, "preferences", None) is not None:
                    self.preferences.close()

        dialog.connect("response", chosen)
        dialog.present(window)

    def _signed_out(self, _result: object) -> None:
        if self.vault is not None:
            self.vault.refresh_status()

    def show_shortcuts(self) -> None:
        window = self.ensure_window()
        dialog, self.shortcut_sections = build_dialog()
        self.shortcuts_dialog = dialog
        dialog.present(window)

    def show_about(self) -> None:
        window = self.ensure_window()
        about = Adw.AboutDialog(
            application_name=_("Passwords"),
            application_icon=APP_ID,
            developer_name="Alex Mextner",
            version="0.1.0",
            website="https://github.com/alex-mextner/passwords-app",
            issue_url="https://github.com/alex-mextner/passwords-app/issues",
            license_type=Gtk.License.MIT_X11,
            comments=_(
                "Your iCloud Keychain passwords on Linux, in sync with your Apple devices and "
                "GNOME Keyring."
            ),
        )
        self.about_dialog = about
        about.present(window)

    # ---------------------------------------------------------------- search provider
    def _search_items(self) -> list[tuple[Item, str]]:
        if self.vault is None:
            return []
        return [
            (obj.item, obj.hay)
            for obj in (self.vault.items.get_item(i) for i in range(self.vault.items.get_n_items()))
            if obj is not None
        ]

    def _lookup(self, item_id: str) -> Item | None:
        obj = self.vault.find(item_id) if self.vault is not None else None
        return obj.item if obj is not None else None

    def activate_result(self, item_id: str) -> None:
        """Shell result chosen: show it and copy its password, with a notification."""
        window = self.ensure_window()
        window.present()
        window.reveal_and_copy(item_id, self._notify_copied)

    def _notify_copied(self, title: str, seconds: int) -> None:
        notification = Gio.Notification.new(_("Password copied"))
        body = (
            ngettext(
                "The password for {title} is on the clipboard for {n} second.",
                "The password for {title} is on the clipboard for {n} seconds.",
                seconds,
            ).format(title=title, n=seconds)
            if seconds
            else _("The password for {title} is on the clipboard.").format(title=title)
        )
        notification.set_body(body)
        notification.set_icon(Gio.ThemedIcon.new(APP_ID))
        self.send_notification("password-copied", notification)

    def launch_search(self, text: str) -> None:
        window = self.ensure_window()
        window.present()
        window.list_page.search.set_text(text)
        window.focus_search()
