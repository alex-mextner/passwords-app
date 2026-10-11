# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The real GTK app, drawn in a private headless gnome-shell, talking to the real daemon.

As in tests/gui, the app runs inside the test process (a Wayland client of the private shell)
so a scenario reads what the window shows from its widgets: the list rows, the detail page,
the banners, the Deleted view. Only its D-Bus connection differs from the GUI tests: it goes
to the stack's private bus, where the real `passwords-appd` serves, not to a fake daemon.

`Desktop` (one per session: the shell and the registered application) lives in the
`desktop` fixture; `AppWindow` is one window per stack.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from tests.e2e.stack import pump, wait_until
from tests.gui import support

if TYPE_CHECKING:
    from pathlib import Path

    from tests.harness.gnome_shell import GnomeShellSession

    from passwords_app.app.records import Item, TrashEntry


@dataclass
class Desktop:
    shell: GnomeShellSession
    application: Any


def _variant(text: str) -> Any:
    from gi.repository import GLib  # noqa: PLC0415

    return GLib.Variant("s", text)


class AppWindow:
    """The Passwords window on the stack's bus; methods read or drive it like a user."""

    def __init__(self, desktop: Desktop, address: str) -> None:
        from gi.repository import Adw, Gio  # noqa: PLC0415

        from passwords_app.app import i18n  # noqa: PLC0415
        from passwords_app.app.ui.application import settings_schema_source  # noqa: PLC0415

        self.desktop = desktop
        self.shell = desktop.shell
        self.application = desktop.application
        i18n.setup(["en"])
        source = settings_schema_source()
        assert source is not None
        schema = source.lookup(support.APP_ID, True)  # noqa: FBT003
        assert schema is not None
        self.settings = Gio.Settings.new_full(schema, Gio.memory_settings_backend_new(), None)
        self.connection = Gio.DBusConnection.new_for_address_sync(
            address,
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
            | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
            None,
            None,
        )
        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
        app = self.application
        app._connection = self.connection
        app._settings = self.settings
        app._authorizer = None
        app.attach()
        self.window = app.ensure_window()
        self.window.present()
        wait_until(self.window.get_mapped, what="app window mapped")
        wait_until(lambda: self.vault.loaded, what="app list loaded from the daemon")

    def close(self) -> None:
        # Drop focus first: a late Wayland event must not reach a destroyed focused entry.
        self.window.set_focus(None)
        pump(0.2)
        self.application.detach()
        pump(0.05)
        self.connection.close_sync(None)

    # --- reading ---------------------------------------------------------------------------

    @property
    def vault(self) -> Any:
        return self.window.vault

    def items(self) -> list[Item]:
        store = self.vault.items
        return [store.get_item(i).item for i in range(store.get_n_items())]

    def item(self, item_id: str) -> Item | None:
        obj = self.vault.find(item_id)
        return None if obj is None else cast("Item", obj.item)

    def titles(self) -> list[str]:
        """Titles of the rows the list shows in the current section."""
        page = self.window.list_page
        return [
            page.filtered.get_item(i).item.display_title for i in range(page.filtered.get_n_items())
        ]

    def trash(self) -> list[TrashEntry]:
        store = self.vault.trash
        return [store.get_item(i).entry for i in range(store.get_n_items())]

    def deleted_titles(self) -> list[str]:
        """Titles of the rows the Deleted view shows."""
        page = self.window.list_page
        rows = page.trash_filtered
        return [rows.get_item(i).entry.item.display_title for i in range(rows.get_n_items())]

    def list_view_shown(self) -> str:
        """What the list pane shows: "items", "trash", "empty" or "loading" (the spinner)."""
        return str(self.window.list_page.stack.get_visible_child_name())

    def status_title(self) -> str:
        return str(self.window.status_button.content.get_label())

    @property
    def pause_banner(self) -> Any:
        return self.window.list_page.pause_banner

    @property
    def signin_banner(self) -> Any:
        return self.window.list_page.signin_banner

    # --- driving ---------------------------------------------------------------------------

    def section(self, name: str) -> None:
        """Sidebar: "all", "codes", "security" or "deleted"."""
        self.window.activate_action("win.section", _variant(name))
        pump(0.2)

    def select(self, item_id: str) -> Item:
        """Click the list row of `item_id`; returns the item the detail page shows."""
        from passwords_app.app.sections import Kind  # noqa: PLC0415

        page = self.window.list_page
        if page.section.kind is Kind.DELETED:
            self.section("all")
        wait_until(lambda: page.select_id(item_id), what=f"row {item_id} in the list")
        return wait_until(
            lambda: (
                (shown := self.window.detail.item) is not None and shown.id == item_id and shown
            ),
            what=f"detail of {item_id}",
        )

    def detail_shows(self, item_id: str, **expected: object) -> bool:
        """Probe: the detail page shows `item_id` with these field values (e.g. password=…).

        Selects the row when another one is shown; the page re-renders by itself when a sync
        changes the shown item, so polling this sees background updates."""
        from passwords_app.app.sections import Kind  # noqa: PLC0415

        shown = self.window.detail.item
        if shown is None or shown.id != item_id:
            page = self.window.list_page
            if page.section.kind is Kind.DELETED:
                self.section("all")
            page.select_id(item_id)
            return False
        return all(getattr(shown, name) == value for name, value in expected.items())

    def new_password(self, url: str, username: str, password: str, *, title: str = "") -> None:
        """The New Password dialog, filled and saved."""
        self.window.activate_action("win.new-password", None)
        dialog = wait_until(lambda: getattr(self.window, "new_dialog", None), what="dialog")
        dialog.form.url.set_text(url)
        dialog.form.username.set_text(username)
        dialog.form.password.set_text(password)
        if title:
            dialog.form.title.set_text(title)
        dialog.save_button.emit("clicked")
        wait_until(self._toast("Password saved"), what="'Password saved' toast")

    def edit(self, item_id: str, **fields: str) -> None:
        """Edit in place: select, Edit, change `fields` (title/url/username/password/notes)."""
        self.select(item_id)
        self.window.activate_action("win.edit", None)
        wait_until(lambda: self.window.detail.editing, what="edit mode")
        form = self.window.detail.form
        for name, value in fields.items():
            widget = getattr(form, name)
            if hasattr(widget, "set_text"):
                widget.set_text(value)
            else:  # a multi-line view (notes)
                widget.get_buffer().set_text(value)
        self.window.activate_action("win.save-edit", None)
        wait_until(lambda: not self.window.detail.editing, what="edit saved")
        wait_until(self._toast("Saved"), what="'Saved' toast")

    def delete(self, item_id: str) -> None:
        self.select(item_id)
        self.window.activate_action("win.delete", None)
        wait_until(lambda: self.item(item_id) is None, what="item gone from the app")

    def restore(self, trash_id: str) -> None:
        """Deleted view → select the entry → Restore."""
        self.section("deleted")
        page = self.window.list_page

        def position() -> int | None:
            for i in range(page.trash_filtered.get_n_items()):
                if page.trash_filtered.get_item(i).entry.trash_id == trash_id:
                    return i + 1  # truthy even for row 0
            return None

        row = wait_until(position, what=f"trash entry {trash_id} in Deleted")
        page.trash_selection.set_selected(row - 1)
        button = wait_until(
            lambda: self._button(self.window.detail, "Restore"), what="Restore button"
        )
        button.emit("clicked")
        wait_until(self._toast("Restored"), what="'Restored' toast")

    def resolve_pause(self, response: str) -> None:
        """Pause banner → Review… → "apply" or "restore" in the dialog."""
        banner = self.pause_banner
        wait_until(banner.get_revealed, what="pause banner")
        self.window.activate_action("win.review-pause", None)
        dialog = wait_until(lambda: self.window.pause_dialog, what="pause dialog")
        # Click the dialog's button (emitting "response" alone would leave the dialog open).
        label = dialog.get_response_label(response)
        button = wait_until(lambda: self._button(dialog, label), what=f"{label!r} button")
        button.emit("clicked")
        expected = "Deletions applied" if response == "apply" else "Passwords restored"
        wait_until(self._toast(expected), what=f"{expected!r} toast", timeout=60)

    def _toast(self, title: str) -> Any:
        return lambda: (
            self.window.last_toast is not None and (self.window.last_toast.get_title() == title)
        )

    @staticmethod
    def _button(root: Any, label: str) -> Any:
        try:
            return support.find_button(root, label)
        except AssertionError:
            return None

    # --- proof -----------------------------------------------------------------------------

    def screenshot(self, path: Path) -> Path:
        """The window as the shell draws it (cropped from a full-monitor capture)."""
        from gi.repository import GdkPixbuf  # noqa: PLC0415

        pump(0.9)  # let banners, toasts and crossfades settle
        raw = path.with_suffix(".full.png")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.shell.screenshot(raw)
        x, y, w, h = json.loads(
            json.loads(
                self.shell.eval_js(
                    "const w = global.display.get_tab_list(0, null)[0];"
                    "const r = w.get_frame_rect(); JSON.stringify([r.x, r.y, r.width, r.height])"
                )
            )
        )
        pad = 24
        full = GdkPixbuf.Pixbuf.new_from_file(str(raw))
        x0, y0 = max(0, x - pad), max(0, y - pad)
        w0 = min(full.get_width() - x0, w + 2 * pad)
        h0 = min(full.get_height() - y0, h + 2 * pad)
        full.new_subpixbuf(x0, y0, w0, h0).savev(str(path), "png", [], [])
        raw.unlink()
        return path
