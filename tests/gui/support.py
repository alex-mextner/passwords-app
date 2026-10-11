# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Drive the real app inside a private headless GNOME Shell.

The test process itself becomes a Wayland client of the headless shell and talks D-Bus on the
shell's private session bus, where a `FakeDaemon` stands in for passwords-appd. Gtk must not
be imported before `prepare_environment()` points the process at that compositor: importing
Gtk opens the display named by the environment, which would otherwise be the developer's.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast, override

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from tests.fakes.fake_daemon import FakeDaemonThread
    from tests.harness.gnome_shell import GnomeShellSession

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
APP_ID = "io.github.alex_mextner.Passwords"


def safe_environment() -> None:
    """Make sure nothing in this process can reach the developer's display or session bus."""
    os.environ.pop("DISPLAY", None)
    os.environ["GDK_BACKEND"] = "wayland"
    os.environ["WAYLAND_DISPLAY"] = "/nonexistent/passwords-app-test/wayland-0"
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/nonexistent/passwords-app-test/bus"
    os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/nonexistent/passwords-app-test/system"
    os.environ["GSETTINGS_BACKEND"] = "memory"
    os.environ["GTK_A11Y"] = "test"
    os.environ["NO_AT_BRIDGE"] = "1"
    # The headless compositor keeps stale pixels from partially redrawn frames (stray dots
    # over changed header titles in screenshots); full redraws make every frame exact.
    os.environ["GSK_DEBUG"] = "full-redraw"
    # PyGObject's GLib overrides warn about their own deprecated aliases while loading;
    # with `filterwarnings = error` that would abort the import. GLib/Gio open no display.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import gi.events  # noqa: F401, PLC0415 - imported lazily by Gio's async overrides
        from gi.repository import Gio, GLib  # noqa: F401, PLC0415


def compile_schemas(target: Path) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    subprocess.run(  # noqa: S603 - fixed tool on our own files
        [
            shutil.which("glib-compile-schemas") or "glib-compile-schemas",
            "--strict",
            f"--targetdir={target}",
            str(DATA / "glib-2.0" / "schemas"),
        ],
        check=True,
    )
    return target


def compile_catalogs(target: Path) -> Path:
    """`po/<lang>.po` → `<target>/<lang>/LC_MESSAGES/passwords-app.mo`."""
    msgfmt = shutil.which("msgfmt")
    for po in sorted((ROOT / "po").glob("*.po")):
        out = target / po.stem / "LC_MESSAGES"
        out.mkdir(parents=True, exist_ok=True)
        if msgfmt is None:
            msg = "msgfmt is required to compile translations"
            raise RuntimeError(msg)
        subprocess.run(  # noqa: S603
            [msgfmt, "--check", "-o", str(out / "passwords-app.mo"), str(po)], check=True
        )
    return target


def install_into_session(shell: GnomeShellSession) -> None:
    """Desktop file, icons and search provider where the private shell looks for them.

    The search provider goes first: the shell reloads providers when the app list changes,
    which installing the desktop file triggers.
    """
    share = shell.root / "share"
    providers = share / "gnome-shell" / "search-providers"
    providers.mkdir(parents=True, exist_ok=True)
    shutil.copy(
        DATA / "search-providers" / f"{APP_ID}.search-provider.ini",
        providers / f"{APP_ID}.search-provider.ini",
    )
    shutil.copytree(DATA / "icons", share / "icons", dirs_exist_ok=True)
    apps = share / "applications"
    apps.mkdir(parents=True, exist_ok=True)
    # GLib hides desktop entries whose Exec binary is not on PATH; the private session's PATH
    # has no `passwords-app`, so point Exec at this interpreter instead.
    desktop = (DATA / "applications" / f"{APP_ID}.desktop").read_text(encoding="utf-8")
    launcher = f"{sys.executable} -m passwords_app.app.main"
    desktop = re.sub(r"^Exec=passwords-app", f"Exec={launcher}", desktop, flags=re.MULTILINE)
    (apps / f"{APP_ID}.desktop").write_text(desktop, encoding="utf-8")


def app_shell_session(size: str, lang: str = "C.UTF-8") -> GnomeShellSession:
    """A shell that already knows the app (desktop file, icon, search provider) at startup.

    The shell only watches application directories that exist when it starts, so the files
    must be in place before it launches.
    """
    from tests.harness.gnome_shell import GnomeShellSession  # noqa: PLC0415

    class AppShellSession(GnomeShellSession):
        @override
        def _prepare_root(self, shell_major: str) -> None:
            super()._prepare_root(shell_major)
            install_into_session(self)

    return AppShellSession(size, lang=lang)


def point_process_at(shell: GnomeShellSession, schemas: Path, locales: Path) -> None:
    env = shell.env()
    for key in (
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "DBUS_SYSTEM_BUS_ADDRESS",
        "XDG_DATA_DIRS",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
    ):
        os.environ[key] = env[key]
    os.environ["WAYLAND_DISPLAY"] = str(shell.runtime_dir / env["WAYLAND_DISPLAY"])
    os.environ["GSETTINGS_SCHEMA_DIR"] = str(schemas)
    os.environ["PASSWORDS_APP_LOCALEDIR"] = str(locales)


KEYBOARD_JS = (
    "const Clutter = imports.gi.Clutter;"
    "if (!global._paKeyboard) {"
    "  const seat = global.stage.context.get_backend().get_default_seat();"
    "  global._paKeyboard = seat.create_virtual_device("
    "    Clutter.InputDeviceType.KEYBOARD_DEVICE); }"
    "true"
)


def add_virtual_keyboard(shell: GnomeShellSession) -> None:
    """A headless seat has no keyboard; without one no window ever gets keyboard focus."""
    shell.eval_js(KEYBOARD_JS)


def press(shell: GnomeShellSession, *combos: str) -> None:
    """Press key combos through the compositor, e.g. `press(shell, "ctrl+f", "n", "Down")`.

    Each combo is `+`-joined Clutter key names (without `KEY_`); modifiers are held while
    the last key is pressed, exactly as a user would type them.
    """
    aliases = {"ctrl": "Control_L", "shift": "Shift_L", "alt": "Alt_L", "super": "Super_L"}
    steps: list[str] = []
    for combo in combos:
        keys = [aliases.get(k.lower(), k) for k in combo.split("+")]
        down = [f"[Clutter.KEY_{k}, Clutter.KeyState.PRESSED]" for k in keys]
        up = [f"[Clutter.KEY_{k}, Clutter.KeyState.RELEASED]" for k in reversed(keys)]
        steps.extend(down + up)
    shell.eval_js(
        KEYBOARD_JS.removesuffix("true")
        + "const GLib = imports.gi.GLib;"
        + f"for (const [k, s] of [{', '.join(steps)}]) "
        + "global._paKeyboard.notify_keyval(GLib.get_monotonic_time(), k, s);"
        + "true"
    )


def type_text(shell: GnomeShellSession, text: str) -> None:
    names = {" ": "space", ".": "period", "-": "minus", "@": "at", "_": "underscore"}
    press(shell, *(names.get(c, c) for c in text))


def import_gtk() -> Any:
    """Import Gtk/Adw once the environment is safe; PyGObject's own deprecations are muted."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import gi  # noqa: PLC0415

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi import repository  # noqa: PLC0415
        from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: F401, PLC0415

        import passwords_app.app.ui.application  # noqa: F401, PLC0415
    return repository


# ---------------------------------------------------------------------- main-loop helpers
def pump(seconds: float = 0.05) -> None:
    from gi.repository import GLib  # noqa: PLC0415

    context = GLib.MainContext.default()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        while context.iteration(False):  # noqa: FBT003
            pass
        time.sleep(0.005)


def wait_until[T](
    probe: Callable[[], T | None], *, timeout: float = 5.0, what: str = "condition"
) -> T:
    """Run the main loop until `probe()` is truthy (so never None); fail after `timeout`."""
    from gi.repository import GLib  # noqa: PLC0415

    context = GLib.MainContext.default()
    deadline = time.monotonic() + timeout
    while True:
        while context.iteration(False):  # noqa: FBT003
            pass
        result = probe()
        if result:
            return result
        if time.monotonic() > deadline:
            msg = f"timed out after {timeout}s waiting for {what}"
            raise AssertionError(msg)
        time.sleep(0.01)


def wait_toast(app: AppUnderTest, title: str) -> None:
    """Wait for the toast the app shows from a daemon reply.

    Tests that synchronize on the fake daemon's state see the change before the app's reply
    callback has run, so a toast must be awaited, not read right away.
    """
    wait_until(
        lambda: app.window.last_toast is not None and app.window.last_toast.get_title() == title,
        what=f"toast {title!r}",
    )


# ---------------------------------------------------------------------- widget helpers
def walk(widget: Any) -> Iterator[Any]:
    yield widget
    child = widget.get_first_child()
    while child is not None:
        yield from walk(child)
        child = child.get_next_sibling()


def find_button(root: Any, label: str) -> Any:
    from gi.repository import Gtk  # noqa: PLC0415

    for widget in walk(root):
        if isinstance(widget, Gtk.Button) and widget.get_label() == label and widget.get_mapped():
            return widget
    msg = f"no mapped button labelled {label!r}"
    raise AssertionError(msg)


def wait_button(root: Any, label: str, timeout: float = 5.0) -> Any:
    """`find_button`, waiting for reveal animations to map it."""

    def probe() -> Any:
        try:
            return find_button(root, label)
        except AssertionError:
            return None

    return wait_until(probe, timeout=timeout, what=f"button {label!r}")


def visible_texts(root: Any) -> list[str]:
    from gi.repository import Gtk  # noqa: PLC0415

    return [
        w.get_text()
        for w in walk(root)
        if isinstance(w, Gtk.Label) and w.get_mapped() and w.get_text()
    ]


def clipboard_text(window: Any, timeout: float = 3.0) -> str | None:
    """Read the clipboard through Wayland, as any other app would."""
    result: list[str | None] = []

    def done(clipboard: Any, res: Any) -> None:
        try:
            result.append(clipboard.read_text_finish(res))
        except Exception:  # noqa: BLE001 - empty clipboard reads as an error
            result.append(None)

    window.get_clipboard().read_text_async(None, done)
    wait_until(lambda: result, timeout=timeout, what="clipboard read")
    return result[0]


@dataclass
class AppUnderTest:
    """One app window on a fresh fake daemon; see the `app` fixture."""

    application: Any
    window: Any
    fake: FakeDaemonThread
    settings: Any
    authorizations: list[bool] = field(default_factory=list)

    @property
    def vault(self) -> Any:
        return self.window.vault

    def call(self, fn: Callable[[Any], Any]) -> Any:
        """Run `fn(daemon)` on the fake daemon's loop."""
        return self.fake.call(fn)

    def code_now(self, item_id: str) -> str:
        """The code the daemon's clock gives right now, computed independently of the app."""
        from passwords_app.core.otp import code_at, parse_otpauth  # noqa: PLC0415

        cred = self.call(lambda d: d.items[item_id])
        now = self.call(lambda d: d.clock())
        return code_at(parse_otpauth(cred.otpauth), now)[0]

    def delete_remotely(self, item_id: str) -> None:
        """As if the item was deleted on an iPhone and the daemon synced it."""

        def remove(d: Any) -> None:
            d._to_trash(item_id, "deleted-in-icloud")
            d._items_changed([item_id])

        self.call(remove)

    def wait_loaded(self) -> None:
        wait_until(lambda: self.vault.loaded, what="item list")

    def wait_scanned(self) -> None:
        wait_until(lambda: self.vault.loaded and not self.vault.scanning, what="security scan")

    def select(self, title: str) -> Any:
        """Select the visible list item titled `title`; returns its Item once shown."""
        page = self.window.list_page
        for position in range(page.filtered.get_n_items()):
            obj = cast("Any", page.filtered.get_item(position))
            if obj.item.display_title == title:
                break
        else:
            msg = f"{title!r} is not in the list"
            raise AssertionError(msg)
        page.selection.set_selected(position)
        expected = obj.item.id

        def shown() -> bool:
            item = self.window.detail.item
            return bool(item is not None and item.id == expected)

        wait_until(shown, what=f"detail of {title}")
        return self.window.detail.item

    def titles(self) -> list[str]:
        page = self.window.list_page
        return [
            cast("Any", page.filtered.get_item(i)).item.display_title
            for i in range(page.filtered.get_n_items())
        ]
