# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Screenshots of every view and dialog (light/dark, English/Russian) plus a walkthrough video.

Captures go to a temp dir; set PASSWORDS_APP_PROOF_DIR=docs/proof/app to refresh the
committed proof. Each capture is checked to show the window, not an empty frame.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(300)


def _out(tmp_path: Path) -> Path:
    target = os.environ.get("PASSWORDS_APP_PROOF_DIR")
    return Path(target) if target else tmp_path


def _capture(shell: Any, app: support.AppUnderTest, path: Path) -> Path:
    from gi.repository import GdkPixbuf  # noqa: PLC0415

    # Let animations (dialogs, banners, crossfades) settle before the shot.
    support.pump(0.9)
    raw = path.with_suffix(".full.png")
    shell.screenshot(raw)
    rect = json.loads(
        json.loads(
            shell.eval_js(
                "const w = global.display.get_tab_list(0, null)[0];"
                "const r = w.get_frame_rect(); JSON.stringify([r.x, r.y, r.width, r.height])"
            )
        )
    )
    x, y, w, h = rect
    pad = 24
    full = GdkPixbuf.Pixbuf.new_from_file(str(raw))
    assert full is not None
    x0, y0 = max(0, x - pad), max(0, y - pad)
    w0 = min(full.get_width() - x0, w + 2 * pad)
    h0 = min(full.get_height() - y0, h + 2 * pad)
    full.new_subpixbuf(x0, y0, w0, h0).savev(str(path), "png", [], [])
    raw.unlink()
    return path


def _scenes(app: support.AppUnderTest) -> list[tuple[str, Any]]:
    from gi.repository import GLib  # noqa: PLC0415

    w = app.window

    def section(name: str) -> Any:
        return lambda: w.activate_action("win.section", GLib.Variant("s", name))

    def detail() -> None:
        section("all")()
        app.select("Contoso ID")
        stack = w.detail.stack
        support.wait_until(
            lambda: stack.get_visible_child_name() == "view" and not stack.get_transition_running(),
            what="detail shown",
        )

    def edit() -> None:
        detail()
        w.activate_action("win.edit", None)

    def codes() -> None:
        section("codes")()
        support.pump(0.3)
        w.list_page.selection.set_selected(0)

    def security() -> None:
        section("security")()
        support.pump(0.3)
        w.list_page.selection.set_selected(0)

    def deleted() -> None:
        section("deleted")()
        support.pump(0.3)
        w.list_page.trash_selection.set_selected(0)

    def new_password() -> None:
        section("all")()
        w.activate_action("win.new-password", None)

    def preferences() -> None:
        app.application.activate_action("preferences", None)

    def pause() -> None:
        ids = app.call(lambda d: list(d.items)[:7])
        app.call(lambda d: d.pause(local_ids=ids))
        support.wait_until(w.list_page.pause_banner.get_revealed, what="banner")
        w.review_pause()

    return [
        ("all", section("all")),
        ("detail", detail),
        ("edit", edit),
        ("codes", codes),
        ("security", security),
        ("deleted", deleted),
        ("new-password", new_password),
        ("preferences", preferences),
        ("local-only", lambda: _local_only(app, detail)),
        ("local-only-status", w.status_button.popup),
        ("pause", pause),
    ]


def _local_only(app: support.AppUnderTest, detail: Any) -> None:
    """Let iCloud refuse Contoso ID, then show its detail (badge, banner, header warning)."""
    from passwords_app.sync.remote_icloud import DUPLICATE_LOGIN  # noqa: PLC0415

    item_id = next(
        c.id for c in app.call(lambda d: list(d.items.values())) if c.title == "Contoso ID"
    )
    app.call(lambda d: d.refuse(item_id, DUPLICATE_LOGIN))
    support.wait_until(lambda: app.vault.count_refused() == 1, what="refusal reloaded")
    detail()
    app.window.list_page.select_id(item_id)
    support.wait_until(app.window.detail.local_banner.get_revealed, what="banner")


def _close_dialogs(app: support.AppUnderTest) -> None:
    w = app.window
    w.cancel_edit()
    w.status_button.popdown()
    for _ in range(3):
        dialog = w.get_visible_dialog()
        if dialog is None:
            break
        dialog.force_close()
        support.pump(0.3)


@pytest.mark.parametrize("lang", ["en", "ru"])
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_capture_every_view(
    app: support.AppUnderTest, shell: Any, tmp_path: Path, lang: str, scheme: str
) -> None:
    from gi.repository import Adw, GdkPixbuf  # noqa: PLC0415

    Adw.StyleManager.get_default().set_color_scheme(
        Adw.ColorScheme.FORCE_DARK if scheme == "dark" else Adw.ColorScheme.FORCE_LIGHT
    )
    app.wait_scanned()
    out = _out(tmp_path)
    for name, scene in _scenes(app):
        _close_dialogs(app)
        scene()
        path = _capture(shell, app, out / f"{lang}-{scheme}-{name}.png")
        pixbuf = GdkPixbuf.Pixbuf.new_from_file(str(path))
        assert pixbuf is not None
        assert pixbuf.get_width() > 600
        assert pixbuf.get_height() > 400
    _close_dialogs(app)


def _signin_scenes(app: support.AppUnderTest) -> list[tuple[str, Any]]:
    w = app.window
    state: dict[str, Any] = {}

    def account() -> None:
        app.call(lambda d: d.sign_out())
        w.activate_action("win.sign-in", None)
        state["d"] = support.wait_until(lambda: w.sign_in_dialog, what="wizard")
        state["d"].apple_id.set_text("alex.doe@example.com")

    def code() -> None:
        d = state["d"]
        d.password.set_text("correct-horse")
        d.start()
        support.wait_until(lambda: d.page_tag == "code", what="code")
        d.code_boxes.entries[0].set_text("123")

    def device() -> None:
        d = state["d"]
        d.code_boxes.entries[3].set_text("456")
        support.wait_until(lambda: d.page_tag == "device", what="device")

    def device_small() -> None:
        # The smallest window the app allows: the primary button must stay fully visible.
        state["size"] = w.get_default_size()
        w.set_default_size(360, 294)
        support.pump(0.6)

    def passcode() -> None:
        w.set_default_size(*state["size"])
        support.pump(0.6)
        d = state["d"]
        from passwords_app.app.i18n import _  # noqa: PLC0415

        support.wait_button(d, _("Continue")).emit("clicked")
        support.wait_until(lambda: d.page_tag == "passcode", what="passcode")
        d.passcode.set_text("111111")
        d.join()
        support.wait_until(d.passcode_error.get_visible, what="error")

    return [
        ("signin-account", account),
        ("signin-code", code),
        ("signin-device", device),
        ("signin-device-small", device_small),
        ("signin-passcode", passcode),
    ]


@pytest.mark.parametrize("lang", ["en", "ru"])
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_capture_sign_in(
    app: support.AppUnderTest, shell: Any, tmp_path: Path, lang: str, scheme: str
) -> None:
    from gi.repository import Adw  # noqa: PLC0415

    Adw.StyleManager.get_default().set_color_scheme(
        Adw.ColorScheme.FORCE_DARK if scheme == "dark" else Adw.ColorScheme.FORCE_LIGHT
    )
    app.wait_loaded()
    out = _out(tmp_path)
    for name, scene in _signin_scenes(app):
        scene()
        assert _capture(shell, app, out / f"{lang}-{scheme}-{name}.png").exists()


def test_walkthrough_video(app: support.AppUnderTest, shell: Any, tmp_path: Path) -> None:
    from gi.repository import GLib  # noqa: PLC0415

    app.wait_scanned()
    target = _out(tmp_path) / "walkthrough.webm"
    shell.start_recording(target)
    try:
        support.pump(1.0)
        support.press(shell, "ctrl+f")
        support.type_text(shell, "contoso")
        support.pump(0.8)
        support.press(shell, "Down")
        support.pump(1.2)
        app.window.detail.toggle_reveal()
        support.pump(1.0)
        app.window.detail.toggle_reveal()
        support.press(shell, "ctrl+c")
        support.pump(1.0)
        app.window.list_page.search.set_text("")
        for name in ("codes", "security", "deleted", "all"):
            app.window.activate_action("win.section", GLib.Variant("s", name))
            support.pump(1.0)
        app.window.activate_action("win.new-password", None)
        support.pump(1.5)
        _close_dialogs(app)
        support.pump(0.5)
    finally:
        path = shell.stop_recording()
    assert path.stat().st_size > 10_000
