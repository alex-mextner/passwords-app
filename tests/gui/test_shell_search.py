# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""GNOME Shell search provider, exercised by the real Shell's overview search."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.gui import support

pytestmark = pytest.mark.timeout(120)

PROVIDER = "io.github.alex_mextner.Passwords.desktop"
MAIN = "import('resource:///org/gnome/shell/ui/main.js').then(Main => {%s})"
FIND = (
    "const p = Main.overview._overview._controls._searchController._searchResults"
    f"._providers.find(p => p.id === '{PROVIDER}');"
)


@pytest.fixture
def overview(app: support.AppUnderTest, shell: Any) -> Any:
    from passwords_app.app.dbus_export import claim_app_name, release_app_name  # noqa: PLC0415

    app.wait_loaded()
    assert claim_app_name(app.application.connection)
    shell.eval_js(MAIN % "Main.overview.show(); return true")
    support.pump(0.6)
    yield shell
    shell.eval_js(
        MAIN % "Main.overview._overview._controls._searchEntry.set_text(''); "
        "Main.overview.hide(); return true"
    )
    release_app_name(app.application.connection)
    support.pump(0.6)


def _search(shell: Any, text: str) -> None:
    shell.eval_js(
        MAIN % f"Main.overview._overview._controls._searchEntry.set_text({json.dumps(text)}); "
        "return true"
    )


def _shown_ids(shell: Any) -> list[str]:
    ids: list[str] = json.loads(
        json.loads(
            shell.eval_js(
                MAIN % (FIND + "return JSON.stringify(Object.keys(p.display._resultDisplays))")
            )
        )
    )
    return ids


def test_provider_is_registered_with_the_shell(overview: Any) -> None:
    ids = json.loads(
        json.loads(
            overview.eval_js(
                MAIN % "return JSON.stringify(Main.overview._overview._controls._searchController"
                "._searchResults._providers.map(p => p.id))"
            )
        )
    )
    assert PROVIDER in ids


def test_typing_a_site_lists_matching_logins(app: support.AppUnderTest, overview: Any) -> None:
    from passwords_app.app.dbus_export import search  # noqa: PLC0415

    _search(overview, "northwind")
    expected = search(app.application._search_items(), ["northwind"])
    support.wait_until(lambda: set(_shown_ids(overview)) == set(expected), what="results")
    assert expected


def test_result_metadata_has_no_secrets(app: support.AppUnderTest, overview: Any) -> None:
    _search(overview, "northwind mail")
    support.wait_until(lambda: _shown_ids(overview), what="results")
    item_id = _shown_ids(overview)[0]
    names = json.loads(
        json.loads(
            overview.eval_js(
                MAIN
                % (
                    FIND + f"const d = p.display._resultDisplays['{item_id}'];"
                    "return JSON.stringify([d.metaInfo.name, d.metaInfo.description])"
                )
            )
        )
    )
    item = app.vault.find(item_id).item
    password = app.call(lambda d: d.items[item_id].password)
    assert names[0] == item.display_title
    assert password not in " ".join(names)


def test_activating_a_result_copies_its_password(app: support.AppUnderTest, overview: Any) -> None:
    _search(overview, "northwind mail")
    support.wait_until(lambda: _shown_ids(overview), what="results")
    item_id = _shown_ids(overview)[0]
    # What the overview does on Enter: activate the result, then close.
    overview.eval_js(
        MAIN
        % (
            FIND + f"p.activateResult('{item_id}', ['northwind', 'mail']);"
            "Main.overview.hide(); return true"
        )
    )
    password = app.call(lambda d: d.items[item_id].password)
    support.wait_until(
        lambda: support.clipboard_text(app.window) == password, what="password on clipboard"
    )
    support.wait_until(
        lambda: (
            app.window.list_page.selected_item() is not None
            and app.window.list_page.selected_item().item.id == item_id
        ),
        what="item shown",
    )
    assert app.window.clipboard.pending


def test_activation_sends_a_notification(app: support.AppUnderTest, overview: Any) -> None:
    _search(overview, "contoso id")
    support.wait_until(lambda: _shown_ids(overview), what="results")
    item_id = _shown_ids(overview)[0]
    overview.eval_js(
        MAIN % (FIND + f"p.activateResult('{item_id}', ['contoso', 'id']); return true")
    )

    def titles() -> list[tuple[str, str]]:
        raw = overview.eval_js(
            MAIN % "return JSON.stringify(Main.messageTray.getSources().flatMap("
            "s => s.notifications.map(n => [n.title, n.body])))"
        )
        pairs: list[tuple[str, str]] = json.loads(json.loads(raw))
        return pairs

    found = support.wait_until(
        lambda: [b for t, b in titles() if t == "Password copied" and "Contoso ID" in b],
        what="notification",
    )
    assert "45 seconds" in found[-1]


def test_launch_search_opens_the_app_with_the_terms(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    app.application.launch_search("coho winery")
    support.wait_until(lambda: app.titles() == ["Coho Winery"], what="filtered in app")
    assert app.window.list_page.search.get_text() == "coho winery"


def test_search_provider_start_opens_no_window(shell: Any) -> None:
    """D-Bus activation for a search must not pop a window before the user picks a result."""
    from gi.repository import Gio, GLib  # noqa: PLC0415
    from tests.fakes.fake_daemon import FakeDaemon, FakeDaemonThread  # noqa: PLC0415

    from passwords_app.app.constants import APP_BUS_NAME, APP_ID  # noqa: PLC0415

    bus = Gio.DBusConnection.new_for_address_sync(
        shell.bus_address,
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
        | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )

    def owned() -> bool:
        (has_owner,) = bus.call_sync(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            GLib.Variant("(s)", (APP_BUS_NAME,)),
            GLib.VariantType.new("(b)"),
            Gio.DBusCallFlags.NONE,
            5000,
            None,
        ).unpack()
        return bool(has_owner)

    with FakeDaemonThread(shell.bus_address, FakeDaemon.demo(datetime.now(UTC))):
        proc = shell.spawn(
            [sys.executable, "-m", "passwords_app.app.main", "--search-provider"],
            GSETTINGS_SCHEMA_DIR=os.environ["GSETTINGS_SCHEMA_DIR"],
            PASSWORDS_APP_LOCALEDIR=os.environ["PASSWORDS_APP_LOCALEDIR"],
        )
        try:
            support.wait_until(owned, timeout=20, what="provider on the bus")
            time.sleep(1.5)  # long enough for a window to be mapped if one were shown
            assert proc.poll() is None  # still serving searches
            assert [w for w in shell.windows() if w.app_id == APP_ID] == []
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            bus.close_sync(None)
