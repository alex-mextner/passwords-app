# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The app's own bus exports: single-instance handover and the Shell search provider.

Exports live on one private-bus connection and are called from a second one, exactly as the
Shell or a second app launch would.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
import warnings
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import pytest

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import gi.events  # noqa: F401 - imported lazily by Gio's async overrides
    from gi.repository import Gio, GLib

    from passwords_app.app.constants import APP_BUS_NAME, APP_OBJECT_PATH, SEARCH_PROVIDER_PATH
    from passwords_app.app.dbus_export import (
        MAX_RESULTS,
        AppExports,
        claim_app_name,
        forward_to_primary,
        release_app_name,
        result_meta,
        search,
    )
    from passwords_app.app.records import Item
    from passwords_app.app.search import haystack

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence
    from pathlib import Path

pytestmark = [
    pytest.mark.timeout(60),
    # PyGObject's MainContext.iteration override touches asyncio APIs Python 3.14 deprecates.
    pytest.mark.filterwarnings(r"ignore:'asyncio\.\w+' is deprecated:DeprecationWarning"),
]

PW = "example-pw-1"
SEARCH_IFACE = "org.gnome.Shell.SearchProvider2"
_BUS_CONFIG = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={socket}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"""


def _item(item_id: str, title: str, url: str, username: str = "") -> Item:
    return Item(id=item_id, url=url, title=title, username=username, password=PW)


ITEMS = [
    _item("mail", "Northwind Mail", "https://mail.northwind.example", "jane@example.com"),
    _item("cal", "Northwind Calendar", "https://calendar.northwind.example", "jane"),
    _item("bank", "Example Bank", "https://bank.example.org", "jdoe"),
    _item("shop", "Shop", "https://shop.example.com", "jane@example.com"),
    _item("cafe", "Café Lumière", "https://cafe-lumiere.example"),
    _item("bare", "", "https://www.bare.example", "jane"),
]
BY_ID = {i.id: i for i in ITEMS}


def pairs(items: Sequence[Item] = ITEMS) -> list[tuple[Item, str]]:
    return [(i, haystack(i)) for i in items]


# ---------------------------------------------------------------------- search


@pytest.mark.parametrize(
    ("terms", "ids"),
    [
        ([], []),
        (["", "  "], []),
        (["northwind"], ["cal", "mail"]),
        (["NORTHWIND", "mail"], ["mail"]),
        (["mail", "northwind"], ["mail"]),
        (["jane"], ["bare", "cal", "mail", "shop"]),
        (["cafe"], ["cafe"]),
        (["lumiere"], ["cafe"]),
        (["bank", "jane"], []),
        (["zzz"], []),
    ],
)
def test_search(terms: list[str], ids: list[str]) -> None:
    assert search(pairs(), terms) == ids


def test_title_prefix_matches_rank_first() -> None:
    # Example Bank's title starts with the term; the others only mention it in a URL or name.
    assert search(pairs(), ["example"])[0] == "bank"
    assert search(pairs(), ["sho"]) == ["shop"]
    ranked = search(pairs(), ["n"])
    assert ranked[:2] == ["cal", "mail"]  # titles starting with "n", alphabetical


def test_search_is_limited() -> None:
    many = [_item(f"id{n:02d}", f"Site {n:02d}", f"https://s{n}.example") for n in range(20)]
    found = search(pairs(many), ["site"])
    assert len(found) == MAX_RESULTS
    assert found == [f"id{n:02d}" for n in range(MAX_RESULTS)]


# ---------------------------------------------------------------------- result metas


def test_result_meta_never_contains_the_password() -> None:
    meta = result_meta(ITEMS[0])
    assert set(meta) == {"id", "name", "description", "gicon"}
    values = {k: v.get_string() for k, v in meta.items()}
    assert values["id"] == "mail"
    assert values["name"] == "Northwind Mail"
    assert values["description"] == "jane@example.com · mail.northwind.example"
    assert Gio.Icon.new_for_string(values["gicon"]) is not None
    assert all(PW not in v for v in values.values())


@pytest.mark.parametrize(
    ("item", "name", "description"),
    [
        (_item("a", "", "https://www.bare.example"), "bare.example", "bare.example"),
        (_item("b", "Router", "", "admin"), "Router", "admin"),
        (_item("c", "Note", ""), "Note", ""),
    ],
)
def test_result_meta_fallbacks(item: Item, name: str, description: str) -> None:
    meta = result_meta(item)
    assert meta["name"].get_string() == name
    assert meta["description"].get_string() == description


# ---------------------------------------------------------------------- bus harness


@pytest.fixture
def bus_address(tmp_path: Path) -> Iterator[str]:
    """A bare private dbus-daemon; no keyring, no access to the user's session."""
    binary = shutil.which("dbus-daemon")
    if binary is None:
        pytest.skip("dbus-daemon is not installed")
    socket = tmp_path / "bus"
    config = tmp_path / "bus.conf"
    config.write_text(_BUS_CONFIG.format(socket=socket))
    proc = subprocess.Popen(  # noqa: S603 - fixed argv built from a trusted binary
        [binary, f"--config-file={config}", "--nofork", "--print-address"],
        stdout=subprocess.PIPE,
        env={"PATH": os.environ.get("PATH", "")},
    )
    assert proc.stdout is not None
    address = proc.stdout.readline().decode().strip()
    try:
        yield address
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        proc.stdout.close()


def _connect(address: str) -> Gio.DBusConnection:
    return Gio.DBusConnection.new_for_address_sync(
        address,
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
        | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )


@pytest.fixture
def connections(bus_address: str) -> Iterator[tuple[Gio.DBusConnection, Gio.DBusConnection]]:
    primary, other = _connect(bus_address), _connect(bus_address)
    try:
        yield primary, other
    finally:
        primary.close_sync(None)
        other.close_sync(None)


def wait_until[T](probe: Callable[[], T], *, timeout: float = 10.0, what: str = "reply") -> T:
    """Run the default main context until `probe()` is truthy."""
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
        time.sleep(0.005)


@dataclass
class Recorder:
    activations: int = 0
    actions: list[str] = field(default_factory=list)
    results: list[str] = field(default_factory=list)
    launches: list[str] = field(default_factory=list)

    def activate(self) -> None:
        self.activations += 1


@pytest.fixture
def exported(
    connections: tuple[Gio.DBusConnection, Gio.DBusConnection],
) -> Iterator[tuple[Recorder, Gio.DBusConnection, AppExports]]:
    primary, other = connections
    recorder = Recorder()
    exports = AppExports(
        primary,
        items=pairs,
        lookup=BY_ID.get,
        on_activate=recorder.activate,
        on_action=recorder.actions.append,
        on_result=recorder.results.append,
        on_launch_search=recorder.launches.append,
    )
    assert claim_app_name(primary)
    try:
        yield recorder, other, exports
    finally:
        exports.close()


def call(
    conn: Gio.DBusConnection,
    target: tuple[str, str],
    method: str,
    params: GLib.Variant | None,
    reply_type: str | None = None,
) -> tuple[object, ...]:
    """Asynchronous call pumped from this thread (the exports answer on this main context)."""
    box: list[tuple[object, ...] | GLib.Error] = []

    def finished(c: Gio.DBusConnection, result: Gio.AsyncResult) -> None:
        try:
            reply = c.call_finish(result)
        except GLib.Error as err:
            box.append(err)
            return
        box.append(cast("tuple[object, ...]", reply.unpack()) if reply else ())

    path, iface = target
    conn.call(
        APP_BUS_NAME,
        path,
        iface,
        method,
        params,
        GLib.VariantType.new(reply_type) if reply_type else None,
        Gio.DBusCallFlags.NONE,
        5000,
        None,
        finished,
    )
    wait_until(lambda: box)
    value = box[0]
    if isinstance(value, GLib.Error):
        raise value
    return value


def shell(conn: Gio.DBusConnection, method: str, params: GLib.Variant, reply: str | None) -> object:
    out = call(conn, (SEARCH_PROVIDER_PATH, SEARCH_IFACE), method, params, reply)
    return out[0] if out else None


# ---------------------------------------------------------------------- search provider


def test_initial_result_set(exported: tuple[Recorder, Gio.DBusConnection, AppExports]) -> None:
    _rec, other, _exports = exported
    found = shell(other, "GetInitialResultSet", GLib.Variant("(as)", (["northwind"],)), "(as)")
    assert found == ["cal", "mail"]
    none = shell(other, "GetInitialResultSet", GLib.Variant("(as)", ([],)), "(as)")
    assert none == []


def test_subsearch_only_narrows_previous_results(
    exported: tuple[Recorder, Gio.DBusConnection, AppExports],
) -> None:
    _rec, other, _exports = exported
    params = GLib.Variant("(asas)", (["mail", "shop"], ["jane"]))
    assert shell(other, "GetSubsearchResultSet", params, "(as)") == ["mail", "shop"]
    params = GLib.Variant("(asas)", (["cal"], ["northwind", "mail"]))
    assert shell(other, "GetSubsearchResultSet", params, "(as)") == []


def test_result_metas_over_the_bus(
    exported: tuple[Recorder, Gio.DBusConnection, AppExports],
) -> None:
    _rec, other, _exports = exported
    params = GLib.Variant("(as)", (["shop", "unknown", "mail"],))
    metas = cast("list[dict[str, str]]", shell(other, "GetResultMetas", params, "(aa{sv})"))
    assert [m["id"] for m in metas] == ["shop", "mail"]
    assert metas[1]["name"] == "Northwind Mail"
    assert all(PW not in str(value) for meta in metas for value in meta.values())


def test_activate_result_and_launch_search(
    exported: tuple[Recorder, Gio.DBusConnection, AppExports],
) -> None:
    recorder, other, _exports = exported
    shell(other, "ActivateResult", GLib.Variant("(sasu)", ("bank", ["bank"], 42)), None)
    assert recorder.results == ["bank"]
    shell(other, "LaunchSearch", GLib.Variant("(asu)", (["north", "wind"], 42)), None)
    assert recorder.launches == ["north wind"]


def test_application_interface(
    exported: tuple[Recorder, Gio.DBusConnection, AppExports],
) -> None:
    recorder, other, _exports = exported
    iface = "org.freedesktop.Application"
    call(other, (APP_OBJECT_PATH, iface), "Activate", GLib.Variant("(a{sv})", ({},)))
    call(other, (APP_OBJECT_PATH, iface), "Open", GLib.Variant("(asa{sv})", ([], {})))
    params = GLib.Variant("(sava{sv})", ("new-password", [], {}))
    call(other, (APP_OBJECT_PATH, iface), "ActivateAction", params)
    assert recorder.activations == 2
    assert recorder.actions == ["new-password"]


def test_close_unregisters(exported: tuple[Recorder, Gio.DBusConnection, AppExports]) -> None:
    _rec, other, exports = exported
    exports.close()
    with pytest.raises(GLib.Error, match=r"UnknownMethod|UnknownObject|No such"):
        shell(other, "GetInitialResultSet", GLib.Variant("(as)", (["x"],)), "(as)")


# ---------------------------------------------------------------------- single instance


def test_claim_app_name_is_exclusive(
    connections: tuple[Gio.DBusConnection, Gio.DBusConnection],
) -> None:
    primary, other = connections
    assert claim_app_name(primary) is True
    assert claim_app_name(primary) is True  # already the owner
    assert claim_app_name(other) is False
    release_app_name(primary)
    assert claim_app_name(other) is True


def _forward(conn: Gio.DBusConnection, action: str | None) -> list[BaseException]:
    """Run the blocking handover in a thread while this thread serves the primary."""
    errors: list[BaseException] = []

    def run() -> None:
        try:
            forward_to_primary(conn, action)
        except BaseException as exc:  # noqa: BLE001 - reported to the test thread
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    wait_until(lambda: not thread.is_alive(), what="handover")
    thread.join()
    return errors


@pytest.mark.parametrize(
    ("action", "activations", "actions"), [(None, 1, []), ("new-password", 0, ["new-password"])]
)
def test_forward_to_primary(
    exported: tuple[Recorder, Gio.DBusConnection, AppExports],
    action: str | None,
    activations: int,
    actions: list[str],
) -> None:
    recorder, other, _exports = exported
    assert _forward(other, action) == []
    assert recorder.activations == activations
    assert recorder.actions == actions


def test_forward_without_primary_raises(
    connections: tuple[Gio.DBusConnection, Gio.DBusConnection],
) -> None:
    _primary, other = connections
    [error] = _forward(other, None)
    assert isinstance(error, GLib.Error)
