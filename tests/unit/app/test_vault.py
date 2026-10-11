# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Vault: the app's live, password-free view of the fake daemon on a private bus."""

from __future__ import annotations

import gc
import os
import shutil
import subprocess
import threading
import time
import warnings
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, ClassVar, override

import pytest
import requests
from tests.fakes.fake_daemon import FakeDaemon, FakeDaemonThread

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import gi.events  # noqa: F401 - imported lazily by Gio's async overrides
    from gi.repository import Gio, GLib

    from passwords_app.app import i18n
    from passwords_app.app.client import DaemonClient, DaemonError
    from passwords_app.app.records import (
        Draft,
        Item,
        Status,
        SyncState,
        TrashEntry,
        TrashReason,
        display_host,
    )
    from passwords_app.app.security import HibpClient, Issue, Report, hibp_split
    from passwords_app.app.sorting import SortOrder, sort_key
    from passwords_app.app.vault import ItemObject, TrashObject, Vault
    from passwords_app.core.strength import assess, reused

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from passwords_app.app.client import Done
    from passwords_app.core.model import Credential

pytestmark = [
    pytest.mark.timeout(60),
    # PyGObject's MainContext.iteration override touches asyncio APIs Python 3.14 deprecates.
    pytest.mark.filterwarnings(r"ignore:'asyncio\.\w+' is deprecated:DeprecationWarning"),
]

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
PW = "example-pw-1"
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


# ---------------------------------------------------------------------- harness


@pytest.fixture(autouse=True)
def _english() -> None:
    i18n.setup(["en"])


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


@pytest.fixture
def connection(bus_address: str) -> Iterator[Gio.DBusConnection]:
    conn = Gio.DBusConnection.new_for_address_sync(
        bus_address,
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
        | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )
    try:
        yield conn
    finally:
        conn.close_sync(None)


@pytest.fixture
def fake(bus_address: str) -> Iterator[FakeDaemonThread]:
    with FakeDaemonThread(bus_address, FakeDaemon.demo(NOW)) as thread:
        yield thread


def wait_until[T](probe: Callable[[], T], *, timeout: float = 15.0, what: str = "condition") -> T:
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


def pump(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    context = GLib.MainContext.default()
    while time.monotonic() < deadline:
        while context.iteration(False):  # noqa: FBT003
            pass
        time.sleep(0.005)


class Events:
    """Records every Vault signal by name (with the `failed` message)."""

    def __init__(self, vault: Vault) -> None:
        self.seen: list[str] = []
        self.failures: list[str] = []
        for name in ("status-changed", "items-changed", "trash-changed", "report-changed"):
            vault.connect(name, partial(self._record, name))
        vault.connect("failed", self._failed)

    def _record(self, name: str, _vault: Vault) -> None:
        self.seen.append(name)

    def _failed(self, _vault: Vault, message: str) -> None:
        self.seen.append("failed")
        self.failures.append(message)

    def count(self, name: str) -> int:
        return self.seen.count(name)


def no_hibp() -> HibpClient:
    msg = "HIBP must not be contacted unless enabled"
    raise AssertionError(msg)


def make_vault(connection: Gio.DBusConnection, hibp: Callable[[], HibpClient] = no_hibp) -> Vault:
    return Vault(DaemonClient(connection), hibp=hibp)


@pytest.fixture
def vault(connection: Gio.DBusConnection, fake: FakeDaemonThread) -> Iterator[Vault]:
    del fake  # only needed running
    v = make_vault(connection)
    v.start()
    wait_until(lambda: v.loaded and v.trash.get_n_items(), what="initial load")
    try:
        yield v
    finally:
        v.stop()


def scanned(vault: Vault, events: Events, before: int) -> None:
    wait_until(lambda: events.count("report-changed") > before, what="security scan")
    assert not vault.scanning


def credentials(fake: FakeDaemonThread) -> list[Credential]:
    return fake.call(lambda d: list(d.items.values()))


def ok[T](start: Callable[[Done[T]], None]) -> T:
    box: list[T | DaemonError] = []
    start(box.append)
    wait_until(lambda: box, what="reply")
    assert not isinstance(box[0], DaemonError), box[0]
    return box[0]


def item_objects(vault: Vault) -> list[ItemObject]:
    objects: list[ItemObject] = []
    for i in range(vault.items.get_n_items()):
        obj = vault.items.get_item(i)
        assert obj is not None
        objects.append(obj)
    return objects


def trash_objects(vault: Vault) -> list[TrashObject]:
    objects: list[TrashObject] = []
    for i in range(vault.trash.get_n_items()):
        obj = vault.trash.get_item(i)
        assert obj is not None
        objects.append(obj)
    return objects


def list_calls(fake: FakeDaemonThread) -> int:
    return fake.call(lambda d: d.calls.count("List"))


# ---------------------------------------------------------------------- model objects


def test_item_object_caches_haystack_and_sort_keys() -> None:
    item = Item(id="a", url="https://www.Exämple.com", title="Café", username="jane")
    obj = ItemObject(item)
    assert "cafe" in obj.hay
    assert "example.com" in obj.hay
    assert obj.issues == frozenset()
    for order in SortOrder:
        assert obj.key(order) == sort_key(item, order)
        assert obj.key(order) is obj.key(order)


def test_trash_object_searches_its_item() -> None:
    entry = TrashEntry(
        "t", TrashReason.CONFLICT, NOW, NOW, Item(id="a", url="https://shop.example")
    )
    assert "shop.example" in TrashObject(entry).hay


# ---------------------------------------------------------------------- loading


def test_initial_load_fills_the_stores(vault: Vault, fake: FakeDaemonThread) -> None:
    creds = credentials(fake)
    assert vault.items.get_n_items() == len(creds) == 60
    listed = {o.item.id for o in item_objects(vault)}
    assert listed == {c.id for c in creds}
    trash = [o.entry for o in trash_objects(vault)]
    assert len(trash) == 5
    assert [e.deleted_at for e in trash] == sorted((e.deleted_at for e in trash), reverse=True)
    wait_until(lambda: vault.status.state is SyncState.IDLE, what="status")
    assert vault.status.item_count == 60
    assert vault.groups() == ["Family"]
    assert vault.count_codes() == 8
    assert vault.count_group("Family") == 6
    assert vault.count_group("Nobody") == 0


def test_store_items_changed_sees_the_vault_loaded(
    connection: Gio.DBusConnection, fake: FakeDaemonThread
) -> None:
    # The list page re-evaluates its spinner from the store's items-changed; a vault still
    # reporting "not loaded" at that moment leaves the list on the spinner for good.
    del fake  # only needed running
    v = make_vault(connection)
    loaded_at_change: list[bool] = []
    v.items.connect("items-changed", lambda *_a: loaded_at_change.append(v.loaded))
    v.start()
    try:
        wait_until(lambda: bool(loaded_at_change), what="first items-changed")
        assert loaded_at_change[0] is True
    finally:
        v.stop()


def test_lookups(vault: Vault) -> None:
    first = vault.items.get_item(3)
    assert first is not None
    assert vault.find(first.item.id) is first
    assert vault.position_of(first.item.id) == 3
    assert vault.find("missing") is None
    assert vault.position_of("missing") is None


def test_refused_passwords_are_counted(vault: Vault, fake: FakeDaemonThread) -> None:
    target = vault.items.get_item(3)
    assert target is not None
    assert vault.count_refused() == 0
    fake.call(lambda d: d.refuse(target.item.id, "refused by iCloud"))
    wait_until(lambda: vault.count_refused() == 1, what="reload after ItemsChanged")
    refused = vault.find(target.item.id)
    assert refused is not None
    assert refused.item.sync_problem == "refused by iCloud"
    fake.call(lambda d: d.accept(target.item.id))
    wait_until(lambda: vault.count_refused() == 0, what="reload after acceptance")


def test_items_changed_burst_coalesces_into_one_list_call(
    vault: Vault, fake: FakeDaemonThread
) -> None:
    events = Events(vault)
    before = list_calls(fake)
    fake.call(lambda d: [d.add_item(f"https://burst{n}.example.com", "jane", PW) for n in range(5)])
    wait_until(lambda: vault.items.get_n_items() == 65, what="reload")
    pump(0.3)
    assert list_calls(fake) == before + 1
    assert events.count("items-changed") == 1
    assert events.count("trash-changed") == 1


def test_reload_names_the_items_the_daemon_announced(vault: Vault, fake: FakeDaemonThread) -> None:
    # A password edit in the second of the previous change leaves the listing as it was;
    # only the daemon's ItemsChanged tells the detail pane to fetch it again (#111).
    target = vault.items.get_item(3)
    assert target is not None
    events = Events(vault)

    def edit_password(d: FakeDaemon) -> None:
        d.items[target.item.id] = replace(d.items[target.item.id], password="example-pw-2")
        d._items_changed([target.item.id])

    fake.call(edit_password)
    wait_until(lambda: events.count("items-changed") == 1, what="reload")
    assert vault.changed_ids == {target.item.id}
    assert vault.find(target.item.id) is target  # the listing itself did not change


def test_unchanged_items_keep_their_objects(vault: Vault, fake: FakeDaemonThread) -> None:
    events = Events(vault)
    scanned(vault, events, 0)
    objects = {o.item.id: o for o in item_objects(vault)}
    victim = next(o for o in objects.values() if o.issues)
    issues = victim.issues
    full = ok(partial(vault.client.get, victim.item.id))
    ok(partial(vault.client.save, replace(Draft.from_item(full), title="Renamed")))
    wait_until(lambda: vault.find(victim.item.id) is not victim, what="reload")
    renamed = vault.find(victim.item.id)
    assert renamed is not None
    assert renamed.item.title == "Renamed"
    assert renamed.issues == issues  # verdicts survive until the next scan replaces them
    for item_id, obj in objects.items():
        if item_id != victim.item.id:
            assert vault.find(item_id) is obj


def test_deleted_item_moves_to_trash(vault: Vault) -> None:
    obj = vault.items.get_item(0)
    assert obj is not None
    ok(partial(vault.client.delete, obj.item.id))
    wait_until(lambda: vault.find(obj.item.id) is None, what="reload")
    wait_until(lambda: vault.trash.get_n_items() == 6, what="trash reload")
    newest = vault.trash.get_item(0)
    assert newest is not None
    assert newest.entry.item.id == obj.item.id


def test_trash_purged_by_retention_leaves_the_deleted_view(
    vault: Vault, fake: FakeDaemonThread
) -> None:
    # Retention purges announce nothing but the status's lower trash_count (#69).
    events = Events(vault)
    before = list_calls(fake)
    oldest = trash_objects(vault)[-1].entry.trash_id
    fake.call(lambda d: d.expire_trash(oldest))
    wait_until(lambda: vault.status.trash_count == 4, what="StatusChanged")
    wait_until(lambda: vault.trash.get_n_items() == 4, what="trash reload")
    assert oldest not in {o.entry.trash_id for o in trash_objects(vault)}
    pump(0.3)
    assert events.count("trash-changed") == 1
    assert list_calls(fake) == before  # the live items did not change


def test_deleting_reloads_the_trash_once(vault: Vault, fake: FakeDaemonThread) -> None:
    # ItemsChanged and the higher trash_count arrive together; one trash reload covers both.
    events = Events(vault)
    obj = vault.items.get_item(0)
    assert obj is not None
    ok(partial(vault.client.delete, obj.item.id))
    wait_until(lambda: vault.trash.get_n_items() == 6, what="trash reload")
    pump(0.3)
    assert events.count("trash-changed") == 1
    assert fake.call(lambda d: d.calls.count("ListTrash")) == 2  # start-up and this one


def test_list_failure_emits_failed(vault: Vault, fake: FakeDaemonThread) -> None:
    events = Events(vault)
    fake.call(lambda d: d.fail_next("List", "Unavailable", "iCloud is busy"))
    vault.reload()
    wait_until(lambda: events.failures, what="failed")
    assert events.failures == ["iCloud is busy"]
    assert vault.items.get_n_items() == 60


# ---------------------------------------------------------------------- status


def test_status_signal_updates_status(vault: Vault, fake: FakeDaemonThread) -> None:
    events = Events(vault)
    fake.call(lambda d: d.go_offline("No connection to iCloud"))
    wait_until(lambda: vault.status.state is SyncState.OFFLINE, what="StatusChanged")
    assert vault.status.message == "No connection to iCloud"
    assert events.count("status-changed") >= 1


def test_daemon_vanish_and_return(vault: Vault, fake: FakeDaemonThread, bus_address: str) -> None:
    fake.__exit__(None, None, None)
    wait_until(lambda: vault.status.state is SyncState.UNREACHABLE, what="vanished")
    daemon = FakeDaemon.demo(NOW)
    daemon.add_item("https://returned.example.com", "jane", PW)
    with FakeDaemonThread(bus_address, daemon):
        wait_until(lambda: vault.status.state is SyncState.IDLE, what="status after return")
        wait_until(lambda: vault.items.get_n_items() == 61, what="reload after return")


def test_no_daemon_at_start_is_unreachable(connection: Gio.DBusConnection) -> None:
    v = make_vault(connection)
    events = Events(v)
    v.start()
    try:
        wait_until(lambda: v.status.state is SyncState.UNREACHABLE, what="status")
        pump(0.2)
        assert events.failures == []  # unreachable is a status, not an error toast
        assert not v.loaded
    finally:
        v.stop()


def test_stop_cancels_pending_work(vault: Vault, fake: FakeDaemonThread) -> None:
    events = Events(vault)
    vault.schedule_reload()
    vault.schedule_scan()
    vault.stop()
    fake.call(lambda d: d.go_offline())
    pump(0.6)
    assert events.seen == []


# ---------------------------------------------------------------------- security scan


def _expected(creds: list[Credential]) -> tuple[set[str], set[str]]:
    weak = {
        c.id
        for c in creds
        if assess(c.password, user_inputs=[u for u in (c.username, display_host(c.url)) if u]).weak
    }
    shared = {item_id for ids in reused(creds).values() for item_id in ids}
    return weak, shared


def test_report_matches_core_strength(vault: Vault, fake: FakeDaemonThread) -> None:
    events = Events(vault)
    scanned(vault, events, 0)
    weak, shared = _expected(credentials(fake))
    assert weak  # the demo vault has weak and reused passwords
    assert len(shared) == 5
    report = vault.report
    assert {i for i in report.flagged if Issue.WEAK in report.of(i)} == weak
    assert {i for i in report.flagged if Issue.REUSED in report.of(i)} == shared
    assert report.count(Issue.COMPROMISED) == 0
    for item_id in shared:
        assert len(report.reused_with[item_id]) in {1, 2}
        obj = vault.find(item_id)
        assert obj is not None
        assert Issue.REUSED in obj.issues
    assert events.failures == []


def test_scan_keeps_no_passwords(vault: Vault, fake: FakeDaemonThread) -> None:
    # Other tests in the same worker may still hold their own Items; only new ones count.
    before = {id(o) for o in gc.get_objects() if isinstance(o, Item)}
    events = Events(vault)
    scanned(vault, events, 0)
    pump(0.1)
    gc.collect()
    passwords = {c.password for c in credentials(fake)}
    held = [
        o
        for o in gc.get_objects()
        if isinstance(o, Item) and id(o) not in before and o.password is not None
    ]
    assert held == []
    for obj in item_objects(vault):
        assert obj.item.password is None
        assert not any(p in obj.hay for p in passwords if len(p) > 3)


def test_stale_scan_is_discarded(vault: Vault) -> None:
    events = Events(vault)
    scanned(vault, events, 0)
    vault.scan()
    vault.scan()  # supersedes the first before any of its fetches return
    scanned(vault, events, 1)
    pump(0.6)
    assert events.count("report-changed") == 2
    current = vault.report
    stale = Report(issues={"x": frozenset({Issue.WEAK})})
    vault._publish(0, stale, hibp_failed=True)
    assert vault.report is current
    assert events.failures == []


def test_scan_survives_failed_gets(vault: Vault, fake: FakeDaemonThread) -> None:
    events = Events(vault)
    scanned(vault, events, 0)
    fake.call(lambda d: d.fail_next("Get", "NotFound", "gone"))
    vault.scan()
    scanned(vault, events, 1)
    assert len(vault.report.issues) == 59  # the failed fetch is simply not scored


def test_hibp_failure_emits_failed(connection: Gio.DBusConnection, fake: FakeDaemonThread) -> None:
    del fake

    def unreachable() -> HibpClient:
        session = requests.Session()
        session.trust_env = False  # never route through a developer's proxy
        return HibpClient(base_url="http://127.0.0.1:1/range/", session=session)

    v = make_vault(connection, unreachable)
    v.hibp_enabled = True
    events = Events(v)
    v.start()
    try:
        scanned(v, events, 0)
        assert events.failures == ["Could not check passwords against known data leaks"]
        assert v.report.count(Issue.WEAK) > 0  # local checks still published
    finally:
        v.stop()


class _Range(BaseHTTPRequestHandler):
    bodies: ClassVar[dict[str, str]] = {}

    def do_GET(self) -> None:
        payload = self.bodies.get(self.path.rsplit("/", 1)[-1], "").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    @override
    def log_message(self, format: str, *args: object) -> None:
        del format, args


def test_hibp_marks_compromised(connection: Gio.DBusConnection, fake: FakeDaemonThread) -> None:
    target = credentials(fake)[0]
    prefix, suffix = hibp_split(target.password)
    handler = type("Handler", (_Range,), {"bodies": {prefix: f"{suffix}:12"}})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    def local() -> HibpClient:
        session = requests.Session()
        session.trust_env = False
        return HibpClient(base_url=f"http://127.0.0.1:{port}/range/", session=session)

    v = make_vault(connection, local)
    v.hibp_enabled = True
    events = Events(v)
    v.start()
    try:
        scanned(v, events, 0)
        assert v.report.count(Issue.COMPROMISED) == 1
        assert Issue.COMPROMISED in v.report.of(target.id)
        assert events.failures == []
    finally:
        v.stop()
        server.shutdown()
        server.server_close()
        thread.join()


def test_status_object_defaults_to_syncing_before_start(connection: Gio.DBusConnection) -> None:
    v = make_vault(connection)
    assert v.status == Status(state=SyncState.SYNCING)
    assert not v.loaded
    assert v.items.get_n_items() == 0
