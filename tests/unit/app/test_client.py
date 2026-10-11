# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""DaemonClient against the fake daemon on a private bare dbus-daemon.

Every test owns its own bus; the client connection is made by address, so nothing here can
reach the developer's session bus or keyring.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import warnings
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlencode

import pytest
from tests.fakes.fake_daemon import FakeDaemon, FakeDaemonThread

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import gi.events  # noqa: F401 - imported lazily by Gio's async overrides
    from gi.repository import Gio, GLib

    from passwords_app.app import client as client_module
    from passwords_app.app.client import DaemonClient, DaemonError, ErrorKind, error_from_glib
    from passwords_app.app.constants import (
        DAEMON_ERROR_PREFIX,
        DAEMON_INTERFACE,
        DAEMON_OBJECT_PATH,
    )
    from passwords_app.app.records import (
        Draft,
        Item,
        RecoveryDevice,
        SignInStep,
        Status,
        StepKind,
        SyncState,
        TrashEntry,
        TrashReason,
    )

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from passwords_app.app.client import Done

pytestmark = [
    pytest.mark.timeout(60),
    # PyGObject's MainContext.iteration override touches asyncio APIs Python 3.14 deprecates.
    pytest.mark.filterwarnings(r"ignore:'asyncio\.\w+' is deprecated:DeprecationWarning"),
]

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
PW = "example-pw-1"
KEY_B32 = "JBSWY3DPEHPK3PXP"
CODE_URI = "otpauth://totp/Example:jane@example.com?" + urlencode({"secret": KEY_B32})
OTHER_NAME = "io.github.alex_mextner.PasswordsTest.Broken"
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
def connection(bus_address: str) -> Iterator[Gio.DBusConnection]:
    conn = _connect(bus_address)
    try:
        yield conn
    finally:
        conn.close_sync(None)


@pytest.fixture
def fake(bus_address: str) -> Iterator[FakeDaemonThread]:
    with FakeDaemonThread(bus_address, FakeDaemon.demo(NOW)) as thread:
        yield thread


@pytest.fixture
def client(connection: Gio.DBusConnection, fake: FakeDaemonThread) -> Iterator[DaemonClient]:
    del fake  # only needed running
    daemon_client = DaemonClient(connection)
    try:
        yield daemon_client
    finally:
        daemon_client.close()


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


def pump(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    context = GLib.MainContext.default()
    while time.monotonic() < deadline:
        while context.iteration(False):  # noqa: FBT003
            pass
        time.sleep(0.005)


def run[T](start: Callable[[Done[T]], None]) -> T | DaemonError:
    box: list[T | DaemonError] = []
    start(box.append)
    wait_until(lambda: box)
    return box[0]


def ok[T](start: Callable[[Done[T]], None]) -> T:
    result = run(start)
    assert not isinstance(result, DaemonError), result
    return result


def fails[T](start: Callable[[Done[T]], None]) -> DaemonError:
    result = run(start)
    assert isinstance(result, DaemonError), result
    return result


def resolving(client: DaemonClient, *, apply: bool) -> Callable[[Done[None]], None]:
    def start(done: Done[None]) -> None:
        client.resolve_pause(apply=apply, done=done)

    return start


def demo_items(fake: FakeDaemonThread) -> dict[str, object]:
    return fake.call(lambda d: dict(d.items))


# ---------------------------------------------------------------------- error_from_glib


@pytest.mark.parametrize("kind", [k for k in ErrorKind if k not in {"Unreachable", "Other"}])
def test_error_from_glib_maps_daemon_errors(kind: ErrorKind) -> None:
    err = Gio.DBusError.new_for_dbus_error(DAEMON_ERROR_PREFIX + kind.value, "Nope: details")
    mapped = error_from_glib(err)
    assert mapped.kind is kind
    assert mapped.message == "Nope: details"
    assert str(mapped) == "Nope: details"


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        (DAEMON_ERROR_PREFIX + "SomethingNew", ErrorKind.OTHER),
        ("org.freedesktop.DBus.Error.ServiceUnknown", ErrorKind.UNREACHABLE),
        ("org.freedesktop.DBus.Error.NameHasNoOwner", ErrorKind.UNREACHABLE),
        ("org.freedesktop.DBus.Error.NoReply", ErrorKind.UNREACHABLE),
        ("org.freedesktop.DBus.Error.Spawn.ChildExited", ErrorKind.UNREACHABLE),
        ("org.freedesktop.DBus.Error.Spawn.ServiceNotFound", ErrorKind.UNREACHABLE),
        ("org.freedesktop.DBus.Error.Failed", ErrorKind.OTHER),
    ],
)
def test_error_from_glib_other_names(name: str, kind: ErrorKind) -> None:
    mapped = error_from_glib(Gio.DBusError.new_for_dbus_error(name, "text"))
    assert mapped.kind is kind
    assert mapped.message == "text"


def test_error_from_glib_closed_connection_is_unreachable() -> None:
    err: GLib.Error = GLib.Error.new_literal(
        Gio.io_error_quark(), "closed", int(Gio.IOErrorEnum.CLOSED)
    )
    assert error_from_glib(err).kind is ErrorKind.UNREACHABLE


def test_error_from_glib_plain_glib_error_is_other() -> None:
    err: GLib.Error = GLib.Error.new_literal(
        Gio.io_error_quark(), "boom", int(Gio.IOErrorEnum.FAILED)
    )
    mapped = error_from_glib(err)
    assert (mapped.kind, mapped.message) == (ErrorKind.OTHER, "boom")


# ---------------------------------------------------------------------- save_payload


def test_save_payload_types_every_key() -> None:
    payload = client_module.save_payload(
        Draft(
            url=" https://example.com ",
            username="jane",
            password=PW,
            title="Example",
            otpauth=CODE_URI,
            alt_urls=("https://example.org", " "),
            group="Family",
            id="item-1",
        )
    )
    assert payload.get_type_string() == "(a{sv})"
    fields = payload.get_child_value(0)
    types = {
        fields.get_child_value(i).get_child_value(0).get_string(): fields.get_child_value(i)
        .get_child_value(1)
        .get_variant()
        .get_type_string()
        for i in range(fields.n_children())
    }
    assert types == {
        "id": "s",
        "url": "s",
        "username": "s",
        "password": "s",
        "title": "s",
        "notes": "s",
        "otpauth": "s",
        "alt_urls": "as",
        "group": "s",
    }
    (unpacked,) = cast("tuple[dict[str, object]]", payload.unpack())
    assert unpacked["url"] == "https://example.com"
    assert unpacked["alt_urls"] == ["https://example.org"]


@pytest.mark.parametrize(
    ("value", "signature"), [(True, "b"), ("x", "s"), (["a", "b"], "as"), ((), "as")]
)
def test_wire_value_types(value: object, signature: str) -> None:
    assert client_module._wire_value(value).get_type_string() == signature


@pytest.mark.parametrize("value", [1, 1.5, None, {"a": "b"}])
def test_wire_value_rejects_unsupported_types(value: object) -> None:
    with pytest.raises(TypeError, match="unsupported Save value type"):
        client_module._wire_value(value)


# ---------------------------------------------------------------------- reads


def test_get_status(client: DaemonClient) -> None:
    status = ok(client.get_status)
    assert status.state is SyncState.IDLE
    assert status.apple_id == "alex.doe@example.com"
    assert status.item_count == 60
    assert status.trash_count == 5
    assert status.last_sync is not None
    assert status.last_sync == NOW - timedelta(minutes=2)


def test_list_items_has_no_secrets(client: DaemonClient, fake: FakeDaemonThread) -> None:
    items = ok(client.list_items)
    assert {i.id for i in items} == set(demo_items(fake))
    assert all(isinstance(i, Item) for i in items)
    assert all(i.password is None and i.otpauth is None for i in items)
    assert sum(i.has_code for i in items) == 8
    assert sum(i.group == "Family" for i in items) == 6
    mail = next(i for i in items if i.title == "Northwind Mail")
    assert mail.alt_urls == ("https://northwind.example",)
    assert mail.created < mail.modified or mail.created == mail.modified


def test_get_returns_secrets(client: DaemonClient) -> None:
    listed = ok(client.list_items)
    with_code = next(i for i in listed if i.has_code)
    item = ok(partial(client.get, with_code.id))
    assert item.id == with_code.id
    assert item.password
    assert item.otpauth is not None
    assert item.otpauth.startswith("otpauth://totp/")
    assert item.has_code


def test_list_trash(client: DaemonClient) -> None:
    trash = ok(client.list_trash)
    assert len(trash) == 5
    assert all(isinstance(e, TrashEntry) for e in trash)
    assert {e.reason for e in trash} == {
        TrashReason.DELETED_ON_LINUX,
        TrashReason.DELETED_IN_ICLOUD,
        TrashReason.CONFLICT,
        TrashReason.DELETED_BOTH,
    }
    for entry in trash:
        assert (entry.expires_at - entry.deleted_at).days == 90


def test_get_code(client: DaemonClient) -> None:
    item = next(i for i in ok(client.list_items) if i.has_code)
    code, left = ok(partial(client.get_code, item.id))
    assert len(code) == 6
    assert code.isdigit()
    assert 1 <= left <= 30


def test_get_code_without_code_is_not_found(client: DaemonClient) -> None:
    item = next(i for i in ok(client.list_items) if not i.has_code)
    assert fails(partial(client.get_code, item.id)).kind is ErrorKind.NOT_FOUND


def test_get_unknown_item_is_not_found_with_clean_message(client: DaemonClient) -> None:
    err = fails(partial(client.get, "missing"))
    assert err.kind is ErrorKind.NOT_FOUND
    assert err.message == "no item 'missing'"


# ---------------------------------------------------------------------- writes


def test_save_new_item_round_trips(client: DaemonClient) -> None:
    draft = Draft(
        url="https://new.example.com",
        username="jane@example.com",
        password=PW,
        title="New Example",
        notes="note",
        otpauth=CODE_URI,
        alt_urls=("https://alt.example.com",),
        group="Family",
    )
    new_id = ok(partial(client.save, draft))
    assert new_id
    item = ok(partial(client.get, new_id))
    assert (item.url, item.username, item.password, item.title, item.notes) == (
        "https://new.example.com",
        "jane@example.com",
        PW,
        "New Example",
        "note",
    )
    assert item.otpauth == CODE_URI
    assert item.alt_urls == ("https://alt.example.com",)
    assert item.group == "Family"


def test_save_update_clears_fields(client: DaemonClient) -> None:
    listed = next(i for i in ok(client.list_items) if i.notes)
    full = ok(partial(client.get, listed.id))
    draft = Draft.from_item(full)
    saved = ok(partial(client.save, replace(draft, notes="")))
    assert saved == listed.id
    assert ok(partial(client.get, listed.id)).notes == ""


def test_save_invalid_is_invalid(client: DaemonClient) -> None:
    err = fails(partial(client.save, Draft(url="")))
    assert err.kind is ErrorKind.INVALID
    assert err.message == "url must not be empty"


def test_delete_restore_purge(client: DaemonClient) -> None:
    item = ok(client.list_items)[0]
    assert ok(partial(client.delete, item.id)) is None
    assert item.id not in {i.id for i in ok(client.list_items)}
    entry = next(e for e in ok(client.list_trash) if e.item.id == item.id)
    assert entry.reason is TrashReason.DELETED_ON_LINUX
    restored = ok(partial(client.restore, entry.trash_id))
    assert restored != item.id  # a fresh id, as SyncEngine.restore gives
    back = {i.id: i for i in ok(client.list_items)}[restored]
    assert (back.url, back.username) == (item.url, item.username)
    victim = ok(client.list_trash)[0]
    assert ok(partial(client.purge, victim.trash_id)) is None
    assert victim.trash_id not in {e.trash_id for e in ok(client.list_trash)}


def test_delete_missing_is_not_found(client: DaemonClient) -> None:
    assert fails(partial(client.delete, "missing")).kind is ErrorKind.NOT_FOUND


def test_sync_now_and_resolve_pause(client: DaemonClient, fake: FakeDaemonThread) -> None:
    fake.call(lambda d: setattr(d, "sync_duration", 0.01))
    assert ok(client.sync_now) is None
    assert ok(client.get_status).state is SyncState.IDLE
    err = fails(resolving(client, apply=True))
    assert err.kind is ErrorKind.INVALID
    ids = list(demo_items(fake))
    fake.call(lambda d: d.pause(local_ids=ids[:2], remote_ids=ids[2:3]))
    paused = ok(client.get_status)
    assert paused.state is SyncState.PAUSED
    assert paused.pending_deletions == 3
    assert ok(resolving(client, apply=False)) is None
    assert ok(client.get_status).state is SyncState.IDLE
    assert len(ok(client.list_items)) == 60


def test_sync_now_offline_is_unavailable(client: DaemonClient, fake: FakeDaemonThread) -> None:
    fake.call(lambda d: d.go_offline("No connection to iCloud"))
    err = fails(client.sync_now)
    assert (err.kind, err.message) == (ErrorKind.UNAVAILABLE, "No connection to iCloud")


# ---------------------------------------------------------------------- sign-in


def test_sign_in_flow(client: DaemonClient, fake: FakeDaemonThread) -> None:
    fake.call(lambda d: d.sign_out())
    secret = fake.call(lambda d: d.apple_password)
    code = fake.call(lambda d: d.verification_code)
    passcode = fake.call(lambda d: d.device_passcode)
    fake.call(lambda d: setattr(d, "join_duration", 0.01))

    step = ok(partial(client.sign_in_start, "jane@example.com", secret))
    assert step == SignInStep(
        StepKind.CODE, "trusted-device", "Enter the code shown on your trusted Apple device"
    )
    sms = ok(client.sign_in_request_sms)
    assert (sms.step, sms.destination) == (StepKind.CODE, "sms")
    wrong = fails(partial(client.sign_in_code, "000000"))
    assert (wrong.kind, wrong.message) == (
        ErrorKind.WRONG_CODE,
        "The verification code is incorrect",
    )
    assert ok(partial(client.sign_in_code, code)).step is StepKind.DEVICE
    devices = ok(client.recovery_devices)
    assert all(isinstance(d, RecoveryDevice) for d in devices)
    assert [d.model for d in devices] == ["iPhone17,1", "iPad16,3", "Mac15,12"]
    bad = fails(partial(client.join_keychain, devices[0].id, "999999"))
    assert bad.kind is ErrorKind.WRONG_PASSCODE
    assert bad.message == "Wrong passcode. 9 attempts left on this device."
    done_step = ok(partial(client.join_keychain, devices[0].id, passcode))
    assert done_step.step is StepKind.DONE
    assert ok(client.get_status).apple_id == "jane@example.com"
    assert ok(client.sign_out) is None
    assert ok(client.get_status).state is SyncState.SIGNED_OUT


def test_sign_in_wrong_password_is_auth_required(client: DaemonClient) -> None:
    err = fails(partial(client.sign_in_start, "jane@example.com", "wrong"))
    assert err.kind is ErrorKind.AUTH_REQUIRED


# ---------------------------------------------------------------------- injected errors


ERROR_CASES: list[tuple[str, Callable[[DaemonClient, Done[Any]], None]]] = [
    ("GetStatus", lambda c, d: c.get_status(d)),
    ("List", lambda c, d: c.list_items(d)),
    ("Get", lambda c, d: c.get("x", d)),
    ("Save", lambda c, d: c.save(Draft(url="example.com"), d)),
    ("Delete", lambda c, d: c.delete("x", d)),
    ("ListTrash", lambda c, d: c.list_trash(d)),
    ("Restore", lambda c, d: c.restore("x", d)),
    ("Purge", lambda c, d: c.purge("x", d)),
    ("SyncNow", lambda c, d: c.sync_now(d)),
    ("ResolvePause", lambda c, d: c.resolve_pause(apply=True, done=d)),
    ("GetCode", lambda c, d: c.get_code("x", d)),
    ("SignInStart", lambda c, d: c.sign_in_start("a", "b", d)),
    ("SignInCode", lambda c, d: c.sign_in_code("1", d)),
    ("SignInRequestSms", lambda c, d: c.sign_in_request_sms(d)),
    ("ListRecoveryDevices", lambda c, d: c.recovery_devices(d)),
    ("JoinKeychain", lambda c, d: c.join_keychain("x", "y", d)),
    ("SignOut", lambda c, d: c.sign_out(d)),
]


@pytest.mark.parametrize(("method", "invoke"), ERROR_CASES, ids=[m for m, _ in ERROR_CASES])
def test_every_method_reports_injected_errors(
    client: DaemonClient,
    fake: FakeDaemonThread,
    method: str,
    invoke: Callable[[DaemonClient, Done[Any]], None],
) -> None:
    fake.call(lambda d: d.fail_next(method, "Locked", "The vault is locked"))
    err = fails(partial(invoke, client))
    assert (err.kind, err.message) == (ErrorKind.LOCKED, "The vault is locked")


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("NotFound", ErrorKind.NOT_FOUND),
        ("Invalid", ErrorKind.INVALID),
        ("Unavailable", ErrorKind.UNAVAILABLE),
        ("AuthRequired", ErrorKind.AUTH_REQUIRED),
        ("WrongCode", ErrorKind.WRONG_CODE),
        ("WrongPasscode", ErrorKind.WRONG_PASSCODE),
        ("Locked", ErrorKind.LOCKED),
        ("Unheard", ErrorKind.OTHER),
        ("org.freedesktop.DBus.Error.Failed", ErrorKind.OTHER),
        ("org.freedesktop.DBus.Error.NoReply", ErrorKind.UNREACHABLE),
    ],
)
def test_error_kinds_over_the_bus(
    client: DaemonClient, fake: FakeDaemonThread, name: str, kind: ErrorKind
) -> None:
    fake.call(lambda d: d.fail_next("GetStatus", name, "Something: went wrong"))
    err = fails(client.get_status)
    assert err.kind is kind
    assert err.message == "Something: went wrong"
    assert ok(client.get_status).state is SyncState.IDLE  # only the next call fails


def test_no_daemon_is_unreachable(connection: Gio.DBusConnection) -> None:
    lonely = DaemonClient(connection)
    err = fails(lonely.get_status)
    assert err.kind is ErrorKind.UNREACHABLE


def test_closed_connection_is_unreachable(bus_address: str, fake: FakeDaemonThread) -> None:
    del fake
    conn = _connect(bus_address)
    conn.close_sync(None)
    assert fails(DaemonClient(conn).get_status).kind is ErrorKind.UNREACHABLE


# ---------------------------------------------------------------------- malformed replies

_BROKEN_XML = f"""
<node>
  <interface name="{DAEMON_INTERFACE}">
    <method name="GetStatus"><arg type="a{{sv}}" direction="out"/></method>
    <method name="List"><arg type="aa{{sv}}" direction="out"/></method>
    <method name="Get"><arg type="s" direction="in"/><arg type="s" direction="out"/></method>
  </interface>
</node>
"""


@pytest.fixture
def broken(bus_address: str) -> Iterator[Gio.DBusConnection]:
    """A misbehaving daemon: type-correct but contract-violating or mistyped replies."""
    conn = _connect(bus_address)

    def on_call(
        _conn: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        method: str,
        _params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        if method == "GetStatus":
            invocation.return_value(GLib.Variant("(a{sv})", ({"state": GLib.Variant("i", 1)},)))
        elif method == "List":
            invocation.return_value(GLib.Variant("(aa{sv})", ([{"id": GLib.Variant("s", "")}],)))
        else:
            invocation.return_value(GLib.Variant("(s)", ("not a dict",)))

    info = Gio.DBusNodeInfo.new_for_xml(_BROKEN_XML).interfaces[0]
    registration = conn.register_object_with_closures2(
        DAEMON_OBJECT_PATH, info, on_call, None, None
    )
    conn.call_sync(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "RequestName",
        GLib.Variant("(su)", (OTHER_NAME, 4)),
        GLib.VariantType.new("(u)"),
        Gio.DBusCallFlags.NONE,
        5000,
        None,
    )
    try:
        yield conn
    finally:
        conn.unregister_object(registration)
        conn.close_sync(None)


def test_contract_violating_reply_is_other(
    connection: Gio.DBusConnection, broken: Gio.DBusConnection
) -> None:
    del broken
    bad = DaemonClient(connection, bus_name=OTHER_NAME)
    status_err = fails(bad.get_status)
    assert status_err.kind is ErrorKind.OTHER
    assert status_err.message.startswith("unexpected reply to GetStatus: ")
    list_err = fails(bad.list_items)
    assert list_err.kind is ErrorKind.OTHER
    assert "item without id" in list_err.message


def test_mistyped_reply_is_other(
    connection: Gio.DBusConnection, broken: Gio.DBusConnection
) -> None:
    del broken
    bad = DaemonClient(connection, bus_name=OTHER_NAME)
    assert fails(partial(bad.get, "x")).kind is ErrorKind.OTHER


# ---------------------------------------------------------------------- signals and watch


def test_subscribe_delivers_status_and_items(client: DaemonClient, fake: FakeDaemonThread) -> None:
    statuses: list[Status] = []
    batches: list[list[str]] = []
    client.subscribe(statuses.append, batches.append)
    ok(client.get_status)  # the match rules are in place once a round trip completes
    fake.call(lambda d: d.go_offline("No connection to iCloud"))
    wait_until(lambda: statuses, what="StatusChanged")
    assert statuses[-1].state is SyncState.OFFLINE
    assert statuses[-1].message == "No connection to iCloud"
    new_id = fake.call(lambda d: d.add_item("https://added.example.com", "jane", PW))
    wait_until(lambda: batches, what="ItemsChanged")
    assert batches == [[new_id]]


def test_malformed_status_signal_is_dropped(
    client: DaemonClient, fake: FakeDaemonThread, bus_address: str
) -> None:
    del fake
    statuses: list[Status] = []
    batches: list[list[str]] = []
    # Subscribing by well-known name matches the owner's unique name, so use a client that
    # treats the misbehaving connection as its daemon.
    impostor = _connect(bus_address)
    try:
        unique = impostor.get_unique_name()
        assert unique is not None
        watcher = DaemonClient(client.connection, bus_name=unique)
        watcher.subscribe(statuses.append, batches.append)
        for state in (GLib.Variant("i", 1), GLib.Variant("s", "idle")):
            impostor.emit_signal(
                None,
                DAEMON_OBJECT_PATH,
                DAEMON_INTERFACE,
                "StatusChanged",
                GLib.Variant("(a{sv})", ({"state": state},)),
            )
        impostor.flush_sync(None)
        wait_until(lambda: statuses, what="the well-formed StatusChanged")
        assert [s.state for s in statuses] == [SyncState.IDLE]
        watcher.close()
    finally:
        impostor.close_sync(None)


def test_mistyped_signals_are_dropped_without_raising(
    client: DaemonClient, bus_address: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    raised: list[BaseException] = []
    # PyGObject reports exceptions escaping a signal callback through sys.excepthook.
    monkeypatch.setattr(sys, "excepthook", lambda _t, exc, _tb: raised.append(exc))
    statuses: list[Status] = []
    batches: list[list[str]] = []
    impostor = _connect(bus_address)
    try:
        unique = impostor.get_unique_name()
        assert unique is not None
        watcher = DaemonClient(client.connection, bus_name=unique)
        watcher.subscribe(statuses.append, batches.append)
        signals = [
            ("StatusChanged", GLib.Variant("(i)", (1,))),
            ("ItemsChanged", GLib.Variant("(i)", (1,))),
            ("ItemsChanged", GLib.Variant("(as)", (["a", "b"],))),
        ]
        for member, params in signals:
            impostor.emit_signal(None, DAEMON_OBJECT_PATH, DAEMON_INTERFACE, member, params)
        impostor.flush_sync(None)
        wait_until(lambda: batches, what="the well-formed ItemsChanged")
        assert batches == [["a", "b"]]
        assert statuses == []
        assert raised == []
        watcher.close()
    finally:
        impostor.close_sync(None)


def test_close_stops_signal_delivery(client: DaemonClient, fake: FakeDaemonThread) -> None:
    batches: list[list[str]] = []
    client.subscribe(lambda _s: None, batches.append)
    ok(client.get_status)
    client.close()
    fake.call(lambda d: d.add_item("https://late.example.com", "jane", PW))
    pump(0.3)
    assert batches == []


def test_watch_reports_appear_and_vanish(connection: Gio.DBusConnection, bus_address: str) -> None:
    events: list[str] = []
    watcher = DaemonClient(connection)
    watcher.watch(lambda: events.append("up"), lambda: events.append("down"))
    wait_until(lambda: events, what="initial vanished")
    assert events == ["down"]
    with FakeDaemonThread(bus_address, FakeDaemon.demo(NOW)):
        wait_until(lambda: events[-1] == "up", what="appeared")
    wait_until(lambda: events[-1] == "down", what="vanished")
    assert events == ["down", "up", "down"]
    watcher.close()
    with FakeDaemonThread(bus_address, FakeDaemon.demo(NOW)):
        pump(0.3)
    assert events == ["down", "up", "down"]
