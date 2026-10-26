# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The fake daemon speaks the real D-Bus contract, so GUI tests exercise the same wire behavior.

Every test talks to the fake over a private, bare dbus-daemon through a separate client
connection; nothing touches the user's session bus or keyring.
"""

from __future__ import annotations

import asyncio
import base64
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from dbus_fast import DBusError, Message, MessageType, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.introspection import Arg, Node
from tests.fakes.fake_daemon import (
    BUS_NAME,
    ERROR_PREFIX,
    INTERFACE,
    OBJECT_PATH,
    FakeDaemon,
    FakeDaemonThread,
    demo_dataset,
)

from passwords_app.core.otp import parse_otpauth
from passwords_app.core.strength import assess, reused

REPO = Path(__file__).resolve().parents[3]
CONTRACT = REPO / "data" / "dbus" / "io.github.alex_mextner.Passwords1.xml"
NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
DAY_MS = 24 * 3600 * 1000
APPLE_ID = "alex.doe@example.com"
# The fake's fictional sign-in answers are its documented defaults.
_DEFAULTS = FakeDaemon()
APPLE_PW = _DEFAULTS.apple_password
CODE = _DEFAULTS.verification_code
PASSCODE = _DEFAULTS.device_passcode
PW_A = "example-pw-1"
PW_B = "example-pw-2"
# ResolvePause(b apply) arguments.
APPLY, KEEP = True, False
ITEM_KEYS = {
    "id": "s",
    "url": "s",
    "username": "s",
    "title": "s",
    "notes": "s",
    "group": "s",
    "alt_urls": "as",
    "created": "x",
    "modified": "x",
    "has_code": "b",
    "sync_problem": "s",
}
STATUS_KEYS = {
    "state": "s",
    "apple_id": "s",
    "item_count": "u",
    "trash_count": "u",
    "last_sync": "x",
    "next_sync": "x",
    "message": "s",
    "pending_local_deletions": "as",
    "pending_remote_deletions": "as",
    "join_pending": "b",
}
# RFC 6238 appendix B: SHA-1 with the ASCII key "12345678901234567890", 8 digits.
_RFC_KEY = base64.b32encode(b"12345678901234567890").decode()
RFC_OTPAUTH = f"otpauth://totp/RFC:test?secret={_RFC_KEY}&digits=8&issuer=RFC"
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


def ms(at: datetime) -> int:
    return int(at.timestamp() * 1000)


@dataclass
class Clock:
    now: datetime = NOW

    def __call__(self) -> datetime:
        return self.now


def unwrap(value: Any) -> Any:
    if isinstance(value, Variant):
        return unwrap(value.value)
    if isinstance(value, dict):
        return {k: unwrap(v) for k, v in value.items()}
    if isinstance(value, list):
        return [unwrap(v) for v in value]
    return value


@dataclass
class Client:
    """A second connection that calls the fake and records its signals."""

    bus: MessageBus
    signals: list[tuple[str, Any]] = field(default_factory=list)
    _arrived: asyncio.Event = field(default_factory=asyncio.Event)

    def on_message(self, msg: Message) -> None:
        if msg.message_type is MessageType.SIGNAL and msg.interface == INTERFACE:
            assert msg.member is not None
            self.signals.append((msg.member, unwrap(msg.body[0])))
            self._arrived.set()

    async def raw(self, member: str, signature: str = "", *body: Any) -> list[Any]:
        reply = await self.bus.call(
            Message(
                destination=BUS_NAME,
                path=OBJECT_PATH,
                interface=INTERFACE,
                member=member,
                signature=signature,
                body=list(body),
            )
        )
        if reply.message_type is MessageType.ERROR:
            assert reply.error_name is not None
            raise DBusError(reply.error_name, reply.body[0])
        return list(reply.body)

    async def call(self, member: str, signature: str = "", *body: Any) -> Any:
        """Unwrapped single return value (None for methods without one)."""
        out = await self.raw(member, signature, *body)
        return unwrap(out[0]) if out else None

    async def error(self, member: str, signature: str = "", *body: Any) -> DBusError:
        with pytest.raises(DBusError) as caught:
            await self.raw(member, signature, *body)
        return caught.value

    async def save(self, **fields: Any) -> str:
        item = {
            k: v if isinstance(v, Variant) else Variant("as" if k == "alt_urls" else "s", v)
            for k, v in fields.items()
        }
        result: str = await self.call("Save", "a{sv}", item)
        return result

    async def status(self) -> dict[str, Any]:
        result: dict[str, Any] = await self.call("GetStatus")
        return result

    async def wait_for(self, member: str, predicate: Callable[[Any], bool] = bool) -> Any:
        async with asyncio.timeout(5):
            while True:
                for name, body in self.signals:
                    if name == member and predicate(body):
                        return body
                self._arrived.clear()
                await self._arrived.wait()

    def emitted(self, member: str) -> list[Any]:
        return [body for name, body in self.signals if name == member]

    async def settle(self) -> None:
        # A round trip through the bus flushes every signal the fake sent before it.
        await self.call("GetStatus")


def error_name(err: DBusError) -> str:
    return err.type.removeprefix(ERROR_PREFIX)


# ---------------------------------------------------------------------- fixtures


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
def clock() -> Clock:
    return Clock()


Serve = Callable[[FakeDaemon], Awaitable[Client]]


@pytest.fixture
async def serve(bus_address: str) -> AsyncIterator[Serve]:
    started: list[FakeDaemon] = []
    clients: list[MessageBus] = []

    async def start(daemon: FakeDaemon) -> Client:
        await daemon.start(bus_address)
        started.append(daemon)
        bus = await MessageBus(bus_address=bus_address).connect()
        clients.append(bus)
        client = Client(bus)
        bus.add_message_handler(client.on_message)
        await bus.call(
            Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="AddMatch",
                signature="s",
                body=[f"type='signal',interface='{INTERFACE}'"],
            )
        )
        return client

    yield start
    for bus in clients:
        bus.disconnect()
    for daemon in started:
        await daemon.stop()


@pytest.fixture
def fake(clock: Clock) -> FakeDaemon:
    daemon = FakeDaemon(clock=clock)
    daemon.sync_duration = 0.05
    daemon.join_duration = 0.05
    return daemon


@pytest.fixture
async def client(fake: FakeDaemon, serve: Serve) -> Client:
    return await serve(fake)


@pytest.fixture
async def signed_in(clock: Clock, serve: Serve) -> tuple[FakeDaemon, Client]:
    daemon = FakeDaemon(clock=clock, state="idle", apple_id=APPLE_ID)
    daemon.sync_duration = 0.05
    return daemon, await serve(daemon)


# ---------------------------------------------------------------------- contract


async def test_exported_interface_matches_the_contract_xml(client: Client) -> None:
    reply = await client.bus.call(
        Message(
            destination=BUS_NAME,
            path=OBJECT_PATH,
            interface="org.freedesktop.DBus.Introspectable",
            member="Introspect",
        )
    )

    def sig(args: list[Arg]) -> str:
        return "".join(str(a.signature) for a in args)

    def members(xml: str) -> tuple[set[tuple[str, str, str]], set[tuple[str, str]]]:
        (iface,) = [i for i in Node.parse(xml).interfaces if i.name == INTERFACE]
        methods = {(m.name, sig(m.in_args), sig(m.out_args)) for m in iface.methods}
        signals = {(s.name, sig(s.args)) for s in iface.signals}
        return methods, signals

    assert members(reply.body[0]) == members(CONTRACT.read_text())


async def test_second_daemon_cannot_take_the_name(client: Client, bus_address: str) -> None:
    other = FakeDaemon()
    with pytest.raises(RuntimeError, match="already owned"):
        await other.start(bus_address)
    assert await client.status()


# ---------------------------------------------------------------------- status


async def test_status_carries_every_key_with_contract_types(client: Client) -> None:
    (status,) = await client.raw("GetStatus")
    assert {k: v.signature for k, v in status.items()} == STATUS_KEYS


async def test_fresh_daemon_is_signed_out_and_empty(client: Client) -> None:
    status = await client.status()
    assert status["state"] == "signed-out"
    assert status["apple_id"] == ""
    assert status["item_count"] == 0
    assert status["last_sync"] == 0
    assert status["next_sync"] == 0


@pytest.mark.parametrize(
    ("hook", "state", "message"),
    [
        (lambda d: d.go_offline("No network"), "offline", "No network"),
        (lambda d: d.require_signin("Session expired"), "signin-required", "Session expired"),
        (lambda d: d.set_error("Keyring is locked"), "error", "Keyring is locked"),
        (lambda d: d.start_syncing(), "syncing", ""),
        (lambda d: d.go_idle(), "idle", ""),
        (lambda d: d.set_state("paused", "held"), "paused", "held"),
    ],
)
async def test_state_hooks_emit_status_changed(
    fake: FakeDaemon,
    client: Client,
    hook: Callable[[FakeDaemon], None],
    state: str,
    message: str,
) -> None:
    hook(fake)
    body = await client.wait_for("StatusChanged", lambda s: s["state"] == state)
    assert body["message"] == message
    assert set(body) == set(STATUS_KEYS)
    assert (await client.status())["state"] == state


async def test_unchanged_status_emits_no_signal(fake: FakeDaemon, client: Client) -> None:
    fake.go_offline("down")
    fake.go_offline("down")
    await client.settle()
    assert len(client.emitted("StatusChanged")) == 1


def test_set_state_rejects_unknown_state(fake: FakeDaemon) -> None:
    with pytest.raises(ValueError, match="unknown state"):
        fake.set_state("napping")  # type: ignore[arg-type]


async def test_go_idle_sets_last_and_next_sync(fake: FakeDaemon, client: Client) -> None:
    fake.go_idle()
    status = await client.status()
    assert status["last_sync"] == ms(NOW)
    assert status["next_sync"] == ms(NOW + fake.sync_interval)


# ---------------------------------------------------------------------- items


async def test_list_items_carry_every_key_but_no_secrets(fake: FakeDaemon, client: Client) -> None:
    fake.add_item("https://shop.example.com", "jdoe", PW_A, otpauth=RFC_OTPAUTH)
    (items,) = await client.raw("List")
    (item,) = items
    assert {k: v.signature for k, v in item.items()} == ITEM_KEYS
    assert item["has_code"].value is True
    assert item["group"].value == ""


async def test_get_adds_password_and_empty_otpauth(fake: FakeDaemon, client: Client) -> None:
    item_id = fake.add_item("https://shop.example.com", "jdoe", PW_A, title="Shop")
    item = await client.call("Get", "s", item_id)
    assert set(item) == set(ITEM_KEYS) | {"password", "otpauth"}
    assert item["password"] == PW_A
    assert item["otpauth"] == ""
    assert item["title"] == "Shop"
    assert item["has_code"] is False


async def test_get_unknown_id_is_not_found(client: Client) -> None:
    assert error_name(await client.error("Get", "s", "NOPE")) == "NotFound"


@pytest.mark.parametrize("given_id", [None, ""])
async def test_save_without_id_creates_with_uppercase_uuid(
    client: Client, given_id: str | None
) -> None:
    fields: dict[str, Any] = {"url": "https://bank.example.org", "username": "adoe"}
    if given_id is not None:
        fields["id"] = given_id
    item_id = await client.save(**fields)
    assert item_id == item_id.upper()
    assert len(item_id) == 36
    item = await client.call("Get", "s", item_id)
    assert item["created"] == item["modified"] == ms(NOW)
    assert item["username"] == "adoe"
    assert item["password"] == ""
    assert item["title"] == ""


async def test_save_with_id_is_a_partial_update(client: Client, clock: Clock) -> None:
    item_id = await client.save(
        url="https://bank.example.org",
        username="adoe",
        password=PW_A,
        notes="branch: Elm",
        alt_urls=["https://login.bank.example.org"],
    )
    clock.now = NOW + timedelta(hours=1)
    assert await client.save(id=item_id, password=PW_B) == item_id
    item = await client.call("Get", "s", item_id)
    assert item["password"] == PW_B
    assert item["username"] == "adoe"
    assert item["notes"] == "branch: Elm"
    assert item["alt_urls"] == ["https://login.bank.example.org"]
    assert item["created"] == ms(NOW)
    assert item["modified"] == ms(clock.now)


async def test_save_empty_strings_clear_optional_fields(client: Client) -> None:
    item_id = await client.save(
        url="https://bank.example.org", title="Bank", notes="n", group="Family", otpauth=RFC_OTPAUTH
    )
    await client.save(id=item_id, title="", notes="", group="", otpauth="")
    item = await client.call("Get", "s", item_id)
    assert (item["title"], item["notes"], item["group"], item["otpauth"]) == ("", "", "", "")
    assert item["has_code"] is False


async def test_save_accepts_and_ignores_read_only_keys(client: Client) -> None:
    item_id = await client.save(
        url="https://bank.example.org",
        created=Variant("x", 1),
        modified=Variant("x", 2),
        has_code=Variant("b", value=True),
        sync_problem=Variant("s", "made up by a client"),
    )
    item = await client.call("Get", "s", item_id)
    assert item["created"] == ms(NOW)
    assert item["has_code"] is False
    assert item["sync_problem"] == ""


@pytest.mark.parametrize(
    "extra",
    [
        {"color": Variant("s", "red")},
        {"username": Variant("i", 7)},
        {"alt_urls": Variant("s", "https://a.example")},
        {"created": Variant("s", "yesterday")},
        {"has_code": Variant("s", "yes")},
    ],
    ids=["unknown-key", "wrong-type", "alt-urls-not-array", "created-as-string", "has-code-str"],
)
async def test_save_rejects_unknown_keys_and_wrong_types(
    client: Client, extra: dict[str, Variant]
) -> None:
    err = await client.error(
        "Save", "a{sv}", {"url": Variant("s", "https://bank.example.org"), **extra}
    )
    assert error_name(err) == "Invalid"
    assert await client.call("List") == []


async def test_save_requires_a_url(client: Client) -> None:
    err = await client.error("Save", "a{sv}", {"username": Variant("s", "x")})
    assert error_name(err) == "Invalid"
    item_id = await client.save(url="https://bank.example.org")
    err = await client.error(
        "Save", "a{sv}", {"id": Variant("s", item_id), "url": Variant("s", "")}
    )
    assert error_name(err) == "Invalid"


async def test_save_rejects_unparsable_otpauth(client: Client) -> None:
    err = await client.error(
        "Save",
        "a{sv}",
        {"url": Variant("s", "https://a.example"), "otpauth": Variant("s", "otpauth://hotp/x")},
    )
    assert error_name(err) == "Invalid"


async def test_save_unknown_id_is_not_found(client: Client) -> None:
    err = await client.error("Save", "a{sv}", {"id": Variant("s", "MISSING")})
    assert error_name(err) == "NotFound"


async def test_save_emits_items_changed_and_status(client: Client) -> None:
    item_id = await client.save(url="https://bank.example.org")
    assert await client.wait_for("ItemsChanged") == [item_id]
    status = await client.wait_for("StatusChanged")
    assert status["item_count"] == 1


async def test_add_item_hook_signals_and_lists(fake: FakeDaemon, client: Client) -> None:
    item_id = fake.add_item("https://a.example", title="A", group="Family")
    assert await client.wait_for("ItemsChanged") == [item_id]
    (item,) = await client.call("List")
    assert item["group"] == "Family"


async def test_refuse_and_accept_hooks_set_the_sync_problem(
    fake: FakeDaemon, client: Client
) -> None:
    refused = fake.add_item("https://a.example", "bob", PW_A)
    fine = fake.add_item("https://a.example", "ann", PW_B)
    await client.settle()
    client.signals.clear()
    fake.refuse(refused, "another password for this website and username already exists")
    assert await client.wait_for("ItemsChanged") == [refused]
    status = await client.wait_for("StatusChanged")
    assert status["state"] == "idle"
    assert status["message"].startswith("iCloud did not accept the password for bob")
    listed = {i["id"]: i["sync_problem"] for i in await client.call("List")}
    assert listed == {
        refused: "another password for this website and username already exists",
        fine: "",
    }
    matched = {
        i["id"]: i["sync_problem"] for i in await client.call("Match", "s", "https://a.example")
    }
    assert matched == listed
    assert (await client.call("Get", "s", refused))["sync_problem"] == listed[refused]
    await client.settle()
    client.signals.clear()
    fake.accept(refused)
    assert await client.wait_for("ItemsChanged") == [refused]
    assert (await client.call("Get", "s", refused))["sync_problem"] == ""
    assert (await client.status())["message"] == ""


# ---------------------------------------------------------------------- trash


async def test_delete_moves_item_to_trash_for_90_days(
    fake: FakeDaemon, client: Client, clock: Clock
) -> None:
    item_id = fake.add_item("https://a.example", "jdoe", PW_A, otpauth=RFC_OTPAUTH)
    clock.now = NOW + timedelta(days=1)
    await client.call("Delete", "s", item_id)
    assert await client.call("List") == []
    (entry,) = await client.call("ListTrash")
    assert entry["reason"] == "deleted-on-linux"
    assert entry["deleted_at"] == ms(clock.now)
    assert entry["expires_at"] == entry["deleted_at"] + 90 * DAY_MS
    assert entry["item"]["id"] == item_id
    assert "password" not in entry["item"]
    assert "otpauth" not in entry["item"]
    assert await client.wait_for("ItemsChanged") == [item_id]
    assert (await client.status())["trash_count"] == 1


async def test_trash_entry_signature(fake: FakeDaemon, client: Client) -> None:
    await client.call("Delete", "s", fake.add_item("https://a.example"))
    ((entry,),) = await client.raw("ListTrash")
    assert {k: v.signature for k, v in entry.items()} == {
        "trash_id": "s",
        "reason": "s",
        "deleted_at": "x",
        "expires_at": "x",
        "item": "a{sv}",
    }


async def test_delete_unknown_is_not_found(client: Client) -> None:
    assert error_name(await client.error("Delete", "s", "NOPE")) == "NotFound"


async def test_restore_gets_a_fresh_id_and_modification_time(
    fake: FakeDaemon, client: Client, clock: Clock
) -> None:
    item_id = fake.add_item("https://a.example", "jdoe", PW_A)
    await client.call("Delete", "s", item_id)
    (entry,) = await client.call("ListTrash")
    client.signals.clear()
    clock.now = NOW + timedelta(hours=2)
    restored = await client.call("Restore", "s", entry["trash_id"])
    assert restored != item_id  # the old id may be tombstoned in iCloud
    item = await client.call("Get", "s", restored)
    assert item["password"] == PW_A
    assert item["modified"] == ms(clock.now)
    assert error_name(await client.error("Get", "s", item_id)) == "NotFound"
    assert await client.call("ListTrash") == []
    assert await client.wait_for("ItemsChanged") == [restored]


async def test_restore_leaves_a_live_item_with_the_old_id_alone(
    fake: FakeDaemon, client: Client
) -> None:
    item_id = fake.add_item("https://a.example", item_id="SAME-ID")
    await client.call("Delete", "s", item_id)
    fake.add_item("https://b.example", item_id="SAME-ID")
    (entry,) = await client.call("ListTrash")
    restored = await client.call("Restore", "s", entry["trash_id"])
    assert restored != "SAME-ID"
    urls = {i["id"]: i["url"] for i in await client.call("List")}
    assert urls == {"SAME-ID": "https://b.example", restored: "https://a.example"}


async def test_purge_drops_the_entry(fake: FakeDaemon, client: Client) -> None:
    item_id = fake.add_item("https://a.example")
    await client.call("Delete", "s", item_id)
    (entry,) = await client.call("ListTrash")
    client.signals.clear()
    await client.call("Purge", "s", entry["trash_id"])
    assert await client.call("ListTrash") == []
    assert await client.call("List") == []
    assert await client.wait_for("ItemsChanged") == [item_id]


@pytest.mark.parametrize("method", ["Restore", "Purge"])
async def test_unknown_trash_id_is_not_found(client: Client, method: str) -> None:
    assert error_name(await client.error(method, "s", "NOPE")) == "NotFound"


# ---------------------------------------------------------------------- match + codes


async def test_match_lists_exact_host_before_same_site(fake: FakeDaemon, client: Client) -> None:
    site = fake.add_item("https://northwind.example", "site")
    exact = fake.add_item("https://mail.northwind.example", "exact")
    alt = fake.add_item(
        "https://other.example", "alt", alt_urls=["https://www.mail.northwind.example"]
    )
    fake.add_item("https://contoso.example", "unrelated")
    found = await client.call("Match", "s", "https://mail.northwind.example/inbox")
    assert [i["id"] for i in found] == [exact, alt, site]
    for item in found:
        assert set(item) == set(ITEM_KEYS)


async def test_match_honours_ip_and_port(fake: FakeDaemon, client: Client) -> None:
    router = fake.add_item("https://192.0.2.10:8443", "admin")
    fake.add_item("https://192.0.2.10:9443", "other-port")
    found = await client.call("Match", "s", "https://192.0.2.10:8443/login")
    assert [i["id"] for i in found] == [router]


@pytest.mark.parametrize(
    "vector",
    [(59, "94287082", 1), (1111111109, "07081804", 1), (1234567890, "89005924", 30)],
)
async def test_get_code_follows_rfc6238(
    fake: FakeDaemon, client: Client, clock: Clock, vector: tuple[int, str, int]
) -> None:
    unix, code, left = vector
    item_id = fake.add_item("https://a.example", otpauth=RFC_OTPAUTH)
    clock.now = datetime.fromtimestamp(unix, UTC)
    assert await client.raw("GetCode", "s", item_id) == [code, left]


async def test_get_code_without_code_is_not_found(fake: FakeDaemon, client: Client) -> None:
    item_id = fake.add_item("https://a.example")
    assert error_name(await client.error("GetCode", "s", item_id)) == "NotFound"
    assert error_name(await client.error("GetCode", "s", "NOPE")) == "NotFound"


# ---------------------------------------------------------------------- sync


async def test_sync_now_goes_syncing_then_idle(
    signed_in: tuple[FakeDaemon, Client], clock: Clock
) -> None:
    fake, client = signed_in
    fake.sync_duration = 0.2
    task = asyncio.create_task(client.call("SyncNow"))
    await client.wait_for("StatusChanged", lambda s: s["state"] == "syncing")
    assert not task.done()
    assert (await client.status())["state"] == "syncing"
    await task
    states = [s["state"] for s in client.emitted("StatusChanged")]
    assert states == ["syncing", "idle"]
    assert (await client.status())["last_sync"] == ms(clock.now)


async def test_sync_now_signed_out_requires_auth(client: Client) -> None:
    assert error_name(await client.error("SyncNow")) == "AuthRequired"


async def test_sync_now_offline_is_unavailable_and_stays_offline(
    signed_in: tuple[FakeDaemon, Client],
) -> None:
    fake, client = signed_in
    fake.go_offline("No network")
    err = await client.error("SyncNow")
    assert error_name(err) == "Unavailable"
    assert (await client.status())["state"] == "offline"


async def test_sync_now_while_paused_changes_nothing(
    signed_in: tuple[FakeDaemon, Client],
) -> None:
    fake, client = signed_in
    fake.pause(local_ids=["X"])
    before = await client.status()
    client.signals.clear()
    await client.call("SyncNow")
    assert await client.status() == before
    assert client.emitted("StatusChanged") == []


async def test_pause_hook_publishes_pending_deletions(
    signed_in: tuple[FakeDaemon, Client],
) -> None:
    fake, client = signed_in
    fake.pause(local_ids=["A", "B"], remote_ids=["C"])
    status = await client.wait_for("StatusChanged", lambda s: s["state"] == "paused")
    assert status["pending_local_deletions"] == ["A", "B"]
    assert status["pending_remote_deletions"] == ["C"]
    assert "3" in status["message"]


async def test_resolve_pause_when_not_paused_is_invalid(
    signed_in: tuple[FakeDaemon, Client],
) -> None:
    _, client = signed_in
    assert error_name(await client.error("ResolvePause", "b", APPLY)) == "Invalid"


async def test_resolve_pause_apply_trashes_pending_items(
    signed_in: tuple[FakeDaemon, Client],
) -> None:
    fake, client = signed_in
    gone_remote = fake.add_item("https://a.example")
    gone_local = fake.add_item("https://b.example")
    kept = fake.add_item("https://c.example")
    fake.pause(local_ids=[gone_remote], remote_ids=[gone_local])
    await client.settle()
    client.signals.clear()
    await client.call("ResolvePause", "b", APPLY)
    assert [i["id"] for i in await client.call("List")] == [kept]
    reasons = {e["item"]["id"]: e["reason"] for e in await client.call("ListTrash")}
    assert reasons == {gone_remote: "deleted-in-icloud", gone_local: "deleted-on-linux"}
    status = await client.status()
    assert status["state"] == "idle"
    assert status["pending_local_deletions"] == status["pending_remote_deletions"] == []
    assert sorted(await client.wait_for("ItemsChanged")) == sorted([gone_remote, gone_local])
    await client.wait_for("StatusChanged", lambda s: s["state"] == "idle")


async def test_resolve_pause_restore_keeps_items(signed_in: tuple[FakeDaemon, Client]) -> None:
    fake, client = signed_in
    item_id = fake.add_item("https://a.example")
    fake.pause(local_ids=[item_id])
    await client.settle()
    client.signals.clear()
    await client.call("ResolvePause", "b", KEEP)
    assert [i["id"] for i in await client.call("List")] == [item_id]
    assert await client.call("ListTrash") == []
    status = await client.wait_for("StatusChanged", lambda s: s["state"] == "idle")
    assert status["pending_local_deletions"] == []
    assert await client.wait_for("ItemsChanged") == [item_id]


# ---------------------------------------------------------------------- sign-in


async def test_sign_in_happy_path_with_two_factor(client: Client) -> None:
    step = await client.call("SignInStart", "ss", APPLE_ID, APPLE_PW)
    assert (step["step"], step["destination"]) == ("code", "trusted-device")
    sms = await client.call("SignInRequestSms")
    assert (sms["step"], sms["destination"]) == ("code", "sms")
    step = await client.call("SignInCode", "s", CODE)
    assert step["step"] == "device"
    status = await client.status()
    assert (status["state"], status["apple_id"]) == ("signin-required", APPLE_ID)

    devices = await client.call("ListRecoveryDevices")
    assert 2 <= len(devices) <= 3
    assert all(set(d) == {"id", "name", "model", "serial"} for d in devices)
    step = await client.call("JoinKeychain", "ss", devices[0]["id"], PASSCODE)
    assert step["step"] == "done"
    assert set(step) == {"step", "destination", "message"}
    status = await client.status()
    assert (status["state"], status["apple_id"]) == ("idle", APPLE_ID)
    await client.wait_for("StatusChanged", lambda s: s["state"] == "idle")


async def test_sign_in_without_two_factor_goes_straight_to_device(
    fake: FakeDaemon, client: Client
) -> None:
    fake.require_2fa = False
    step = await client.call("SignInStart", "ss", APPLE_ID, APPLE_PW)
    assert step["step"] == "device"
    assert error_name(await client.error("SignInCode", "s", CODE)) == "Invalid"
    assert len(await client.call("ListRecoveryDevices")) >= 2


async def test_sign_in_wrong_password(client: Client) -> None:
    err = await client.error("SignInStart", "ss", APPLE_ID, "not-the-password")
    assert error_name(err) == "AuthRequired"
    assert err.text == "Apple ID or password is incorrect"
    assert (await client.status())["state"] == "signed-out"


async def test_sign_in_wrong_code_can_be_retried(client: Client) -> None:
    await client.call("SignInStart", "ss", APPLE_ID, APPLE_PW)
    assert error_name(await client.error("SignInCode", "s", "654321")) == "WrongCode"
    assert (await client.call("SignInCode", "s", CODE))["step"] == "device"


@pytest.mark.parametrize(
    ("method", "sig", "args"), [("SignInCode", "s", (CODE,)), ("SignInRequestSms", "", ())]
)
async def test_code_steps_before_sign_in_start_are_invalid(
    client: Client, method: str, sig: str, args: tuple[str, ...]
) -> None:
    assert error_name(await client.error(method, sig, *args)) == "Invalid"


async def test_recovery_devices_need_a_signed_in_apple_id(client: Client) -> None:
    assert error_name(await client.error("ListRecoveryDevices")) == "AuthRequired"


async def _to_device_step(fake: FakeDaemon, client: Client) -> list[dict[str, Any]]:
    fake.require_2fa = False
    await client.call("SignInStart", "ss", APPLE_ID, APPLE_PW)
    devices: list[dict[str, Any]] = await client.call("ListRecoveryDevices")
    return devices


async def test_join_with_unlisted_device_is_invalid(fake: FakeDaemon, client: Client) -> None:
    await _to_device_step(fake, client)
    err = await client.error("JoinKeychain", "ss", "not-a-device", PASSCODE)
    assert error_name(err) == "Invalid"


async def test_wrong_passcode_counts_down_then_destroys_that_copy(
    fake: FakeDaemon, client: Client
) -> None:
    first, second, *_ = await _to_device_step(fake, client)
    for left in range(9, 0, -1):
        err = await client.error("JoinKeychain", "ss", first["id"], "999999")
        assert error_name(err) == "WrongPasscode"
        noun = "attempt" if left == 1 else "attempts"
        assert err.text == f"Wrong passcode. {left} {noun} left on this device."
    err = await client.error("JoinKeychain", "ss", first["id"], "999999")
    assert (error_name(err), err.text) == ("Unavailable", "device recovery copy destroyed")
    err = await client.error("JoinKeychain", "ss", first["id"], PASSCODE)
    assert error_name(err) == "Unavailable"
    assert (await client.call("JoinKeychain", "ss", second["id"], PASSCODE))["step"] == "done"


async def test_sign_out_clears_the_account(signed_in: tuple[FakeDaemon, Client]) -> None:
    _, client = signed_in
    await client.call("SignOut")
    status = await client.wait_for("StatusChanged", lambda s: s["state"] == "signed-out")
    assert status["apple_id"] == ""


async def test_sign_out_during_a_join_wins(fake: FakeDaemon, client: Client) -> None:
    first, *_ = await _to_device_step(fake, client)
    fake.join_duration = 0.5
    join = asyncio.create_task(client.error("JoinKeychain", "ss", first["id"], PASSCODE))
    await asyncio.sleep(0.1)  # the join is now waiting out join_duration
    await client.call("SignOut")
    assert error_name(await join) == "AuthRequired"
    status = await client.call("GetStatus")
    assert (status["state"], status["apple_id"]) == ("signed-out", "")


# ---------------------------------------------------------------------- test knobs


@pytest.mark.parametrize("name", ["Locked", f"{ERROR_PREFIX}Locked"])
async def test_fail_next_fails_exactly_one_call(
    fake: FakeDaemon, client: Client, name: str
) -> None:
    fake.fail_next("List", name, "keyring is locked")
    err = await client.error("List")
    assert (err.type, err.text) == (f"{ERROR_PREFIX}Locked", "keyring is locked")
    assert await client.call("List") == []


async def test_calls_record_method_names_only(fake: FakeDaemon, client: Client) -> None:
    await client.save(url="https://a.example", password=PW_A)
    await client.call("SignInStart", "ss", APPLE_ID, APPLE_PW)
    assert fake.calls == ["Save", "SignInStart"]


async def test_latency_delays_every_method(fake: FakeDaemon, client: Client) -> None:
    fake.latency = 0.15
    started = time.monotonic()
    await client.call("GetStatus")
    assert time.monotonic() - started >= 0.15


# ---------------------------------------------------------------------- demo data


def _host(url: str) -> str:
    host = urlsplit(url).hostname
    assert host is not None
    return host


def _is_fictional(host: str) -> bool:
    labels = host.split(".")
    return (
        labels[-1] == "example"
        or ".".join(labels[-2:]) in {"example.com", "example.org", "example.net"}
        or host.startswith("192.0.2.")
    )


def test_demo_dataset_is_deterministic() -> None:
    assert demo_dataset(NOW) == demo_dataset(NOW)
    later_items, _ = demo_dataset(NOW + timedelta(days=1))
    assert later_items[0].created == demo_dataset(NOW)[0][0].created + timedelta(days=1)


def test_demo_dataset_looks_like_a_real_vault() -> None:
    items, trash = demo_dataset(NOW)
    assert 55 <= len(items) <= 65
    assert len({c.id for c in items} | {e.credential.id for e in trash}) == len(items) + 5
    assert 7 <= sum(1 for c in items if c.otpauth) <= 9
    assert sum(1 for c in items if c.notes) >= 10
    assert 5 <= sum(1 for c in items if c.group == "Family") <= 7
    assert any(c.alt_urls for c in items)
    assert sum(1 for c in items if not c.username) == 1
    assert any(not c.title.isascii() for c in items if c.title)
    assert any(_host(c.url) == "192.0.2.10" and ":8443" in c.url for c in items)
    ages = [NOW - c.created for c in items]
    assert min(ages) < timedelta(days=60)
    assert max(ages) > timedelta(days=900)
    assert all(c.created <= c.modified <= NOW for c in items)


def test_demo_dataset_reuse_and_weakness_match_the_security_view() -> None:
    items, _ = demo_dataset(NOW)
    assert sorted(len(ids) for ids in reused(items).values()) == [2, 3]
    assert 4 <= sum(1 for c in items if assess(c.password).weak) <= 6


def test_demo_dataset_only_uses_fictional_hosts() -> None:
    items, trash = demo_dataset(NOW)
    creds = [*items, *(e.credential for e in trash)]
    hosts = {_host(u) for c in creds for u in (c.url, *c.alt_urls)}
    assert [h for h in hosts if not _is_fictional(h)] == []


def test_demo_codes_parse_with_an_issuer() -> None:
    items, _ = demo_dataset(NOW)
    for c in items:
        if c.otpauth:
            assert parse_otpauth(c.otpauth).issuer == c.title


def test_demo_trash_ages_and_reasons() -> None:
    _, trash = demo_dataset(NOW)
    assert sorted((NOW - e.deleted_at).days for e in trash) == [2, 15, 40, 80, 88]
    assert len({e.reason for e in trash}) >= 3
    assert all(e.expires_at(timedelta(days=90)) > NOW for e in trash)


async def test_demo_daemon_is_signed_in_and_recently_synced(serve: Serve) -> None:
    client = await serve(FakeDaemon.demo(NOW))
    status = await client.status()
    assert status["state"] == "idle"
    assert status["apple_id"] == APPLE_ID
    assert status["last_sync"] == ms(NOW - timedelta(minutes=2))
    assert status["item_count"] == len(demo_dataset(NOW)[0])
    assert status["trash_count"] == 5


# ---------------------------------------------------------------------- thread + CLI


def _fake_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "FakeDaemon"]


async def _remote_status(bus_address: str) -> dict[str, Any]:
    bus = await MessageBus(bus_address=bus_address).connect()
    try:
        return await Client(bus).status()
    finally:
        bus.disconnect()


def test_thread_serves_a_non_asyncio_caller(bus_address: str) -> None:
    async def count(d: FakeDaemon) -> int:
        await asyncio.sleep(0)
        return len(d.items)

    with FakeDaemonThread(bus_address) as served:
        item_id = served.call(lambda d: d.add_item("https://a.example"))
        assert served.call(count) == 1
        assert item_id in served.daemon.items
        assert asyncio.run(_remote_status(bus_address))["item_count"] == 1
        assert _fake_threads()
    assert _fake_threads() == []


def test_thread_reports_a_taken_name(bus_address: str) -> None:
    with FakeDaemonThread(bus_address), pytest.raises(RuntimeError, match="already owned"):
        FakeDaemonThread(bus_address).__enter__()
    assert _fake_threads() == []


def test_cli_serves_the_demo_until_sigterm(bus_address: str) -> None:
    argv = [sys.executable, "-m", "tests.fakes.fake_daemon", "--bus-address", bus_address]
    proc = subprocess.Popen(  # noqa: S603 - argv is fixed
        [*argv, "--state", "paused"], cwd=REPO, stdout=subprocess.PIPE
    )
    assert proc.stdout is not None
    try:
        assert proc.stdout.readline() == b"ready\n"
        status = asyncio.run(_remote_status(bus_address))
        assert status["state"] == "paused"
        assert status["pending_local_deletions"]
    finally:
        proc.send_signal(signal.SIGTERM)
        returncode = proc.wait(timeout=10)
        proc.stdout.close()
    assert returncode == 0
