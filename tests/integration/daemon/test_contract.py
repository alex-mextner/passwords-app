# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The daemon on a private bus speaks exactly data/dbus/io.github.alex_mextner.Passwords1.xml."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from dbus_fast import Message, MessageType, Variant
from dbus_fast import introspection as intr
from tests.fakes.memory_stores import make_credential
from tests.integration.daemon.support import CallError, Client, RunningDaemon, wait_for
from tests.unit.daemon.otp_fixtures import RFC_SEED, otpauth_uri

from passwords_app.daemon import BUS_NAME, INTERFACE, OBJECT_PATH
from passwords_app.sync.remote_icloud import DUPLICATE_LOGIN

if TYPE_CHECKING:
    from dbus_fast.aio import MessageBus

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]

XML = Path(__file__).parents[3] / "data" / "dbus" / "io.github.alex_mextner.Passwords1.xml"
ERR = f"{INTERFACE}.Error."
HIDDEN = "contract-test-hidden-value"
OTP = otpauth_uri(issuer="Example")


def contract() -> intr.Interface:
    (interface,) = [i for i in intr.Node.parse(XML.read_text()).interfaces if i.name == INTERFACE]
    return interface


def shape(interface: intr.Interface) -> dict[str, Any]:
    return {
        "methods": {
            m.name: [
                (a.name, a.type.signature, None if a.direction is None else a.direction.value)
                for a in (*m.in_args, *m.out_args)
            ]
            for m in interface.methods
        },
        "signals": {
            s.name: [(a.name, a.type.signature) for a in s.args] for s in interface.signals
        },
        "properties": sorted(p.name for p in interface.properties),
    }


def out_signature(member: str) -> str:
    (method,) = [m for m in contract().methods if m.name == member]
    return "".join(a.type.signature for a in method.out_args)


def s(value: str) -> Variant:
    return Variant("s", value)


def login(**extra: Variant) -> dict[str, Variant]:
    return {
        "url": s("https://shop.example.com"),
        "username": s("ann"),
        "password": s(HIDDEN),
        **extra,
    }


async def raw_call(
    bus: MessageBus, member: str, signature: str = "", body: list[Any] | None = None
) -> Message:
    reply = await bus.call(
        Message(
            destination=BUS_NAME,
            path=OBJECT_PATH,
            interface=INTERFACE,
            member=member,
            signature=signature,
            body=body or [],
        )
    )
    assert reply is not None
    return reply


# ---------------------------------------------------------------- shape


async def test_introspection_matches_the_published_xml(client: Client) -> None:
    reply = await client.bus.call(
        Message(
            destination=BUS_NAME,
            path=OBJECT_PATH,
            interface="org.freedesktop.DBus.Introspectable",
            member="Introspect",
        )
    )
    assert reply is not None
    node = intr.Node.parse(reply.body[0])
    (served,) = [i for i in node.interfaces if i.name == INTERFACE]
    assert shape(served) == shape(contract())


async def test_bus_name_is_owned_by_the_daemon(client: Client, running: RunningDaemon) -> None:
    reply = await client.bus.call(
        Message(
            destination="org.freedesktop.DBus",
            path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus",
            member="GetNameOwner",
            signature="s",
            body=[BUS_NAME],
        )
    )
    assert reply is not None
    assert reply.body[0] == running.bus.unique_name


@pytest.fixture
async def seeded(running: RunningDaemon, client: Client) -> dict[str, str]:
    """One item with a code, one trash entry, and their ids."""
    running.local.put(make_credential("ITEM", password=HIDDEN, otpauth=OTP))
    running.local.put(make_credential("GONE"))
    await client.call("SyncNow")
    await client.call("Delete", "s", "GONE")
    (entry,) = await client.one("ListTrash")
    return {"item": "ITEM", "trash": entry["trash_id"].value}


METHOD_CALLS: list[tuple[str, str, Any]] = [
    ("GetStatus", "", lambda _ids: []),
    ("List", "", lambda _ids: []),
    ("Get", "s", lambda ids: [ids["item"]]),
    ("Save", "a{sv}", lambda _ids: [login()]),
    ("Delete", "s", lambda ids: [ids["item"]]),
    ("ListTrash", "", lambda _ids: []),
    ("Restore", "s", lambda ids: [ids["trash"]]),
    ("Purge", "s", lambda ids: [ids["trash"]]),
    ("SyncNow", "", lambda _ids: []),
    ("Match", "s", lambda _ids: ["https://item.example.com/login"]),
    ("GetCode", "s", lambda ids: [ids["item"]]),
]


@pytest.mark.parametrize(
    ("member", "signature", "body"), METHOD_CALLS, ids=[m for m, *_ in METHOD_CALLS]
)
async def test_reply_signatures_match_the_contract(
    client: Client, seeded: dict[str, str], member: str, signature: str, body: Any
) -> None:
    reply = await raw_call(client.bus, member, signature, body(seeded))
    assert reply.message_type == MessageType.METHOD_RETURN, reply.body
    assert reply.signature == out_signature(member)


DUMMY = {"s": "x", "b": False, "a{sv}": {}}


async def test_every_contract_method_answers_with_its_own_signature(client: Client) -> None:
    # Placeholder arguments: every method must either succeed with the contract's reply
    # signature or refuse with one of the interface's named errors, never "unknown method".
    for method in contract().methods:
        signature = "".join(a.type.signature for a in method.in_args)
        body = [DUMMY[a.type.signature] for a in method.in_args]
        reply = await raw_call(client.bus, method.name, signature, body)
        if reply.message_type == MessageType.ERROR:
            assert (reply.error_name or "").startswith(ERR), (method.name, reply.error_name)
        else:
            assert reply.signature == out_signature(method.name), method.name


async def test_wrong_argument_types_are_refused(client: Client) -> None:
    reply = await raw_call(client.bus, "Get", "u", [7])
    assert reply.message_type == MessageType.ERROR
    assert not (reply.error_name or "").startswith(ERR)


async def test_unknown_method_is_refused(client: Client) -> None:
    reply = await raw_call(client.bus, "DropAllPasswords")
    assert reply.error_name == "org.freedesktop.DBus.Error.UnknownMethod"


# ---------------------------------------------------------------- item dicts


async def test_list_never_carries_secrets(client: Client, seeded: dict[str, str]) -> None:
    reply = await raw_call(client.bus, "List")
    (item,) = reply.body[0]
    assert "password" not in item
    assert "otpauth" not in item
    assert item["has_code"].value is True
    assert HIDDEN not in repr(reply.body)
    assert RFC_SEED not in repr(reply.body)


async def test_match_never_carries_secrets(client: Client, seeded: dict[str, str]) -> None:
    reply = await raw_call(client.bus, "Match", "s", ["https://item.example.com/"])
    (item,) = reply.body[0]
    assert item["id"].value == "ITEM"
    assert HIDDEN not in repr(reply.body)
    assert RFC_SEED not in repr(reply.body)


async def test_trash_never_carries_secrets(client: Client, running: RunningDaemon) -> None:
    running.local.put(make_credential("X", password=HIDDEN, otpauth=OTP))
    await client.call("SyncNow")
    await client.call("Delete", "s", "X")
    reply = await raw_call(client.bus, "ListTrash")
    (entry,) = reply.body[0]
    assert set(entry) == {"trash_id", "reason", "deleted_at", "expires_at", "item"}
    assert entry["reason"].value == "deleted-on-linux"
    assert HIDDEN not in repr(reply.body)
    assert RFC_SEED not in repr(reply.body)


async def test_get_is_the_only_way_to_secrets(client: Client, seeded: dict[str, str]) -> None:
    item = await client.one("Get", "s", "ITEM")
    assert item["password"].value == HIDDEN
    assert item["otpauth"].value == OTP


async def test_item_dict_keys_and_types(client: Client, seeded: dict[str, str]) -> None:
    item = await client.one("Get", "s", "ITEM")
    assert {k: v.signature for k, v in item.items()} == {
        "id": "s",
        "url": "s",
        "username": "s",
        "title": "s",
        "notes": "s",
        "alt_urls": "as",
        "group": "s",
        "created": "x",
        "modified": "x",
        "has_code": "b",
        "password": "s",
        "otpauth": "s",
    }


async def test_save_get_round_trip(client: Client) -> None:
    new_id = await client.one(
        "Save",
        "a{sv}",
        login(
            title=s("Shop"),
            notes=s("multi\nline ✓"),
            otpauth=s(OTP),
            alt_urls=Variant("as", ["https://pay.example.com"]),
        ),
    )
    item = await client.one("Get", "s", new_id)
    values = {k: v.value for k, v in item.items()}
    assert values["url"] == "https://shop.example.com"
    assert values["username"] == "ann"
    assert values["password"] == HIDDEN
    assert values["title"] == "Shop"
    assert values["notes"] == "multi\nline ✓"
    assert values["otpauth"] == OTP
    assert values["alt_urls"] == ["https://pay.example.com"]
    assert values["created"] == values["modified"] > 0


async def test_save_with_empty_id_creates(client: Client) -> None:
    assert await client.one("Save", "a{sv}", login(id=s("")))


async def test_save_echoing_a_get_dict_updates(client: Client, seeded: dict[str, str]) -> None:
    item = await client.one("Get", "s", "ITEM")
    item["title"] = s("Renamed")
    assert await client.one("Save", "a{sv}", item) == "ITEM"
    assert (await client.one("Get", "s", "ITEM"))["title"].value == "Renamed"


async def test_get_code(client: Client, seeded: dict[str, str]) -> None:
    code, left = await client.call("GetCode", "s", "ITEM")
    assert code.isdigit()
    assert len(code) == 6
    assert 1 <= left <= 30


# ---------------------------------------------------------------- errors


@pytest.mark.parametrize(
    ("member", "signature", "body"),
    [
        ("Get", "s", ["NOPE"]),
        ("Delete", "s", ["NOPE"]),
        ("GetCode", "s", ["NOPE"]),
        ("Restore", "s", ["NOPE"]),
        ("Purge", "s", ["NOPE"]),
        ("Save", "a{sv}", [{"id": Variant("s", "NOPE"), "title": Variant("s", "x")}]),
    ],
)
async def test_not_found(client: Client, member: str, signature: str, body: list[Any]) -> None:
    with pytest.raises(CallError) as info:
        await client.call(member, signature, *body)
    assert info.value.name == ERR + "NotFound"


async def test_code_for_item_without_code_is_not_found(
    client: Client, running: RunningDaemon
) -> None:
    running.local.put(make_credential("PLAIN"))
    with pytest.raises(CallError) as info:
        await client.call("GetCode", "s", "PLAIN")
    assert info.value.name == ERR + "NotFound"


SITE = Variant("s", "https://example.com")
PW = Variant("s", "pw")


@pytest.mark.parametrize(
    "item",
    [
        {"bogus": Variant("s", "x")},
        {"url": Variant("i", 1)},
        {"username": Variant("s", "x"), "password": PW},
        {"url": SITE},
        {"url": SITE, "password": Variant("s", "")},
        {"url": Variant("s", "mailto:me@example.com"), "password": PW},
        {"url": SITE, "password": PW, "otpauth": Variant("s", "otpauth://totp/x")},
        {"url": SITE, "password": PW, "alt_urls": Variant("s", "x")},
    ],
)
async def test_invalid_saves(
    client: Client, running: RunningDaemon, item: dict[str, Variant]
) -> None:
    with pytest.raises(CallError) as info:
        await client.call("Save", "a{sv}", item)
    assert info.value.name == ERR + "Invalid"
    assert len(running.local.items) == 0


async def test_resolve_pause_without_pause_is_invalid(client: Client) -> None:
    with pytest.raises(CallError) as info:
        await client.call("ResolvePause", "b", True)  # noqa: FBT003
    assert info.value.name == ERR + "Invalid"


@pytest.mark.parametrize(
    ("member", "signature", "body"),
    [
        ("List", "", []),
        ("Get", "s", ["A"]),
        ("Match", "s", ["https://a.example.com"]),
        ("Save", "a{sv}", [login()]),
        ("Delete", "s", ["A"]),
    ],
)
async def test_locked_keyring(
    client: Client, running: RunningDaemon, member: str, signature: str, body: list[Any]
) -> None:
    running.local.put(make_credential("A"))
    running.local.lock()
    with pytest.raises(CallError) as info:
        await client.call(member, signature, *body)
    assert info.value.name == ERR + "Locked"


async def test_engine_crash_is_reported_without_internals(
    client: Client, running: RunningDaemon
) -> None:
    running.remote.fail_next("fetch", RuntimeError("/home/someone/private/path"))
    await client.call("SyncNow")
    status = await client.one("GetStatus")
    assert status["state"].value == "error"
    assert "/home/someone" not in status["message"].value


# ---------------------------------------------------------------- signals


async def test_status_changed_is_emitted_during_sync(client: Client) -> None:
    await client.call("SyncNow")
    await wait_for(lambda: len(client.signal_bodies("StatusChanged")) >= 2)
    states = [b["state"].value for b in client.signal_bodies("StatusChanged")]
    assert "syncing" in states
    assert states[-1] == "idle"
    last = client.signal_bodies("StatusChanged")[-1]
    assert {k: v.signature for k, v in last.items()} == {
        "state": "s",
        "apple_id": "s",
        "item_count": "u",
        "trash_count": "u",
        "last_sync": "x",
        "next_sync": "x",
        "message": "s",
        "pending_local_deletions": "as",
        "pending_remote_deletions": "as",
    }


async def test_items_changed_after_save(client: Client) -> None:
    await client.call("List")  # first read establishes what clients have seen
    new_id = await client.one("Save", "a{sv}", login())
    await wait_for(lambda: any(new_id in b for b in client.signal_bodies("ItemsChanged")))


async def test_items_changed_after_icloud_edit(client: Client, running: RunningDaemon) -> None:
    running.remote.put(make_credential("PHONE"))
    await client.call("SyncNow")
    await wait_for(lambda: any("PHONE" in b for b in client.signal_bodies("ItemsChanged")))
    assert {m.signature for m in client.signals if m.member == "ItemsChanged"} == {"as"}


async def test_signals_come_from_the_object_path(client: Client) -> None:
    await client.call("SyncNow")
    await wait_for(lambda: bool(client.signals))
    assert {m.path for m in client.signals} == {OBJECT_PATH}


async def test_signals_never_carry_secrets(client: Client, running: RunningDaemon) -> None:
    running.remote.put(make_credential("Z", password=HIDDEN, otpauth=OTP))
    await client.call("SyncNow")
    await client.one("Save", "a{sv}", login())
    await wait_for(lambda: bool(client.signal_bodies("ItemsChanged")))
    dump = repr([m.body for m in client.signals])
    assert HIDDEN not in dump
    assert RFC_SEED not in dump


# ---------------------------------------------------------------- pause over D-Bus


async def test_pause_and_resolve(client: Client, running: RunningDaemon) -> None:
    for i in range(7):
        running.remote.put(make_credential(f"P{i}"))
    await client.call("SyncNow")
    for i in range(7):
        running.remote.remove(f"P{i}")
    await client.call("SyncNow")
    status = await client.one("GetStatus")
    assert status["state"].value == "paused"
    assert sorted(status["pending_local_deletions"].value) == [f"P{i}" for i in range(7)]
    assert status["pending_remote_deletions"].value == []
    assert running.notifier.topics() == ["pause"]
    await client.call("ResolvePause", "b", False)  # noqa: FBT003
    status = await client.one("GetStatus")
    assert status["state"].value == "idle"
    assert status["pending_local_deletions"].value == []
    assert len(running.remote.items) == 7


async def test_offline_status(client: Client, running: RunningDaemon) -> None:
    running.remote.offline = True
    await client.call("SyncNow")
    assert (await client.one("GetStatus"))["state"].value == "offline"


async def test_a_login_icloud_refuses_is_explained_in_the_status(
    client: Client, running: RunningDaemon
) -> None:
    # The contract has no per-item flag: the status message and a notification carry it.
    running.remote.reject("R", DUPLICATE_LOGIN)
    running.local.put(make_credential("R", url="https://example.com", username="bob"))
    await client.call("SyncNow")
    status = await client.one("GetStatus")
    assert status["state"].value == "idle"
    message = status["message"].value
    assert message.startswith(
        f"iCloud did not accept the password for bob on https://example.com: {DUPLICATE_LOGIN}."
    )
    await wait_for(lambda: client.signal_bodies("StatusChanged")[-1]["message"].value == message)
    assert running.notifier.topics() == ["refused:R"]
    item = await client.one("Get", "s", "R")
    assert set(item) == {
        "id",
        "url",
        "username",
        "title",
        "notes",
        "alt_urls",
        "group",
        "created",
        "modified",
        "has_code",
        "password",
        "otpauth",
    }
