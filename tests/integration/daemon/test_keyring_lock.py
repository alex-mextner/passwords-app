# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""No cached password is served once the real gnome-keyring is locked.

"iCloud Passwords" unlocks itself with a password stored in the login keyring, so it stays
out of reach only while the login keyring is locked too: that is what these tests lock,
the way locking the keyring in Seahorse (or logging out) does.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from dbus_fast import Message, MessageType, Variant
from dbus_fast.aio import MessageBus
from tests.fakes.memory_stores import MemoryRemote, make_credential
from tests.harness.dbus_session import LOGIN_COLLECTION, lock_collection, unlock_collection
from tests.integration.daemon.support import STATE_KEY, wait_for
from tests.unit.daemon.fake_clock import FakeClock
from tests.unit.daemon.fakes import FakeAccount, FakeNotifier

from passwords_app.daemon.controller import Daemon
from passwords_app.daemon.errors import LockedError
from passwords_app.daemon.keyring_lock import (
    BUS_IFACE,
    COLLECTION_IFACE,
    PROPERTIES_IFACE,
    SECRETS_NAME,
    KeyringLockWatch,
    is_lock_change,
)
from passwords_app.keyring.secret_service import SecretServiceStore
from passwords_app.store.state import StateStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]

COLLECTION = "/org/freedesktop/secrets/collection/x"


def properties_changed(interface: str, changed: dict[str, Variant], gone: list[str]) -> Message:
    return Message.new_signal(
        COLLECTION, PROPERTIES_IFACE, "PropertiesChanged", "sa{sv}as", [interface, changed, gone]
    )


def owner_changed(name: str) -> Message:
    return Message.new_signal(
        "/org/freedesktop/DBus", BUS_IFACE, "NameOwnerChanged", "sss", [name, ":1.1", ""]
    )


LOCKED = {"Locked": Variant("b", True)}  # noqa: FBT003 - D-Bus boolean value


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (properties_changed(COLLECTION_IFACE, LOCKED, []), True),
        (properties_changed(COLLECTION_IFACE, {}, ["Locked"]), True),
        (properties_changed(COLLECTION_IFACE, {"Label": Variant("s", "x")}, []), False),
        (properties_changed("org.freedesktop.Secret.Item", LOCKED, []), False),
        (owner_changed(SECRETS_NAME), True),
        (owner_changed("org.example.Other"), False),
        (Message(path=COLLECTION, interface=PROPERTIES_IFACE, member="PropertiesChanged"), False),
    ],
)
def test_is_lock_change(message: Message, *, expected: bool) -> None:
    assert is_lock_change(message) is expected


def test_a_malformed_properties_signal_is_ignored() -> None:
    message = Message.new_signal(COLLECTION, PROPERTIES_IFACE, "PropertiesChanged", "s", ["x"])
    assert message.message_type == MessageType.SIGNAL
    assert not is_lock_change(message)


class Served:
    def __init__(self, daemon: Daemon, store: SecretServiceStore) -> None:
        self.daemon = daemon
        self.store = store


@pytest.fixture
async def served(private_bus: str, tmp_path: Path) -> AsyncIterator[Served]:
    bus = await MessageBus(bus_address=private_bus).connect()
    store = await SecretServiceStore.open(bus)
    daemon = Daemon(
        account=FakeAccount(MemoryRemote()),
        local=store,
        state=StateStore(tmp_path / "state.db", STATE_KEY),
        clock=FakeClock(),
        notifier=FakeNotifier(),
    )
    watch = KeyringLockWatch(bus, daemon.keyring_lock_changed)
    await watch.start()
    try:
        await store.upsert(make_credential("A"))
        yield Served(daemon, store)
    finally:
        await watch.stop()
        daemon.close()
        bus.disconnect()


async def locked_out(daemon: Daemon) -> bool:
    try:
        await daemon.get("A")
    except LockedError:
        return True
    return False


async def lock_keyring(address: str, store: SecretServiceStore) -> None:
    await lock_collection(address, LOGIN_COLLECTION)
    await lock_collection(address, store.collection)


async def test_locking_the_keyring_stops_serving_cached_passwords(
    private_bus: str, served: Served
) -> None:
    assert (await served.daemon.get("A")).password == "pw-A"
    await lock_keyring(private_bus, served.store)
    await wait_for(lambda: locked_out(served.daemon))
    with pytest.raises(LockedError):
        await served.daemon.list_items()


async def test_items_come_back_after_unlocking(private_bus: str, served: Served) -> None:
    await served.daemon.get("A")
    await lock_keyring(private_bus, served.store)
    await wait_for(lambda: locked_out(served.daemon))
    await unlock_collection(private_bus, LOGIN_COLLECTION)
    assert (await served.daemon.get("A")).password == "pw-A"
