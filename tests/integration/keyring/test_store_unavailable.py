# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Review Focus 1: a keyring we cannot fully read must raise, never look empty (S17)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from tests.harness.dbus_session import (
    KEYRING_PASSWORD,
    LOGIN_COLLECTION,
    PrivateSession,
    lock_collection,
    unlock_collection,
)
from tests.integration.keyring.support import (
    cred,
    items_of,
    kill_keyring_daemon,
    seahorse_create,
)

from passwords_app.keyring.client import COLLECTION, SecretServiceClient
from passwords_app.keyring.secret_service import SecretServiceStore
from passwords_app.sync.ports import LocalUnavailable

if TYPE_CHECKING:
    from dbus_fast.aio import MessageBus

pytestmark = pytest.mark.integration


async def lock_everything(address: str, store: SecretServiceStore) -> None:
    await lock_collection(address, store.collection)
    await lock_collection(address, LOGIN_COLLECTION)


async def test_locked_keyring_fetch_raises_instead_of_returning_empty(
    store: SecretServiceStore, private_bus: str
) -> None:
    await store.upsert(cred(1))
    await lock_everything(private_bus, store)
    with pytest.raises(LocalUnavailable, match="login keyring is locked"):
        await store.fetch()


@pytest.mark.parametrize("operation", ["upsert", "delete"])
async def test_locked_keyring_refuses_writes(
    store: SecretServiceStore, private_bus: str, seahorse: SecretServiceClient, operation: str
) -> None:
    await store.upsert(cred(1))
    await lock_everything(private_bus, store)
    write = store.upsert(cred(2)) if operation == "upsert" else store.delete(cred(1).id)
    with pytest.raises(LocalUnavailable):
        await write
    await unlock_collection(private_bus, LOGIN_COLLECTION, KEYRING_PASSWORD)
    assert set((await store.fetch()).items) == {cred(1).id}
    assert len(await items_of(seahorse, store.collection)) == 1


async def test_unlocking_the_login_keyring_makes_sync_work_again(
    store: SecretServiceStore, private_bus: str
) -> None:
    await store.upsert(cred(1))
    await lock_everything(private_bus, store)
    with pytest.raises(LocalUnavailable):
        await store.fetch()
    await unlock_collection(private_bus, LOGIN_COLLECTION, KEYRING_PASSWORD)
    assert set((await store.fetch()).items) == {cred(1).id}


async def test_collection_locked_alone_is_unlocked_silently(
    store: SecretServiceStore, private_bus: str, seahorse: SecretServiceClient
) -> None:
    # e.g. after login: gnome-keyring unlocks only "login"; ours is unlocked without a prompt.
    await store.upsert(cred(1))
    await lock_collection(private_bus, store.collection)
    assert await seahorse.is_locked(store.collection) is True
    assert set((await store.fetch()).items) == {cred(1).id}
    assert await seahorse.is_locked(store.collection) is False


async def test_missing_unlock_password_means_unavailable(
    store: SecretServiceStore, private_bus: str, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    for item in await seahorse.search(LOGIN_COLLECTION, {"application": "passwords-app"}):
        await seahorse.delete_item(item)
    await lock_collection(private_bus, store.collection)
    with pytest.raises(LocalUnavailable, match="no stored password"):
        await store.fetch()


async def test_wrong_unlock_password_means_unavailable(
    store: SecretServiceStore, private_bus: str, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    for item in await seahorse.search(LOGIN_COLLECTION, {"application": "passwords-app"}):
        await seahorse.set_secret(item, b"not-the-password")
    await lock_collection(private_bus, store.collection)
    with pytest.raises(LocalUnavailable):
        await store.fetch()


async def test_collection_deleted_by_the_user_is_unavailable_not_empty(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    await seahorse.call(store.collection, COLLECTION, "Delete")
    with pytest.raises(LocalUnavailable):
        await store.fetch()
    # It is not silently recreated behind the engine's back either.
    assert store.collection not in await seahorse.collections()


async def test_keyring_daemon_gone_is_unavailable(
    store: SecretServiceStore, private_session: PrivateSession
) -> None:
    await store.upsert(cred(1))
    kill_keyring_daemon(private_session.root)
    with pytest.raises(LocalUnavailable):
        await store.fetch()
    with pytest.raises(LocalUnavailable):
        await store.upsert(cred(2))


async def test_open_without_a_secret_service_is_unavailable(
    bus: MessageBus, private_session: PrivateSession
) -> None:
    kill_keyring_daemon(private_session.root)
    with pytest.raises(LocalUnavailable):
        await SecretServiceStore.open(bus)


async def test_open_with_locked_login_and_no_collection_is_unavailable(
    bus: MessageBus, private_bus: str, seahorse: SecretServiceClient
) -> None:
    await lock_collection(private_bus, LOGIN_COLLECTION)
    with pytest.raises(LocalUnavailable, match="login keyring is locked"):
        await SecretServiceStore.open(bus)
    labels = [
        await seahorse.get_property(path, COLLECTION, "Label")
        for path in await seahorse.collections()
    ]
    assert "iCloud Passwords" not in labels


async def test_disconnected_bus_is_unavailable(store: SecretServiceStore, bus: MessageBus) -> None:
    await store.upsert(cred(1))
    bus.disconnect()
    with pytest.raises(LocalUnavailable):
        await store.fetch()


@pytest.mark.parametrize(
    "read",
    [
        ("get_secrets", None),
        ("get_property", "Attributes"),
        ("get_property", "Modified"),
        ("get_property", "Label"),
        ("get_property", "Created"),
    ],
    ids=lambda read: read[1] or read[0],
)
async def test_collection_locked_in_the_middle_of_a_fetch(
    store: SecretServiceStore,
    private_bus: str,
    monkeypatch: pytest.MonkeyPatch,
    read: tuple[str, str | None],
) -> None:
    # The user hits "Lock" in Seahorse while we read: whichever read comes back locked,
    # it must not turn into "these items are gone".
    method, trigger = read
    for n in range(1, 6):
        await store.upsert(cred(n))
    # An unparsable item never gets a pa-id, so every fetch reads its label and creation.
    await seahorse_create(store._client, store.collection, "Gmail")
    original = getattr(SecretServiceClient, method)
    locked = False

    async def lock_then_call(self: SecretServiceClient, *args: object) -> object:
        nonlocal locked
        if not locked and (trigger is None or trigger in args):
            locked = True
            await lock_collection(private_bus, store.collection)
            await lock_collection(private_bus, LOGIN_COLLECTION)
        return await original(self, *args)

    monkeypatch.setattr(SecretServiceClient, method, lock_then_call)
    with pytest.raises(LocalUnavailable, match="locked"):
        await store.fetch()
    assert locked


async def test_synced_item_turned_unreadable_pauses_instead_of_vanishing(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    # Missing from the snapshot would read as a local delete and remove it from iCloud.
    await store.upsert(cred(1))
    await store.upsert(cred(2))
    (path,) = await seahorse.search(store.collection, {"pa-id": cred(1).id})
    await seahorse.set_secret(path, b"\xff\xfe not utf-8")
    with pytest.raises(LocalUnavailable, match="cannot be read"):
        await store.fetch()


async def test_unreadable_duplicate_of_a_readable_item_is_only_reported(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    attributes = {"xdg:schema": "io.github.alex_mextner.Passwords", "pa-id": cred(1).id}
    copy = await seahorse.create_item(
        store.collection, "copy", attributes, b"\xff not utf-8", replace=False
    )
    snapshot = await store.fetch()
    assert set(snapshot.items) == {cred(1).id}
    assert [r.ref for r in snapshot.rejected] == [copy]
