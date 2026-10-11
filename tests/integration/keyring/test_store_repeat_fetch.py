# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""A repeat fetch reuses what it read before only while the item's ``Modified`` stood still.

gnome-keyring looks every item up by scanning all of them, so each property read costs
O(items); a repeat fetch of an unchanged collection reads only ``Modified`` per item. These
tests pin down that every kind of edit between two fetches is still seen.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest
from dbus_fast import Variant
from tests.harness.dbus_session import LOGIN_COLLECTION, lock_collection
from tests.integration.keyring.support import (
    cred,
    items_of,
    next_second,
    raw_item,
    seahorse_create,
    spy_property_reads,
)

from passwords_app.keyring.client import ITEM, SecretServiceClient
from passwords_app.sync.ports import LocalUnavailable

if TYPE_CHECKING:
    from passwords_app.keyring.secret_service import SecretServiceStore

pytestmark = pytest.mark.integration


async def test_repeat_fetch_of_unchanged_items_reads_only_their_modified(
    store: SecretServiceStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    for n in range(1, 4):
        await store.upsert(cred(n))
    await next_second()
    first = await store.fetch()
    reads = spy_property_reads(monkeypatch)
    second = await store.fetch()
    assert second == first
    assert sorted(reads) == ["Items", "Locked", "Locked", "Modified", "Modified", "Modified"]


async def test_item_modified_in_the_second_the_fetch_began_is_read_again(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    # gnome-keyring's Modified has one-second resolution: a rename in the same second as
    # the fetch that read the item leaves Modified unchanged, so that read is not reused.
    await store.upsert(cred(1))
    (path,) = await items_of(seahorse, store.collection)
    await next_second()
    began = int(time.time())
    await store.upsert(cred(1, username="bob"))
    await store.fetch()
    await seahorse.set_property(path, ITEM, "Label", Variant("s", "Work VPN \u2014 bob"))
    renamed = await store.fetch()
    assert int(time.time()) == began, "the edit must land in the second the fetch began"
    assert renamed.items[cred(1).id].title == "Work VPN"


async def test_rename_after_a_fetch_is_seen(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    (path,) = await items_of(seahorse, store.collection)
    await next_second()
    await store.fetch()
    await seahorse.set_property(path, ITEM, "Label", Variant("s", "Work VPN \u2014 user1"))
    assert (await store.fetch()).items[cred(1).id].title == "Work VPN"


async def test_attribute_edit_after_a_fetch_is_seen(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    (path,) = await items_of(seahorse, store.collection)
    await next_second()
    await store.fetch()
    _, attributes, _ = await raw_item(seahorse, path)
    attributes["notes"] = "edited elsewhere"
    await seahorse.set_property(path, ITEM, "Attributes", Variant("a{ss}", attributes))
    assert (await store.fetch()).items[cred(1).id].notes == "edited elsewhere"


async def test_password_edit_after_a_fetch_is_seen_as_newer(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    (path,) = await items_of(seahorse, store.collection)
    _, attributes, _ = await raw_item(seahorse, path)
    attributes["pa-synced"] = str(int(time.time()) - 600)
    await seahorse.set_property(path, ITEM, "Attributes", Variant("a{ss}", attributes))
    await next_second()
    before = (await store.fetch()).items[cred(1).id]
    await next_second()
    edited_value = b"FAKE-EDITED"
    await seahorse.set_secret(path, edited_value)
    edited = (await store.fetch()).items[cred(1).id]
    assert edited.password.encode() == edited_value
    assert edited.modified > before.modified


async def test_item_replaced_after_a_fetch_is_read_afresh(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    # gnome-keyring may hand a deleted item's path to the next item it creates.
    await store.upsert(cred(1))
    await store.upsert(cred(2))
    await next_second()
    await store.fetch()
    await store.delete(cred(2).id)
    await seahorse_create(seahorse, store.collection, "carol @ site3.example.com", "FAKE-NEW")
    snapshot = await store.fetch()
    assert {(c.username, c.password) for c in snapshot.items.values()} == {
        ("user1", "FAKE-PW-1"),
        ("carol", "FAKE-NEW"),
    }


async def test_collection_locked_during_a_repeat_fetch(
    store: SecretServiceStore, private_bus: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    for n in range(1, 4):
        await store.upsert(cred(n))
    await next_second()
    await store.fetch()
    original = SecretServiceClient.get_property
    locked = False

    async def lock_then_read(
        self: SecretServiceClient, path: str, interface: str, name: str
    ) -> object:
        nonlocal locked
        if not locked and name == "Modified":
            locked = True
            await lock_collection(private_bus, store.collection)
            await lock_collection(private_bus, LOGIN_COLLECTION)
        return await original(self, path, interface, name)

    monkeypatch.setattr(SecretServiceClient, "get_property", lock_then_read)
    with pytest.raises(LocalUnavailable, match="locked"):
        await store.fetch()
    assert locked
