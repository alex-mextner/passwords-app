# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Items people create or edit in Seahorse (S7-S9, S24, Review Focus 3)."""

from __future__ import annotations

import asyncio
import re
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from dbus_fast import Variant
from tests.integration.keyring.support import cred, items_of, raw_item, seahorse_create

from passwords_app.keyring.client import ITEM, SecretServiceClient
from passwords_app.keyring.secret_service import SecretServiceStore

if TYPE_CHECKING:
    from dbus_fast.aio import MessageBus

pytestmark = pytest.mark.integration

UUID = re.compile(r"^[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$")


async def test_seahorse_item_is_adopted_and_written_back(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    path = await seahorse_create(seahorse, store.collection, "alice @ example.com", "FAKE-S1")
    snapshot = await store.fetch()
    (credential,) = snapshot.items.values()
    assert UUID.match(credential.id)
    assert (credential.url, credential.username, credential.password) == (
        "https://example.com",
        "alice",
        "FAKE-S1",
    )
    label, attributes, value = await raw_item(seahorse, path)
    assert attributes["pa-id"] == credential.id
    assert attributes["xdg:schema"] == "io.github.alex_mextner.Passwords"
    assert attributes["url"] == "https://example.com"
    assert label == "example.com \u2014 alice"
    assert value == b"FAKE-S1"


async def test_adopted_id_is_stable_across_fetches(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await seahorse_create(seahorse, store.collection, "example.com bob")
    first = await store.fetch()
    second = await store.fetch()
    assert set(first.items) == set(second.items)
    assert len(second.items) == 1


async def test_concurrent_fetches_adopt_with_the_same_id(
    bus: MessageBus, other_bus: MessageBus, seahorse: SecretServiceClient
) -> None:
    # e.g. the daemon and the app fetching at once: both write back, both must agree.
    first_store = await SecretServiceStore.open(bus)
    second_store = await SecretServiceStore.open(other_bus)
    path = await seahorse_create(seahorse, first_store.collection, "alice @ example.com")
    first, second = await asyncio.gather(first_store.fetch(), second_store.fetch())
    assert set(first.items) == set(second.items)
    (credential_id,) = first.items
    _, attributes, _ = await raw_item(seahorse, path)
    assert attributes["pa-id"] == credential_id


async def test_adoption_that_cannot_be_written_back_is_rejected_not_fatal(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    attributes = {
        "xdg:schema": "io.github.alex_mextner.Passwords",
        "url": "https://restored.example",
        "alt-urls": "https://a.example\n",
    }
    bad = await seahorse.create_item(
        store.collection, "restored", attributes, b"FAKE-R", replace=False
    )
    await store.upsert(cred(1))
    snapshot = await store.fetch()
    assert set(snapshot.items) == {cred(1).id}
    assert [r.ref for r in snapshot.rejected] == [bad]


@pytest.mark.parametrize(
    ("label", "url", "username"),
    [
        ("alice @ example.com", "https://example.com", "alice"),
        ("example.com bob", "https://example.com", "bob"),
        ("https://x.example/ \u2014 carol", "https://x.example", "carol"),
        ("https://router.example/admin", "https://router.example/admin", ""),
        ("алиса @ пример.рф", "https://пример.рф", "алиса"),
        ("admin @ 192.168.1.1:8080", "https://192.168.1.1:8080", "admin"),
        ("😀 @ i❤.ws", "https://i❤.ws", "😀"),
    ],
)
async def test_label_shapes_adopt_through_the_real_keyring(
    store: SecretServiceStore,
    seahorse: SecretServiceClient,
    label: str,
    url: str,
    username: str,
) -> None:
    await seahorse_create(seahorse, store.collection, label)
    (credential,) = (await store.fetch()).items.values()
    assert (credential.url, credential.username) == (url, username)


@pytest.mark.parametrize(
    ("label", "reason"),
    [
        ("Gmail", "no website"),
        ("alice@example.com", "e-mail address"),
        ("ftp://files.example.com", "http and https"),
        ("bob @ straße.de", "invalid host"),
        ("", "empty"),
    ],
)
async def test_unparseable_item_is_reported_and_left_alone(
    store: SecretServiceStore, seahorse: SecretServiceClient, label: str, reason: str
) -> None:
    path = await seahorse_create(seahorse, store.collection, label, "FAKE-KEEP")
    before = await raw_item(seahorse, path)
    snapshot = await store.fetch()
    assert dict(snapshot.items) == {}
    (rejected,) = snapshot.rejected
    assert (rejected.ref, rejected.label) == (path, label)
    assert reason in rejected.reason
    assert await raw_item(seahorse, path) == before


async def test_rejected_items_do_not_hide_good_ones(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    await seahorse_create(seahorse, store.collection, "My notes")
    await seahorse_create(seahorse, store.collection, "dave @ example.org")
    snapshot = await store.fetch()
    assert len(snapshot.items) == 2
    assert cred(1).id in snapshot.items
    assert [r.label for r in snapshot.rejected] == ["My notes"]


async def test_binary_secret_is_rejected(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await seahorse.create_item(
        store.collection,
        "bin @ example.com",
        {"xdg:schema": "org.gnome.keyring.Note"},
        b"\xff\xfe\x00",
        replace=False,
        content_type="application/octet-stream",
    )
    (rejected,) = (await store.fetch()).rejected
    assert "not text" in rejected.reason


async def test_seahorse_password_edit_is_seen_as_a_newer_change(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    (path,) = await items_of(seahorse, store.collection)
    _, attributes, _ = await raw_item(seahorse, path)
    # Pretend our write happened a while ago; Seahorse then changes only the secret.
    attributes["pa-synced"] = str(int(time.time()) - 600)
    await seahorse.set_property(path, ITEM, "Attributes", Variant("a{ss}", attributes))
    edited_value = b"FAKE-EDITED"
    await seahorse.set_secret(path, edited_value)
    edited = (await store.fetch()).items[cred(1).id]
    assert edited.password.encode() == edited_value
    assert edited.modified > cred(1).modified
    assert abs((edited.modified - datetime.now(UTC)).total_seconds()) < 60


async def test_seahorse_rename_becomes_the_title(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    (path,) = await items_of(seahorse, store.collection)
    _, attributes, _ = await raw_item(seahorse, path)
    # A person renames long after our write.
    attributes["pa-synced"] = str(int(time.time()) - 600)
    await seahorse.set_property(path, ITEM, "Attributes", Variant("a{ss}", attributes))
    await seahorse.set_property(path, ITEM, "Label", Variant("s", "Work VPN \u2014 user1"))
    assert (await store.fetch()).items[cred(1).id].title == "Work VPN"


async def test_seahorse_rename_right_after_our_write_becomes_the_title(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    # Same second as our write: Modified cannot tell the two apart, the label read does.
    await store.upsert(cred(1))
    (path,) = await items_of(seahorse, store.collection)
    await seahorse.set_property(path, ITEM, "Label", Variant("s", "Work VPN \u2014 user1"))
    assert (await store.fetch()).items[cred(1).id].title == "Work VPN"


async def test_seahorse_delete_is_a_missing_item(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    await store.upsert(cred(2))
    first = (await seahorse.search(store.collection, {"pa-id": cred(1).id}))[0]
    await seahorse.delete_item(first)
    assert set((await store.fetch()).items) == {cred(2).id}


async def test_duplicate_ids_keep_the_oldest_and_report_the_rest(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    copy = await seahorse.create_item(
        store.collection,
        "copy",
        {
            "pa-id": cred(1).id,
            "xdg:schema": "io.github.alex_mextner.Passwords",
            "url": "https://copy.example",
        },
        b"FAKE-COPY",
        replace=False,
    )
    snapshot = await store.fetch()
    assert snapshot.items[cred(1).id] == cred(1)
    (rejected,) = snapshot.rejected
    assert rejected.ref == copy
    assert "already has this id" in rejected.reason


async def test_upsert_collapses_duplicate_ids(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    await seahorse.create_item(
        store.collection,
        "copy",
        {"pa-id": cred(1).id, "url": "https://copy.example"},
        b"FAKE-COPY",
        replace=False,
    )
    updated = cred(1, pw="FAKE-AFTER")
    await store.upsert(updated)
    assert len(await items_of(seahorse, store.collection)) == 1
    snapshot = await store.fetch()
    assert snapshot.items[updated.id] == updated
    assert snapshot.rejected == ()


async def test_first_sync_linking_inputs_are_complete(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    # S24: a collection people filled by hand before the first sync is read in full.
    labels = [f"user{n} @ site{n}.example.com" for n in range(1, 11)]
    for label in labels:
        await seahorse_create(seahorse, store.collection, label, f"FAKE-{label}")
    snapshot = await store.fetch()
    assert sorted((c.username, c.url) for c in snapshot.items.values()) == sorted(
        (f"user{n}", f"https://site{n}.example.com") for n in range(1, 11)
    )
    assert len({c.id for c in snapshot.items.values()}) == 10
