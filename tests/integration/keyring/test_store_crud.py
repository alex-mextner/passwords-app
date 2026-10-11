# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""SecretServiceStore against a real gnome-keyring: CRUD, fidelity, Unicode, isolation."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest
from tests.integration.keyring.support import cred, items_of, raw_item, seahorse_create

from passwords_app.keyring.client import TEXT, SecretServiceClient
from passwords_app.keyring.mapping import item_content
from passwords_app.keyring.secret_service import SecretServiceStore
from passwords_app.sync.ports import ConflictError

if TYPE_CHECKING:
    from dbus_fast.aio import MessageBus

    from passwords_app.core.model import Credential

pytestmark = pytest.mark.integration


async def test_new_collection_starts_empty(store: SecretServiceStore) -> None:
    snapshot = await store.fetch()
    assert dict(snapshot.items) == {}
    assert snapshot.rejected == ()


async def test_create_then_fetch(store: SecretServiceStore) -> None:
    await store.upsert(cred(1))
    snapshot = await store.fetch()
    assert dict(snapshot.items) == {cred(1).id: cred(1)}


async def test_update_keeps_a_single_item(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    changed = cred(1, pw="FAKE-NEW", username="renamed", title="Renamed site")
    await store.upsert(changed)
    assert dict((await store.fetch()).items) == {changed.id: changed}
    assert len(await items_of(seahorse, store.collection)) == 1


async def test_update_can_drop_optional_fields(store: SecretServiceStore) -> None:
    full = cred(1, notes="n", otpauth="otpauth://totp/x", alt_urls=("https://a",), group="g")
    await store.upsert(full)
    bare = cred(1)
    await store.upsert(bare)
    assert (await store.fetch()).items[bare.id] == bare


async def test_delete(store: SecretServiceStore) -> None:
    await store.upsert(cred(1))
    await store.upsert(cred(2))
    await store.delete(cred(1).id)
    assert set((await store.fetch()).items) == {cred(2).id}


async def test_delete_missing_id_is_a_no_op(store: SecretServiceStore) -> None:
    await store.upsert(cred(1))
    await store.delete("NOT-THERE")
    assert set((await store.fetch()).items) == {cred(1).id}


async def test_many_items_keep_their_identity(store: SecretServiceStore) -> None:
    creds = [cred(n) for n in range(1, 31)]
    for c in creds:
        await store.upsert(c)
    assert dict((await store.fetch()).items) == {c.id: c for c in creds}


async def test_stored_item_matches_the_spec_layout(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    c = cred(1, title="Bank", notes="pin hint", alt_urls=("https://m.site1.example.com",))
    await store.upsert(c)
    (path,) = await items_of(seahorse, store.collection)
    label, attributes, value = await raw_item(seahorse, path)
    expected = item_content(c, written_at=0)
    assert label == "Bank \u2014 user1"
    assert value == b"FAKE-PW-1"
    synced = attributes.pop("pa-synced")
    assert abs(int(synced) - datetime.now(UTC).timestamp()) < 60
    assert attributes == {k: v for k, v in expected.attributes.items() if k != "pa-synced"}


async def test_items_carry_the_schema_libsecret_apps_search_by(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    await store.upsert(cred(2))
    found = await seahorse.search(
        store.collection,
        {"xdg:schema": "io.github.alex_mextner.Passwords", "server": "site2.example.com"},
    )
    assert len(found) == 1
    assert (await raw_item(seahorse, found[0]))[2] == b"FAKE-PW-2"


UNICODE_CASES = [
    pytest.param(
        cred(1, url="https://пример.рф/вход", username="алиса", pw="пароль-ёж"), id="cyrillic"
    ),
    pytest.param(cred(1, title="🔑 Банк 🏦", username="😀", pw="🙈🙉🙊"), id="emoji"),
    pytest.param(cred(1, url="https://例子.测试", username="用户", pw="密码"), id="cjk"),
    pytest.param(
        cred(1, url="https://münchen.de", username="Jörg", notes="Grüße\nZeile 2"), id="umlauts"
    ),
    pytest.param(cred(1, username="", title="no user"), id="empty-username"),
    pytest.param(cred(1, url="https://192.168.1.1:8443/admin", username="admin"), id="ip-port"),
    pytest.param(cred(1, url="https://[2001:db8::1]:8080", username="root"), id="ipv6"),
    pytest.param(cred(1, pw="x" * 20_000, notes="n" * 10_000), id="long"),
    pytest.param(cred(1, pw=""), id="empty-password"),
    pytest.param(cred(1, pw="tab\tnew\nline\u0000nul"), id="control-chars-in-password"),
    pytest.param(cred(1, username="a \u2014 b", title="x \u2014 y"), id="separator-inside"),
    pytest.param(
        cred(
            1,
            created=datetime(
                2001, 2, 3, 4, 5, 6, 7, tzinfo=timezone(timedelta(hours=5, minutes=30))
            ),
            modified=datetime(2030, 1, 1, tzinfo=timezone(timedelta(hours=-11))),
        ),
        id="odd-timezones",
    ),
]


@pytest.mark.parametrize("credential", UNICODE_CASES)
async def test_round_trip_through_gnome_keyring(
    store: SecretServiceStore, credential: Credential
) -> None:
    await store.upsert(credential)
    fetched = (await store.fetch()).items[credential.id]
    assert fetched == credential
    assert fetched.content_hash() == credential.content_hash()


async def test_reopening_sees_the_same_items(store: SecretServiceStore, bus: MessageBus) -> None:
    await store.upsert(cred(1))
    reopened = await SecretServiceStore.open(bus)
    assert reopened.collection == store.collection
    assert dict((await reopened.fetch()).items) == {cred(1).id: cred(1)}


async def test_other_collections_are_never_read(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    # What other apps keep in the login keyring must never look like credentials to sync.
    login = "/org/freedesktop/secrets/collection/login"
    await seahorse_create(seahorse, login, "Chrome Safe Storage", "FAKE-CHROME")
    await seahorse_create(seahorse, login, "alice @ example.com", "FAKE-LOGIN")
    await seahorse.create_item(
        login,
        "GOA google account",
        {"goa-identity": "google:account_1"},
        b"FAKE-TOKEN",
        replace=False,
    )
    await seahorse.create_item(
        login,
        "Home Wi-Fi",
        {"setting-name": "802-11-wireless-security", "setting-key": "psk"},
        b"FAKE-PSK",
        replace=False,
    )
    snapshot = await store.fetch()
    assert dict(snapshot.items) == {}
    assert snapshot.rejected == ()


async def test_two_labels_are_two_independent_collections(bus: MessageBus) -> None:
    first = await SecretServiceStore.open(bus, label="iCloud Passwords")
    second = await SecretServiceStore.open(bus, label="Test Passwords")
    assert first.collection != second.collection
    await first.upsert(cred(1))
    await second.upsert(cred(2))
    assert set((await first.fetch()).items) == {cred(1).id}
    assert set((await second.fetch()).items) == {cred(2).id}


async def test_upsert_refuses_unstorable_alt_urls_without_writing(
    store: SecretServiceStore,
) -> None:
    with pytest.raises(ValueError, match="alternative URLs"):
        await store.upsert(replace(cred(1), alt_urls=("a\nb",)))
    assert dict((await store.fetch()).items) == {}


async def test_update_with_unstorable_text_leaves_the_item_untouched(
    store: SecretServiceStore,
) -> None:
    await store.upsert(cred(1))
    with pytest.raises(ValueError, match="NUL"):
        await store.upsert(cred(1, pw="FAKE-NEW", username="bob", notes="a\x00b"))
    assert dict((await store.fetch()).items) == {cred(1).id: cred(1)}


async def test_fetch_never_sees_a_half_written_update(
    store: SecretServiceStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An update is secret, then attributes, then label; pause right after the secret.
    old = cred(1)
    new = cred(1, pw="FAKE-NEW", url="https://new.example", username="bob")
    await store.upsert(old)
    secret_written = asyncio.Event()
    resume = asyncio.Event()
    set_secret = SecretServiceClient.set_secret

    async def paused_set_secret(
        self: SecretServiceClient, item: str, value: bytes, content_type: str = TEXT
    ) -> None:
        await set_secret(self, item, value, content_type)
        secret_written.set()
        await resume.wait()

    monkeypatch.setattr(SecretServiceClient, "set_secret", paused_set_secret)
    write = asyncio.create_task(store.upsert(new))
    await secret_written.wait()
    read = asyncio.create_task(store.fetch())
    await asyncio.sleep(0.2)
    assert not read.done()
    resume.set()
    await write
    assert dict((await read).items) == {new.id: new}


async def test_write_is_stamped_when_it_happens_not_when_it_was_requested(
    store: SecretServiceStore, seahorse: SecretServiceClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A write that waited (lock, unlock) must not later read as someone else's edit; hold
    # the store busy while the upsert queues.
    async with store._io:  # pyright: ignore[reportPrivateUsage]
        write = asyncio.create_task(store.upsert(cred(1)))
        await asyncio.sleep(0.1)
        stamp = int(time.time()) + 5
        monkeypatch.setattr(time, "time", lambda: float(stamp))
    await write
    (path,) = await items_of(seahorse, store.collection)
    _, attributes, _ = await raw_item(seahorse, path)
    assert attributes["pa-synced"] == str(stamp)
    assert dict((await store.fetch()).items) == {cred(1).id: cred(1)}


# ---------------------------------------------------------------- conditional writes


async def _edit_in_seahorse(seahorse: SecretServiceClient, store: SecretServiceStore) -> None:
    (path,) = await items_of(seahorse, store.collection)
    await seahorse.set_secret(path, b"FAKE-TYPED-IN-SEAHORSE")


async def test_conditional_update_of_the_version_read_writes(store: SecretServiceStore) -> None:
    await store.upsert(cred(1))
    changed = cred(1, pw="FAKE-NEW")
    await store.upsert(changed, expected=cred(1).content_hash())
    assert (await store.fetch()).items[changed.id] == changed


async def test_conditional_update_refuses_an_item_edited_since(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    await _edit_in_seahorse(seahorse, store)
    with pytest.raises(ConflictError):
        await store.upsert(cred(1, pw="FAKE-NEW"), expected=cred(1).content_hash())
    assert (await store.fetch()).items[cred(1).id].password == "FAKE-TYPED-IN-SEAHORSE"


async def test_conditional_update_refuses_an_item_deleted_since(
    store: SecretServiceStore,
) -> None:
    with pytest.raises(ConflictError):
        await store.upsert(cred(1), expected=cred(1).content_hash())
    assert dict((await store.fetch()).items) == {}


async def test_conditional_delete_refuses_an_item_edited_since(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    await _edit_in_seahorse(seahorse, store)
    with pytest.raises(ConflictError):
        await store.delete(cred(1).id, expected=cred(1).content_hash())
    assert set((await store.fetch()).items) == {cred(1).id}
    await store.delete(cred(1).id, expected=None)
    assert dict((await store.fetch()).items) == {}


async def test_conditional_delete_of_a_missing_item_is_a_no_op(store: SecretServiceStore) -> None:
    await store.delete("NOT-THERE", expected=cred(1).content_hash())
