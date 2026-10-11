# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""ADR 0001 evidence: an encrypted dedicated collection that unlocks without any prompt."""

from __future__ import annotations

import asyncio
import subprocess
import time
from typing import TYPE_CHECKING

import pytest
from dbus_fast import Message, MessageType, Variant
from tests.harness.dbus_session import LOGIN_COLLECTION, PrivateSession, lock_collection
from tests.integration.keyring.support import cred, kill_keyring_daemon

from passwords_app.keyring import collection as collection_module
from passwords_app.keyring.client import (
    COLLECTION,
    ITEM,
    SERVICE,
    SERVICE_PATH,
    SecretServiceClient,
)
from passwords_app.keyring.collection import keyring_location
from passwords_app.keyring.secret_service import SecretServiceStore

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dbus_fast.aio import MessageBus

pytestmark = pytest.mark.integration

LOCATION = "LOCAL:/keyrings/iCloud_Passwords.keyring"


async def unlock_items(client: SecretServiceClient) -> list[str]:
    return await client.search(LOGIN_COLLECTION, {"application": "passwords-app"})


async def test_collection_is_named_and_findable(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    assert store.collection in await seahorse.collections()
    assert await seahorse.get_property(store.collection, COLLECTION, "Label") == "iCloud Passwords"
    assert keyring_location(store.collection) == LOCATION


async def test_opening_twice_does_not_create_a_second_collection(
    store: SecretServiceStore, bus: MessageBus, seahorse: SecretServiceClient
) -> None:
    before = await seahorse.collections()
    again = await SecretServiceStore.open(bus)
    assert again.collection == store.collection
    assert await seahorse.collections() == before
    assert len(await unlock_items(seahorse)) == 1


async def test_simultaneous_first_opens_share_one_collection(
    bus: MessageBus, other_bus: MessageBus, seahorse: SecretServiceClient
) -> None:
    first, second = await asyncio.gather(
        SecretServiceStore.open(bus), SecretServiceStore.open(other_bus)
    )
    assert first.collection == second.collection
    labels = [
        await seahorse.get_property(path, COLLECTION, "Label")
        for path in await seahorse.collections()
    ]
    assert labels.count("iCloud Passwords") == 1
    await first.upsert(cred(1))
    assert set((await second.fetch()).items) == {cred(1).id}


async def test_keyring_file_is_encrypted(
    store: SecretServiceStore, private_session: PrivateSession
) -> None:
    secret_bits = cred(1, notes="FAKE-NOTE-TEXT", otpauth="otpauth://totp/x?secret=FAKEOTPSEED")
    await store.upsert(secret_bits)
    await lock_collection(private_session.address, store.collection)
    data = (private_session.root / "data" / "keyrings" / "iCloud_Passwords.keyring").read_bytes()
    assert data.startswith(b"GnomeKeyring\n\r\x00\n")
    for plaintext in (b"FAKE-PW-1", b"FAKE-NOTE-TEXT", b"FAKEOTPSEED", b"user1"):
        assert plaintext not in data


async def test_unlock_password_lives_in_the_login_keyring_as_gnome_keyring_expects(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    (item,) = await unlock_items(seahorse)
    props = await seahorse.get_all(item, ITEM)
    assert props["Label"] == "Unlock password for: iCloud Passwords"
    assert props["Attributes"]["keyring"] == LOCATION
    value = (await seahorse.get_secrets([item]))[item]
    assert len(value.decode()) >= 40  # 32 random bytes, URL-safe base64
    assert store.collection.startswith("/org/freedesktop/secrets/collection/")


async def _standard_unlock(bus: MessageBus, collection: str) -> tuple[bool, list[str]]:
    """What Seahorse/libsecret do: Service.Unlock, then run the returned prompt."""
    client = await SecretServiceClient.open(bus)
    unlocked, prompt = await client.call(SERVICE_PATH, SERVICE, "Unlock", "ao", [[collection]])
    if prompt == "/":
        return False, list(unlocked)
    completed: asyncio.Future[list[object]] = asyncio.get_running_loop().create_future()

    def on_message(message: Message) -> None:
        if message.member == "Completed" and message.path == prompt and not completed.done():
            completed.set_result(list(message.body))

    bus.add_message_handler(on_message)
    await bus.call(
        Message(
            destination="org.freedesktop.DBus",
            path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus",
            member="AddMatch",
            signature="s",
            body=[f"type='signal',path='{prompt}'"],
        )
    )
    await client.call(prompt, "org.freedesktop.Secret.Prompt", "Prompt", "s", [""])
    dismissed, result = await asyncio.wait_for(completed, 10)
    assert isinstance(dismissed, bool)
    assert isinstance(result, Variant)
    return dismissed, list(result.value)


async def test_other_apps_unlock_it_without_a_password_dialog(
    store: SecretServiceStore, other_bus: MessageBus, private_bus: str
) -> None:
    # The sandbox bus has no prompter at all: success proves no dialog was needed.
    await lock_collection(private_bus, store.collection)
    dismissed, unlocked = await _standard_unlock(other_bus, store.collection)
    assert dismissed is False
    assert unlocked == [store.collection]


async def test_without_the_stored_password_other_apps_would_need_a_dialog(
    store: SecretServiceStore,
    other_bus: MessageBus,
    private_bus: str,
    seahorse: SecretServiceClient,
) -> None:
    for item in await unlock_items(seahorse):
        await seahorse.delete_item(item)
    await lock_collection(private_bus, store.collection)
    dismissed, unlocked = await _standard_unlock(other_bus, store.collection)
    assert (dismissed, unlocked) == (True, [])


async def test_standard_create_collection_would_prompt(seahorse: SecretServiceClient) -> None:
    # Why we use CreateWithMasterPassword: the standard call always needs a dialog.
    _path, prompt = await seahorse.call(
        SERVICE_PATH,
        SERVICE,
        "CreateCollection",
        "a{sv}s",
        [{f"{COLLECTION}.Label": Variant("s", "Prompted")}, ""],
    )
    assert prompt != "/"


async def test_interrupted_creation_is_repaired_on_next_unlock(
    store: SecretServiceStore, private_bus: str, seahorse: SecretServiceClient
) -> None:
    # Crash after creating the collection but before pointing the password at it.
    (item,) = await unlock_items(seahorse)
    attributes = dict(await seahorse.get_property(item, ITEM, "Attributes"))
    del attributes["keyring"]
    await seahorse.set_property(item, ITEM, "Attributes", Variant("a{ss}", attributes))
    await store.upsert(cred(1))
    await lock_collection(private_bus, store.collection)
    assert set((await store.fetch()).items) == {cred(1).id}
    repaired = await seahorse.get_property(item, ITEM, "Attributes")
    assert repaired["keyring"] == LOCATION


async def test_recreated_collection_drops_the_stale_password(
    store: SecretServiceStore, bus: MessageBus, private_bus: str, seahorse: SecretServiceClient
) -> None:
    await seahorse.call(store.collection, COLLECTION, "Delete")
    fresh = await SecretServiceStore.open(bus)
    (item,) = await unlock_items(seahorse)
    assert (await seahorse.get_property(item, ITEM, "Attributes"))["keyring"] == keyring_location(
        fresh.collection
    )
    await fresh.upsert(cred(1))
    await lock_collection(private_bus, fresh.collection)
    assert set((await fresh.fetch()).items) == {cred(1).id}


async def _pending_password(seahorse: SecretServiceClient) -> str:
    # Another opener mid-creation: password stored, collection not created/pointed at yet.
    return await seahorse.create_item(
        LOGIN_COLLECTION,
        "Unlock password for: iCloud Passwords",
        {
            "application": "passwords-app",
            "type": "keyring-password",
            "pa-keyring": "iCloud Passwords",
        },
        b"FAKE-IN-FLIGHT",
        replace=False,
    )


async def test_concurrent_creation_keeps_the_other_openers_pending_password(
    bus: MessageBus, seahorse: SecretServiceClient
) -> None:
    in_flight = await _pending_password(seahorse)
    await SecretServiceStore.open(bus)
    assert in_flight in await unlock_items(seahorse)


async def test_creation_drops_an_abandoned_pending_password(
    bus: MessageBus, seahorse: SecretServiceClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    abandoned = await _pending_password(seahorse)
    monkeypatch.setattr(collection_module, "PENDING_GRACE_SECONDS", -1)
    await SecretServiceStore.open(bus)
    assert abandoned not in await unlock_items(seahorse)
    assert len(await unlock_items(seahorse)) == 1


async def test_renamed_collection_keeps_its_password(
    store: SecretServiceStore, bus: MessageBus, private_bus: str, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    await seahorse.set_property(store.collection, COLLECTION, "Label", Variant("s", "Old iCloud"))
    fresh = await SecretServiceStore.open(bus)
    assert fresh.collection != store.collection
    assert len(await unlock_items(seahorse)) == 2
    await lock_collection(private_bus, store.collection)
    old = await SecretServiceStore.open(bus, label="Old iCloud")
    assert set((await old.fetch()).items) == {cred(1).id}


@pytest.fixture
def restarted_keyring(private_session: PrivateSession) -> Iterator[subprocess.Popen[bytes]]:
    """Simulate a reboot: a new gnome-keyring on the same data, login unlocked by PAM."""
    kill_keyring_daemon(private_session.root)
    time.sleep(0.2)
    proc = subprocess.Popen(
        ["/usr/bin/gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=dict(private_session.env),
    )
    assert proc.stdin is not None
    proc.stdin.write(private_session.password.encode())
    proc.stdin.close()
    yield proc
    proc.kill()
    proc.wait(5)


async def _wait_for_service(bus: MessageBus) -> None:
    for _ in range(200):
        reply = await bus.call(
            Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="NameHasOwner",
                signature="s",
                body=["org.freedesktop.secrets"],
            )
        )
        assert reply.message_type == MessageType.METHOD_RETURN
        if reply.body[0]:
            return
        await asyncio.sleep(0.05)
    msg = "restarted keyring did not appear"
    raise AssertionError(msg)


async def test_items_survive_a_restart_and_unlock_silently(
    private_session: PrivateSession, bus: MessageBus, request: pytest.FixtureRequest
) -> None:
    first = await SecretServiceStore.open(bus)
    await first.upsert(cred(1, notes="kept"))
    await first.upsert(cred(2))
    request.getfixturevalue("restarted_keyring")
    await _wait_for_service(bus)
    reopened = await SecretServiceStore.open(bus)
    assert reopened.collection == first.collection
    assert dict((await reopened.fetch()).items) == {
        cred(1).id: cred(1, notes="kept"),
        cred(2).id: cred(2),
    }


async def test_same_label_tie_prefers_the_collection_we_can_unlock(
    store: SecretServiceStore, bus: MessageBus, seahorse: SecretServiceClient
) -> None:
    # Someone makes another keyring and names it "iCloud Passwords" too; its path sorts
    # first, but only ours has an unlock password we hold.
    other = await seahorse.create_with_master_password("AAA", "FAKE-OTHER-KEYRING")
    await seahorse.set_property(other, COLLECTION, "Label", Variant("s", "iCloud Passwords"))
    assert min([other, store.collection]) == other
    reopened = await SecretServiceStore.open(bus)
    assert reopened.collection == store.collection
