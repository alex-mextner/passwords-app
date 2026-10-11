# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`changes()` wakes the sync on any item change, including Seahorse password edits."""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

import pytest
from dbus_fast import Variant
from tests.harness.dbus_session import LOGIN_COLLECTION
from tests.integration.keyring.support import cred, items_of, seahorse_create

from passwords_app.keyring import secret_service
from passwords_app.keyring.client import ITEM, SecretServiceClient

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from dbus_fast.aio import MessageBus

    from passwords_app.keyring.secret_service import SecretServiceStore

pytestmark = pytest.mark.integration

QUIET = 0.3  # long enough for a stray signal or file poll to arrive


@pytest.fixture(autouse=True)
def fast_file_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secret_service, "FILE_POLL_SECONDS", 0.05)


class Listener:
    """Counts notifications from `store.changes()` in the background."""

    def __init__(self, store: SecretServiceStore) -> None:
        self._stream = store.changes()
        self.count = 0
        self._consumed = 0
        self._changed = asyncio.Condition()
        self._task: asyncio.Task[None] | None = None

    async def start(self, store: SecretServiceStore) -> None:
        self._task = asyncio.create_task(self._run())
        await asyncio.sleep(0)  # let the generator send AddMatch
        # Any reply on the store's own connection comes after AddMatch was processed.
        await store.fetch()

    async def _run(self) -> None:
        async for _ in self._stream:
            async with self._changed:
                self.count += 1
                self._changed.notify_all()

    async def until(self, count: int) -> None:
        async with asyncio.timeout(5), self._changed:
            await self._changed.wait_for(lambda: self.count >= count)

    async def next(self) -> None:
        """Wait for a notification not yet consumed by an earlier `next()`."""
        await self.until(self._consumed + 1)
        self._consumed = self.count

    async def stop(self) -> None:
        assert self._task is not None
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task


@pytest.fixture
async def listener(store: SecretServiceStore) -> AsyncIterator[Listener]:
    listening = Listener(store)
    await listening.start(store)
    yield listening
    await listening.stop()


async def test_our_create_is_notified(store: SecretServiceStore, listener: Listener) -> None:
    await store.upsert(cred(1))
    await listener.next()


async def test_seahorse_create_is_notified(
    store: SecretServiceStore, seahorse: SecretServiceClient, listener: Listener
) -> None:
    await seahorse_create(seahorse, store.collection, "new @ example.com")
    await listener.next()


async def test_seahorse_secret_edit_is_notified(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    (path,) = await items_of(seahorse, store.collection)
    listening = Listener(store)
    await listening.start(store)
    try:
        await seahorse.set_secret(path, b"FAKE-CHANGED")
        await listening.next()
    finally:
        await listening.stop()


async def test_seahorse_label_edit_is_notified(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    (path,) = await items_of(seahorse, store.collection)
    listening = Listener(store)
    await listening.start(store)
    try:
        await seahorse.set_property(path, ITEM, "Label", Variant("s", "Renamed"))
        await listening.next()
    finally:
        await listening.stop()


async def test_seahorse_delete_is_notified(
    store: SecretServiceStore, seahorse: SecretServiceClient
) -> None:
    await store.upsert(cred(1))
    (path,) = await items_of(seahorse, store.collection)
    listening = Listener(store)
    await listening.start(store)
    try:
        await seahorse.delete_item(path)
        await listening.next()
    finally:
        await listening.stop()


async def test_other_collections_do_not_wake_the_sync(
    seahorse: SecretServiceClient, listener: Listener
) -> None:
    await seahorse_create(seahorse, LOGIN_COLLECTION, "unrelated @ example.com")
    await asyncio.sleep(QUIET)
    assert listener.count == 0


async def test_reading_does_not_wake_the_sync(
    store: SecretServiceStore, listener: Listener
) -> None:
    await store.fetch()
    await asyncio.sleep(QUIET)
    assert listener.count == 0


async def test_every_change_is_counted(
    store: SecretServiceStore, seahorse: SecretServiceClient, listener: Listener
) -> None:
    for n in range(1, 4):
        await store.upsert(cred(n))
    await store.delete(cred(1).id)
    await listener.until(4)


async def test_closing_the_stream_unsubscribes(
    store: SecretServiceStore, bus: MessageBus, seahorse: SecretServiceClient
) -> None:
    listening = Listener(store)
    await listening.start(store)
    await listening.stop()
    await seahorse_create(seahorse, store.collection, "after @ example.com")
    await asyncio.sleep(QUIET)
    assert listening.count == 0
    assert bus.connected
