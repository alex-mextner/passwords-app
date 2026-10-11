# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The properties a fetch read survive a daemon restart, sealed in state.db (#64).

gnome-keyring looks every item up by scanning all of them, so the first fetch of a store
that knows nothing reads three properties per item at O(items) each. A store opened with the
cache an earlier store saved reads only ``Modified`` per unchanged item, like a repeat fetch.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import time
from typing import TYPE_CHECKING

import pytest
from dbus_fast import Variant
from tests.integration.keyring.support import cred, items_of, next_second, spy_property_reads

from passwords_app.keyring import secret_service
from passwords_app.keyring.client import ITEM, SecretServiceClient, SecretServiceError
from passwords_app.keyring.secret_service import SAVED_PROPERTIES_KEY, SecretServiceStore
from passwords_app.store.state import KEY_SIZE, StateStore
from passwords_app.sync.ports import LocalUnavailable

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dbus_fast.aio import MessageBus


pytestmark = pytest.mark.integration

ONLY_MODIFIED = ["Items", "Locked", "Locked", "Modified", "Modified", "Modified"]


@pytest.fixture
def state(tmp_path: Path) -> Iterator[StateStore]:
    with StateStore(tmp_path / "state.db", os.urandom(KEY_SIZE)) as store:
        yield store


class Clock:
    """Stands in for the `time` module of `secret_service`: a wall clock set off by `ahead`."""

    def __init__(self, *, ahead: float) -> None:
        self._ahead = ahead

    def time(self) -> float:
        return time.time() + self._ahead


async def service_gone(_client: SecretServiceClient, _items: list[str]) -> dict[str, bytes]:
    msg = "the Secret Service went away"
    raise SecretServiceError(msg)


def files_in(directory: Path) -> bytes:
    """Every byte state.db and its journal files hold on disk."""
    return b"".join(p.read_bytes() for p in directory.iterdir() if p.is_file())


async def fetched_three(bus: MessageBus, state: StateStore) -> SecretServiceStore:
    """A store that saw three items, all modified before its fetch's second began."""
    store = await SecretServiceStore.open(bus, saved=state)
    for n in range(1, 4):
        await store.upsert(cred(n))
    await next_second()
    await store.fetch()
    return store


async def test_store_opened_after_a_restart_reads_only_modified(
    bus: MessageBus, state: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = await (await fetched_three(bus, state)).fetch()
    restarted = await SecretServiceStore.open(bus, saved=state)
    reads = spy_property_reads(monkeypatch)
    assert await restarted.fetch() == before
    assert sorted(reads) == ONLY_MODIFIED


async def test_edit_made_while_the_daemon_was_down_is_seen(
    bus: MessageBus, state: StateStore, seahorse: SecretServiceClient
) -> None:
    store = await fetched_three(bus, state)
    paths = await items_of(seahorse, store.collection)
    await seahorse.set_property(min(paths), ITEM, "Label", Variant("s", "Work VPN \u2014 user1"))
    restarted = await SecretServiceStore.open(bus, saved=state)
    assert (await restarted.fetch()).items[cred(1).id].title == "Work VPN"


async def test_saved_properties_hold_no_secret_and_no_plaintext(
    bus: MessageBus, state: StateStore, tmp_path: Path
) -> None:
    await fetched_three(bus, state)
    saved = state.get(SAVED_PROPERTIES_KEY)
    assert saved is not None
    assert "user1" in saved  # usernames are in it, which is why the row is sealed
    assert "FAKE-PW" not in saved
    on_disk = files_in(tmp_path)
    assert b"user1" not in on_disk
    assert b"site1.example.com" not in on_disk


async def test_cache_saved_under_a_later_clock_is_dropped(
    bus: MessageBus, state: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Saved while the clock ran an hour ahead: an edit made now, after the clock was set
    # back, could carry a Modified the cache already holds, so none of it can be trusted.
    with monkeypatch.context() as ahead:
        ahead.setattr(secret_service, "time", Clock(ahead=3600))
        await fetched_three(bus, state)
    restarted = await SecretServiceStore.open(bus, saved=state)
    reads = spy_property_reads(monkeypatch)
    await restarted.fetch()
    assert reads.count("Label") == 3


@pytest.mark.parametrize("fetch_fails", [False, True], ids=["fetch-ends", "fetch-fails"])
async def test_clock_set_back_while_running_rewrites_the_saved_properties(
    bus: MessageBus,
    state: StateStore,
    seahorse: SecretServiceClient,
    monkeypatch: pytest.MonkeyPatch,
    fetch_fails: bool,
) -> None:
    # Read under a clock running ahead, an item's properties are kept although its Modified
    # is the current real second. Once the clock is set back, a rename in that same second
    # leaves Modified as it was; the fetch that sees it keeps nothing, and the row saved
    # earlier must not outlive that for a restart after the clock caught up again, even
    # when that fetch failed half-way.
    store = await SecretServiceStore.open(bus, saved=state)
    await next_second()
    second = int(time.time())
    await store.upsert(cred(1))
    with monkeypatch.context() as ahead:
        ahead.setattr(secret_service, "time", Clock(ahead=3600))
        await store.fetch()
    (path,) = await items_of(seahorse, store.collection)
    await seahorse.set_property(path, ITEM, "Label", Variant("s", "Work VPN \u2014 user1"))
    with monkeypatch.context() as broken:
        if fetch_fails:
            broken.setattr(SecretServiceClient, "get_secrets", service_gone)
        with contextlib.suppress(LocalUnavailable):
            await store.fetch()
    assert int(time.time()) == second, "the rename must land in the second of the first read"
    monkeypatch.setattr(secret_service, "time", Clock(ahead=7200))
    restarted = await SecretServiceStore.open(bus, saved=state)
    assert (await restarted.fetch()).items[cred(1).id].title == "Work VPN"


async def test_unreadable_saved_properties_are_ignored(
    bus: MessageBus, state: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = await (await fetched_three(bus, state)).fetch()
    state.set(SAVED_PROPERTIES_KEY, '{"version": 1, "items": "not a mapping"}')
    restarted = await SecretServiceStore.open(bus, saved=state)
    reads = spy_property_reads(monkeypatch)
    assert await restarted.fetch() == before
    assert reads.count("Label") == 3


async def test_saved_properties_that_fail_to_decrypt_are_rebuilt(
    bus: MessageBus, state: StateStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = await (await fetched_three(bus, state)).fetch()
    damage_row(tmp_path / "state.db", SAVED_PROPERTIES_KEY)
    restarted = await SecretServiceStore.open(bus, saved=state)
    reads = spy_property_reads(monkeypatch)
    assert await restarted.fetch() == before
    assert reads.count("Label") == 3
    assert state.get(SAVED_PROPERTIES_KEY) is not None  # sealed afresh by that fetch


def damage_row(path: Path, key: str) -> None:
    with contextlib.closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE kv SET blob = zeroblob(64) WHERE key = ?", (key,))
