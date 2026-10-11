# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Performance budget (spec §12): fetching 2 000 keyring items takes under 2 seconds.

The budget binds every fetch a running or restarted daemon makes: repeat fetches, and the
first fetch after a restart, which starts from the properties state.db kept. Only the very
first fetch of a collection no store has seen reads every item's properties, at O(items)
each in gnome-keyring, and gets its own, looser budget (see #64).
"""

from __future__ import annotations

import asyncio
import os
import statistics
import time
from typing import TYPE_CHECKING

import pytest
from dbus_fast.aio import MessageBus
from tests.harness.dbus_session import start_private_session
from tests.integration.keyring.support import cred, next_second

from passwords_app.keyring.client import SecretServiceClient
from passwords_app.keyring.mapping import item_content
from passwords_app.keyring.secret_service import SecretServiceStore
from passwords_app.store.state import KEY_SIZE, StateStore

if TYPE_CHECKING:
    from pathlib import Path

    from passwords_app.sync.ports import LocalSnapshot

pytestmark = [pytest.mark.integration, pytest.mark.benchmark]

ITEMS = 2_000
REPEATS = 4
REPEAT_BUDGET_SECONDS = 2.0
RESTART_BUDGET_SECONDS = 2.0
# The never-seen fetch makes three property reads per item, and gnome-keyring finds the item
# for each one by scanning every item (its CKA_CLASS index is not unique), so this fetch is
# quadratic in the collection size and bound by gnome-keyring's CPU: 1.7-2.2 s on dedicated
# cores, 3.0-3.1 s on shared CI runners. It happens once per collection, ever: every later
# fetch, restarts included, reads only Modified per unchanged item.
NEVER_SEEN_BUDGET_SECONDS = 4.0
NEVER_SEEN_CAUSE = (
    "gnome-keyring scans all items for every property read (an O(items) lookup by CKA_CLASS),"
    " so a fetch with no saved properties is quadratic; see #64"
)
SESSION_COLLECTION = "/org/freedesktop/secrets/collection/session"


async def test_fetch_2000_items_within_budget(bus: MessageBus, tmp_path: Path) -> None:
    # gnome-keyring rewrites a persistent keyring file on every CreateItem, so filling 2 000
    # items there takes minutes. The fetch issues the same calls against any collection, so
    # the budget is measured on the in-memory "session" collection.
    client = await SecretServiceClient.open(bus)
    state = StateStore(tmp_path / "state.db", os.urandom(KEY_SIZE))
    contents = [
        item_content(cred(n, notes=f"note {n}", title=f"Site {n}"), written_at=int(time.time()))
        for n in range(1, ITEMS + 1)
    ]
    for start in range(0, ITEMS, 50):
        await asyncio.gather(
            *(
                client.create_item(
                    SESSION_COLLECTION, c.label, c.attributes, c.secret, replace=False
                )
                for c in contents[start : start + 50]
            )
        )
    # A daemon fetches long after the last edit; one in the very second an item changed
    # would (correctly) not save that item's properties for reuse.
    await next_second()
    timings: list[float] = []
    snapshots: list[LocalSnapshot] = []

    async def timed_fetch(store: SecretServiceStore) -> None:
        began = time.perf_counter()
        snapshots.append(await store.fetch())
        timings.append(time.perf_counter() - began)

    with state:
        await timed_fetch(SecretServiceStore(client, SESSION_COLLECTION, "session", saved=state))
        # A restarted daemon: a new store, starting from what state.db kept.
        restarted = SecretServiceStore(client, SESSION_COLLECTION, "session", saved=state)
        for _ in range(1 + REPEATS):
            await timed_fetch(restarted)
    for snapshot in snapshots:
        assert len(snapshot.items) == ITEMS
        assert snapshot.rejected == ()
    assert snapshots[-1].items[cred(1234).id].notes == "note 1234"
    never_seen, after_restart = timings[0], timings[1]
    repeat = statistics.median(timings[2:])
    print(  # noqa: T201
        f"2000-item fetch: never-seen first {never_seen:.3f} s "
        f"(budget {NEVER_SEEN_BUDGET_SECONDS} s), "
        f"first after a restart {after_restart:.3f} s (budget {RESTART_BUDGET_SECONDS} s), "
        f"repeat median {repeat:.3f} s (budget {REPEAT_BUDGET_SECONDS} s), "
        f"all timings {[round(t, 3) for t in timings]}"
    )
    assert repeat < REPEAT_BUDGET_SECONDS, f"repeat fetch median {repeat:.3f} s: {timings}"
    assert after_restart < RESTART_BUDGET_SECONDS, (
        f"first fetch after a restart {after_restart:.3f} s: {timings}"
    )
    assert never_seen < NEVER_SEEN_BUDGET_SECONDS, (
        f"never-seen first fetch {never_seen:.3f} s: {timings}; {NEVER_SEEN_CAUSE}"
    )


async def test_large_fetch_stays_within_a_strict_bus_quota() -> None:
    # dbus-daemon's built-in default allows 128 pending replies per connection; a fetch that
    # fired one property read per item at once would fail on such a bus.
    with start_private_session(limits={"max_replies_per_connection": 128}) as session:
        bus = await MessageBus(bus_address=session.address).connect()
        try:
            store = await SecretServiceStore.open(bus)
            for start in range(1, 301, 50):
                await asyncio.gather(*(store.upsert(cred(n)) for n in range(start, start + 50)))
            assert len((await store.fetch()).items) == 300
        finally:
            bus.disconnect()
