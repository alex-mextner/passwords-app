# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Performance budget (spec §12): fetching 2 000 keyring items takes under 2 seconds.

The budget binds the steady-state sync cycle, i.e. repeat fetches. The cold first fetch reads
every item's properties and gets its own, looser budget (see #64).
"""

from __future__ import annotations

import asyncio
import statistics
import time
from typing import TYPE_CHECKING

import pytest
from dbus_fast.aio import MessageBus
from tests.harness.dbus_session import start_private_session
from tests.integration.keyring.support import cred

from passwords_app.keyring.client import SecretServiceClient
from passwords_app.keyring.mapping import item_content
from passwords_app.keyring.secret_service import SecretServiceStore

if TYPE_CHECKING:
    from passwords_app.sync.ports import LocalSnapshot

pytestmark = [pytest.mark.integration, pytest.mark.benchmark]

ITEMS = 2_000
REPEATS = 4
REPEAT_BUDGET_SECONDS = 2.0
COLD_BUDGET_SECONDS = 3.0
SESSION_COLLECTION = "/org/freedesktop/secrets/collection/session"


async def test_fetch_2000_items_within_budget(bus: MessageBus) -> None:
    # gnome-keyring rewrites a persistent keyring file on every CreateItem, so filling 2 000
    # items there takes minutes. The fetch issues the same calls against any collection, so
    # the budget is measured on the in-memory "session" collection.
    client = await SecretServiceClient.open(bus)
    store = SecretServiceStore(client, SESSION_COLLECTION, "session")
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
    timings: list[float] = []
    snapshots: list[LocalSnapshot] = []
    for _ in range(1 + REPEATS):
        began = time.perf_counter()
        snapshots.append(await store.fetch())
        timings.append(time.perf_counter() - began)
    for snapshot in snapshots:
        assert len(snapshot.items) == ITEMS
        assert snapshot.rejected == ()
    assert snapshots[-1].items[cred(1234).id].notes == "note 1234"
    cold, repeat = timings[0], statistics.median(timings[1:])
    print(  # noqa: T201
        f"2000-item fetch: cold first {cold:.3f} s (budget {COLD_BUDGET_SECONDS} s), "
        f"repeat median {repeat:.3f} s (budget {REPEAT_BUDGET_SECONDS} s), "
        f"all timings {[round(t, 3) for t in timings]}"
    )
    assert repeat < REPEAT_BUDGET_SECONDS, f"repeat fetch median {repeat:.3f} s: {timings}"
    assert cold < COLD_BUDGET_SECONDS, f"cold first fetch {cold:.3f} s: {timings}"


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
