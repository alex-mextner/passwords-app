# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""A cycle's writes to the real gnome-keyring do not schedule another cycle; a user's do.

gnome-keyring signals our own writes like anyone else's (and rewrites the keyring file the
store also watches), so this runs against the real Secret Service on a private bus. Sync
timing uses the fake clock; the keyring's signals and file polling run in real time.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from dbus_fast.aio import MessageBus
from tests.fakes.memory_stores import MemoryRemote, make_credential
from tests.integration.daemon.support import STATE_KEY
from tests.unit.daemon.fake_clock import FakeClock, settle
from tests.unit.daemon.fakes import APPLE_ID, FakeAccount, FakeNotifier

from passwords_app.daemon.controller import Daemon
from passwords_app.daemon.scheduler import DEBOUNCE, DEBOUNCE_MAX
from passwords_app.keyring.secret_service import FILE_POLL_SECONDS, SecretServiceStore
from passwords_app.store.state import StateStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]

# Long enough for gnome-keyring's signals and two polls of the keyring file.
SIGNALS_DELIVERED = 2.5 * FILE_POLL_SECONDS


async def signals_delivered() -> None:
    await asyncio.sleep(SIGNALS_DELIVERED)
    await settle()


class Setup:
    def __init__(self, daemon: Daemon, remote: MemoryRemote, clock: FakeClock) -> None:
        self.daemon = daemon
        self.remote = remote
        self.clock = clock

    def fetches(self) -> int:
        return self.remote.calls.count(("fetch", None))


@pytest.fixture
async def setup(private_bus: str, tmp_path: Path) -> AsyncIterator[Setup]:
    bus = await MessageBus(bus_address=private_bus).connect()
    remote, clock = MemoryRemote(), FakeClock()
    account = FakeAccount(remote, apple_id=APPLE_ID, signed_in=True, joined=True)
    daemon = Daemon(
        account=account,
        local=await SecretServiceStore.open(bus),
        state=StateStore(tmp_path / "state.db", STATE_KEY),
        clock=clock,
        notifier=FakeNotifier(),
    )
    try:
        await daemon.start()
        await signals_delivered()  # the first (empty) cycle, and the watch subscribed
        yield Setup(daemon, remote, clock)
    finally:
        await daemon.stop()
        daemon.close()
        bus.disconnect()


async def test_cycle_writes_to_the_keyring_do_not_schedule_another_cycle(setup: Setup) -> None:
    setup.remote.put(make_credential("A", title="Mail", notes="two\nlines"))
    setup.remote.put(make_credential("B", alt_urls=("https://b.example.org",), group="Work"))
    await setup.daemon.sync_now()
    assert {c.id for c in await setup.daemon.list_items()} == {"A", "B"}
    await signals_delivered()
    fetches = setup.fetches()
    await setup.clock.advance(DEBOUNCE_MAX + 1)
    assert setup.fetches() == fetches


async def test_user_edit_right_after_a_cycle_syncs(private_bus: str, setup: Setup) -> None:
    setup.remote.put(make_credential("A"))
    await setup.daemon.sync_now()
    user_bus = await MessageBus(bus_address=private_bus).connect()
    try:
        seahorse = await SecretServiceStore.open(user_bus)
        await seahorse.upsert(make_credential("A", notes="edited by the user", modified=60))
    finally:
        user_bus.disconnect()
    await signals_delivered()
    await setup.clock.advance(DEBOUNCE)
    assert setup.remote.items["A"].credential.notes == "edited by the user"
