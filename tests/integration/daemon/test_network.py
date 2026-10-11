# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Network-up detection against fake NetworkManager / portal services on a private bus.

The private session bus stands in for the system bus too: the watcher only needs a bus that
carries NetworkManager's name, object and signal.
"""

# No `from __future__ import annotations`: dbus-fast evaluates these annotations itself.

import asyncio
from collections.abc import AsyncIterator

import pytest
from dbus_fast import PropertyAccess
from dbus_fast.aio import MessageBus
from dbus_fast.annotations import DBusBool, DBusUInt32
from dbus_fast.service import ServiceInterface, dbus_method, dbus_property, dbus_signal
from tests.integration.daemon.support import wait_for

from passwords_app.daemon.network import (
    NM_NAME,
    NM_PATH,
    PORTAL_IFACE,
    PORTAL_NAME,
    PORTAL_PATH,
    NetworkWatch,
    watch_network,
    watch_networkmanager,
    watch_portal,
)

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]

NM_DISCONNECTED = 20
NM_CONNECTING = 40
NM_CONNECTED_SITE = 60
NM_CONNECTED_GLOBAL = 70


class FakeNetworkManager(ServiceInterface):
    def __init__(self, state: int) -> None:
        super().__init__(NM_NAME)
        self._state = state

    @dbus_property(access=PropertyAccess.READ, name="State")
    def state(self) -> DBusUInt32:
        return self._state

    @dbus_signal(name="StateChanged")
    def state_changed(self) -> DBusUInt32:
        return self._state

    def set(self, state: int) -> None:
        self._state = state
        self.state_changed()


class FakePortal(ServiceInterface):
    def __init__(self, *, available: bool) -> None:
        super().__init__(PORTAL_IFACE)
        self.available = available

    @dbus_method(name="GetAvailable")
    def get_available(self) -> DBusBool:
        return self.available

    @dbus_signal(name="changed")
    def changed(self) -> None:
        return None

    def set(self, *, available: bool) -> None:
        self.available = available
        self.changed()


class Ups:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self) -> None:
        self.count += 1


@pytest.fixture
async def service_bus(private_bus: str) -> AsyncIterator[MessageBus]:
    bus = await MessageBus(bus_address=private_bus).connect()
    yield bus
    bus.disconnect()


@pytest.fixture
async def watcher_bus(private_bus: str) -> AsyncIterator[MessageBus]:
    bus = await MessageBus(bus_address=private_bus).connect()
    yield bus
    bus.disconnect()


async def start_nm(bus: MessageBus, state: int) -> FakeNetworkManager:
    nm = FakeNetworkManager(state)
    bus.export(NM_PATH, nm)
    await bus.request_name(NM_NAME)
    return nm


async def start_portal(bus: MessageBus, *, available: bool) -> FakePortal:
    portal = FakePortal(available=available)
    bus.export(PORTAL_PATH, portal)
    await bus.request_name(PORTAL_NAME)
    return portal


async def test_nm_absent(watcher_bus: MessageBus) -> None:
    assert await watch_networkmanager(watcher_bus, Ups()) is None


async def test_portal_absent(watcher_bus: MessageBus) -> None:
    assert await watch_portal(watcher_bus, Ups()) is None


async def test_neither_available(watcher_bus: MessageBus) -> None:
    assert await watch_network(None, watcher_bus, Ups()) is None


@pytest.mark.parametrize(
    ("initial", "online"),
    [
        (NM_DISCONNECTED, False),
        (NM_CONNECTING, False),
        (NM_CONNECTED_SITE, False),
        (NM_CONNECTED_GLOBAL, True),
    ],
)
async def test_nm_initial_state(
    service_bus: MessageBus, watcher_bus: MessageBus, initial: int, *, online: bool
) -> None:
    await start_nm(service_bus, initial)
    watch = await watch_networkmanager(watcher_bus, Ups())
    assert watch is not None
    assert watch.online is online
    assert watch.source == "NetworkManager"


async def test_nm_fires_on_reconnect_only(service_bus: MessageBus, watcher_bus: MessageBus) -> None:
    nm = await start_nm(service_bus, NM_CONNECTED_GLOBAL)
    ups = Ups()
    watch = await watch_networkmanager(watcher_bus, ups)
    assert watch is not None
    nm.set(NM_DISCONNECTED)
    await wait_for(lambda: not watch.online)
    nm.set(NM_CONNECTING)
    nm.set(NM_CONNECTED_SITE)
    nm.set(NM_CONNECTED_GLOBAL)
    await wait_for(lambda: ups.count == 1)
    nm.set(NM_CONNECTED_GLOBAL)  # no transition, no trigger
    nm.set(NM_DISCONNECTED)
    nm.set(NM_CONNECTED_GLOBAL)
    await wait_for(lambda: ups.count == 2)
    await watch.stop()
    nm.set(NM_DISCONNECTED)
    nm.set(NM_CONNECTED_GLOBAL)
    await asyncio.sleep(0.2)  # time for a (wrongly) still-attached handler to fire
    assert ups.count == 2


async def test_portal_fires_on_reconnect(service_bus: MessageBus, watcher_bus: MessageBus) -> None:
    portal = await start_portal(service_bus, available=False)
    ups = Ups()
    watch = await watch_portal(watcher_bus, ups)
    assert watch is not None
    assert (watch.online, watch.source) == (False, "portal")
    portal.set(available=True)
    await wait_for(lambda: ups.count == 1)
    portal.set(available=True)
    portal.set(available=False)
    await wait_for(lambda: not watch.online)
    portal.set(available=True)
    await wait_for(lambda: ups.count == 2)
    await watch.stop()


async def test_a_burst_of_portal_signals_costs_at_most_two_reads(watcher_bus: MessageBus) -> None:
    ups = Ups()
    watch = NetworkWatch(watcher_bus, "portal", ups, online=False)
    gate = asyncio.Event()
    reads = 0

    async def read() -> bool:
        nonlocal reads
        reads += 1
        await gate.wait()
        return True

    watch.recheck(read)
    await asyncio.sleep(0)
    assert reads == 1  # the first read is in flight
    for _ in range(1000):  # the burst arrives while it waits for the portal
        watch.recheck(read)
    await asyncio.sleep(0)
    assert reads == 1
    gate.set()
    await wait_for(lambda: reads == 2)
    await asyncio.sleep(0.05)
    assert (reads, ups.count, watch.online) == (2, 1, True)
    await watch.stop()


async def test_stop_cancels_a_pending_read(watcher_bus: MessageBus) -> None:
    watch = NetworkWatch(watcher_bus, "portal", Ups(), online=False)
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def read() -> bool:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return True

    watch.recheck(read)
    await started.wait()
    await asyncio.wait_for(watch.stop(), 5)
    assert cancelled.is_set()


async def test_prefers_networkmanager(service_bus: MessageBus, watcher_bus: MessageBus) -> None:
    await start_nm(service_bus, NM_CONNECTED_GLOBAL)
    await start_portal(service_bus, available=True)
    watch = await watch_network(watcher_bus, watcher_bus, Ups())
    assert watch is not None
    assert watch.source == "NetworkManager"


async def test_falls_back_to_the_portal(service_bus: MessageBus, watcher_bus: MessageBus) -> None:
    await start_portal(service_bus, available=True)
    watch = await watch_network(watcher_bus, watcher_bus, Ups())
    assert watch is not None
    assert watch.source == "portal"


async def test_no_system_bus_uses_the_portal(
    service_bus: MessageBus, watcher_bus: MessageBus
) -> None:
    await start_portal(service_bus, available=True)
    watch = await watch_network(None, watcher_bus, Ups())
    assert watch is not None
    assert watch.source == "portal"
