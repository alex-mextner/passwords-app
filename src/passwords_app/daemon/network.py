# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Network-up trigger: call back when connectivity returns, so an offline daemon retries now.

NetworkManager on the system bus is the primary source (`StateChanged`, global connectivity
= 70). Where it is absent the XDG portal's NetworkMonitor on the session bus is used. Only
offline -> online transitions fire; the initial state is read so startup does not count.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING

from dbus_fast import Message, MessageType

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from dbus_fast.aio import MessageBus

NM_NAME = "org.freedesktop.NetworkManager"
NM_PATH = "/org/freedesktop/NetworkManager"
NM_CONNECTED_GLOBAL = 70
PORTAL_NAME = "org.freedesktop.portal.Desktop"
PORTAL_PATH = "/org/freedesktop/portal/desktop"
PORTAL_IFACE = "org.freedesktop.portal.NetworkMonitor"

_log = logging.getLogger(__name__)


async def _call(bus: MessageBus, message: Message) -> list[object] | None:
    reply = await bus.call(message)
    if reply.message_type == MessageType.ERROR:
        return None
    return list(reply.body)


async def bus_match(bus: MessageBus, rule: str, *, remove: bool = False) -> None:
    """Add (or remove) a signal match rule on the bus daemon."""
    await bus.call(
        Message(
            destination="org.freedesktop.DBus",
            path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus",
            member="RemoveMatch" if remove else "AddMatch",
            signature="s",
            body=[rule],
        )
    )


def _signal_rule(path: str, interface: str, member: str) -> str:
    return f"type='signal',path='{path}',interface='{interface}',member='{member}'"


class NetworkWatch:
    """Fires `on_up` on each offline -> online transition; `stop()` detaches it."""

    def __init__(
        self, bus: MessageBus, source: str, on_up: Callable[[], None], *, online: bool
    ) -> None:
        self.bus = bus
        self.source = source
        self.online = online
        self._on_up = on_up
        self._rule = ""
        self._handler: Callable[[Message], None] | None = None
        self._recheck: asyncio.Task[None] | None = None
        self._again = False

    def update(self, *, online: bool) -> None:
        was, self.online = self.online, online
        if online and not was:
            _log.info("network is back (%s)", self.source)
            self._on_up()

    def recheck(self, read: Callable[[], Awaitable[bool | None]]) -> None:
        """Re-read the state: one read at a time; signals during it ask for one more after.

        A burst of signals therefore costs at most two reads, not one D-Bus call each.
        """
        if self._recheck is not None and not self._recheck.done():
            self._again = True
            return
        self._recheck = asyncio.ensure_future(self._rechecking(read))

    async def _rechecking(self, read: Callable[[], Awaitable[bool | None]]) -> None:
        while True:
            self._again = False
            online = await read()
            if online is not None:
                self.update(online=online)
            if not self._again:
                return

    async def attach(self, rule: str, handler: Callable[[Message], None]) -> None:
        self._rule, self._handler = rule, handler
        self.bus.add_message_handler(handler)
        await bus_match(self.bus, rule)

    async def stop(self) -> None:
        if self._handler is not None:
            self.bus.remove_message_handler(self._handler)
            self._handler = None
            if self.bus.connected:
                await bus_match(self.bus, self._rule, remove=True)
        if self._recheck is not None:
            self._recheck.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._recheck
            self._recheck = None


def _is_signal(message: Message, path: str, interface: str, member: str) -> bool:
    return (
        message.message_type == MessageType.SIGNAL
        and message.path == path
        and message.interface == interface
        and message.member == member
    )


async def watch_networkmanager(bus: MessageBus, on_up: Callable[[], None]) -> NetworkWatch | None:
    state = await _call(
        bus,
        Message(
            destination=NM_NAME,
            path=NM_PATH,
            interface="org.freedesktop.DBus.Properties",
            member="Get",
            signature="ss",
            body=[NM_NAME, "State"],
        ),
    )
    if state is None:
        return None
    initial = int(getattr(state[0], "value", 0))
    watch = NetworkWatch(bus, "NetworkManager", on_up, online=initial >= NM_CONNECTED_GLOBAL)

    def handler(message: Message) -> None:
        if _is_signal(message, NM_PATH, NM_NAME, "StateChanged"):
            watch.update(online=int(message.body[0]) >= NM_CONNECTED_GLOBAL)

    await watch.attach(_signal_rule(NM_PATH, NM_NAME, "StateChanged"), handler)
    return watch


async def watch_portal(bus: MessageBus, on_up: Callable[[], None]) -> NetworkWatch | None:
    async def available() -> bool | None:
        result = await _call(
            bus,
            Message(
                destination=PORTAL_NAME,
                path=PORTAL_PATH,
                interface=PORTAL_IFACE,
                member="GetAvailable",
            ),
        )
        return None if result is None else bool(result[0])

    initial = await available()
    if initial is None:
        return None
    watch = NetworkWatch(bus, "portal", on_up, online=initial)

    def handler(message: Message) -> None:
        # `changed` carries no payload; ask for the new availability.
        if _is_signal(message, PORTAL_PATH, PORTAL_IFACE, "changed"):
            watch.recheck(available)

    await watch.attach(_signal_rule(PORTAL_PATH, PORTAL_IFACE, "changed"), handler)
    return watch


async def watch_network(
    system_bus: MessageBus | None, session_bus: MessageBus, on_up: Callable[[], None]
) -> NetworkWatch | None:
    """NetworkManager if reachable, else the portal; None when neither is available."""
    if system_bus is not None:
        watch = await watch_networkmanager(system_bus, on_up)
        if watch is not None:
            return watch
    watch = await watch_portal(session_bus, on_up)
    if watch is None:
        _log.info("no network monitor available; relying on periodic retries")
    return watch
