# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The real daemon on a private session bus, wired to in-memory stores, plus a raw client.

`RunningDaemon` is what `passwords-appd` is in production minus the keyring and iCloud: the
same `Daemon`, `PasswordsService` and `publish()` the entry point uses, with `MemoryRemote`,
`MemoryLocal`, a fake account and a fake clock injected. `Client` speaks plain D-Bus
messages (no proxy, no product code), so contract tests check the wire format itself.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pytest
from dbus_fast import Message, MessageType
from dbus_fast.aio import MessageBus
from tests.fakes.memory_stores import MemoryLocal, MemoryRemote
from tests.unit.daemon.fake_clock import FakeClock, settle
from tests.unit.daemon.fakes import APPLE_ID, FakeAccount, FakeNotifier

from passwords_app.daemon import BUS_NAME, INTERFACE, OBJECT_PATH
from passwords_app.daemon.bus import PatientMessageBus
from passwords_app.daemon.controller import Daemon
from passwords_app.daemon.main import publish
from passwords_app.store.state import StateStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable
    from pathlib import Path

STATE_KEY = bytes(range(32))


class CallError(Exception):
    def __init__(self, name: str, text: str) -> None:
        super().__init__(f"{name}: {text}")
        self.name = name
        self.text = text


@dataclass
class Client:
    bus: MessageBus
    signals: list[Message] = field(default_factory=list)

    async def call(self, member: str, signature: str = "", *body: Any) -> list[Any]:
        reply = await self.bus.call(
            Message(
                destination=BUS_NAME,
                path=OBJECT_PATH,
                interface=INTERFACE,
                member=member,
                signature=signature,
                body=list(body),
            )
        )
        assert reply is not None
        if reply.message_type == MessageType.ERROR:
            raise CallError(reply.error_name or "", str(reply.body[0]) if reply.body else "")
        return list(reply.body)

    async def one(self, member: str, signature: str = "", *body: Any) -> Any:
        (value,) = await self.call(member, signature, *body)
        return value

    async def listen(self) -> None:
        def on_message(message: Message) -> None:
            if message.message_type == MessageType.SIGNAL and message.interface == INTERFACE:
                self.signals.append(message)

        self.bus.add_message_handler(on_message)
        await self.bus.call(
            Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="AddMatch",
                signature="s",
                body=[f"type='signal',interface='{INTERFACE}'"],
            )
        )

    def signal_bodies(self, member: str) -> list[Any]:
        return [m.body[0] for m in self.signals if m.member == member]


@dataclass
class RunningDaemon:
    daemon: Daemon
    remote: MemoryRemote
    local: MemoryLocal
    account: FakeAccount
    notifier: FakeNotifier
    clock: FakeClock
    state: StateStore
    bus: MessageBus


@pytest.fixture
def account_state() -> dict[str, bool]:
    """Override in a test module to start signed out: {"signed_in": False, "joined": False}."""
    return {"signed_in": True, "joined": True}


@pytest.fixture
async def running(
    private_bus: str, tmp_path: Path, account_state: dict[str, bool]
) -> AsyncIterator[RunningDaemon]:
    remote, local, clock, notifier = MemoryRemote(), MemoryLocal(), FakeClock(), FakeNotifier()
    signed_in, joined = account_state["signed_in"], account_state["joined"]
    account = FakeAccount(
        remote, apple_id=APPLE_ID if signed_in else None, signed_in=signed_in, joined=joined
    )
    state = StateStore(tmp_path / "state.db", STATE_KEY)
    daemon = Daemon(account=account, local=local, state=state, clock=clock, notifier=notifier)
    bus = await PatientMessageBus(bus_address=private_bus).connect()
    await publish(bus, daemon)
    await daemon.start()
    await settle()
    yield RunningDaemon(daemon, remote, local, account, notifier, clock, state, bus)
    await daemon.stop()
    daemon.close()
    bus.disconnect()


@pytest.fixture
async def client(private_bus: str, running: RunningDaemon) -> AsyncIterator[Client]:
    bus = await MessageBus(bus_address=private_bus).connect()
    c = Client(bus)
    await c.listen()
    yield c
    bus.disconnect()


async def wait_for(predicate: Callable[[], bool | Awaitable[bool]], limit: float = 5.0) -> None:
    """Poll `predicate` every 10 ms until it is true; fail after `limit` seconds.

    Polling rather than an Event: the condition lives in another connection or process.
    """
    async with asyncio.timeout(limit):
        while True:
            value = predicate()
            if inspect.isawaitable(value):
                value = await value
            if value:
                return
            await asyncio.sleep(0.01)
