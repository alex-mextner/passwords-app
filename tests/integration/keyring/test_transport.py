# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Passwords never cross the session bus in clear: record the wire like `dbus-monitor`."""

from __future__ import annotations

import asyncio
import contextlib
import io
import os
from typing import TYPE_CHECKING

import pytest
from dbus_fast import Message, Variant
from dbus_fast._private.unmarshaller import Unmarshaller
from tests.integration.keyring.support import cred

from passwords_app.keyring.app_key import app_secret
from passwords_app.keyring.dh import ALGORITHM
from passwords_app.keyring.secret_service import SecretServiceStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from dbus_fast.aio import MessageBus

pytestmark = pytest.mark.integration

MARKER = "FAKE-PW-MARKER-7f3a"


class WireMonitor:
    """A bare D-Bus connection that became a monitor and records every byte it gets."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer
        self.raw = bytearray()
        self._task = asyncio.create_task(self._pump())

    @classmethod
    async def attach(cls, address: str) -> WireMonitor:
        path = address.removeprefix("unix:path=").split(",", 1)[0]
        reader, writer = await asyncio.open_unix_connection(path)
        uid_hex = str(os.getuid()).encode().hex()
        writer.write(b"\0AUTH EXTERNAL " + uid_hex.encode() + b"\r\n")
        assert (await reader.readline()).startswith(b"OK ")
        writer.write(b"BEGIN\r\n")
        for serial, member, signature, body in (
            (1, "Hello", "", []),
            (2, "BecomeMonitor", "asu", [[], 0]),
        ):
            message = Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus.Monitoring"
                if member == "BecomeMonitor"
                else "org.freedesktop.DBus",
                member=member,
                signature=signature,
                body=body,
                serial=serial,
            )
            writer.write(bytes(message._marshall(negotiate_unix_fd=False)))
        await writer.drain()
        monitor = cls(reader, writer)
        await asyncio.sleep(0.1)
        return monitor

    async def _pump(self) -> None:
        while chunk := await self._reader.read(65536):
            self.raw.extend(chunk)

    def messages(self) -> list[Message]:
        unmarshaller = Unmarshaller(io.BufferedRWPair(io.BytesIO(bytes(self.raw)), io.BytesIO()))
        found: list[Message] = []
        with contextlib.suppress(EOFError):
            while (message := unmarshaller.unmarshall()) is not None:
                found.append(message)
        return found

    async def close(self) -> None:
        await asyncio.sleep(0.2)  # let the last messages arrive
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._writer.close()


@pytest.fixture
async def monitor(private_bus: str) -> AsyncIterator[WireMonitor]:
    watching = await WireMonitor.attach(private_bus)
    yield watching
    with contextlib.suppress(Exception):
        await watching.close()


async def test_open_session_asks_only_for_the_encrypted_algorithm(
    monitor: WireMonitor, bus: MessageBus
) -> None:
    await SecretServiceStore.open(bus)
    await app_secret(bus, "state-db")
    await monitor.close()
    requested = [m.body[0] for m in monitor.messages() if m.member == "OpenSession"]
    assert len(requested) == 2
    assert set(requested) == {ALGORITHM}


async def test_passwords_are_encrypted_on_the_wire(monitor: WireMonitor, bus: MessageBus) -> None:
    store = await SecretServiceStore.open(bus)
    await store.upsert(cred(1, pw=MARKER))
    assert (await store.fetch()).items[cred(1).id].password == MARKER
    await store.upsert(cred(1, pw=MARKER + "-2"))
    await store.fetch()
    await monitor.close()
    members = {m.member for m in monitor.messages()}
    assert {"CreateItem", "GetSecrets", "SetSecret"} <= members  # the monitor saw the traffic
    assert MARKER.encode() not in monitor.raw


async def test_app_keys_are_encrypted_on_the_wire(monitor: WireMonitor, bus: MessageBus) -> None:
    key = await app_secret(bus, "state-db")
    again = await app_secret(bus, "state-db")
    await monitor.close()
    assert again == key
    assert {"CreateItem", "GetSecrets"} <= {m.member for m in monitor.messages()}
    assert key not in monitor.raw


async def test_monitor_would_see_a_plain_session_secret(
    monitor: WireMonitor, store: SecretServiceStore, other_bus: MessageBus
) -> None:
    # Positive control: the same recording does catch a secret sent with "plain".
    opened = await other_bus.call(
        Message(
            destination="org.freedesktop.secrets",
            path="/org/freedesktop/secrets",
            interface="org.freedesktop.Secret.Service",
            member="OpenSession",
            signature="sv",
            body=["plain", Variant("s", "")],
        )
    )
    session = opened.body[1]
    await other_bus.call(
        Message(
            destination="org.freedesktop.secrets",
            path=store.collection,
            interface="org.freedesktop.Secret.Collection",
            member="CreateItem",
            signature="a{sv}(oayays)b",
            body=[
                {"org.freedesktop.Secret.Item.Label": Variant("s", "plain @ example.com")},
                [session, b"", MARKER.encode(), "text/plain"],
                False,
            ],
        )
    )
    await monitor.close()
    assert MARKER.encode() in monitor.raw
