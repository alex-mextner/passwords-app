# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""DesktopNotifier against a notification server on a private bus."""

# No `from __future__ import annotations`: dbus-fast reads `-> None` of a D-Bus method as the
# string "None" under PEP 563 and rejects it.

from collections.abc import AsyncIterator
from typing import Annotated, Any

import pytest
from dbus_fast import Variant
from dbus_fast.aio import MessageBus
from dbus_fast.annotations import DBusDict, DBusInt32, DBusSignature, DBusStr, DBusUInt32
from dbus_fast.service import ServiceInterface, dbus_method

from passwords_app.daemon import BUS_NAME
from passwords_app.daemon.notify import (
    APP_NAME,
    NOTIFICATIONS_NAME,
    NOTIFICATIONS_PATH,
    DesktopNotifier,
)

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]

StrList = Annotated[list[str], DBusSignature("as")]


class NotificationServer(ServiceInterface):
    """Just enough of org.freedesktop.Notifications (GNOME Shell's side) to observe calls."""

    def __init__(self) -> None:
        super().__init__(NOTIFICATIONS_NAME)
        self.notified: list[tuple[Any, ...]] = []
        self.closed: list[int] = []
        self._next = 41

    @dbus_method(name="Notify")
    def notify(  # noqa: PLR0913, PLR0917 - the spec'd signature
        self,
        app_name: DBusStr,
        replaces_id: DBusUInt32,
        app_icon: DBusStr,
        summary: DBusStr,
        body: DBusStr,
        actions: StrList,
        hints: DBusDict,
        expire_timeout: DBusInt32,
    ) -> DBusUInt32:
        self.notified.append(
            (app_name, replaces_id, app_icon, summary, body, actions, hints, expire_timeout)
        )
        if replaces_id:
            return replaces_id
        self._next += 1
        return self._next

    @dbus_method(name="CloseNotification")
    def close_notification(self, notification_id: DBusUInt32) -> None:
        self.closed.append(notification_id)


@pytest.fixture
async def server(private_bus: str) -> AsyncIterator[NotificationServer]:
    bus = await MessageBus(bus_address=private_bus).connect()
    service = NotificationServer()
    bus.export(NOTIFICATIONS_PATH, service)
    await bus.request_name(NOTIFICATIONS_NAME)
    yield service
    bus.disconnect()


@pytest.fixture
async def notifier(private_bus: str) -> AsyncIterator[DesktopNotifier]:
    bus = await MessageBus(bus_address=private_bus).connect()
    yield DesktopNotifier(bus)
    bus.disconnect()


async def test_notify_sends_app_identity_and_text(
    server: NotificationServer, notifier: DesktopNotifier
) -> None:
    await notifier.notify("pause", "Passwords sync is paused", "8 passwords would be deleted.")
    (call,) = server.notified
    app, replaces, icon, summary, body, actions, hints, timeout = call
    assert (app, replaces, icon) == (APP_NAME, 0, BUS_NAME)
    assert (summary, body) == ("Passwords sync is paused", "8 passwords would be deleted.")
    assert actions == []
    assert hints["desktop-entry"] == Variant("s", BUS_NAME)
    assert timeout == -1


async def test_same_topic_replaces_the_previous_bubble(
    server: NotificationServer, notifier: DesktopNotifier
) -> None:
    await notifier.notify("rejected", "1 item", "a")
    await notifier.notify("rejected", "2 items", "b")
    await notifier.notify("pause", "paused", "c")
    first, second, third = server.notified
    assert first[1] == 0
    assert second[1] == 42  # replaces the id the server gave the first one
    assert third[1] == 0  # another topic, another bubble


async def test_close_withdraws_the_topic(
    server: NotificationServer, notifier: DesktopNotifier
) -> None:
    await notifier.notify("signin", "Sign in", "again")
    await notifier.close("signin")
    await notifier.close("signin")  # already closed: nothing sent
    assert server.closed == [42]
    await notifier.notify("signin", "Sign in", "again")
    assert server.notified[-1][1] == 0


async def test_close_of_unknown_topic_sends_nothing(
    server: NotificationServer, notifier: DesktopNotifier
) -> None:
    await notifier.close("never-shown")
    assert server.closed == []


async def test_missing_server_is_not_an_error(
    private_bus: str, notifier: DesktopNotifier, caplog: pytest.LogCaptureFixture
) -> None:
    await notifier.notify("pause", "paused", "body")
    await notifier.close("pause")
    assert any("notification" in r.getMessage() for r in caplog.records)
