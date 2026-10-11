# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Desktop notifications (org.freedesktop.Notifications) for things the user must act on.

One notification per topic: re-notifying the same topic replaces the visible bubble instead
of stacking a new one, and `close` withdraws it once the condition is resolved. A missing or
failing notification server is logged and otherwise ignored; sync never depends on it.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol

from dbus_fast import Message, MessageType, Variant

from passwords_app.daemon import BUS_NAME

if TYPE_CHECKING:
    from dbus_fast.aio import MessageBus

NOTIFICATIONS_NAME = "org.freedesktop.Notifications"
NOTIFICATIONS_PATH = "/org/freedesktop/Notifications"
APP_NAME = "Passwords"
ICON = BUS_NAME

_log = logging.getLogger(__name__)


class Notifier(Protocol):
    async def notify(self, topic: str, summary: str, body: str) -> None: ...

    async def close(self, topic: str) -> None: ...


class DesktopNotifier:
    def __init__(self, bus: MessageBus) -> None:
        self._bus = bus
        self._ids: dict[str, int] = {}

    async def _call(self, member: str, signature: str, body: list[object]) -> list[object] | None:
        try:
            reply = await self._bus.call(
                Message(
                    destination=NOTIFICATIONS_NAME,
                    path=NOTIFICATIONS_PATH,
                    interface=NOTIFICATIONS_NAME,
                    member=member,
                    signature=signature,
                    body=body,
                )
            )
        except (OSError, EOFError) as exc:
            _log.warning("notification server unreachable: %s", type(exc).__name__)
            return None
        if reply.message_type == MessageType.ERROR:
            _log.warning("notification %s failed: %s", member, reply.error_name)
            return None
        return list(reply.body)

    async def notify(self, topic: str, summary: str, body: str) -> None:
        hints = {"desktop-entry": Variant("s", BUS_NAME), "urgency": Variant("y", 1)}
        replaces = self._ids.get(topic, 0)
        result = await self._call(
            "Notify",
            "susssasa{sv}i",
            [APP_NAME, replaces, ICON, summary, body, [], hints, -1],
        )
        if result:
            self._ids[topic] = int(str(result[0]))

    async def close(self, topic: str) -> None:
        notification = self._ids.pop(topic, None)
        if notification is not None:
            await self._call("CloseNotification", "u", [notification])
