# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Tell the daemon the moment a keyring collection locks, or the keyring service goes away.

The daemon serves items (passwords included) from its last keyring snapshot. gnome-keyring
announces a lock as a `PropertiesChanged` of the collection's `Locked` property, not as an
item change, so the store's change feed never carries it. This watch does, and the daemon
drops its snapshot: the next request reads the keyring again and is refused while locked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dbus_fast import Message, MessageType

from passwords_app.daemon.network import bus_match

if TYPE_CHECKING:
    from collections.abc import Callable

    from dbus_fast.aio import MessageBus

SECRETS_NAME = "org.freedesktop.secrets"
COLLECTION_IFACE = "org.freedesktop.Secret.Collection"
PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"
BUS_IFACE = "org.freedesktop.DBus"

_RULES = (
    (
        f"type='signal',sender='{SECRETS_NAME}',interface='{PROPERTIES_IFACE}',"
        f"member='PropertiesChanged',arg0='{COLLECTION_IFACE}'"
    ),
    (
        f"type='signal',sender='{BUS_IFACE}',interface='{BUS_IFACE}',"
        f"member='NameOwnerChanged',arg0='{SECRETS_NAME}'"
    ),
)


def is_lock_change(message: Message) -> bool:
    """Tell whether a collection's `Locked` property or the keyring service's owner changed."""
    if message.message_type != MessageType.SIGNAL or not message.body:
        return False
    if message.interface == PROPERTIES_IFACE and message.member == "PropertiesChanged":
        if len(message.body) != 3:  # noqa: PLR2004 - (interface, changed, invalidated)
            return False
        interface, changed, invalidated = message.body
        return interface == COLLECTION_IFACE and ("Locked" in changed or "Locked" in invalidated)
    return (
        message.interface == BUS_IFACE
        and message.member == "NameOwnerChanged"
        and message.body[0] == SECRETS_NAME
    )


class KeyringLockWatch:
    def __init__(self, bus: MessageBus, on_change: Callable[[], None]) -> None:
        self._bus = bus
        self._on_change = on_change
        self._attached = False

    def _handle(self, message: Message) -> None:
        if is_lock_change(message):
            self._on_change()

    async def start(self) -> None:
        self._bus.add_message_handler(self._handle)
        self._attached = True
        for rule in _RULES:
            await bus_match(self._bus, rule)

    async def stop(self) -> None:
        if not self._attached:
            return
        self._bus.remove_message_handler(self._handle)
        self._attached = False
        if self._bus.connected:
            for rule in _RULES:
                await bus_match(self._bus, rule, remove=True)
