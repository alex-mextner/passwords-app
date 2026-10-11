# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Minimal async client of the daemon's D-Bus API for the command-line tool.

Replies are unwrapped from Variants into plain Python values so the formatting code never
sees D-Bus types. Calling a method auto-starts `passwords-appd` through D-Bus activation;
if the name cannot be reached at all the call raises `DaemonUnreachableError`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Self, cast

from dbus_fast import Message, MessageType, Variant
from dbus_fast.aio import MessageBus

from passwords_app.daemon import BUS_NAME, INTERFACE, OBJECT_PATH

if TYPE_CHECKING:
    from collections.abc import Iterable

type Plain = dict[str, Any]

_UNREACHABLE = frozenset(
    {
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.NameHasNoOwner",
        "org.freedesktop.DBus.Error.Spawn.ChildExited",
        "org.freedesktop.DBus.Error.Spawn.ExecFailed",
        "org.freedesktop.DBus.Error.Spawn.ServiceNotFound",
        "org.freedesktop.DBus.Error.NoReply",
        "org.freedesktop.DBus.Error.TimedOut",
    }
)


class DaemonCallError(Exception):
    """The daemon answered with an error; `short` is the last part of its D-Bus name."""

    def __init__(self, name: str, message: str) -> None:
        super().__init__(message)
        self.name = name
        self.short = name.rsplit(".", 1)[-1]


class DaemonUnreachableError(Exception):
    """No session bus, or nothing owns (or can be activated as) the daemon's name."""


def unwrap(value: Any) -> Any:  # noqa: ANN401 - D-Bus values are dynamically typed
    if isinstance(value, Variant):
        return unwrap(value.value)
    if isinstance(value, dict):
        return {k: unwrap(v) for k, v in cast("dict[str, Any]", value).items()}
    if isinstance(value, list):
        return [unwrap(v) for v in cast("Iterable[Any]", value)]
    return value


class DaemonClient:
    def __init__(self, bus: MessageBus) -> None:
        self._bus = bus

    @classmethod
    async def connect(cls) -> Self:
        try:
            bus = await MessageBus().connect()
        except (OSError, EOFError, ValueError) as exc:
            msg = f"cannot connect to the session bus ({exc})"
            raise DaemonUnreachableError(msg) from exc
        return cls(bus)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        self._bus.disconnect()

    async def call(self, member: str, signature: str = "", *body: Any) -> list[Any]:  # noqa: ANN401
        reply = await self._bus.call(
            Message(
                destination=BUS_NAME,
                path=OBJECT_PATH,
                interface=INTERFACE,
                member=member,
                signature=signature,
                body=list(body),
            )
        )
        if reply.message_type == MessageType.ERROR:
            name = reply.error_name or ""
            text = str(reply.body[0]) if reply.body else name
            if name in _UNREACHABLE:
                raise DaemonUnreachableError(text)
            raise DaemonCallError(name, text)
        return [unwrap(v) for v in reply.body]

    async def _one(self, member: str, signature: str = "", *body: Any) -> Any:  # noqa: ANN401
        (value,) = await self.call(member, signature, *body)
        return value

    async def status(self) -> Plain:
        return dict(await self._one("GetStatus"))

    async def items(self) -> list[Plain]:
        return list(await self._one("List"))

    async def get(self, item_id: str) -> Plain:
        return dict(await self._one("Get", "s", item_id))

    async def code(self, item_id: str) -> tuple[str, int]:
        code, left = await self.call("GetCode", "s", item_id)
        return str(code), int(left)

    async def trash(self) -> list[Plain]:
        return list(await self._one("ListTrash"))

    async def restore(self, trash_id: str) -> str:
        return str(await self._one("Restore", "s", trash_id))

    async def purge(self, trash_id: str) -> None:
        await self.call("Purge", "s", trash_id)

    async def sync_now(self) -> None:
        await self.call("SyncNow")

    async def resolve_pause(self, *, apply: bool) -> None:
        await self.call("ResolvePause", "b", apply)

    async def sign_in_start(self, apple_id: str, password: str) -> Plain:
        return dict(await self._one("SignInStart", "ss", apple_id, password))

    async def sign_in_code(self, code: str) -> Plain:
        return dict(await self._one("SignInCode", "s", code))

    async def sign_in_request_sms(self) -> Plain:
        return dict(await self._one("SignInRequestSms"))

    async def recovery_devices(self) -> list[Plain]:
        return list(await self._one("ListRecoveryDevices"))

    async def join(self, device_id: str, passcode: str) -> Plain:
        return dict(await self._one("JoinKeychain", "ss", device_id, passcode))

    async def sign_out(self) -> None:
        await self.call("SignOut")
