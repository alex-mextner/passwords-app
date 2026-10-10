# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Minimal async client for the four `passwords-appd` methods the browser needs.

Calls are raw messages rather than an introspected proxy: introspection would cost a round
trip per connection and would let the daemon's XML, not this file, decide what is sent.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from typing import TYPE_CHECKING, Final, cast

from dbus_fast import Message, MessageType, Variant
from dbus_fast.aio import MessageBus

from passwords_app.browser.protocol import Candidate, DaemonStatus, ErrorCode, Login, ProtocolError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

BUS_NAME: Final = "io.github.alex_mextner.Passwords"
OBJECT_PATH: Final = "/io/github/alex_mextner/Passwords"
INTERFACE: Final = "io.github.alex_mextner.Passwords1"
DEFAULT_CALL_TIMEOUT: Final = 10.0
DEFAULT_CONNECT_TIMEOUT: Final = 5.0

_DAEMON_ERROR: Final = f"{INTERFACE}.Error."
_BUS_ERROR: Final = "org.freedesktop.DBus.Error."
ERROR_CODES: Final[Mapping[str, ErrorCode]] = {
    f"{_DAEMON_ERROR}NotFound": "not-found",
    f"{_DAEMON_ERROR}Invalid": "invalid",
    f"{_DAEMON_ERROR}Unavailable": "unavailable",
    f"{_DAEMON_ERROR}AuthRequired": "auth-required",
    f"{_DAEMON_ERROR}Locked": "locked",
    f"{_BUS_ERROR}ServiceUnknown": "daemon-unavailable",
    f"{_BUS_ERROR}NameHasNoOwner": "daemon-unavailable",
    f"{_BUS_ERROR}NoReply": "daemon-unavailable",
    f"{_BUS_ERROR}Disconnected": "daemon-unavailable",
    f"{_BUS_ERROR}Timeout": "daemon-unavailable",
    f"{_BUS_ERROR}TimedOut": "daemon-unavailable",
    f"{_BUS_ERROR}NoServer": "daemon-unavailable",
    f"{_BUS_ERROR}SpawnFailed": "daemon-unavailable",
}
# Fixed texts: the daemon's own error messages are not ours to vouch for as secret-free.
_MESSAGES: Final[Mapping[ErrorCode, str]] = {
    "not-found": "no such item, or it has no verification code",
    "invalid": "the daemon rejected the item",
    "unavailable": "the daemon cannot serve right now",
    "auth-required": "the daemon needs the user to sign in",
    "locked": "the keyring collection is locked",
    "daemon-unavailable": "passwords-appd is not reachable",
}


_MATCH: Final = "Match"
_GETCODE: Final = "GetCode"
_SAVE: Final = "Save"


def error_code(dbus_error_name: str) -> ErrorCode:
    """Protocol code for a D-Bus error name; anything unexpected is `internal`."""
    return ERROR_CODES.get(dbus_error_name, "internal")


def _error(dbus_error_name: str, member: str) -> ProtocolError:
    code = error_code(dbus_error_name)
    detail = _MESSAGES.get(code, "unexpected daemon error")
    return ProtocolError(code, f"{member}: {detail} ({dbus_error_name})")


def _unavailable(detail: str) -> ProtocolError:
    return ProtocolError("daemon-unavailable", f"passwords-appd is not reachable: {detail}")


def _bad_reply(member: str) -> ProtocolError:
    return ProtocolError("internal", f"{member}: unexpected reply from the daemon")


def session_bus_address() -> str | None:
    """Resolve the session bus now (never cached: tests and re-logins change it)."""
    address = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if address:
        return address
    # systemd user sessions put the bus here even when the variable was not exported.
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    return f"unix:path={runtime_dir}/bus" if runtime_dir else None


def _vardict(value: object, member: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _bad_reply(member)
    out: dict[str, object] = {}
    for key, variant in cast("dict[object, object]", value).items():
        if not isinstance(key, str) or not isinstance(variant, Variant):
            raise _bad_reply(member)
        out[key] = variant.value
    return out


def _field[T](d: Mapping[str, object], key: str, kind: type[T], default: T, member: str) -> T:
    value = d.get(key, default)
    # bool is an int subclass; a boolean count or an integer flag is a broken reply.
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise _bad_reply(member)
    return value


def _candidate(value: object) -> Candidate:
    d = _vardict(value, _MATCH)
    item_id = _field(d, "id", str, "", _MATCH)
    if not item_id:
        raise _bad_reply(_MATCH)
    alt_urls = _field(d, "alt_urls", list, [], _MATCH)
    if not all(isinstance(u, str) for u in cast("list[object]", alt_urls)):
        raise _bad_reply(_MATCH)
    return Candidate(
        id=item_id,
        title=_field(d, "title", str, "", _MATCH),
        username=_field(d, "username", str, "", _MATCH),
        url=_field(d, "url", str, "", _MATCH),
        alt_urls=tuple(cast("list[str]", alt_urls)),
        has_code=_field(d, "has_code", bool, False, _MATCH),  # noqa: FBT003 - default value
    )


def _disconnect(bus: MessageBus | None) -> None:
    # Releases the socket of a half-open or broken connection; failing to is not an error.
    if bus is not None:
        with contextlib.suppress(Exception):
            bus.disconnect()


class DaemonClient:
    """Lazily connected client; reconnects on the next call after the bus went away."""

    def __init__(
        self,
        *,
        call_timeout: float = DEFAULT_CALL_TIMEOUT,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    ) -> None:
        self._call_timeout = call_timeout
        self._connect_timeout = connect_timeout
        self._bus: MessageBus | None = None

    async def _connection(self) -> MessageBus:
        if self._bus is not None and self._bus.connected:
            return self._bus
        self._drop()
        address = session_bus_address()
        if address is None:
            msg = "no session bus address"
            raise _unavailable(msg)
        bus: MessageBus | None = None
        try:
            bus = MessageBus(bus_address=address)
            await asyncio.wait_for(bus.connect(), self._connect_timeout)
        except TimeoutError:
            _disconnect(bus)
            msg = "connecting to the session bus timed out"
            raise _unavailable(msg) from None
        # Bad addresses, refused sockets and auth failures all mean the same to the browser.
        except Exception as e:  # noqa: BLE001
            _disconnect(bus)
            msg = f"cannot connect to the session bus ({type(e).__name__})"
            raise _unavailable(msg) from None
        self._bus = bus
        return bus

    def _drop(self) -> None:
        bus, self._bus = self._bus, None
        _disconnect(bus)

    async def _call(
        self, member: str, signature: str = "", body: Sequence[object] = ()
    ) -> list[object]:
        bus = await self._connection()
        message = Message(
            destination=BUS_NAME,
            path=OBJECT_PATH,
            interface=INTERFACE,
            member=member,
            signature=signature,
            body=list(body),
        )
        try:
            reply = await asyncio.wait_for(bus.call(message), self._call_timeout)
        except TimeoutError:
            msg = f"{member} timed out"
            raise _unavailable(msg) from None
        # The connection broke mid-call (EOF, reset); start over on the next request.
        except Exception as e:  # noqa: BLE001
            self._drop()
            msg = f"{member} failed ({type(e).__name__})"
            raise _unavailable(msg) from None
        if reply.message_type is MessageType.ERROR:
            raise _error(reply.error_name or "", member)
        return cast("list[object]", reply.body)

    async def status(self) -> DaemonStatus:
        body = await self._call("GetStatus")
        d = _vardict(body[0] if body else None, "GetStatus")
        return DaemonStatus(
            state=_field(d, "state", str, "", "GetStatus"),
            message=_field(d, "message", str, "", "GetStatus"),
            item_count=_field(d, "item_count", int, 0, "GetStatus"),
        )

    async def match(self, url: str) -> list[Candidate]:
        body = await self._call("Match", "s", [url])
        items = body[0] if body else None
        if not isinstance(items, list):
            raise _bad_reply(_MATCH)
        return [_candidate(item) for item in cast("list[object]", items)]

    async def login(self, item_id: str) -> Login:
        body = await self._call("Get", "s", [item_id])
        d = _vardict(body[0] if body else None, "Get")
        return Login(
            username=_field(d, "username", str, "", "Get"),
            password=_field(d, "password", str, "", "Get"),
        )

    async def code(self, item_id: str) -> tuple[str, int]:
        body = await self._call("GetCode", "s", [item_id])
        if len(body) != 2:  # noqa: PLR2004 - (code, seconds_left)
            raise _bad_reply(_GETCODE)
        code, seconds_left = body
        if (
            not isinstance(code, str)
            or not isinstance(seconds_left, int)
            or isinstance(seconds_left, bool)
        ):
            raise _bad_reply(_GETCODE)
        return code, seconds_left

    async def save(self, fields: Mapping[str, str]) -> str:
        item = {key: Variant("s", value) for key, value in fields.items()}
        body = await self._call("Save", "a{sv}", [item])
        item_id = body[0] if body else None
        if not isinstance(item_id, str) or not item_id:
            raise _bad_reply(_SAVE)
        return item_id

    async def close(self) -> None:
        self._drop()
