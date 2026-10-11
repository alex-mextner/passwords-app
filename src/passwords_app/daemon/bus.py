# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The daemon's D-Bus connection: dbus-fast's, except that a full socket is not fatal.

dbus-fast writes to a non-blocking socket and treats every exception from `send()` as a lost
connection, BlockingIOError (EAGAIN) included. EAGAIN only means the bus has not read what was
already sent: a List reply with hundreds of items fills the socket, the next reply finds it
full, and the library closed the connection under the daemon (issue #122). dbus-fast 5.2.0 and
its main branch as of 2026-10-11 still do this, and the writer is not pluggable, so
`PatientMessageBus` swaps its own in right after connecting.
"""

# dbus-fast annotates the writer's futures as bare `asyncio.Future`, which pyright reads as
# Future[Unknown]; nothing here depends on their result type.
# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false
# pyright: reportUnknownVariableType=false

from __future__ import annotations

import array
import socket
from typing import TYPE_CHECKING, Any, Self, cast, override

from dbus_fast.aio import MessageBus
from dbus_fast.aio.message_bus import (
    _MessageWriter,  # pyright: ignore[reportPrivateUsage] - see the module docstring
)

if TYPE_CHECKING:
    import asyncio


def _resolve(fut: asyncio.Future[Any] | None) -> None:
    if fut is not None and not fut.done():
        fut.set_result(None)


def _fail(fut: asyncio.Future[Any] | None, exc: Exception) -> None:
    if fut is not None and not fut.done():
        fut.set_exception(exc)


class _PatientWriter(_MessageWriter):
    @override
    def write_callback(self, remove_writer: bool = True) -> None:
        """dbus-fast 5.2.0's write loop, except that a full socket waits instead of disconnecting.

        On BlockingIOError nothing of the pending chunk was sent (file descriptors included), so
        returning leaves it queued; the event loop calls back once the socket is writable:
        `schedule_write()` registers the callback whenever a buffer is pending, and a callback
        the loop is already running stays registered.
        """
        # Both are set before the writer exists: `connect()` creates it after the socket.
        sock, fd = cast("socket.socket", self.sock), cast("int", self.fd)
        try:
            while True:
                if self.buf is None:
                    if not self.messages:
                        if remove_writer:
                            self.loop.remove_writer(fd)
                        return
                    buf, unix_fds, fut = self.messages.popleft()
                    self.unix_fds = unix_fds
                    self.buf = memoryview(buf)
                    self.offset = 0
                    self.fut = fut

                if self.unix_fds and self.negotiate_unix_fd:
                    ancdata = [
                        (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", self.unix_fds))
                    ]
                    self.offset += sock.sendmsg([self.buf[self.offset :]], ancdata)
                    self.unix_fds = None
                else:
                    self.offset += sock.send(self.buf[self.offset :])

                if self.offset < len(self.buf):
                    return  # partly sent: wait for writable

                self.buf = None
                _resolve(self.fut)
        except BlockingIOError:
            return
        except Exception as exc:  # noqa: BLE001 - any other send error ends the connection
            if self.bus._user_disconnect:  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                _resolve(self.fut)
            else:
                _fail(self.fut, exc)
            self.bus._finalize(exc)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


class PatientMessageBus(MessageBus):
    """An asyncio `MessageBus` whose writes wait out a full socket instead of disconnecting."""

    @override
    async def connect(self) -> Self:
        await super().connect()
        writer = _PatientWriter(self)
        # Nothing is queued yet (the Hello handshake is written directly to the socket), so
        # only the stock writer's idle callback registration is left to drop with it.
        self._loop.remove_writer(cast("int", writer.fd))
        self._writer = writer
        return self
