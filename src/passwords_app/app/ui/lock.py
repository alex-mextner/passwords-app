# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Optional app lock after idle, unlocked through polkit (`auth_self`: every unlock asks again).

polkit shows GNOME's own authentication dialog, so fingerprint login works wherever the user
configured it. Without the shipped policy (or without polkit at all) the lock is unavailable
and the preference says so instead of failing at unlock time.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from gi.repository import Gio, GLib

from passwords_app.app.constants import POLKIT_UNLOCK_ACTION

if TYPE_CHECKING:
    from collections.abc import Callable

_POLKIT = ("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
_AUTHORITY = "org.freedesktop.PolicyKit1.Authority"
_ALLOW_USER_INTERACTION = 1
_AUTH_TIMEOUT_MS = 5 * 60_000

type Authorizer = Callable[[Callable[[bool], None]], None]


def _process_start_time(pid: int) -> int:
    # Field 22 of /proc/<pid>/stat; the command name (field 2) may contain spaces, so split
    # after its closing parenthesis.
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    return int(stat.rsplit(")", 1)[1].split()[19])


class PolkitAuthorizer:
    """Asks polkit whether this user may unlock; polkit prompts for their password."""

    def __init__(self, system_bus: Gio.DBusConnection | None = None) -> None:
        self._bus = system_bus

    def _connection(self) -> Gio.DBusConnection | None:
        if self._bus is None:
            try:
                self._bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
            except GLib.Error:
                return None
        return self._bus

    def check_available(self, done: Callable[[bool], None]) -> None:
        """Report True when polkit runs and knows our action (the policy file is installed)."""
        bus = self._connection()
        if bus is None:
            done(False)  # noqa: FBT003
            return

        def finished(conn: Gio.DBusConnection, result: Gio.AsyncResult) -> None:
            try:
                (actions,) = conn.call_finish(result).unpack()
            except GLib.Error:
                done(False)  # noqa: FBT003
                return
            done(any(a[0] == POLKIT_UNLOCK_ACTION for a in actions))

        bus.call(
            _POLKIT[0],
            _POLKIT[1],
            _AUTHORITY,
            "EnumerateActions",
            GLib.Variant("(s)", ("",)),
            GLib.VariantType.new("(a(ssssssuuua{ss}))"),
            Gio.DBusCallFlags.NONE,
            5000,
            None,
            finished,
        )

    def __call__(self, done: Callable[[bool], None]) -> None:
        bus = self._connection()
        if bus is None:
            done(False)  # noqa: FBT003
            return
        pid = os.getpid()
        subject = (
            "unix-process",
            {
                "pid": GLib.Variant("u", pid),
                "start-time": GLib.Variant("t", _process_start_time(pid)),
            },
        )
        params = GLib.Variant(
            "((sa{sv})sa{ss}us)",
            (subject, POLKIT_UNLOCK_ACTION, {}, _ALLOW_USER_INTERACTION, ""),
        )

        def finished(conn: Gio.DBusConnection, result: Gio.AsyncResult) -> None:
            try:
                ((authorized, _challenge, _details),) = conn.call_finish(result).unpack()
            except GLib.Error:
                done(False)  # noqa: FBT003
                return
            done(bool(authorized))

        bus.call(
            _POLKIT[0],
            _POLKIT[1],
            _AUTHORITY,
            "CheckAuthorization",
            params,
            GLib.VariantType.new("((bba{ss}))"),
            Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION,
            _AUTH_TIMEOUT_MS,
            None,
            finished,
        )


class IdleTimer:
    """Fires `on_idle` after `minutes()` without user input; `poke()` on every input."""

    def __init__(self, minutes: Callable[[], int], on_idle: Callable[[], None]) -> None:
        self._minutes = minutes
        self._on_idle = on_idle
        self._source = 0
        self.armed = False

    def arm(self) -> None:
        self.armed = True
        self.poke()

    def disarm(self) -> None:
        self.armed = False
        if self._source:
            GLib.source_remove(self._source)
            self._source = 0

    def poke(self) -> None:
        if not self.armed:
            return
        if self._source:
            GLib.source_remove(self._source)
        self._source = GLib.timeout_add_seconds(max(1, self._minutes()) * 60, self._fire)

    def _fire(self) -> bool:
        self._source = 0
        self._on_idle()
        return GLib.SOURCE_REMOVE
