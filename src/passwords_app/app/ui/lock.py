# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Optional app lock after idle, unlocked through polkit (`auth_self`: every unlock asks again).

polkit shows GNOME's own authentication dialog, so fingerprint login works wherever the user
configured it. Without the shipped policy (or without polkit at all) the lock is unavailable
and the preference says so instead of failing at unlock time. `FingerprintProbe` tells whether
that dialog can actually offer a fingerprint, so the texts promise one only then.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from gi.repository import Gio, GLib

from passwords_app.app.constants import POLKIT_UNLOCK_ACTION
from passwords_app.app.i18n import _

if TYPE_CHECKING:
    from collections.abc import Callable

_POLKIT = ("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
_AUTHORITY = "org.freedesktop.PolicyKit1.Authority"
_ALLOW_USER_INTERACTION = 1
_AUTH_TIMEOUT_MS = 5 * 60_000
_FPRINT = "net.reactivated.Fprint"
_FPRINT_MANAGER = "/net/reactivated/Fprint/Manager"
_PROBE_TIMEOUT_MS = 5000

type Authorizer = Callable[[Callable[[bool], None]], None]


def _system_bus() -> Gio.DBusConnection | None:
    try:
        return Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    except GLib.Error:
        return None


def unlock_hint(*, fingerprint: bool) -> str:
    """Return the lock screen's line; a fingerprint is promised only if the probe found a reader."""
    if fingerprint:
        return _("Unlock with your password or fingerprint.")
    return _("Unlock with your password.")


def idle_lock_hint(*, fingerprint: bool) -> str:
    """Return the Lock When Idle preference's subtitle, worded like `unlock_hint`."""
    if fingerprint:
        return _("Ask for your password or fingerprint after a period without use.")
    return _("Ask for your password after a period without use.")


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
            self._bus = _system_bus()
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


class FingerprintProbe:
    """Reports whether this machine has a fingerprint reader and the user enrolled a finger.

    Asks fprintd on the system bus, read-only: the default device, then its enrolled fingers
    for the calling user. Any failure (no fprintd, no reader, nothing enrolled, no bus) is
    False, so no text promises a fingerprint that cannot be given.
    """

    def __init__(self, system_bus: Gio.DBusConnection | None = None) -> None:
        self._bus = system_bus

    def __call__(self, done: Callable[[bool], None]) -> None:
        if self._bus is None:
            self._bus = _system_bus()
        bus = self._bus
        if bus is None:
            done(False)  # noqa: FBT003
            return

        def listed(conn: Gio.DBusConnection, result: Gio.AsyncResult) -> None:
            try:
                (fingers,) = conn.call_finish(result).unpack()
            except GLib.Error:
                done(False)  # noqa: FBT003
                return
            done(bool(fingers))

        def found(conn: Gio.DBusConnection, result: Gio.AsyncResult) -> None:
            try:
                (device,) = conn.call_finish(result).unpack()
            except GLib.Error:
                done(False)  # noqa: FBT003
                return
            conn.call(
                _FPRINT,
                device,
                f"{_FPRINT}.Device",
                "ListEnrolledFingers",
                GLib.Variant("(s)", ("",)),  # the empty name means the calling user
                GLib.VariantType.new("(as)"),
                Gio.DBusCallFlags.NONE,
                _PROBE_TIMEOUT_MS,
                None,
                listed,
            )

        bus.call(
            _FPRINT,
            _FPRINT_MANAGER,
            f"{_FPRINT}.Manager",
            "GetDefaultDevice",
            None,
            GLib.VariantType.new("(o)"),
            Gio.DBusCallFlags.NONE,
            _PROBE_TIMEOUT_MS,
            None,
            found,
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
