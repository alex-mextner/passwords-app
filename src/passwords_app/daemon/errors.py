# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Errors the daemon reports to its D-Bus clients.

Each class carries the D-Bus error name from the interface XML, so the service layer turns
any `DaemonError` into the matching reply without a lookup table that could drift. Messages
are shown to the user as-is and therefore never quote secrets or raw input.
"""

from __future__ import annotations

from typing import ClassVar

from passwords_app.daemon import INTERFACE

_PREFIX = f"{INTERFACE}.Error."


class DaemonError(Exception):
    dbus_name: ClassVar[str] = "org.freedesktop.DBus.Error.Failed"


class NotFoundError(DaemonError):
    dbus_name = _PREFIX + "NotFound"


class InvalidError(DaemonError):
    dbus_name = _PREFIX + "Invalid"


class UnavailableError(DaemonError):
    dbus_name = _PREFIX + "Unavailable"


class AuthRequiredError(DaemonError):
    dbus_name = _PREFIX + "AuthRequired"


class WrongCodeError(DaemonError):
    dbus_name = _PREFIX + "WrongCode"


class WrongPasscodeError(DaemonError):
    dbus_name = _PREFIX + "WrongPasscode"


class LockedError(DaemonError):
    dbus_name = _PREFIX + "Locked"
