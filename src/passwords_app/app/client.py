# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Asynchronous Gio client for passwords-appd (interface io.github.alex_mextner.Passwords1).

Every call is non-blocking and reports back on the GLib main context with either the parsed
value or a `DaemonError`, so the UI never freezes while the daemon talks to iCloud. The app
talks to nothing else: no keyring, no network, no files with secrets.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from gi.repository import Gio, GLib

from passwords_app.app.constants import (
    DAEMON_BUS_NAME,
    DAEMON_ERROR_PREFIX,
    DAEMON_INTERFACE,
    DAEMON_OBJECT_PATH,
)
from passwords_app.app.records import (
    Draft,
    Item,
    RecoveryDevice,
    ReplyError,
    SignInStep,
    Status,
    TrashEntry,
    Wire,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

_DEFAULT_TIMEOUT_MS = 25_000
# A sync cycle or a keychain join waits on Apple's servers; the daemon returns when done.
_LONG_TIMEOUT_MS = 10 * 60_000


class ErrorKind(StrEnum):
    NOT_FOUND = "NotFound"
    INVALID = "Invalid"
    UNAVAILABLE = "Unavailable"
    AUTH_REQUIRED = "AuthRequired"
    WRONG_CODE = "WrongCode"
    WRONG_PASSCODE = "WrongPasscode"
    LOCKED = "Locked"
    # The daemon is not running and could not be started.
    UNREACHABLE = "Unreachable"
    OTHER = "Other"


_UNREACHABLE_NAMES = frozenset(
    {
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.NameHasNoOwner",
        "org.freedesktop.DBus.Error.NoReply",
        "org.freedesktop.DBus.Error.Spawn.ChildExited",
        "org.freedesktop.DBus.Error.Spawn.ServiceNotFound",
    }
)


class DaemonError(Exception):
    """A failed call; `message` is user-facing text from the daemon (shown verbatim)."""

    def __init__(self, kind: ErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


def error_from_glib(err: GLib.Error) -> DaemonError:
    """Map a GDBus error to a `DaemonError`, stripping the `GDBus.Error:<name>: ` prefix."""
    remote = Gio.DBusError.get_remote_error(err)
    text = err.message or ""
    if remote and text.startswith(f"GDBus.Error:{remote}"):
        text = text[len(f"GDBus.Error:{remote}") :].removeprefix(":").strip()
    if remote and remote.startswith(DAEMON_ERROR_PREFIX):
        try:
            kind = ErrorKind(remote.removeprefix(DAEMON_ERROR_PREFIX))
        except ValueError:
            kind = ErrorKind.OTHER
        return DaemonError(kind, text)
    if remote in _UNREACHABLE_NAMES or err.matches(Gio.io_error_quark(), Gio.IOErrorEnum.CLOSED):
        return DaemonError(ErrorKind.UNREACHABLE, text)
    return DaemonError(ErrorKind.OTHER, text)


type Done[T] = Callable[[T | DaemonError], None]


def _wire_value(value: object) -> GLib.Variant:
    if isinstance(value, bool):
        return GLib.Variant("b", value)
    if isinstance(value, str):
        return GLib.Variant("s", value)
    if isinstance(value, list | tuple):
        return GLib.Variant("as", [str(v) for v in cast("Sequence[object]", value)])
    msg = f"unsupported Save value type {type(value).__name__}"
    raise TypeError(msg)


def save_payload(draft: Draft) -> GLib.Variant:
    return GLib.Variant("(a{sv})", ({k: _wire_value(v) for k, v in draft.to_wire().items()},))


class DaemonClient:
    """Thin typed wrapper around one D-Bus connection to the daemon."""

    def __init__(self, connection: Gio.DBusConnection, *, bus_name: str = DAEMON_BUS_NAME) -> None:
        self.connection = connection
        self.bus_name = bus_name
        self._subscriptions: list[int] = []
        self._watch = 0

    # ---------------------------------------------------------------- plumbing
    def _call[T](  # noqa: PLR0913 - mirrors Gio.DBusConnection.call, which every method feeds
        self,
        method: str,
        params: GLib.Variant | None,
        reply_type: str | None,
        convert: Callable[[tuple[object, ...]], T],
        done: Done[T],
        *,
        timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    ) -> None:
        def finished(conn: Gio.DBusConnection, result: Gio.AsyncResult) -> None:
            try:
                reply = conn.call_finish(result)
            except GLib.Error as err:
                done(error_from_glib(err))
                return
            try:
                values = cast("tuple[object, ...]", reply.unpack()) if reply else ()
                value = convert(values)
            except (ReplyError, TypeError, ValueError) as exc:
                done(DaemonError(ErrorKind.OTHER, f"unexpected reply to {method}: {exc}"))
                return
            done(value)

        self.connection.call(
            self.bus_name,
            DAEMON_OBJECT_PATH,
            DAEMON_INTERFACE,
            method,
            params,
            GLib.VariantType.new(reply_type) if reply_type else None,
            Gio.DBusCallFlags.NONE,
            timeout_ms,
            None,
            finished,
        )

    def subscribe(
        self,
        on_status: Callable[[Status], None],
        on_items: Callable[[list[str]], None],
    ) -> None:
        """Forward StatusChanged and ItemsChanged; malformed signals are dropped."""

        def status_signal(
            _connection: Gio.DBusConnection,
            _sender: str | None,
            _object_path: str,
            _interface: str,
            _signal: str,
            params: GLib.Variant,
        ) -> None:
            if params.get_type_string() != "(a{sv})":
                return
            try:
                (raw,) = cast("tuple[Wire]", params.unpack())
                on_status(Status.from_wire(raw))
            except (ReplyError, ValueError, TypeError):
                return

        def items_signal(
            _connection: Gio.DBusConnection,
            _sender: str | None,
            _object_path: str,
            _interface: str,
            _signal: str,
            params: GLib.Variant,
        ) -> None:
            if params.get_type_string() != "(as)":
                return
            (ids,) = cast("tuple[list[str]]", params.unpack())
            on_items(list(ids))

        for member, handler in (("StatusChanged", status_signal), ("ItemsChanged", items_signal)):
            self._subscriptions.append(
                self.connection.signal_subscribe(
                    self.bus_name,
                    DAEMON_INTERFACE,
                    member,
                    DAEMON_OBJECT_PATH,
                    None,
                    Gio.DBusSignalFlags.NONE,
                    handler,
                )
            )

    def watch(self, on_appeared: Callable[[], None], on_vanished: Callable[[], None]) -> None:
        """Track whether the daemon is on the bus (restarts, crashes, first start)."""
        self._watch = Gio.bus_watch_name_on_connection(
            self.connection,
            self.bus_name,
            Gio.BusNameWatcherFlags.NONE,
            lambda *_args: on_appeared(),
            lambda *_args: on_vanished(),
        )

    def close(self) -> None:
        for sub in self._subscriptions:
            self.connection.signal_unsubscribe(sub)
        self._subscriptions.clear()
        if self._watch:
            Gio.bus_unwatch_name(self._watch)
            self._watch = 0

    # ---------------------------------------------------------------- API
    def get_status(self, done: Done[Status]) -> None:
        self._call(
            "GetStatus", None, "(a{sv})", lambda v: Status.from_wire(cast("Wire", v[0])), done
        )

    def list_items(self, done: Done[list[Item]]) -> None:
        self._call(
            "List",
            None,
            "(aa{sv})",
            lambda v: [Item.from_wire(d) for d in cast("list[Wire]", v[0])],
            done,
        )

    def get(self, item_id: str, done: Done[Item]) -> None:
        self._call(
            "Get",
            GLib.Variant("(s)", (item_id,)),
            "(a{sv})",
            lambda v: Item.from_wire(cast("Wire", v[0])),
            done,
        )

    def save(self, draft: Draft, done: Done[str]) -> None:
        self._call("Save", save_payload(draft), "(s)", lambda v: str(v[0]), done)

    def delete(self, item_id: str, done: Done[None]) -> None:
        self._call("Delete", GLib.Variant("(s)", (item_id,)), None, lambda _v: None, done)

    def list_trash(self, done: Done[list[TrashEntry]]) -> None:
        self._call(
            "ListTrash",
            None,
            "(aa{sv})",
            lambda v: [TrashEntry.from_wire(d) for d in cast("list[Wire]", v[0])],
            done,
        )

    def restore(self, trash_id: str, done: Done[str]) -> None:
        self._call("Restore", GLib.Variant("(s)", (trash_id,)), "(s)", lambda v: str(v[0]), done)

    def purge(self, trash_id: str, done: Done[None]) -> None:
        self._call("Purge", GLib.Variant("(s)", (trash_id,)), None, lambda _v: None, done)

    def sync_now(self, done: Done[None]) -> None:
        self._call("SyncNow", None, None, lambda _v: None, done, timeout_ms=_LONG_TIMEOUT_MS)

    def resolve_pause(self, *, apply: bool, done: Done[None]) -> None:
        self._call(
            "ResolvePause",
            GLib.Variant("(b)", (apply,)),
            None,
            lambda _v: None,
            done,
            timeout_ms=_LONG_TIMEOUT_MS,
        )

    def get_code(self, item_id: str, done: Done[tuple[str, int]]) -> None:
        self._call(
            "GetCode",
            GLib.Variant("(s)", (item_id,)),
            "(su)",
            lambda v: (str(v[0]), int(cast("int", v[1]))),
            done,
        )

    def sign_in_start(self, apple_id: str, password: str, done: Done[SignInStep]) -> None:
        self._call(
            "SignInStart",
            GLib.Variant("(ss)", (apple_id, password)),
            "(a{sv})",
            lambda v: SignInStep.from_wire(cast("Wire", v[0])),
            done,
            timeout_ms=_LONG_TIMEOUT_MS,
        )

    def sign_in_code(self, code: str, done: Done[SignInStep]) -> None:
        self._call(
            "SignInCode",
            GLib.Variant("(s)", (code,)),
            "(a{sv})",
            lambda v: SignInStep.from_wire(cast("Wire", v[0])),
            done,
            timeout_ms=_LONG_TIMEOUT_MS,
        )

    def sign_in_request_sms(self, done: Done[SignInStep]) -> None:
        self._call(
            "SignInRequestSms",
            None,
            "(a{sv})",
            lambda v: SignInStep.from_wire(cast("Wire", v[0])),
            done,
        )

    def recovery_devices(self, done: Done[list[RecoveryDevice]]) -> None:
        self._call(
            "ListRecoveryDevices",
            None,
            "(aa{sv})",
            lambda v: [RecoveryDevice.from_wire(d) for d in cast("list[Wire]", v[0])],
            done,
            timeout_ms=_LONG_TIMEOUT_MS,
        )

    def join_keychain(self, device_id: str, passcode: str, done: Done[SignInStep]) -> None:
        self._call(
            "JoinKeychain",
            GLib.Variant("(ss)", (device_id, passcode)),
            "(a{sv})",
            lambda v: SignInStep.from_wire(cast("Wire", v[0])),
            done,
            timeout_ms=_LONG_TIMEOUT_MS,
        )

    def sign_out(self, done: Done[None]) -> None:
        self._call("SignOut", None, None, lambda _v: None, done)
