# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""In-memory `passwords-appd` on a private D-Bus, for GUI, screenshot and browser tests.

Implements every method and signal of `data/dbus/io.github.alex_mextner.Passwords1.xml` with
the real daemon's dict conventions, but keeps all state in memory and never touches iCloud or
a keyring. It only ever connects to the bus address it is given.

API summary:

`FakeDaemon(items=(), trash=(), *, clock=..., state="signed-out", apple_id="")`
- `await start(bus_address)` / `await stop()`: export + own the bus name / disconnect.
- Knobs: `latency` (s, slept at the start of every method), `sync_duration`, `join_duration`,
  `require_2fa`, `apple_password`, `verification_code`, `device_passcode`, `clock`.
- Hooks (call on the daemon's loop): `set_state`, `start_syncing`, `go_idle`, `go_offline`,
  `require_signin`, `sign_out`, `pause`, `set_error`, `add_item`, `refuse`/`accept` (iCloud
  refuses or takes one login: its `sync_problem`). Status changes emit StatusChanged; item
  changes emit ItemsChanged.
- `fail_next(method, error_name, message)`: the next call of D-Bus `method` raises that error.
- `calls`: D-Bus method names in call order (never arguments: they may be secrets).
- `FakeDaemon.demo(now)`: seeded with `demo_dataset`, signed in and idle.

`FakeDaemonThread(bus_address, daemon=None)`: runs the daemon on its own asyncio loop in a
background thread so a GLib-driven test thread never blocks; `call(fn)` runs `fn(daemon)` there.

`python -m tests.fakes.fake_daemon --bus-address ADDR [--state S] [--latency S]` serves the
demo daemon until SIGTERM/SIGINT and prints `ready` once the name is owned.
"""

import argparse
import asyncio
import base64
import dataclasses
import hashlib
import inspect
import signal
import sys
import threading
import uuid
from collections.abc import Awaitable, Callable, Coroutine, Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Final, Literal, Self, cast, get_args, overload
from urllib.parse import quote

from dbus_fast import BusType, DBusError, NameFlag, RequestNameReply, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.annotations import DBusBool, DBusSignature, DBusStr
from dbus_fast.service import ServiceInterface, dbus_method, dbus_signal

from passwords_app.core import urls
from passwords_app.core.model import Credential, TrashEntry, TrashReason
from passwords_app.core.otp import code_at, parse_otpauth
from passwords_app.core.urls import MatchKind

BUS_NAME: Final = "io.github.alex_mextner.Passwords"
OBJECT_PATH: Final = "/io/github/alex_mextner/Passwords"
INTERFACE: Final = "io.github.alex_mextner.Passwords1"
ERROR_PREFIX: Final = f"{INTERFACE}.Error."
TRASH_RETENTION: Final = timedelta(days=90)
PASSCODE_ATTEMPTS: Final = 10
NOT_FOUND: Final = "NotFound"
INVALID: Final = "Invalid"
UNAVAILABLE: Final = "Unavailable"
AUTH_REQUIRED: Final = "AuthRequired"
WRONG_CODE: Final = "WrongCode"
WRONG_PASSCODE: Final = "WrongPasscode"

State = Literal["signed-out", "syncing", "idle", "paused", "offline", "signin-required", "error"]
STATES: Final[tuple[str, ...]] = get_args(State)

VariantDict = dict[str, Variant]
DBusVardict = Annotated[VariantDict, DBusSignature("a{sv}")]
DBusVardictList = Annotated[list[VariantDict], DBusSignature("aa{sv}")]
DBusStrList = Annotated[list[str], DBusSignature("as")]
DBusCode = Annotated[tuple[str, int], DBusSignature("su")]

# Signature of every key Save() accepts; the read-only ones are type-checked, then ignored.
_SAVE_KEYS: Final = {
    "id": "s",
    "url": "s",
    "username": "s",
    "password": "s",
    "title": "s",
    "notes": "s",
    "otpauth": "s",
    "group": "s",
    "alt_urls": "as",
    "created": "x",
    "modified": "x",
    "has_code": "b",
    "sync_problem": "s",
}
_READ_ONLY_KEYS: Final = frozenset({"created", "modified", "has_code", "sync_problem"})
_OPTIONAL_TEXT: Final = frozenset({"title", "notes", "otpauth", "group"})

# Apple's default device names use the typographic apostrophe.
_DEFAULT_RECOVERY_DEVICES: Final = (
    ("6D1F0A52-0001", "Alex’s iPhone", "iPhone17,1", "F2LXXXXX01"),  # noqa: RUF001
    ("6D1F0A52-0002", "Alex’s iPad", "iPad16,3", "DMPXXXXX02"),  # noqa: RUF001
    ("6D1F0A52-0003", "Alex’s MacBook Air", "Mac15,12", "C02XXXXX03"),  # noqa: RUF001
)
_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _ms(at: datetime) -> int:
    return (at - _EPOCH) // timedelta(milliseconds=1)


def _new_id() -> str:
    return str(uuid.uuid4()).upper()


def _error(name: str, message: str) -> DBusError:
    return DBusError(name if "." in name else ERROR_PREFIX + name, message)


def item_dict(c: Credential, *, secrets: bool = False, sync_problem: str = "") -> VariantDict:
    """Wire form of a credential; `secrets` adds password + otpauth (Get() only)."""
    d: VariantDict = {
        "id": Variant("s", c.id),
        "url": Variant("s", c.url),
        "username": Variant("s", c.username),
        "title": Variant("s", c.title or ""),
        "notes": Variant("s", c.notes or ""),
        "group": Variant("s", c.group or ""),
        "alt_urls": Variant("as", list(c.alt_urls)),
        "created": Variant("x", _ms(c.created)),
        "modified": Variant("x", _ms(c.modified)),
        "has_code": Variant("b", bool(c.otpauth)),
        "sync_problem": Variant("s", sync_problem),
    }
    if secrets:
        d["password"] = Variant("s", c.password)
        d["otpauth"] = Variant("s", c.otpauth or "")
    return d


def _step(step: str, destination: str = "", message: str = "") -> VariantDict:
    return {
        "step": Variant("s", step),
        "destination": Variant("s", destination),
        "message": Variant("s", message),
    }


class FakeDaemon(ServiceInterface):
    """The daemon's D-Bus interface over in-memory state; see the module docstring."""

    def __init__(  # noqa: PLR0913 - every knob is keyword-only and optional
        self,
        items: Iterable[Credential] = (),
        trash: Iterable[TrashEntry] = (),
        *,
        clock: Callable[[], datetime] = _utcnow,
        state: State = "signed-out",
        apple_id: str = "",
        last_sync: datetime | None = None,
    ) -> None:
        super().__init__(INTERFACE)
        self.clock = clock
        self.latency = 0.0
        self.sync_duration = 0.3
        self.join_duration = 0.5
        self.sync_interval = timedelta(minutes=15)
        self.require_2fa = True
        # Fictional credentials the fake accepts; never real ones.
        self.apple_password = "correct-horse"
        self.verification_code = "123456"
        self.device_passcode = "000000"
        self.recovery_devices: list[tuple[str, str, str, str]] = list(_DEFAULT_RECOVERY_DEVICES)
        self.calls: list[str] = []
        self.items: dict[str, Credential] = {c.id: c for c in items}
        self.trash: dict[str, TrashEntry] = {e.trash_id: e for e in trash}
        # Item id -> why iCloud refuses to store it (the item dicts' sync_problem).
        self.sync_problems: dict[str, str] = {}
        self._state: State = state
        self._apple_id = apple_id
        self._message = ""
        self._last_sync = last_sync
        self._pending_local: list[str] = []
        self._pending_remote: list[str] = []
        self._failures: dict[str, DBusError] = {}
        self._signin_stage: Literal["none", "code", "device", "done"] = (
            "done" if apple_id and state != "signed-out" else "none"
        )
        self._signin_apple_id = ""
        self._listed_devices: set[str] = set()
        self._attempts: dict[str, int] = {}
        # Bumped on sign-out so a join still waiting out join_duration cannot sign back in.
        self._auth_epoch = 0
        self._bus: MessageBus | None = None
        self._last_status = self._status_values()

    @classmethod
    def demo(cls, now: datetime | None = None) -> Self:
        """Daemon seeded with `demo_dataset`: signed in, idle, synced two minutes ago."""
        now = now or _utcnow()
        items, trash = demo_dataset(now)
        return cls(
            items,
            trash,
            state="idle",
            apple_id="alex.doe@example.com",
            last_sync=now - timedelta(minutes=2),
        )

    # ------------------------------------------------------------------ lifecycle

    async def start(self, bus_address: str) -> None:
        """Connect to `bus_address`, export the object and own the bus name."""
        bus = await MessageBus(bus_address=bus_address, bus_type=BusType.SESSION).connect()
        bus.export(OBJECT_PATH, self)
        reply = await bus.request_name(BUS_NAME, NameFlag.DO_NOT_QUEUE)
        if reply is not RequestNameReply.PRIMARY_OWNER:
            bus.disconnect()
            msg = f"{BUS_NAME} is already owned on {bus_address}"
            raise RuntimeError(msg)
        self._bus = bus

    async def stop(self) -> None:
        bus, self._bus = self._bus, None
        if bus is not None:
            bus.unexport(OBJECT_PATH, self)
            bus.disconnect()
            await bus.wait_for_disconnect()  # type: ignore[no-untyped-call]

    # ------------------------------------------------------------------ hooks

    @property
    def state(self) -> State:
        return self._state

    @property
    def apple_id(self) -> str:
        return self._apple_id

    def fail_next(self, method: str, error_name: str, message: str = "") -> None:
        """Make the next call of D-Bus `method` raise `error_name` (short or full name)."""
        self._failures[method] = _error(error_name, message or f"injected {error_name}")

    def set_state(self, state: State, message: str = "") -> None:
        if state not in STATES:
            msg = f"unknown state {state!r}"
            raise ValueError(msg)
        self._state = state
        self._message = message
        if state != "paused":
            self._pending_local.clear()
            self._pending_remote.clear()
        self._publish_status()

    def start_syncing(self) -> None:
        self.set_state("syncing")

    def go_idle(self) -> None:
        self._last_sync = self.clock()
        self.set_state("idle")

    def go_offline(self, message: str = "No connection to iCloud") -> None:
        self.set_state("offline", message)

    def require_signin(self, message: str = "Sign in to iCloud again to keep syncing") -> None:
        self._signin_stage = "none"
        self.set_state("signin-required", message)

    def sign_out(self) -> None:
        self._auth_epoch += 1
        self._apple_id = ""
        self._signin_stage = "none"
        self._listed_devices.clear()
        self.set_state("signed-out")

    def set_error(self, message: str) -> None:
        self.set_state("error", message)

    def pause(
        self,
        local_ids: Sequence[str] = (),
        remote_ids: Sequence[str] = (),
        message: str | None = None,
    ) -> None:
        """Pause sync as the mass-deletion guard does, with the deletions it is holding back."""
        total = len(local_ids) + len(remote_ids)
        self._state = "paused"
        self._message = (
            message
            if message is not None
            else f"Sync paused: {total} deletions are waiting for your confirmation"
        )
        self._pending_local = list(local_ids)
        self._pending_remote = list(remote_ids)
        self._publish_status()

    def expire_trash(self, trash_id: str) -> None:
        """Drop a trash entry past its retention as a sync cycle does: StatusChanged only."""
        del self.trash[trash_id]
        self._publish_status()

    def add_item(  # noqa: PLR0913 - mirrors the Credential fields
        self,
        url: str,
        username: str = "",
        password: str = "",
        *,
        title: str | None = None,
        notes: str | None = None,
        otpauth: str | None = None,
        alt_urls: Sequence[str] = (),
        group: str | None = None,
        item_id: str | None = None,
    ) -> str:
        """Insert an item as if it arrived from iCloud; returns its id."""
        now = self.clock()
        c = Credential(
            id=item_id or _new_id(),
            url=url,
            username=username,
            password=password,
            created=now,
            modified=now,
            title=title,
            notes=notes,
            otpauth=otpauth,
            alt_urls=tuple(alt_urls),
            group=group,
        )
        self.items[c.id] = c
        self._items_changed([c.id])
        return c.id

    def refuse(self, item_id: str, reason: str) -> None:
        """As if iCloud refused to store this login: the daemon's status and sync_problem."""
        c = self._get_item(item_id)
        self.sync_problems[item_id] = reason
        self.items_changed([item_id])
        self._last_sync = self.clock()
        self.set_state(
            "idle",
            f"iCloud did not accept the password for {c.username} on {c.url}: {reason}. "
            "Everything else is syncing; edit or delete this password to fix it.",
        )

    def accept(self, item_id: str) -> None:
        """As if iCloud took a login it refused before."""
        del self.sync_problems[item_id]
        if not self.sync_problems:
            self._message = ""
        self.items_changed([item_id])
        self._publish_status()

    # ------------------------------------------------------------------ internals

    def _status_values(self) -> dict[str, object]:
        last = _ms(self._last_sync) if self._last_sync else 0
        next_sync = (
            _ms(self._last_sync + self.sync_interval)
            if self._last_sync and self._state == "idle"
            else 0
        )
        return {
            "state": self._state,
            "apple_id": self._apple_id,
            "item_count": len(self.items),
            "trash_count": len(self.trash),
            "last_sync": last,
            "next_sync": next_sync,
            "message": self._message,
            "pending_local_deletions": list(self._pending_local),
            "pending_remote_deletions": list(self._pending_remote),
        }

    def _status(self) -> VariantDict:
        v = self._status_values()
        return {
            "state": Variant("s", v["state"]),
            "apple_id": Variant("s", v["apple_id"]),
            "item_count": Variant("u", v["item_count"]),
            "trash_count": Variant("u", v["trash_count"]),
            "last_sync": Variant("x", v["last_sync"]),
            "next_sync": Variant("x", v["next_sync"]),
            "message": Variant("s", v["message"]),
            "pending_local_deletions": Variant("as", v["pending_local_deletions"]),
            "pending_remote_deletions": Variant("as", v["pending_remote_deletions"]),
        }

    def _publish_status(self) -> None:
        # Only real changes are signalled, like the daemon: clients re-render on every signal.
        values = self._status_values()
        if values != self._last_status:
            self._last_status = values
            self.status_changed(self._status())

    def _items_changed(self, ids: Sequence[str]) -> None:
        self.items_changed(list(ids))
        self._publish_status()

    async def _enter(self, method: str) -> None:
        self.calls.append(method)
        if self.latency:
            await asyncio.sleep(self.latency)
        failure = self._failures.pop(method, None)
        if failure is not None:
            raise failure

    def _to_trash(self, item_id: str, reason: TrashReason) -> None:
        c = self.items.pop(item_id)
        entry = TrashEntry(trash_id=_new_id(), credential=c, deleted_at=self.clock(), reason=reason)
        self.trash[entry.trash_id] = entry

    def _trash_dict(self, e: TrashEntry) -> VariantDict:
        return {
            "trash_id": Variant("s", e.trash_id),
            "reason": Variant("s", e.reason),
            "deleted_at": Variant("x", _ms(e.deleted_at)),
            "expires_at": Variant("x", _ms(e.expires_at(TRASH_RETENTION))),
            "item": Variant("a{sv}", item_dict(e.credential)),
        }

    def _get_item(self, item_id: str) -> Credential:
        c = self.items.get(item_id)
        if c is None:
            raise _error(NOT_FOUND, f"no item {item_id!r}")
        return c

    def _get_trash(self, trash_id: str) -> TrashEntry:
        e = self.trash.get(trash_id)
        if e is None:
            raise _error(NOT_FOUND, f"no trash entry {trash_id!r}")
        return e

    def _build(self, fields: VariantDict) -> Credential:
        for key, value in fields.items():
            expected = _SAVE_KEYS.get(key)
            if expected is None:
                raise _error(INVALID, f"unknown key {key!r}")
            if value.signature != expected:
                raise _error(INVALID, f"{key!r} must have type {expected!r}")
        # Variant values are untyped; the signature check above guarantees each one's type.
        updates: dict[str, Any] = {
            k: v.value for k, v in fields.items() if k not in _READ_ONLY_KEYS and k != "id"
        }
        for key in _OPTIONAL_TEXT & updates.keys():
            updates[key] = updates[key] or None
        if "alt_urls" in updates:
            updates["alt_urls"] = tuple(updates["alt_urls"])
        if updates.get("otpauth"):
            try:
                parse_otpauth(updates["otpauth"])
            except ValueError as e:
                raise _error(INVALID, f"otpauth: {e}") from None
        item_id: str = fields["id"].value if "id" in fields else ""
        current = self._get_item(item_id) if item_id else None
        url = updates.get("url", current.url if current else "")
        if not url:
            raise _error(INVALID, "url must not be empty")
        now = self.clock()
        if current is None:
            current = Credential(
                id=_new_id(), url=url, username="", password="", created=now, modified=now
            )
        return dataclasses.replace(current, **updates, modified=now)

    # ------------------------------------------------------------------ D-Bus: items

    @dbus_method(name="GetStatus")
    async def get_status(self) -> DBusVardict:
        await self._enter("GetStatus")
        return self._status()

    @dbus_method(name="List")
    async def list_items(self) -> DBusVardictList:
        await self._enter("List")
        return [self._item(c) for c in self.items.values()]

    @dbus_method(name="Get")
    async def get(self, item_id: DBusStr) -> DBusVardict:
        await self._enter("Get")
        return self._item(self._get_item(item_id), secrets=True)

    def _item(self, c: Credential, *, secrets: bool = False) -> VariantDict:
        return item_dict(c, secrets=secrets, sync_problem=self.sync_problems.get(c.id, ""))

    @dbus_method(name="Save")
    async def save(self, item: DBusVardict) -> DBusStr:
        await self._enter("Save")
        c = self._build(item)
        self.items[c.id] = c
        self._items_changed([c.id])
        return c.id

    @dbus_method(name="Delete")
    async def delete(self, item_id: DBusStr) -> None:
        await self._enter("Delete")
        self._get_item(item_id)
        self._to_trash(item_id, "deleted-on-linux")
        self.sync_problems.pop(item_id, None)
        self._items_changed([item_id])

    @dbus_method(name="ListTrash")
    async def list_trash(self) -> DBusVardictList:
        await self._enter("ListTrash")
        return [self._trash_dict(e) for e in self.trash.values()]

    @dbus_method(name="Restore")
    async def restore(self, trash_id: DBusStr) -> DBusStr:
        await self._enter("Restore")
        entry = self.trash.pop(self._get_trash(trash_id).trash_id)
        # Like SyncEngine.restore: always a fresh id and modification time, because the old
        # id may be live (a conflict winner) or tombstoned in iCloud.
        c = dataclasses.replace(entry.credential, id=_new_id(), modified=self.clock())
        self.items[c.id] = c
        self._items_changed([c.id])
        return c.id

    @dbus_method(name="Purge")
    async def purge(self, trash_id: DBusStr) -> None:
        await self._enter("Purge")
        entry = self.trash.pop(self._get_trash(trash_id).trash_id)
        self._items_changed([entry.credential.id])

    @dbus_method(name="Match")
    async def match(self, url: DBusStr) -> DBusVardictList:
        await self._enter("Match")
        kinds = [(urls.match(url, c), c) for c in self.items.values()]
        return [
            self._item(c)
            for wanted in (MatchKind.EXACT_HOST, MatchKind.SAME_SITE)
            for kind, c in kinds
            if kind is wanted
        ]

    @dbus_method(name="GetCode")
    async def get_code(self, item_id: DBusStr) -> DBusCode:
        await self._enter("GetCode")
        c = self._get_item(item_id)
        if not c.otpauth:
            raise _error(NOT_FOUND, f"item {item_id!r} has no verification code")
        return code_at(parse_otpauth(c.otpauth), self.clock())

    # ------------------------------------------------------------------ D-Bus: sync

    @dbus_method(name="SyncNow")
    async def sync_now(self) -> None:
        await self._enter("SyncNow")
        if self._state in {"signed-out", "signin-required"}:
            raise _error(AUTH_REQUIRED, "Sign in to iCloud first")
        if self._state == "offline":
            raise _error(UNAVAILABLE, self._message or "No connection to iCloud")
        if self._state == "paused":
            return
        self.set_state("syncing")
        await asyncio.sleep(self.sync_duration)
        # A hook may have moved the state on mid-cycle (offline, paused...); keep that state.
        if self._state == "syncing":
            self.go_idle()

    @dbus_method(name="ResolvePause")
    async def resolve_pause(self, apply: DBusBool) -> None:
        await self._enter("ResolvePause")
        if self._state != "paused":
            raise _error(INVALID, "sync is not paused")
        ids = [*self._pending_local, *self._pending_remote]
        if apply:
            for item_id in self._pending_local:
                if item_id in self.items:
                    self._to_trash(item_id, "deleted-in-icloud")
            for item_id in self._pending_remote:
                if item_id in self.items:
                    self._to_trash(item_id, "deleted-on-linux")
        self._last_sync = self.clock()
        self.set_state("idle")
        self.items_changed(ids)

    # ------------------------------------------------------------------ D-Bus: sign-in

    @dbus_method(name="SignInStart")
    async def sign_in_start(self, apple_id: DBusStr, password: DBusStr) -> DBusVardict:
        await self._enter("SignInStart")
        if password != self.apple_password:
            raise _error(AUTH_REQUIRED, "Apple ID or password is incorrect")
        self._signin_apple_id = apple_id
        if self.require_2fa:
            self._signin_stage = "code"
            return _step(
                "code", "trusted-device", "Enter the code shown on your trusted Apple device"
            )
        return self._signed_in()

    @dbus_method(name="SignInRequestSms")
    async def sign_in_request_sms(self) -> DBusVardict:
        await self._enter("SignInRequestSms")
        if self._signin_stage != "code":
            raise _error(INVALID, "no verification code is pending")
        return _step("code", "sms", "Enter the code sent to your phone number ending in 01")

    @dbus_method(name="SignInCode")
    async def sign_in_code(self, code: DBusStr) -> DBusVardict:
        await self._enter("SignInCode")
        if self._signin_stage != "code":
            raise _error(INVALID, "no verification code is pending")
        if code != self.verification_code:
            raise _error(WRONG_CODE, "The verification code is incorrect")
        return self._signed_in()

    def _signed_in(self) -> VariantDict:
        # Signed in to Apple, but this computer cannot read the keychain until it joins.
        self._signin_stage = "device"
        self._apple_id = self._signin_apple_id
        self.set_state("signin-required", "Confirm with a device passcode to finish signing in")
        return _step("device", "", "Confirm with the screen passcode of one of your devices")

    @dbus_method(name="ListRecoveryDevices")
    async def list_recovery_devices(self) -> DBusVardictList:
        await self._enter("ListRecoveryDevices")
        if self._signin_stage != "device":
            raise _error(AUTH_REQUIRED, "Sign in with your Apple ID first")
        self._listed_devices = {d[0] for d in self.recovery_devices}
        return [
            {
                "id": Variant("s", device_id),
                "name": Variant("s", name),
                "model": Variant("s", model),
                "serial": Variant("s", serial),
            }
            for device_id, name, model, serial in self.recovery_devices
        ]

    @dbus_method(name="JoinKeychain")
    async def join_keychain(self, device_id: DBusStr, passcode: DBusStr) -> DBusVardict:
        await self._enter("JoinKeychain")
        if self._signin_stage != "device":
            raise _error(AUTH_REQUIRED, "Sign in with your Apple ID first")
        if device_id not in self._listed_devices:
            raise _error(INVALID, f"unknown device {device_id!r}")
        left = self._attempts.setdefault(device_id, PASSCODE_ATTEMPTS)
        if left == 0:
            raise _error(UNAVAILABLE, "device recovery copy destroyed")
        if passcode != self.device_passcode:
            left -= 1
            self._attempts[device_id] = left
            if left == 0:
                raise _error(UNAVAILABLE, "device recovery copy destroyed")
            noun = "attempt" if left == 1 else "attempts"
            raise _error(WRONG_PASSCODE, f"Wrong passcode. {left} {noun} left on this device.")
        epoch = self._auth_epoch
        await asyncio.sleep(self.join_duration)
        if epoch != self._auth_epoch:
            raise _error(AUTH_REQUIRED, "Signed out while joining; sign in again")
        self._signin_stage = "done"
        self._last_sync = self.clock()
        self.set_state("idle")
        return _step("done", "", "This computer can now use your iCloud Keychain")

    @dbus_method(name="SignOut")
    async def sign_out_method(self) -> None:
        await self._enter("SignOut")
        self.sign_out()

    # ------------------------------------------------------------------ signals

    @dbus_signal(name="StatusChanged")
    def status_changed(self, status: VariantDict) -> DBusVardict:
        return status

    @dbus_signal(name="ItemsChanged")
    def items_changed(self, ids: list[str]) -> DBusStrList:
        return ids


class FakeDaemonThread:
    """Serve a FakeDaemon from a private asyncio loop in a background thread."""

    def __init__(self, bus_address: str, daemon: FakeDaemon | None = None) -> None:
        self.bus_address = bus_address
        self.daemon = daemon if daemon is not None else FakeDaemon()
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, name="FakeDaemon", daemon=True)

    def _run(self) -> None:
        loop = self._loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.daemon.start(self.bus_address))
        except BaseException as e:  # noqa: BLE001 - handed to the starting thread
            self._startup_error = e
            self._ready.set()
            loop.close()
            return
        self._ready.set()
        loop.run_forever()
        # Method calls still sleeping (SyncNow, latency) must not outlive the loop.
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()

    def __enter__(self) -> Self:
        self._thread.start()
        self._ready.wait()
        if self._startup_error is not None:
            self._thread.join()
            raise self._startup_error
        return self

    def __exit__(self, *_: object) -> None:
        if self._loop.is_closed():
            return
        asyncio.run_coroutine_threadsafe(self.daemon.stop(), self._loop).result()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()

    @overload
    def call[T](
        self, fn: Callable[[FakeDaemon], Coroutine[Any, Any, T]], timeout: float = 30
    ) -> T: ...
    @overload
    def call[T](self, fn: Callable[[FakeDaemon], T], timeout: float = 30) -> T: ...
    def call(self, fn: Callable[[FakeDaemon], object], timeout: float = 30) -> object:
        """Run `fn(daemon)` (sync or async) on the daemon's loop and return its result."""

        async def run() -> object:
            result = fn(self.daemon)
            if inspect.isawaitable(result):
                return await cast("Awaitable[object]", result)
            return result

        return asyncio.run_coroutine_threadsafe(run(), self._loop).result(timeout)


# ---------------------------------------------------------------------- demo data

# (title, url, username). Every host is reserved for documentation (`*.example`,
# `example.com/org/net`, 192.0.2.0/24), so screenshots never show a real service.
_DEMO_SITES: Final = (
    ("Northwind Mail", "https://mail.northwind.example", "alex.doe@example.com"),
    ("Contoso ID", "https://id.contoso.example", "alex.doe"),
    ("Example Shop", "https://shop.example.com", "alex.doe@example.com"),
    ("Example Bank", "https://bank.example.org", "adoe1987"),
    ("Fabrikam Cloud", "https://cloud.fabrikam.example", "alex.doe@example.com"),
    ("Tailspin Airlines", "https://www.tailspin.example", "ADOE4471"),
    ("Wide World Importers", "https://wwi.example", "alex.doe@example.com"),
    ("Adventure Works", "https://adventure-works.example", "alexd"),
    ("Litware Code", "https://git.litware.example", "alexdoe"),
    ("Proseware Docs", "https://docs.proseware.example", "alex.doe@example.com"),
    ("Woodgrove Bank", "https://online.woodgrove.example", "40021984"),
    ("Margie's Travel", "https://margies-travel.example", "alex.doe@example.com"),
    ("Coho Winery", "https://cohowinery.example", "alex.doe@example.com"),
    ("Lucerne Publishing", "https://lucerne-publishing.example", "a.doe"),
    ("Fourth Coffee", "https://fourthcoffee.example", "alex.doe@example.com"),
    ("Alpine Ski House", "https://alpineskihouse.example", "alex.doe@example.com"),
    ("Blue Yonder Airlines", "https://blueyonder.example", "BY88213"),
    ("City Power & Light", "https://my.citypower.example", "alex.doe@example.com"),
    ("Graphic Design Institute", "https://learn.gdi.example", "jdoe"),
    ("Humongous Insurance", "https://portal.humongous.example", "alex.doe@example.com"),
    ("Trey Research", "https://trey-research.example", "alex"),
    ("VanArsdel Media", "https://stream.vanarsdel.example", "alex.doe@example.com"),
    ("Relecloud", "https://console.relecloud.example", "alex.doe@example.com"),
    ("Wingtip Toys", "https://wingtiptoys.example", "family.doe@example.com"),
    ("School Bridge", "https://parents.schoolbridge.example", "family.doe@example.com"),
    ("Example Forum", "https://forum.example.net", "alexd"),
    ("Example News", "https://news.example.org", "alex.doe@example.com"),
    ("Example Wiki", "https://wiki.example.org", "AlexDoe"),
    ("Home Router", "https://192.0.2.10:8443", "admin"),
    ("Home NAS", "https://nas.home.example", "admin"),
    ("Café Lumière", "https://cafe-lumiere.example", "alex.doe@example.com"),
    ("Почта Пример", "https://pochta.primer.example", "alex.doe@example.com"),
    ("Bücherei Beispiel", "https://buecherei.example", "alex.doe"),
    ("東京 Example Hotel", "https://hotel-tokyo.example", "alex.doe@example.com"),
    ("Northwind Calendar", "https://calendar.northwind.example", "alex.doe@example.com"),
    ("Contoso Support", "https://support.contoso.example", "alex.doe@example.com"),
    ("Fabrikam Photos", "https://photos.fabrikam.example", "alex.doe@example.com"),
    ("Example Pay", "https://pay.example.com", "alex.doe@example.com"),
    ("Example Mobile", "https://account.examplemobile.example", "555-0100"),
    ("FitGym Members", "https://members.fitgym.example", "alex.doe@example.com"),
    ("Office Guest Wi-Fi", "https://wifi.office.example", ""),
    ("VoltPoint Charging", "https://charge.voltpoint.example", "alex.doe@example.com"),
    ("Pizzeria Napoli", "https://order.pizzeria.example", "alex.doe@example.com"),
    ("Tax Office", "https://tax.gov.example", "AD-55-1290"),
    ("Clinic Patient Portal", "https://patient.clinic.example", "alex.doe@example.com"),
    ("Tunes Music", "https://music.tunes.example", "alex.doe@example.com"),
    ("Example Prints", "https://prints.example.com", "alex.doe@example.com"),
    ("Example Registrar", "https://registrar.example.net", "alexdoe"),
    ("SecureLine VPN", "https://vpn.secureline.example", "alex.doe@example.com"),
    ("Litware CI", "https://ci.litware.example", "alexdoe"),
    ("Fabrikam Family Share", "https://share.fabrikam.example", "family.doe@example.com"),
    ("Example Groceries", "https://groceries.example.com", "family.doe@example.com"),
    ("Wingtip Kids", "https://kids.wingtiptoys.example", "family.doe@example.com"),
    ("Neighbors", "https://app.neighbors.example", "alex.doe@example.com"),
    ("DriveNow Rentals", "https://rent.drivenow.example", "alex.doe@example.com"),
    ("Example Docs", "https://docs.example.com", "alex.doe@example.com"),
    ("Example Webmail (old)", "https://webmail.example.net", "alex.doe1990@example.net"),
    ("LearnHub Courses", "https://courses.learnhub.example", "alex.doe@example.com"),
    ("Board Game Club", "https://boardgames.example.org", "meeple_alex"),
    ("VetCare Pets", "https://pets.vetcare.example", "family.doe@example.com"),
)
_DEMO_WEAK: Final = {
    12: "iloveyou2",
    25: "password1",
    39: "letmein!",
    42: "qwerty123",
    58: "sunshine1",
}
_DEMO_REUSED: Final = {
    6: "kuvzyn-mepqo4-Raxdut",
    11: "kuvzyn-mepqo4-Raxdut",
    45: "kuvzyn-mepqo4-Raxdut",
    21: "hobwe7-Gyctaf-sinzup",
    54: "hobwe7-Gyctaf-sinzup",
}
_DEMO_CODES: Final = frozenset({0, 1, 3, 8, 10, 22, 47, 48})
_DEMO_FAMILY: Final = frozenset({23, 24, 50, 51, 52, 59})
_DEMO_ALT_URLS: Final = {
    0: ("https://northwind.example",),
    1: ("https://login.contoso.example", "https://account.contoso.example"),
    21: ("https://vanarsdel.example",),
    37: ("https://checkout.example.com",),
}
_DEMO_NOTES: Final = {
    3: "Security question: first pet → Biscuit",
    5: "Frequent flyer number TS-0042-1187",
    10: "Card PIN is not stored here. Branch: Elm Street",
    17: "Account no. 7700-1234; meter read on the 25th",
    24: "Kids: Mia (grade 3) and Leo (grade 1)",
    28: "Firmware 4.2. Wi-Fi password is on the sticker",
    29: "RAID 1, 2 x 4 TB. Admin panel only on the home network",
    43: "Taxpayer number on the paper letter from March",
    44: "Dr. Example, Tue/Thu",
    56: "Old account; forwards to Northwind Mail",
}
_DEMO_TRASH: Final = (
    ("Old Forum", "https://oldforum.example.net", "alexd", 2, "deleted-on-linux"),
    (
        "Contoso Trial",
        "https://trial.contoso.example",
        "alex.doe@example.com",
        15,
        "deleted-in-icloud",
    ),
    ("Northwind Mail", "https://mail.northwind.example", "alex.doe@example.com", 40, "conflict"),
    ("Coupon Shop", "https://coupons.example.com", "alex.doe@example.com", 80, "deleted-both"),
    ("Tailspin (old)", "https://old.tailspin.example", "ADOE4471", 88, "deleted-on-linux"),
)
_DEMO_NAMESPACE: Final = uuid.UUID("0b6a3c5e-2f4d-4a8e-9c1b-7d2e5f6a8b90")
_APPLE_ALPHABET: Final = "abcdefghijkmnopqrstuvwxyz"
_RANDOM_ALPHABET: Final = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@^_"


def _demo_id(kind: str, index: int) -> str:
    return str(uuid.uuid5(_DEMO_NAMESPACE, f"{kind}-{index}")).upper()


def _demo_password(index: int) -> str:
    """Deterministic strong password: Apple style for most, random-looking for every 4th."""
    digest = hashlib.sha256(f"demo-password-{index}".encode()).digest()
    if index % 4 == 3:
        return "".join(_RANDOM_ALPHABET[b % len(_RANDOM_ALPHABET)] for b in digest[:20])
    chars = [_APPLE_ALPHABET[b % len(_APPLE_ALPHABET)] for b in digest[:18]]
    # Apple's generator puts exactly one capital and one digit somewhere in the 18 letters.
    upper, digit = digest[18] % 18, (digest[18] % 18 + 1 + digest[19] % 17) % 18
    chars[upper] = chars[upper].upper()
    chars[digit] = str(digest[20] % 10)
    return "-".join("".join(chars[i : i + 6]) for i in (0, 6, 12))


def _demo_otpauth(index: int, issuer: str, account: str) -> str:
    secret = base64.b32encode(hashlib.sha256(f"demo-otp-{index}".encode()).digest()[:10]).decode()
    label = quote(f"{issuer}:{account}", safe="")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"


def demo_dataset(now: datetime) -> tuple[list[Credential], list[TrashEntry]]:
    """The fictional vault every screenshot shows; identical output for the same `now`."""
    items: list[Credential] = []
    for i, (title, url, username) in enumerate(_DEMO_SITES):
        age = (i * 89) % 1050 + 20
        created = now - timedelta(days=age, hours=(i * 7) % 24)
        modified = now - timedelta(days=age - (i * 53) % age, minutes=(i * 13) % 60)
        modified = max(modified, created)
        items.append(
            Credential(
                id=_demo_id("item", i),
                url=url,
                username=username,
                password=_DEMO_WEAK.get(i) or _DEMO_REUSED.get(i) or _demo_password(i),
                created=created,
                modified=modified,
                title=title,
                notes=_DEMO_NOTES.get(i),
                otpauth=_demo_otpauth(i, title, username) if i in _DEMO_CODES else None,
                alt_urls=_DEMO_ALT_URLS.get(i, ()),
                group="Family" if i in _DEMO_FAMILY else None,
            )
        )
    trash: list[TrashEntry] = []
    for i, (title, url, username, days_ago, reason) in enumerate(_DEMO_TRASH):
        deleted_at = now - timedelta(days=days_ago, hours=i * 3)
        created = deleted_at - timedelta(days=200 + i * 40)
        trash.append(
            TrashEntry(
                trash_id=_demo_id("trash", i),
                credential=Credential(
                    id=_demo_id("trashed-item", i),
                    url=url,
                    username=username,
                    password=_demo_password(100 + i),
                    created=created,
                    modified=deleted_at - timedelta(days=3),
                    title=title,
                ),
                deleted_at=deleted_at,
                reason=cast("TrashReason", reason),
            )
        )
    return items, trash


# ---------------------------------------------------------------------- CLI


def _apply_state(daemon: FakeDaemon, state: str) -> None:
    if state == "paused":
        ids = list(daemon.items)
        daemon.pause(local_ids=ids[:3], remote_ids=ids[3:4])
    elif state == "signin-required":
        daemon.require_signin()
    elif state == "offline":
        daemon.go_offline()
    elif state == "signed-out":
        daemon.sign_out()


async def _serve(bus_address: str, state: str, latency: float) -> None:
    daemon = FakeDaemon.demo()
    daemon.latency = latency
    _apply_state(daemon, state)
    await daemon.start(bus_address)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    sys.stdout.write("ready\n")
    sys.stdout.flush()
    await stop.wait()
    await daemon.stop()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Serve the fake passwords-appd demo vault.")
    parser.add_argument("--bus-address", required=True, help="private bus to serve on")
    parser.add_argument(
        "--state",
        choices=("idle", "paused", "signin-required", "offline", "signed-out"),
        default="idle",
    )
    parser.add_argument("--latency", type=float, default=0.0, help="seconds per method call")
    args = parser.parse_args(argv)
    asyncio.run(_serve(args.bus_address, args.state, args.latency))


if __name__ == "__main__":
    main()
