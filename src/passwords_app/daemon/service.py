# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`io.github.alex_mextner.Passwords1` on D-Bus, exactly as data/dbus/*.Passwords1.xml says.

A thin shell over `Daemon`: it converts between Variants and domain objects, turns
`DaemonError`s into the interface's named errors, and notes every call as client activity
(which keeps the 60 s sync cadence while the app or a browser is in use).

This module deliberately does not use `from __future__ import annotations`: dbus-fast reads
the D-Bus signatures from the annotations at class creation, so the aliases below must be
real runtime objects.
"""

import contextlib
from collections.abc import Generator
from typing import Annotated, override

from dbus_fast import Variant
from dbus_fast import introspection as intr
from dbus_fast.annotations import DBusBool, DBusDict, DBusSignature, DBusStr
from dbus_fast.errors import DBusError
from dbus_fast.service import ServiceInterface, dbus_method, dbus_signal

from passwords_app.daemon import INTERFACE
from passwords_app.daemon.controller import Daemon
from passwords_app.daemon.errors import DaemonError
from passwords_app.daemon.items import item_dict, parse_edit, trash_dict
from passwords_app.daemon.status import Status

DictList = Annotated[list[dict[str, Variant]], DBusSignature("aa{sv}")]
StrList = Annotated[list[str], DBusSignature("as")]
CodeReply = Annotated[tuple[str, int], DBusSignature("su")]

# dbus-fast names in-args after the Python parameters but leaves results unnamed; these are
# the names the interface XML gives them, so introspection matches the published contract.
_OUT_ARG_NAMES: dict[str, tuple[str, ...]] = {
    "GetStatus": ("status",),
    "List": ("items",),
    "Get": ("item",),
    "Save": ("id",),
    "ListTrash": ("entries",),
    "Restore": ("id",),
    "Match": ("items",),
    "GetCode": ("code", "seconds_left"),
    "SignInStart": ("step",),
    "SignInCode": ("step",),
    "SignInRequestSms": ("step",),
    "ListRecoveryDevices": ("devices",),
    "JoinKeychain": ("step",),
    "StatusChanged": ("status",),
    "ItemsChanged": ("ids",),
}


@contextlib.contextmanager
def _replies() -> Generator[None]:
    try:
        yield
    except DaemonError as exc:
        raise DBusError(exc.dbus_name, str(exc)) from exc


class PasswordsService(ServiceInterface):
    def __init__(self, daemon: Daemon) -> None:
        super().__init__(INTERFACE)
        self._d = daemon
        daemon.on_status = self._on_status
        daemon.on_items = self._on_items

    @override
    def introspect(self) -> intr.Interface:
        interface = super().introspect()
        for method in interface.methods:
            for arg, name in zip(method.out_args, _OUT_ARG_NAMES.get(method.name, ()), strict=True):
                arg.name = name
        for signal in interface.signals:
            for arg, name in zip(signal.args, _OUT_ARG_NAMES.get(signal.name, ()), strict=True):
                arg.name = name
        return interface

    def _on_status(self, status: Status) -> None:
        self.status_changed(status.to_dbus())

    def _on_items(self, ids: list[str]) -> None:
        self.items_changed(ids)

    # ------------------------------------------------------------------ status and items

    @dbus_method(name="GetStatus")
    def get_status(self) -> DBusDict:
        self._d.touch()
        return self._d.status().to_dbus()

    @dbus_method(name="List")
    async def list_items(self) -> DictList:
        self._d.touch()
        with _replies():
            return [item_dict(c) for c in await self._d.list_items()]

    @dbus_method(name="Get")
    async def get(self, id: DBusStr) -> DBusDict:  # noqa: A002 - XML arg name
        self._d.touch()
        with _replies():
            return item_dict(await self._d.get(id), secrets=True)

    @dbus_method(name="Save")
    async def save(self, item: DBusDict) -> DBusStr:
        self._d.touch()
        with _replies():
            return await self._d.save(parse_edit(item))

    @dbus_method(name="Delete")
    async def delete(self, id: DBusStr) -> None:  # noqa: A002 - XML arg name
        self._d.touch()
        with _replies():
            await self._d.delete(id)

    # ------------------------------------------------------------------ trash

    @dbus_method(name="ListTrash")
    def list_trash(self) -> DictList:
        self._d.touch()
        retention = self._d.policy.trash_retention
        return [trash_dict(e, retention) for e in self._d.trash()]

    @dbus_method(name="Restore")
    async def restore(self, trash_id: DBusStr) -> DBusStr:
        self._d.touch()
        with _replies():
            return await self._d.restore(trash_id)

    @dbus_method(name="Purge")
    def purge(self, trash_id: DBusStr) -> None:
        self._d.touch()
        with _replies():
            self._d.purge(trash_id)

    # ------------------------------------------------------------------ sync control

    @dbus_method(name="SyncNow")
    async def sync_now(self) -> None:
        self._d.touch()
        with _replies():
            await self._d.sync_now()

    @dbus_method(name="ResolvePause")
    async def resolve_pause(self, apply: DBusBool) -> None:
        self._d.touch()
        with _replies():
            await self._d.resolve_pause(apply=apply)

    # ------------------------------------------------------------------ browser helpers

    @dbus_method(name="Match")
    async def match(self, url: DBusStr) -> DictList:
        self._d.touch()
        with _replies():
            return [item_dict(c) for c in await self._d.match(url)]

    @dbus_method(name="GetCode")
    async def get_code(self, id: DBusStr) -> CodeReply:  # noqa: A002 - XML arg name
        self._d.touch()
        with _replies():
            return await self._d.code(id)

    # ------------------------------------------------------------------ sign-in

    @dbus_method(name="SignInStart")
    async def sign_in_start(self, apple_id: DBusStr, password: DBusStr) -> DBusDict:
        with _replies():
            return (await self._d.sign_in_start(apple_id, password)).to_dbus()

    @dbus_method(name="SignInCode")
    async def sign_in_code(self, code: DBusStr) -> DBusDict:
        with _replies():
            return (await self._d.sign_in_code(code)).to_dbus()

    @dbus_method(name="SignInRequestSms")
    async def sign_in_request_sms(self) -> DBusDict:
        with _replies():
            return (await self._d.sign_in_request_sms()).to_dbus()

    @dbus_method(name="ListRecoveryDevices")
    async def list_recovery_devices(self) -> DictList:
        with _replies():
            return [
                {
                    "id": Variant("s", d.id),
                    "name": Variant("s", d.name),
                    "model": Variant("s", d.model),
                    "serial": Variant("s", d.serial),
                }
                for d in await self._d.recovery_devices()
            ]

    @dbus_method(name="JoinKeychain")
    async def join_keychain(self, device_id: DBusStr, passcode: DBusStr) -> DBusDict:
        with _replies():
            return (await self._d.join(device_id, passcode)).to_dbus()

    @dbus_method(name="SignOut")
    async def sign_out(self) -> None:
        with _replies():
            await self._d.sign_out()

    # ------------------------------------------------------------------ signals

    @dbus_signal(name="StatusChanged")
    def status_changed(self, status: dict[str, Variant]) -> DBusDict:
        return status

    @dbus_signal(name="ItemsChanged")
    def items_changed(self, ids: list[str]) -> StrList:
        return ids
