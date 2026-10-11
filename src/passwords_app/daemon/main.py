# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`passwords-appd` entry point: wire the real stores to the daemon and serve it on D-Bus.

Startup needs the keyring: the state.db key lives in the default collection and the synced
items in "iCloud Passwords". If either is locked (e.g. before the user unlocked the login
keyring) the process exits with EX_TEMPFAIL and systemd restarts it later, rather than
holding the bus name while unable to answer anything.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal
import sys
from typing import TYPE_CHECKING

from dbus_fast import BusType, RequestNameReply
from dbus_fast.aio import MessageBus

from passwords_app.daemon import BUS_NAME, OBJECT_PATH
from passwords_app.daemon.account import ICloudAccount
from passwords_app.daemon.controller import Daemon
from passwords_app.daemon.keyring_lock import KeyringLockWatch
from passwords_app.daemon.network import watch_network
from passwords_app.daemon.notify import DesktopNotifier
from passwords_app.daemon.paths import state_path
from passwords_app.daemon.scheduler import SystemClock
from passwords_app.daemon.service import PasswordsService
from passwords_app.sync.ports import LocalUnavailable

if TYPE_CHECKING:
    from collections.abc import Sequence

    from passwords_app.store.state import StateStore

EX_OK = 0
EX_ALREADY_RUNNING = 1
EX_TEMPFAIL = 75  # sysexits.h: try again later
STATE_KEY_NAME = "state-key"

_log = logging.getLogger("passwords_app.daemon")


class AlreadyRunningError(RuntimeError):
    """Another process owns the daemon's bus name."""


async def publish(bus: MessageBus, daemon: Daemon) -> PasswordsService:
    """Export the API and take the well-known name (only once the object answers)."""
    service = PasswordsService(daemon)
    bus.export(OBJECT_PATH, service)
    reply = await bus.request_name(BUS_NAME)
    if reply not in {RequestNameReply.PRIMARY_OWNER, RequestNameReply.ALREADY_OWNER}:
        bus.unexport(OBJECT_PATH, service)
        msg = f"{BUS_NAME} is already owned by another process"
        raise AlreadyRunningError(msg)
    return service


async def open_state(bus: MessageBus) -> StateStore:
    from passwords_app.keyring.app_key import app_secret  # noqa: PLC0415 - keeps --help fast
    from passwords_app.store.state import StateStore  # noqa: PLC0415

    key = await app_secret(bus, STATE_KEY_NAME)
    return StateStore(state_path(), key)


async def build_daemon(bus: MessageBus) -> Daemon:
    """Production wiring: Secret Service, state.db, the iCloud account."""
    from passwords_app.keyring.secret_service import SecretServiceStore  # noqa: PLC0415

    state = await open_state(bus)
    try:
        local = await SecretServiceStore.open(bus, saved=state)
        account = await asyncio.to_thread(ICloudAccount.load)
    except BaseException:
        state.close()
        raise
    return Daemon(
        account=account,
        local=local,
        state=state,
        clock=SystemClock(),
        notifier=DesktopNotifier(bus),
    )


async def _system_bus() -> MessageBus | None:
    try:
        return await MessageBus(bus_type=BusType.SYSTEM).connect()
    except (OSError, EOFError, ValueError) as exc:
        _log.info("system bus unavailable (%s); using the portal for network state", exc)
        return None


async def serve(stop: asyncio.Event) -> int:
    bus = await MessageBus().connect()
    try:
        daemon = await build_daemon(bus)
    except LocalUnavailable as exc:
        _log.warning("keyring not available yet (%s); exiting for a later restart", exc)
        bus.disconnect()
        return EX_TEMPFAIL
    system_bus = await _system_bus()
    try:
        await publish(bus, daemon)
        lock_watch = KeyringLockWatch(bus, daemon.keyring_lock_changed)
        await lock_watch.start()
        await daemon.start()
        watch = await watch_network(system_bus, bus, daemon.scheduler.network_up)
        _log.info("daemon ready on %s", BUS_NAME)
        # dbus-fast leaves wait_for_disconnect unannotated; it returns None once closed.
        disconnected = asyncio.ensure_future(
            bus.wait_for_disconnect()  # type: ignore[no-untyped-call]
        )
        stopped = asyncio.ensure_future(stop.wait())
        await asyncio.wait({disconnected, stopped}, return_when=asyncio.FIRST_COMPLETED)
        for task in (disconnected, stopped):
            task.cancel()
        if watch is not None:
            with contextlib.suppress(Exception):
                await watch.stop()
        with contextlib.suppress(Exception):
            await lock_watch.stop()
        await daemon.stop()
    except AlreadyRunningError as exc:
        _log.error("%s", exc)
        return EX_ALREADY_RUNNING
    finally:
        daemon.close()
        if system_bus is not None:
            system_bus.disconnect()
        bus.disconnect()
    return EX_OK


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="passwords-appd",
        description="Background service that keeps iCloud Keychain and GNOME Keyring in sync.",
    )
    parser.add_argument("--debug", action="store_true", help="log debugging detail")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    async def run() -> int:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, stop.set)
        return await serve(stop)

    return asyncio.run(run())
