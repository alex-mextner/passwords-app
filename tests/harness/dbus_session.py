# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""A throwaway D-Bus session bus with its own unlocked gnome-keyring, for integration tests.

Tests must never reach the owner's session bus or login keyring, so isolation is enforced
here rather than trusted to each test: the child processes get an environment built from
scratch (nothing inherited except PATH and locale), every directory they may write lives
under one temp root, and `assert_isolated` refuses to start anything whose environment could
point outside that root. While a fixture is active the test process itself also sees the
private bus and temp HOME/XDG dirs, so code that falls back to "the default session bus" or
`~/.config` lands in the sandbox instead of the real desktop.

Usage from a conftest::

    from tests.harness.dbus_session import private_bus, private_session  # re-export fixtures

`private_bus` is the bus address (str); `private_session` adds the env for launching
subprocesses on that bus, the temp root, and the keyring password.
"""

from __future__ import annotations

import asyncio
import os
import pwd
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from dbus_fast import Message, MessageType, Variant
from dbus_fast.aio import MessageBus

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator, Mapping

KEYRING_PASSWORD = "passwords-app-test-keyring"
LOGIN_COLLECTION = "/org/freedesktop/secrets/collection/login"

_DBUS_DAEMON = "/usr/bin/dbus-daemon"
_KEYRING_DAEMON = "/usr/bin/gnome-keyring-daemon"
_SECRETS_NAME = "org.freedesktop.secrets"
_SECRETS_PATH = "/org/freedesktop/secrets"
_STARTUP_TIMEOUT = 15.0
_STOP_TIMEOUT = 5.0
# Directories handed to the children; each becomes an env var pointing inside the root.
_DIR_VARS = {
    "HOME": "home",
    "XDG_DATA_HOME": "data",
    "XDG_CONFIG_HOME": "config",
    "XDG_CACHE_HOME": "cache",
    "XDG_STATE_HOME": "state",
    "XDG_RUNTIME_DIR": "runtime",
}
# Inherited variables that would let a child find the real desktop session.
_FORBIDDEN_VARS = (
    "DBUS_SYSTEM_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "GNOME_KEYRING_CONTROL",
    "SSH_AUTH_SOCK",
    "XDG_DATA_DIRS",
    "XDG_CONFIG_DIRS",
)
_BUS_CONFIG = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={socket}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
{limits}
</busconfig>
"""
# The stock session bus (/usr/share/dbus-1/session.conf) lifts dbus-daemon's defaults so far
# that they are never hit; mirror the ones a client can run into so tests see the real bus.
SESSION_LIMITS = {
    "max_incoming_bytes": 1_000_000_000,
    "max_outgoing_bytes": 1_000_000_000,
    "max_message_size": 1_000_000_000,
    "max_match_rules_per_connection": 50_000,
    "max_replies_per_connection": 50_000,
}


class IsolationError(AssertionError):
    """The environment built for a private bus could reach the real desktop session."""


@dataclass(frozen=True, slots=True)
class PrivateSession:
    address: str
    env: Mapping[str, str]
    root: Path
    password: str


def build_env(root: Path) -> dict[str, str]:
    """Environment for children of the private session; nothing inherited but PATH/locale."""
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for var, sub in _DIR_VARS.items():
        env[var] = str(root / sub)
    return env


def _bus_socket(root: Path) -> Path:
    return root / _DIR_VARS["XDG_RUNTIME_DIR"] / "bus"


def assert_isolated(env: Mapping[str, str], root: Path) -> None:
    """Raise `IsolationError` unless every path the env exposes is inside `root`."""
    root = root.resolve()
    # The passwd entry, not $HOME: the fixture repoints $HOME into the sandbox.
    real_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    if root == real_home or real_home.is_relative_to(root):
        msg = f"sandbox root {root} would contain the real home"
        raise IsolationError(msg)
    for var in _DIR_VARS:
        value = env.get(var)
        if value is None or not Path(value).resolve().is_relative_to(root):
            msg = f"{var}={value!r} is outside the sandbox {root}"
            raise IsolationError(msg)
    leaked = [var for var in _FORBIDDEN_VARS if var in env]
    if leaked:
        msg = f"sandbox env carries desktop session variables: {leaked}"
        raise IsolationError(msg)
    address = env.get("DBUS_SESSION_BUS_ADDRESS")
    if address is not None:
        expected = f"unix:path={_bus_socket(root)}"
        if not _is_sandbox_address(address, _bus_socket(root)):
            msg = f"DBUS_SESSION_BUS_ADDRESS={address!r} is not the sandbox bus {expected}"
            raise IsolationError(msg)


def _is_sandbox_address(address: str, socket: Path) -> bool:
    # Parsed, not prefix-matched: an address may carry `;` fallbacks or a duplicate `path=`
    # (clients honour the last one), either of which could route to the real bus.
    transport, _, options = address.partition(":")
    if transport != "unix" or ";" in address:
        return False
    pairs = [option.partition("=") for option in options.split(",")]
    keys = [key for key, _, _ in pairs]
    if len(keys) != len(set(keys)) or not set(keys) <= {"path", "guid"}:
        return False
    return {key: value for key, _, value in pairs}.get("path") == str(socket)


def _run_sync[T](coro_factory: Callable[[], Coroutine[object, object, T]]) -> T:
    # A private loop on a worker thread: callers may already be inside pytest-asyncio's loop.
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro_factory()).result()


async def _call(address: str, message: Message) -> list[object]:
    bus = await MessageBus(bus_address=address).connect()
    try:
        reply = await bus.call(message)
    finally:
        bus.disconnect()
    if reply.message_type == MessageType.ERROR:
        detail = reply.error_name
        msg = f"{message.member} on {message.path} failed: {detail}"
        raise RuntimeError(msg)
    return list(reply.body)


async def _wait_for_keyring(address: str, keyring: subprocess.Popen[bytes]) -> None:
    # One connection for the whole wait: a handshake per 20 ms poll is pure churn.
    deadline = time.monotonic() + _STARTUP_TIMEOUT
    query = Message(
        destination="org.freedesktop.DBus",
        path="/org/freedesktop/DBus",
        interface="org.freedesktop.DBus",
        member="NameHasOwner",
        signature="s",
        body=[_SECRETS_NAME],
    )
    bus = await MessageBus(bus_address=address).connect()
    try:
        while True:
            reply = await bus.call(query)
            if reply.message_type != MessageType.ERROR and reply.body == [True]:
                return
            if keyring.poll() is not None or time.monotonic() > deadline:
                msg = f"gnome-keyring-daemon did not come up on {address}"
                raise RuntimeError(msg)
            await asyncio.sleep(0.02)
    finally:
        bus.disconnect()


def _stop(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(_STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(_STOP_TIMEOUT)


@contextmanager
def start_private_session(
    password: str = KEYRING_PASSWORD, limits: Mapping[str, int] | None = None
) -> Generator[PrivateSession]:
    """Start dbus-daemon + gnome-keyring under a fresh temp root; tear both down on exit.

    `limits` overrides entries of `SESSION_LIMITS`, e.g. to prove a client stays within a
    stricter bus quota.
    """
    # mkdtemp in /tmp keeps the socket path short (AF_UNIX paths are capped at 108 bytes).
    root = Path(tempfile.mkdtemp(prefix="pa-bus-")).resolve()
    procs: list[subprocess.Popen[bytes]] = []
    try:
        env = build_env(root)
        for var in _DIR_VARS:
            Path(env[var]).mkdir(mode=0o700)
        socket = _bus_socket(root)
        config = root / "bus.conf"
        limit_lines = "\n".join(
            f'  <limit name="{name}">{value}</limit>'
            for name, value in {**SESSION_LIMITS, **(limits or {})}.items()
        )
        config.write_text(_BUS_CONFIG.format(socket=socket, limits=limit_lines), encoding="utf-8")
        assert_isolated(env, root)
        bus = subprocess.Popen(  # noqa: S603 - fixed binary, args built here
            [_DBUS_DAEMON, "--config-file", str(config), "--nofork", "--print-address=1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        procs.append(bus)
        assert bus.stdout is not None
        address = bus.stdout.readline().decode().strip()
        bus.stdout.close()
        env["DBUS_SESSION_BUS_ADDRESS"] = address
        assert_isolated(env, root)
        with (root / "gnome-keyring.log").open("wb") as log:
            keyring = subprocess.Popen(  # noqa: S603 - fixed binary, args built here
                [_KEYRING_DAEMON, "--foreground", "--unlock", "--components=secrets"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=log,
                env=env,
            )
        procs.append(keyring)
        assert keyring.stdin is not None
        keyring.stdin.write(password.encode())
        keyring.stdin.close()
        _run_sync(lambda: _wait_for_keyring(address, keyring))
        yield PrivateSession(address=address, env=dict(env), root=root, password=password)
    finally:
        for proc in reversed(procs):
            _stop(proc)
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def private_session(monkeypatch: pytest.MonkeyPatch) -> Generator[PrivateSession]:
    """A fresh private bus + unlocked keyring; the test process is pointed at it too."""
    with start_private_session() as session:
        for var in (*_DIR_VARS, "DBUS_SESSION_BUS_ADDRESS"):
            monkeypatch.setenv(var, session.env[var])
        for var in _FORBIDDEN_VARS:
            monkeypatch.delenv(var, raising=False)
        yield session


@pytest.fixture
def private_bus(private_session: PrivateSession) -> str:
    """Address of a fresh session bus whose gnome-keyring is unlocked with KEYRING_PASSWORD."""
    return private_session.address


async def lock_collection(address: str, collection: str = LOGIN_COLLECTION) -> None:
    """Lock a collection the way Seahorse's "Lock" does (no prompt involved)."""
    await _call(
        address,
        Message(
            destination=_SECRETS_NAME,
            path=_SECRETS_PATH,
            interface="org.freedesktop.Secret.Service",
            member="Lock",
            signature="ao",
            body=[[collection]],
        ),
    )


async def unlock_collection(
    address: str, collection: str = LOGIN_COLLECTION, password: str = KEYRING_PASSWORD
) -> None:
    """Unlock a collection with its password, without any prompt."""
    bus = await MessageBus(bus_address=address).connect()
    try:
        opened = await bus.call(
            Message(
                destination=_SECRETS_NAME,
                path=_SECRETS_PATH,
                interface="org.freedesktop.Secret.Service",
                member="OpenSession",
                signature="sv",
                # The harness deliberately uses the plain algorithm so it does not depend on
                # the product's DH implementation it is there to test.
                body=["plain", Variant("s", "")],
            )
        )
        if opened.message_type == MessageType.ERROR:
            msg = "OpenSession failed"
            raise RuntimeError(msg)
        session_path = opened.body[1]
        reply = await bus.call(
            Message(
                destination=_SECRETS_NAME,
                path=_SECRETS_PATH,
                interface="org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface",
                member="UnlockWithMasterPassword",
                signature="o(oayays)",
                body=[collection, [session_path, b"", password.encode(), "text/plain"]],
            )
        )
        if reply.message_type == MessageType.ERROR:
            detail = reply.error_name
            msg = f"unlocking {collection} failed: {detail}"
            raise RuntimeError(msg)
    finally:
        bus.disconnect()
