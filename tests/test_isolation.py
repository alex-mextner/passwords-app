# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Proof that the suite-wide safety net in ``tests/conftest.py`` holds.

Every test runs with HOME, the XDG directories and the session bus address pointed into a
throwaway root, so the real login keyring and ``~/.config/passwords-app`` are unreachable;
the private keyring harness still provides a working bus when a test asks for one.
"""

from __future__ import annotations

import os
import pwd
import stat
from pathlib import Path

import pytest
import secretstorage
from dbus_fast.aio import MessageBus
from dbus_fast.message import Message
from secretstorage.exceptions import SecretServiceNotAvailableException
from tests.conftest import ISOLATED_DIRS, ISOLATED_ROOT, REMOVED_VARS, isolate
from tests.harness.dbus_session import private_bus, private_session

__all__ = ["private_bus", "private_session"]

REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)


@pytest.mark.parametrize("var", sorted(ISOLATED_DIRS))
def test_user_directories_point_into_the_isolated_root(var: str) -> None:
    value = Path(os.environ[var])
    assert value.is_relative_to(ISOLATED_ROOT)
    assert not value.is_relative_to(REAL_HOME)
    assert value.is_dir()


def test_home_relative_config_paths_resolve_inside_the_root() -> None:
    config = Path("~/.config/passwords-app").expanduser()
    assert config.is_relative_to(ISOLATED_ROOT)
    assert Path.home().is_relative_to(ISOLATED_ROOT)


def test_runtime_dir_is_private_to_the_user() -> None:
    mode = stat.S_IMODE(Path(os.environ["XDG_RUNTIME_DIR"]).stat().st_mode)
    assert mode & 0o077 == 0


def test_session_bus_address_names_a_socket_that_does_not_exist() -> None:
    address = os.environ["DBUS_SESSION_BUS_ADDRESS"]
    assert address.startswith("unix:path=")
    socket = Path(address.removeprefix("unix:path="))
    assert socket.is_relative_to(ISOLATED_ROOT)
    assert not socket.exists()


@pytest.mark.parametrize("var", REMOVED_VARS)
def test_desktop_session_variables_are_removed(var: str) -> None:
    assert var not in os.environ


def test_secretstorage_cannot_reach_any_session_bus() -> None:
    # jeepney surfaces the missing socket as a plain OSError; newer secretstorage wraps it.
    with pytest.raises((SecretServiceNotAvailableException, OSError)):
        secretstorage.dbus_init()


@pytest.mark.timeout(30)
async def test_dbus_fast_cannot_connect_to_the_default_session_bus() -> None:
    with pytest.raises((FileNotFoundError, ConnectionRefusedError)):
        await MessageBus().connect()


def test_isolate_overrides_real_locations_and_keeps_tool_caches(tmp_path: Path) -> None:
    environ = {
        "HOME": str(REAL_HOME),
        "XDG_CONFIG_HOME": str(REAL_HOME / ".config"),
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
        "DISPLAY": ":0",
        "PLAYWRIGHT_BROWSERS_PATH": "/opt/browsers",
    }
    isolate(environ, tmp_path)
    assert environ["HOME"] == str(tmp_path / "home")
    assert environ["XDG_CONFIG_HOME"] == str(tmp_path / "config")
    assert environ["DBUS_SESSION_BUS_ADDRESS"] == f"unix:path={tmp_path / 'no-session-bus'}"
    assert "DISPLAY" not in environ
    assert environ["PLAYWRIGHT_BROWSERS_PATH"] == "/opt/browsers"  # an explicit choice wins


def test_isolate_is_idempotent(tmp_path: Path) -> None:
    first: dict[str, str] = {}
    isolate(first, tmp_path)
    second = dict(first)
    isolate(second, tmp_path)
    assert first == second


@pytest.mark.integration
@pytest.mark.timeout(60)
async def test_private_bus_still_provides_a_working_session_bus(private_bus: str) -> None:
    assert private_bus == os.environ["DBUS_SESSION_BUS_ADDRESS"]
    bus = await MessageBus().connect()  # the default address now resolves to the sandbox bus
    try:
        reply = await bus.call(
            Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="NameHasOwner",
                signature="s",
                body=["org.freedesktop.secrets"],
            )
        )
        assert reply is not None
        assert reply.body == [True]
    finally:
        bus.disconnect()
