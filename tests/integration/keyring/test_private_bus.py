# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The private-bus harness itself: it must be impossible for it to reach the real session."""

from __future__ import annotations

import os
import pwd
from pathlib import Path

import pytest
from dbus_fast import Message, MessageType
from dbus_fast.aio import MessageBus
from tests.harness.dbus_session import (
    KEYRING_PASSWORD,
    LOGIN_COLLECTION,
    IsolationError,
    PrivateSession,
    assert_isolated,
    build_env,
    lock_collection,
    start_private_session,
    unlock_collection,
)

pytestmark = pytest.mark.integration

DIR_VARS = (
    "HOME",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
)
FORBIDDEN = (
    "DBUS_SYSTEM_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "GNOME_KEYRING_CONTROL",
    "SSH_AUTH_SOCK",
    "XDG_DATA_DIRS",
    "XDG_CONFIG_DIRS",
)
NOT_THE_KEYRING_PASSWORD = KEYRING_PASSWORD[::-1]


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "sandbox"
    root.mkdir()
    return root


def test_build_env_inherits_nothing_from_the_desktop(
    sandbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
    env = build_env(sandbox)
    assert set(env) == {"PATH", "LANG", "LC_ALL", *DIR_VARS}
    assert_isolated(env, sandbox)


@pytest.mark.parametrize("var", DIR_VARS)
def test_dir_var_outside_root_is_refused(sandbox: Path, var: str) -> None:
    env = build_env(sandbox)
    env[var] = str(Path.home())
    with pytest.raises(IsolationError, match=var):
        assert_isolated(env, sandbox)


@pytest.mark.parametrize("var", DIR_VARS)
def test_missing_dir_var_is_refused(sandbox: Path, var: str) -> None:
    env = build_env(sandbox)
    del env[var]
    with pytest.raises(IsolationError, match=var):
        assert_isolated(env, sandbox)


def test_dotdot_escape_from_root_is_refused(sandbox: Path) -> None:
    env = build_env(sandbox)
    env["XDG_DATA_HOME"] = str(sandbox / ".." / ".." / "elsewhere")
    with pytest.raises(IsolationError, match="XDG_DATA_HOME"):
        assert_isolated(env, sandbox)


@pytest.mark.parametrize("var", FORBIDDEN)
def test_desktop_session_variables_are_refused(sandbox: Path, var: str) -> None:
    env = build_env(sandbox)
    env[var] = "anything"
    with pytest.raises(IsolationError, match=var):
        assert_isolated(env, sandbox)


@pytest.mark.parametrize(
    "address",
    [
        "unix:path=/run/user/1000/bus",
        "unix:abstract=/tmp/dbus-real",
        "tcp:host=127.0.0.1,port=1234",
    ],
)
def test_bus_address_outside_root_is_refused(sandbox: Path, address: str) -> None:
    env = build_env(sandbox)
    env["DBUS_SESSION_BUS_ADDRESS"] = address
    with pytest.raises(IsolationError, match="DBUS_SESSION_BUS_ADDRESS"):
        assert_isolated(env, sandbox)


@pytest.mark.parametrize(
    "suffix",
    [
        ",path=/run/user/1000/bus",
        ";unix:path=/run/user/1000/bus",
        ",abstract=/tmp/dbus-real",
        "-other",
    ],
)
def test_bus_address_that_only_starts_with_the_sandbox_socket_is_refused(
    sandbox: Path, suffix: str
) -> None:
    env = build_env(sandbox)
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={sandbox.resolve()}/runtime/bus{suffix}"
    with pytest.raises(IsolationError, match="DBUS_SESSION_BUS_ADDRESS"):
        assert_isolated(env, sandbox)


def test_bus_address_with_the_daemon_guid_is_accepted(sandbox: Path) -> None:
    env = build_env(sandbox)
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={sandbox.resolve()}/runtime/bus,guid=0123abcd"
    assert_isolated(env, sandbox)


def test_root_containing_the_real_home_is_refused() -> None:
    # The passwd entry, as `assert_isolated` uses: $HOME may point elsewhere (CI containers).
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    with pytest.raises(IsolationError, match="real home"):
        assert_isolated(build_env(home.parent), home.parent)


def test_session_runs_on_its_own_bus_and_cleans_up() -> None:
    real_address = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    with start_private_session() as session:
        root = session.root
        assert session.address != real_address
        assert session.address.startswith(f"unix:path={root}/")
        assert (root / "data" / "keyrings" / "login.keyring").is_file()
        assert_isolated(session.env, root)
    assert not root.exists()


def _environ_of_processes_under(root: Path) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            raw = (proc / "environ").read_bytes()
        except OSError:
            continue
        entries = raw.decode(errors="replace").split("\0")
        env = dict(entry.split("=", 1) for entry in entries if "=" in entry)
        if env.get("XDG_RUNTIME_DIR", "").startswith(str(root)) and "PYTEST_VERSION" not in env:
            found.append(env)
    return found


def test_children_really_run_with_the_sandbox_environment(
    private_session: PrivateSession,
) -> None:
    children = _environ_of_processes_under(private_session.root)
    assert len(children) == 2  # dbus-daemon and gnome-keyring-daemon
    for env in children:
        assert_isolated(env, private_session.root)


def test_fixture_points_the_test_process_at_the_sandbox(
    private_session: PrivateSession,
) -> None:
    assert os.environ["DBUS_SESSION_BUS_ADDRESS"] == private_session.address
    assert Path.home() == private_session.root / "home"
    for var in FORBIDDEN:
        assert var not in os.environ


async def _locked(address: str, collection: str) -> bool:
    bus = await MessageBus(bus_address=address).connect()
    try:
        reply = await bus.call(
            Message(
                destination="org.freedesktop.secrets",
                path=collection,
                interface="org.freedesktop.DBus.Properties",
                member="Get",
                signature="ss",
                body=["org.freedesktop.Secret.Collection", "Locked"],
            )
        )
    finally:
        bus.disconnect()
    assert reply is not None
    assert reply.message_type == MessageType.METHOD_RETURN
    locked = reply.body[0].value
    assert isinstance(locked, bool)
    return locked


async def test_login_keyring_starts_unlocked(private_bus: str) -> None:
    assert await _locked(private_bus, LOGIN_COLLECTION) is False


async def test_lock_then_unlock_with_known_password(private_bus: str) -> None:
    await lock_collection(private_bus)
    assert await _locked(private_bus, LOGIN_COLLECTION) is True
    await unlock_collection(private_bus, LOGIN_COLLECTION, KEYRING_PASSWORD)
    assert await _locked(private_bus, LOGIN_COLLECTION) is False


async def test_unlock_with_wrong_password_fails_and_stays_locked(private_bus: str) -> None:
    await lock_collection(private_bus)
    with pytest.raises(RuntimeError, match="unlocking"):
        await unlock_collection(private_bus, LOGIN_COLLECTION, NOT_THE_KEYRING_PASSWORD)
    assert await _locked(private_bus, LOGIN_COLLECTION) is True
