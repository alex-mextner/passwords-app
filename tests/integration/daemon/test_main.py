# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`passwords-appd` wiring: bus name ownership, state.db location and key, start/stop."""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import stat
import struct
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from dbus_fast import Message, MessageType
from dbus_fast.aio import MessageBus
from tests.fakes.memory_stores import MemoryLocal, MemoryRemote, make_credential
from tests.integration.daemon.support import STATE_KEY, wait_for
from tests.integration.keyring.support import next_second
from tests.unit.daemon.fake_clock import FakeClock
from tests.unit.daemon.fakes import FakeAccount, FakeNotifier

from passwords_app.daemon import BUS_NAME, INTERFACE, OBJECT_PATH, main, paths
from passwords_app.daemon.account import ICloudAccount
from passwords_app.daemon.controller import Daemon
from passwords_app.keyring.secret_service import SAVED_PROPERTIES_KEY, SecretServiceStore
from passwords_app.store.state import StateStore
from passwords_app.sync.ports import LocalUnavailable

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from tests.harness.dbus_session import PrivateSession

    from passwords_app.core.model import Credential

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]


@pytest.fixture(autouse=True)
def no_system_bus(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never reach the host's real system bus (NetworkManager lives there)."""

    async def none() -> None:
        return None

    monkeypatch.setattr(main, "_system_bus", none)


def memory_daemon(tmp_path: Path, local: MemoryLocal | None = None) -> Daemon:
    remote = MemoryRemote({"A": make_credential("A")})
    account = FakeAccount(remote, apple_id="a@example.com", signed_in=True, joined=True)
    return Daemon(
        account=account,
        local=MemoryLocal() if local is None else local,
        state=StateStore(tmp_path / "state.db", STATE_KEY),
        clock=FakeClock(),
        notifier=FakeNotifier(),
    )


@pytest.fixture
async def bus(private_bus: str) -> AsyncIterator[MessageBus]:
    connection = await MessageBus(bus_address=private_bus).connect()
    yield connection
    connection.disconnect()


async def name_owner(bus: MessageBus) -> str | None:
    reply = await bus.call(
        Message(
            destination="org.freedesktop.DBus",
            path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus",
            member="GetNameOwner",
            signature="s",
            body=[BUS_NAME],
        )
    )
    assert reply is not None
    return None if reply.message_type == MessageType.ERROR else str(reply.body[0])


def test_data_dir_follows_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert paths.state_path() == tmp_path / "xdg" / "passwords-app" / "state.db"


def test_data_dir_defaults_to_local_share(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert paths.state_path() == tmp_path / ".local" / "share" / "passwords-app" / "state.db"


def test_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main.main(["--help"])
    assert info.value.code == 0
    assert "passwords-appd" in capsys.readouterr().out


async def test_second_instance_is_refused(private_bus: str, tmp_path: Path) -> None:
    first_bus = await MessageBus(bus_address=private_bus).connect()
    second_bus = await MessageBus(bus_address=private_bus).connect()
    first, second = memory_daemon(tmp_path / "1"), memory_daemon(tmp_path / "2")
    try:
        await main.publish(first_bus, first)
        with pytest.raises(main.AlreadyRunningError):
            await main.publish(second_bus, second)
        assert await name_owner(second_bus) == first_bus.unique_name
    finally:
        first.close()
        second.close()
        first_bus.disconnect()
        second_bus.disconnect()


async def test_open_state_creates_a_private_db_keyed_from_the_keyring(
    private_session: PrivateSession, bus: MessageBus
) -> None:
    store = await main.open_state(bus)
    store.set("probe", "value")
    store.close()
    path = paths.state_path()
    assert path.is_relative_to(private_session.root)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # The same key comes back from the keyring: the data written above is readable.
    again = await main.open_state(bus)
    assert again.get("probe") == "value"
    again.close()


async def test_build_daemon_uses_the_real_keyring(
    private_bus: str, bus: MessageBus, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = MemoryRemote({"FROM-ICLOUD": make_credential("FROM-ICLOUD")})
    account = FakeAccount(remote, apple_id="a@example.com", signed_in=True, joined=True)
    monkeypatch.setattr(ICloudAccount, "load", staticmethod(lambda: account))
    daemon = await main.build_daemon(bus)
    try:
        await daemon.start()
        await daemon.sync_now()
        assert [c.id for c in await daemon.list_items()] == ["FROM-ICLOUD"]
    finally:
        await daemon.stop()
        daemon.close()


async def test_build_daemon_keeps_what_its_keyring_fetch_read_in_state(
    private_bus: str, bus: MessageBus, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A restarted daemon starts from these instead of reading every item in full (#64).
    await (await SecretServiceStore.open(bus)).upsert(make_credential("FROM-KEYRING"))
    await next_second()
    account = FakeAccount(MemoryRemote(), apple_id="a@example.com", signed_in=True, joined=True)
    monkeypatch.setattr(ICloudAccount, "load", staticmethod(lambda: account))
    daemon = await main.build_daemon(bus)
    try:
        await daemon.start()
        await daemon.sync_now()
    finally:
        await daemon.stop()
        daemon.close()
    state = await main.open_state(bus)
    try:
        assert "FROM-KEYRING" in (state.get(SAVED_PROPERTIES_KEY) or "")
    finally:
        state.close()


async def test_serve_exits_for_a_later_restart_when_the_keyring_is_locked(
    private_bus: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def locked(bus: MessageBus) -> Daemon:
        msg = "the default keyring is locked"
        raise LocalUnavailable(msg)

    monkeypatch.setattr(main, "build_daemon", locked)
    assert await main.serve(asyncio.Event()) == main.EX_TEMPFAIL


async def test_serve_runs_until_stopped_and_releases_the_name(
    private_bus: str, bus: MessageBus, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def build(_: MessageBus) -> Daemon:
        return memory_daemon(tmp_path)

    monkeypatch.setattr(main, "build_daemon", build)
    stop = asyncio.Event()
    server = asyncio.create_task(main.serve(stop))

    async def owned() -> bool:
        return await name_owner(bus) is not None

    await wait_for(owned, limit=10)
    reply = await bus.call(
        Message(destination=BUS_NAME, path=OBJECT_PATH, interface=INTERFACE, member="GetStatus")
    )
    assert reply is not None
    assert reply.message_type == MessageType.METHOD_RETURN
    stop.set()
    assert await asyncio.wait_for(server, 10) == main.EX_OK

    async def released() -> bool:
        return await name_owner(bus) is None

    await wait_for(released, limit=10)


async def test_serve_refuses_when_already_running(
    private_bus: str, bus: MessageBus, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    await bus.request_name(BUS_NAME)

    async def build(_: MessageBus) -> Daemon:
        return memory_daemon(tmp_path)

    monkeypatch.setattr(main, "build_daemon", build)
    assert await main.serve(asyncio.Event()) == main.EX_ALREADY_RUNNING


def bus_socket(connection: MessageBus) -> socket.socket:
    sock = connection._sock
    assert sock is not None
    return sock


def private_bus_daemon_pid(daemon_bus: MessageBus, session: PrivateSession) -> int:
    """Pid of the dbus-daemon at the other end of the socket, proven to be the private one."""
    credentials = bus_socket(daemon_bus).getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    pid, _, _ = struct.unpack("3i", credentials)
    command_line = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    assert command_line[0].endswith(b"dbus-daemon")
    assert str(session.root).encode() in b" ".join(command_line)
    return int(pid)


async def test_serve_survives_a_full_bus_socket_while_replying(
    private_session: PrivateSession,
    bus: MessageBus,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Issue #122: two List replies go out while the bus is not draining the daemon's socket.
    # The first fills the socket, the second finds it full (EAGAIN); dbus-fast used to treat
    # that as a lost connection and the daemon exited.
    items = 300
    local = MemoryLocal({f"ID-{n}": make_credential(f"ID-{n}") for n in range(items)})
    daemon = memory_daemon(tmp_path, local)
    served: list[MessageBus] = []
    bus_pid: list[int] = []

    async def build(daemon_bus: MessageBus) -> Daemon:
        served.append(daemon_bus)
        return daemon

    entered = 0
    both_entered = asyncio.Event()
    list_items = daemon.list_items

    async def list_items_once_the_bus_stalls() -> list[Credential]:
        # Both calls reply only after the bus stopped reading, so neither reply can drain.
        nonlocal entered
        entered += 1
        if entered == 2:
            os.kill(bus_pid[0], signal.SIGSTOP)
            both_entered.set()
        await both_entered.wait()
        return await list_items()

    monkeypatch.setattr(main, "build_daemon", build)
    monkeypatch.setattr(daemon, "list_items", list_items_once_the_bus_stalls)
    stop = asyncio.Event()
    server = asyncio.create_task(main.serve(stop))

    async def owned() -> bool:
        return await name_owner(bus) is not None

    await wait_for(owned, limit=10)
    (daemon_bus,) = served
    bus_pid.append(private_bus_daemon_pid(daemon_bus, private_session))
    # The smallest send buffer the kernel allows, so a few hundred items overflow it.
    bus_socket(daemon_bus).setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    calls = [
        asyncio.create_task(
            bus.call(
                Message(destination=BUS_NAME, path=OBJECT_PATH, interface=INTERFACE, member="List")
            )
        )
        for _ in range(2)
    ]
    try:
        await asyncio.wait_for(both_entered.wait(), 10)
        await asyncio.sleep(0.5)
        assert not server.done(), "the daemon exited while its bus socket was full"
        assert daemon_bus.connected
    finally:
        os.kill(bus_pid[0], signal.SIGCONT)
    for call in calls:
        reply = await asyncio.wait_for(call, 10)
        assert reply is not None
        assert reply.message_type == MessageType.METHOD_RETURN
        assert {item["id"].value for item in reply.body[0]} == set(local.items)
    assert daemon_bus.connected
    stop.set()
    assert await asyncio.wait_for(server, 10) == main.EX_OK


async def test_serve_fails_when_the_bus_connection_is_lost(
    bus: MessageBus, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A failure exit status is what makes systemd's Restart=on-failure bring the daemon back.
    served: list[MessageBus] = []

    async def build(daemon_bus: MessageBus) -> Daemon:
        served.append(daemon_bus)
        return memory_daemon(tmp_path)

    monkeypatch.setattr(main, "build_daemon", build)
    server = asyncio.create_task(main.serve(asyncio.Event()))

    async def owned() -> bool:
        return await name_owner(bus) is not None

    await wait_for(owned, limit=10)
    (daemon_bus,) = served
    bus_socket(daemon_bus).shutdown(socket.SHUT_RDWR)
    assert await asyncio.wait_for(server, 10) == main.EX_TEMPFAIL
