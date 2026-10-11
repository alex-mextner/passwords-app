# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The CLI without a daemon, and `doctor` against a private session (keyring + daemon)."""

from __future__ import annotations

import asyncio
import json
import socket
from typing import TYPE_CHECKING

import pytest
from dbus_fast.aio import MessageBus
from tests.harness.dbus_session import lock_collection
from tests.unit.cli.terminal import ScriptedTerminal

from passwords_app.cli import doctor
from passwords_app.cli import main as cli
from passwords_app.keyring.secret_service import SecretServiceStore

if TYPE_CHECKING:
    from pathlib import Path

    from tests.harness.dbus_session import PrivateSession
    from tests.integration.daemon.support import RunningDaemon

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]


def closed_port() -> tuple[str, int]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return "127.0.0.1", int(s.getsockname()[1])


@pytest.mark.usefixtures("private_session")
@pytest.mark.parametrize("argv", [["status"], ["list"], ["sync"], ["trash"]])
def test_no_daemon_exits_3(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(argv, ctx=cli.Context(terminal=ScriptedTerminal()))
    assert code == cli.EXIT_DAEMON
    err = capsys.readouterr().err
    assert "not reachable" in err
    assert "passwords-app doctor" in err


def test_no_session_bus_exits_3(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", f"unix:path={tmp_path}/no-such-bus")
    assert cli.main(["status"], ctx=cli.Context(terminal=ScriptedTerminal())) == cli.EXIT_DAEMON


def by_name(checks: list[doctor.Check]) -> dict[str, doctor.Check]:
    return {c.name: c for c in checks}


@pytest.mark.usefixtures("private_session")
async def test_doctor_without_daemon(tmp_path: Path) -> None:
    checks = by_name(await doctor.run_checks(tmp_path, anisette=closed_port()))
    assert checks["Sync service (passwords-appd)"].level == "fail"
    assert "Sync state" not in checks
    assert checks["Apple sign-in helper (anisette)"].level == "fail"
    assert checks['Keyring collection "iCloud Passwords"'].level == "warn"
    assert not doctor.healthy(list(checks.values()))


async def test_doctor_with_daemon_and_keyring(
    running: RunningDaemon, private_session: PrivateSession, tmp_path: Path
) -> None:
    bus = await MessageBus(bus_address=private_session.address).connect()
    try:
        await SecretServiceStore.open(bus)  # creates and unlocks the collection
    finally:
        bus.disconnect()
    checks = by_name(await doctor.run_checks(tmp_path, anisette=closed_port()))
    assert checks["Sync service (passwords-appd)"].level == "ok"
    assert checks["Sync state"].level == "ok"
    assert checks['Keyring collection "iCloud Passwords"'].level == "ok"


async def test_doctor_reports_a_locked_collection(
    private_session: PrivateSession, tmp_path: Path
) -> None:
    bus = await MessageBus(bus_address=private_session.address).connect()
    try:
        store = await SecretServiceStore.open(bus)
    finally:
        bus.disconnect()
    await lock_collection(private_session.address, store.collection)
    check = by_name(await doctor.run_checks(tmp_path, anisette=closed_port()))[
        'Keyring collection "iCloud Passwords"'
    ]
    assert (check.level, check.detail) == ("warn", "locked")


async def test_doctor_cli_json_and_exit_code(
    running: RunningDaemon, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _host, port = closed_port()
    monkeypatch.setattr(doctor, "ANISETTE_PORT", port)
    monkeypatch.setenv("HOME", str(tmp_path))
    term = ScriptedTerminal()
    code = await asyncio.to_thread(cli.main, ["doctor", "--json"], ctx=cli.Context(terminal=term))
    assert code == cli.EXIT_FAILED  # anisette is down
    names = {c["name"]: c["level"] for c in json.loads(term.output)}
    assert names["Apple sign-in helper (anisette)"] == "fail"
    assert names["Sync service (passwords-appd)"] == "ok"
