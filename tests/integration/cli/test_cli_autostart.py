# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`passwords-app` starts a stopped service itself, and says why when it cannot.

The daemon is the real one on a private session bus. "Stopped" means it has let go of its bus
name; the unit that would start it is a fake that records the calls, so no test touches the
owner's systemd.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from tests.unit.cli.terminal import ScriptedTerminal

from passwords_app.cli import main as cli
from passwords_app.cli.service import StartOutcome
from passwords_app.daemon import BUS_NAME

if TYPE_CHECKING:
    from tests.integration.daemon.support import RunningDaemon

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]

CRASH_LOG = (
    "Traceback (most recent call last):\n"
    "passwords_app.icloud.auth.session.SessionError: cannot decrypt session.enc: "
    "the master key no longer matches it\n"
    "passwords-appd.service: Main process exited, code=exited, status=1/FAILURE\n"
)


@dataclass
class FakeUnit:
    """Starts the daemon by taking its bus name back, or fails like a crashing process."""

    running: RunningDaemon
    loop: asyncio.AbstractEventLoop
    works: bool = True
    installed: bool = True
    calls: list[str] = field(default_factory=list)

    def is_installed(self) -> bool:
        self.calls.append("is_installed")
        return self.installed

    def start(self) -> StartOutcome:
        self.calls.append("start")
        if not self.works:
            return StartOutcome(ok=False, detail="Job for passwords-appd.service failed")
        asyncio.run_coroutine_threadsafe(self.running.bus.request_name(BUS_NAME), self.loop).result(
            10
        )
        return StartOutcome(ok=True)

    def recent_log(self) -> str:
        self.calls.append("recent_log")
        return CRASH_LOG


async def run_cli(
    unit: FakeUnit, capsys: pytest.CaptureFixture[str], *argv: str
) -> tuple[int, str, str]:
    term = ScriptedTerminal(answers=[])
    ctx = cli.Context(terminal=term, service=unit)
    code = await asyncio.to_thread(cli.main, list(argv), ctx=ctx)
    return code, term.output, capsys.readouterr().err


@pytest.fixture
async def stopped(running: RunningDaemon) -> FakeUnit:
    await running.bus.release_name(BUS_NAME)
    return FakeUnit(running, asyncio.get_running_loop())


async def test_running_daemon_is_not_touched(
    running: RunningDaemon, capsys: pytest.CaptureFixture[str]
) -> None:
    unit = FakeUnit(running, asyncio.get_running_loop())
    code, out, _err = await run_cli(unit, capsys, "status")
    assert code == 0
    assert out
    assert unit.calls == []


async def test_stopped_daemon_is_started_and_the_command_runs(
    stopped: FakeUnit, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = await run_cli(stopped, capsys, "status", "--json")
    assert (code, err) == (0, "")
    assert '"state"' in out
    assert stopped.calls == ["is_installed", "start"]


async def test_failed_start_exits_3_with_the_cause_from_the_log(
    stopped: FakeUnit, capsys: pytest.CaptureFixture[str]
) -> None:
    stopped.works = False
    code, out, err = await run_cli(stopped, capsys, "status")
    assert code == cli.EXIT_DAEMON
    assert out == ""
    assert "could not be started" in err
    assert "cannot decrypt session.enc: the master key no longer matches it" in err
    assert "journalctl --user -u passwords-appd" in err


async def test_without_a_unit_the_old_unreachable_message_stays(
    stopped: FakeUnit, capsys: pytest.CaptureFixture[str]
) -> None:
    stopped.installed = False
    code, _out, err = await run_cli(stopped, capsys, "status")
    assert code == cli.EXIT_DAEMON
    assert "not reachable" in err
    assert stopped.calls == ["is_installed"]
