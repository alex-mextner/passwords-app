# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Starting the sync service from the CLI: reset a failed unit, start it, wait until it answers.

Nothing here touches systemd or a bus: the unit control and the "is the daemon up" probe are
replaced by fakes that record what the CLI asked for.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from passwords_app.cli.service import (
    DaemonStartError,
    StartOutcome,
    ensure_running,
    failure_cause,
)

SESSION_FAILURE = """\
Traceback (most recent call last):
  File "/x/session.py", line 169, in load
nacl.exceptions.CryptoError: Decryption failed
The above exception was the direct cause of the following exception:
Traceback (most recent call last):
  File "/x/main.py", line 10, in <module>
passwords_app.icloud.auth.session.SessionError: cannot decrypt /h/session.enc: wrong master key
passwords-appd.service: Main process exited, code=exited, status=1/FAILURE
passwords-appd.service: Failed with result 'exit-code'.
"""


@dataclass
class FakeUnit:
    installed: bool = True
    start_ok: bool = True
    start_detail: str = ""
    log: str = ""
    calls: list[str] = field(default_factory=list)

    def is_installed(self) -> bool:
        self.calls.append("is_installed")
        return self.installed

    def start(self) -> StartOutcome:
        self.calls.append("start")
        return StartOutcome(self.start_ok, self.start_detail)

    def recent_log(self) -> str:
        self.calls.append("recent_log")
        return self.log


class Probe:
    """`is_up` answers False `down_for` times, then True."""

    def __init__(self, down_for: int) -> None:
        self.down_for = down_for
        self.asked = 0

    async def __call__(self) -> bool:
        self.asked += 1
        return self.asked > self.down_for


async def test_running_daemon_is_left_alone() -> None:
    unit = FakeUnit()
    await ensure_running(Probe(0), unit, wait_seconds=1, interval=0)
    assert unit.calls == []


async def test_stopped_daemon_is_started_and_awaited() -> None:
    unit = FakeUnit()
    probe = Probe(down_for=3)  # down at the first check, then again while it comes up
    await ensure_running(probe, unit, wait_seconds=5, interval=0)
    assert unit.calls == ["is_installed", "start"]
    assert probe.asked == 4


async def test_failed_start_reports_the_cause_from_the_log() -> None:
    unit = FakeUnit(start_ok=False, start_detail="Job failed", log=SESSION_FAILURE)
    with pytest.raises(DaemonStartError) as raised:
        await ensure_running(Probe(10**6), unit, wait_seconds=1, interval=0)
    assert "cannot decrypt /h/session.enc" in str(raised.value)
    assert unit.calls == ["is_installed", "start", "recent_log"]


async def test_started_but_never_answering_reports_the_cause() -> None:
    unit = FakeUnit(log=SESSION_FAILURE)
    with pytest.raises(DaemonStartError) as raised:
        await ensure_running(Probe(10**6), unit, wait_seconds=0.05, interval=0.01)
    assert "cannot decrypt" in str(raised.value)


async def test_a_unit_that_is_not_installed_is_left_to_bus_activation() -> None:
    unit = FakeUnit(installed=False)
    await ensure_running(Probe(10**6), unit, wait_seconds=1, interval=0)
    assert unit.calls == ["is_installed"]


@pytest.mark.parametrize(
    ("log", "detail", "expected"),
    [
        (SESSION_FAILURE, "", "cannot decrypt /h/session.enc: wrong master key"),
        (
            (
                "WARNING passwords_app.daemon: keyring not available yet (the default keyring is "
                "locked); exiting for a later restart\n"
                "passwords-appd.service: Main process exited, code=exited, status=75/TEMPFAIL\n"
            ),
            "",
            "keyring not available yet (the default keyring is locked)",
        ),
        ("", "Failed to start passwords-appd.service: Unit not found.", "Failed to start"),
        ("", "", "no details"),
    ],
)
def test_failure_cause(log: str, detail: str, expected: str) -> None:
    assert expected in failure_cause(log, detail)
