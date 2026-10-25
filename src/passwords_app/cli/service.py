# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Starting `passwords-appd` for the CLI when it is not running.

A command must not tell the user to start the service by hand. When nothing owns the daemon's
bus name the CLI clears the unit's `failed` state (a unit that crashed or hit its restart
limit refuses nothing, but keeps reporting the old failure), starts it through systemd, which
for this `Type=dbus` unit returns only once the name is taken, and waits until the daemon
answers. If the start really fails, the error carries the cause from the unit's journal
(the last exception line the daemon printed), not a generic "not reachable".

Without a systemd user unit (a checkout run by hand, a test bus) nothing is started here and
the D-Bus activation file of the daemon, if any, does the work on the first call.
"""

from __future__ import annotations

import asyncio
import re
import subprocess  # nosec B404 - runs systemctl/journalctl only, fixed argv, no shell
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

UNIT = "passwords-appd.service"
START_TIMEOUT_SECONDS = 30.0
POLL_INTERVAL_SECONDS = 0.2
_SYSTEMCTL_TIMEOUT_SECONDS = 120  # TimeoutStartSec of a Type=dbus unit is 90 s
_JOURNAL_LINES = 60

# `package.module.SomeError: message`, as the last line of a Python traceback.
_EXCEPTION_LINE = re.compile(r"^((?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*(?:Error|Exception)): (.+)$")
# The daemon's own log format: `WARNING passwords_app.daemon: message`.
_LOG_PREFIX = re.compile(r"^(?:DEBUG|INFO|WARNING|ERROR|CRITICAL) [\w.]+: ")


class DaemonStartError(Exception):
    """The service could not be started; the message says why."""


@dataclass(frozen=True)
class StartOutcome:
    ok: bool
    detail: str = ""


class ServiceUnit(Protocol):
    def is_installed(self) -> bool: ...

    def start(self) -> StartOutcome: ...

    def recent_log(self) -> str: ...


def _run(argv: list[str], timeout: float) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
            argv, capture_output=True, text=True, check=False, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


class SystemdUserUnit:
    """The `passwords-appd.service` user unit, driven through `systemctl --user`."""

    def __init__(self, unit: str = UNIT) -> None:
        self._unit = unit

    def is_installed(self) -> bool:
        done = _run(["systemctl", "--user", "show", "-p", "LoadState", "--value", self._unit], 10)
        return done is not None and done.stdout.strip() == "loaded"

    def start(self) -> StartOutcome:
        # A failed unit keeps its failure (and a spent restart budget) until it is reset.
        _run(["systemctl", "--user", "reset-failed", self._unit], 10)
        done = _run(["systemctl", "--user", "start", self._unit], _SYSTEMCTL_TIMEOUT_SECONDS)
        if done is None:
            return StartOutcome(
                ok=False, detail=f"`systemctl --user start {self._unit}` did not finish"
            )
        return StartOutcome(done.returncode == 0, done.stderr.strip())

    def recent_log(self) -> str:
        done = _run(
            [
                "journalctl",
                "--user",
                "-u",
                self._unit,
                "-n",
                str(_JOURNAL_LINES),
                "--no-pager",
                "-o",
                "cat",
            ],
            20,
        )
        return "" if done is None else done.stdout


def _last_exception(lines: list[str]) -> str | None:
    exceptions = [m for line in lines if (m := _EXCEPTION_LINE.match(line))]
    # The daemon's own exceptions say more than the library ones they wrap, whichever order
    # the journal printed the chained traceback in.
    own = [m for m in exceptions if m.group(1).startswith("passwords_app.")]
    chosen = own or exceptions
    return chosen[-1].group(2) if chosen else None


def failure_cause(log: str, detail: str) -> str:
    """Return the line that says why the daemon died: its last exception, else its last output."""
    lines = [line.strip() for line in log.splitlines() if line.strip()]
    exception = _last_exception(lines)
    if exception is not None:
        return exception
    output = [
        _LOG_PREFIX.sub("", line)
        for line in lines
        if not line.startswith(("passwords-appd.service:", "Traceback", "File ", "Started "))
    ]
    return output[-1] if output else detail or "no details in the journal"


async def ensure_running(
    is_up: Callable[[], Awaitable[bool]],
    unit: ServiceUnit,
    *,
    wait_seconds: float = START_TIMEOUT_SECONDS,
    interval: float = POLL_INTERVAL_SECONDS,
) -> None:
    """Return once the daemon answers, starting its unit first when it does not."""
    if await is_up():
        return
    if not await asyncio.to_thread(unit.is_installed):
        return
    outcome = await asyncio.to_thread(unit.start)
    if not outcome.ok:
        log = await asyncio.to_thread(unit.recent_log)
        msg = failure_cause(log, outcome.detail)
        raise DaemonStartError(msg)
    deadline = time.monotonic() + wait_seconds
    while not await is_up():
        if time.monotonic() > deadline:
            log = await asyncio.to_thread(unit.recent_log)
            msg = failure_cause(log, "it started but never answered")
            raise DaemonStartError(msg)
        await asyncio.sleep(interval)
