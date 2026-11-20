# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Run the real `passwords-appd` against the fake Apple services.

The daemon has no configuration for Apple's endpoints, its schedule or its clock, so this
launcher sets them before calling the unmodified `passwords_app.daemon.main.main`:

- `Endpoints` (GrandSlam, loginDelegates, get_account_settings) point at `AppleServices`;
  CloudKit is reached through the session record's gateway, which already names the fake.
- GrandSlam's SRP exchange is replaced by the decision `AppleServices` publishes on `/gsa`
  (signed in, or "a second factor is required"); the rest of the re-login path is real.
- The scheduler's intervals shrink from minutes to about a second, so "every 60 s" and
  "2 s after a local change" happen within a test's patience; their logic is untouched.
- The wall clock is shifted by the number of days in `clock_file` (re-read on every call),
  so "90 days later" is a file write, not a wait. The monotonic clock is the real one.

Everything else (stores, sync engine, policy, D-Bus service) is production code.
Usage: `python tests/e2e/daemon_shim.py <config.json>`.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import requests

from passwords_app.daemon import main as daemon_main
from passwords_app.daemon import scheduler
from passwords_app.icloud import account
from passwords_app.icloud.auth import grandslam
from passwords_app.icloud.auth.gsa import GSAError

if TYPE_CHECKING:
    from passwords_app.icloud.values import Record

_SPD: Record = {
    "adsid": "000000-00-fake-adsid",
    "DsPrsId": 1234567890,
    "t": {"com.apple.gs.idms.pet": {"token": "FAKE-PET-VALUE", "expiry": 1}},
}


class ShiftedClock(scheduler.SystemClock):
    """The system clock, its wall time moved forward by the days written in `days_file`."""

    def __init__(self, days_file: Path) -> None:
        self._days_file = days_file

    def now(self) -> datetime:
        try:
            days = float(self._days_file.read_text(encoding="utf-8") or 0)
        except FileNotFoundError:
            days = 0.0
        return datetime.now(UTC) + timedelta(days=days)


def _scripted_grandslam(decision_url: str) -> None:
    def start(
        gsa: object, username: str, password: str
    ) -> tuple[Record, grandslam.SecondFactor | None]:
        del gsa, password
        decision = requests.get(decision_url, timeout=5).json()
        factor = decision.get("second_factor")
        if factor is None:
            return dict(_SPD), None
        if factor not in {"trusted", "sms"}:
            msg = f"GrandSlam refused the sign-in ({factor})"
            raise GSAError(msg)
        return dict(_SPD), grandslam.SecondFactor(factor, username, "FAKE-IDMS")

    def trigger(gsa: object, factor: grandslam.SecondFactor) -> None:
        del gsa, factor

    grandslam.start = start
    grandslam.trigger = trigger


def configure(config: dict[str, object]) -> None:
    apple = str(config["apple_url"])
    account.Endpoints = functools.partial(  # type: ignore[misc]
        account.Endpoints,
        gsa=f"{apple}/gsa-unused",
        login_delegates=f"{apple}/setup/login",
        account_settings=f"{apple}/setup/settings",
    )
    assert dataclasses.is_dataclass(account.Endpoints.func)  # type: ignore[attr-defined]
    _scripted_grandslam(f"{apple}/gsa")
    timings = config.get("scheduler", {})
    assert isinstance(timings, dict)
    for name, seconds in timings.items():
        assert hasattr(scheduler, name), name
        setattr(scheduler, name, float(seconds))
    clock_file = Path(str(config["clock_file"]))
    daemon_main.SystemClock = functools.partial(ShiftedClock, clock_file)  # type: ignore[misc]


def main(argv: list[str]) -> int:
    config = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    configure(config)
    return daemon_main.main(["--debug"])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
