# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""When sync cycles run (spec §5 "Scheduling").

`Schedule` is the pure timing policy on a monotonic clock: a cycle at start, every 60 s while
a client (app, browser host) has called within the last 5 min and every 5 min otherwise, 2 s
after a local change (debounced, but never postponed more than 10 s by a stream of changes),
immediately on request or when the network comes back, and exponential backoff (30 s doubling
to 30 min) after failed cycles. `Scheduler` runs cycles at the times `Schedule` names and lets
callers wait for a cycle that starts after their request. Both take an injectable clock, so
the timing is tested without real waiting.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

ACTIVE_INTERVAL = 60.0
IDLE_INTERVAL = 300.0
CLIENT_WINDOW = 300.0
DEBOUNCE = 2.0
DEBOUNCE_MAX = 10.0
BACKOFF_FIRST = 30.0
BACKOFF_MAX = 1800.0

_log = logging.getLogger(__name__)


class Clock(Protocol):
    def monotonic(self) -> float: ...

    def now(self) -> datetime:
        """Aware UTC wall-clock time."""
        ...

    async def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def monotonic(self) -> float:
        return asyncio.get_running_loop().time()

    def now(self) -> datetime:
        return datetime.now(UTC)

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


def backoff(failures: int) -> float:
    """Delay before retrying after `failures` consecutive failed cycles (>= 1)."""
    return min(BACKOFF_MAX, BACKOFF_FIRST * 2.0 ** min(failures - 1, 16))


class Schedule:
    def __init__(self, now: float) -> None:
        self._last_end: float | None = None
        self._failures = 0
        self._asap = True  # the cycle at start
        self._client_at: float | None = None
        self._change_first: float | None = None
        self._change_due: float | None = None
        self._start = now

    @property
    def failures(self) -> int:
        return self._failures

    def client_active(self, now: float) -> bool:
        return self._client_at is not None and now - self._client_at <= CLIENT_WINDOW

    def client_seen(self, now: float) -> None:
        self._client_at = now

    def local_changed(self, now: float) -> None:
        if self._change_first is None:
            self._change_first = now
        self._change_due = min(now + DEBOUNCE, self._change_first + DEBOUNCE_MAX)

    def network_up(self) -> None:
        self._failures = 0
        self._asap = True

    def request(self) -> None:
        self._asap = True

    def cycle_started(self) -> None:
        # Changes that arrive while the cycle runs may postdate its fetch, so they schedule
        # another cycle rather than being absorbed by this one.
        self._asap = False
        self._change_first = None
        self._change_due = None

    def cycle_finished(self, now: float, *, ok: bool) -> None:
        self._last_end = now
        self._failures = 0 if ok else self._failures + 1

    def due(self, now: float) -> float:
        """Monotonic time of the next cycle (may be in the past: run now)."""
        if self._asap:
            return now
        last = self._last_end if self._last_end is not None else self._start
        if self._failures:
            regular = last + backoff(self._failures)
        else:
            regular = last + (ACTIVE_INTERVAL if self.client_active(now) else IDLE_INTERVAL)
        return regular if self._change_due is None else min(regular, self._change_due)


class Scheduler:
    """Runs `cycle` (returns True on success) whenever the schedule says so."""

    def __init__(self, cycle: Callable[[], Awaitable[bool]], clock: Clock) -> None:
        self._cycle = cycle
        self._clock = clock
        self._schedule = Schedule(clock.monotonic())
        self._wake = asyncio.Event()
        self._finished = asyncio.Condition()
        self._started = 0
        self._completed = 0

    @property
    def schedule(self) -> Schedule:
        return self._schedule

    def next_run(self) -> datetime:
        """Wall-clock estimate of the next cycle start (now while one is due or running)."""
        mono = self._clock.monotonic()
        wait = max(0.0, self._schedule.due(mono) - mono)
        return self._clock.now() + timedelta(seconds=wait)

    def _poke(self) -> None:
        self._wake.set()

    def client_seen(self) -> None:
        self._schedule.client_seen(self._clock.monotonic())
        self._poke()

    def local_changed(self) -> None:
        self._schedule.local_changed(self._clock.monotonic())
        self._poke()

    def network_up(self) -> None:
        self._schedule.network_up()
        self._poke()

    def request(self) -> None:
        self._schedule.request()
        self._poke()

    async def run_now(self) -> None:
        """Request a cycle and return once a cycle that started after this call finished."""
        target = self._started + 1
        self.request()
        async with self._finished:
            await self._finished.wait_for(lambda: self._completed >= target)

    async def _sleep_until_due(self) -> None:
        while True:
            self._wake.clear()
            now = self._clock.monotonic()
            delay = self._schedule.due(now) - now
            if delay <= 0:
                return
            sleeper = asyncio.ensure_future(self._clock.sleep(delay))
            waker = asyncio.ensure_future(self._wake.wait())
            try:
                await asyncio.wait({sleeper, waker}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                # Not awaited: awaiting a cancelled child here would also swallow our own
                # cancellation (stop()) and keep the loop alive forever.
                sleeper.cancel()
                waker.cancel()

    async def run(self) -> None:
        """Loop forever (until cancelled)."""
        while True:
            await self._sleep_until_due()
            self._schedule.cycle_started()
            self._started += 1
            ok = False
            try:
                ok = await self._cycle()
            except Exception:  # noqa: BLE001 - a failed cycle must not end scheduling
                _log.exception("sync cycle crashed")
            finally:
                self._schedule.cycle_finished(self._clock.monotonic(), ok=ok)
                async with self._finished:
                    self._completed = self._started
                    self._finished.notify_all()
