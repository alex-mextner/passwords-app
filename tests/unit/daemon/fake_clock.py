# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""A clock whose time moves only when a test advances it (implements `scheduler.Clock`)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

START_WALL = datetime(2026, 5, 1, 9, 0, tzinfo=UTC)
_START_MONO = 1000.0


async def settle(rounds: int = 10) -> None:
    """Let every ready task run until the loop is quiet.

    The short real sleeps give `asyncio.to_thread` workers (the daemon's account calls) time
    to finish and hand their result back to the loop.
    """
    for _ in range(rounds):
        for _ in range(5):
            await asyncio.sleep(0)
        await asyncio.sleep(0.002)


class FakeClock:
    def __init__(self, wall: datetime = START_WALL) -> None:
        self._mono = _START_MONO
        self._wall0 = wall
        self._sleepers: list[tuple[float, asyncio.Future[None]]] = []

    def monotonic(self) -> float:
        return self._mono

    def now(self) -> datetime:
        return self._wall0 + timedelta(seconds=self._mono - _START_MONO)

    @property
    def elapsed(self) -> float:
        return self._mono - _START_MONO

    async def sleep(self, seconds: float) -> None:
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        entry = (self._mono + seconds, future)
        self._sleepers.append(entry)
        try:
            await future
        finally:
            if entry in self._sleepers:
                self._sleepers.remove(entry)

    async def advance(self, seconds: float) -> None:
        """Move time forward, waking each sleeper at its deadline (in order) and settling."""
        await settle()
        target = self._mono + seconds
        while True:
            live = [(t, f) for t, f in self._sleepers if not f.done()]
            due = [t for t, _ in live if t <= target]
            if not due:
                break
            self._mono = max(self._mono, min(due))
            for t, f in live:
                if t <= self._mono:
                    f.set_result(None)
            await settle()
        self._mono = target
        await settle()

    def set_wall(self, wall: datetime) -> None:
        """Jump the wall clock without moving monotonic time (e.g. TOTP tests)."""
        self._wall0 = wall - timedelta(seconds=self._mono - _START_MONO)
