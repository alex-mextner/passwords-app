# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Sync timing: start, active/idle intervals, debounce, network-up, backoff (fake clock)."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from tests.unit.daemon.fake_clock import START_WALL, FakeClock, settle

from passwords_app.daemon.scheduler import (
    ACTIVE_INTERVAL,
    BACKOFF_MAX,
    CLIENT_WINDOW,
    DEBOUNCE,
    DEBOUNCE_MAX,
    IDLE_INTERVAL,
    Schedule,
    Scheduler,
    backoff,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

T = 1000.0


def finished(s: Schedule, at: float, *, ok: bool = True) -> Schedule:
    s.cycle_started()
    s.cycle_finished(at, ok=ok)
    return s


# ---------------------------------------------------------------- the pure schedule


def test_first_cycle_is_due_immediately() -> None:
    assert Schedule(T).due(T) == T


def test_idle_interval_after_a_cycle() -> None:
    assert finished(Schedule(T), T).due(T) == T + IDLE_INTERVAL


def test_active_interval_while_a_client_is_recent() -> None:
    s = finished(Schedule(T), T)
    s.client_seen(T)
    assert s.due(T) == T + ACTIVE_INTERVAL


@pytest.mark.parametrize(
    ("seen_ago", "interval"),
    [
        (0, ACTIVE_INTERVAL),
        (CLIENT_WINDOW - 1, ACTIVE_INTERVAL),
        (CLIENT_WINDOW, ACTIVE_INTERVAL),
        (CLIENT_WINDOW + 1, IDLE_INTERVAL),
        (CLIENT_WINDOW * 3, IDLE_INTERVAL),
    ],
)
def test_client_window_boundary(seen_ago: float, interval: float) -> None:
    now = T + 2000
    s = finished(Schedule(T), now)
    s.client_seen(now - seen_ago)
    assert s.due(now) == now + interval


def test_client_appearing_mid_idle_wait_makes_the_cycle_due_now() -> None:
    s = finished(Schedule(T), T)
    s.client_seen(T + 200)
    assert s.due(T + 200) == T + ACTIVE_INTERVAL  # already in the past: run now


def test_local_change_is_debounced() -> None:
    s = finished(Schedule(T), T)
    s.local_changed(T + 10)
    assert s.due(T + 10) == T + 10 + DEBOUNCE


def test_each_change_restarts_the_debounce() -> None:
    s = finished(Schedule(T), T)
    s.local_changed(T + 10)
    s.local_changed(T + 11)
    assert s.due(T + 11) == T + 11 + DEBOUNCE


def test_a_stream_of_changes_cannot_postpone_forever() -> None:
    s = finished(Schedule(T), T)
    for i in range(30):
        s.local_changed(T + 10 + i)
    assert s.due(T + 39) == T + 10 + DEBOUNCE_MAX


def test_debounce_never_delays_an_earlier_regular_cycle() -> None:
    s = finished(Schedule(T), T)
    s.client_seen(T)
    s.local_changed(T + ACTIVE_INTERVAL - 1)
    assert s.due(T + ACTIVE_INTERVAL - 1) == T + ACTIVE_INTERVAL


def test_cycle_start_consumes_pending_changes() -> None:
    s = Schedule(T)
    s.local_changed(T)
    s.cycle_started()
    s.cycle_finished(T + 1, ok=True)
    assert s.due(T + 1) == T + 1 + IDLE_INTERVAL


def test_change_during_a_cycle_schedules_another() -> None:
    s = Schedule(T)
    s.cycle_started()
    s.local_changed(T + 0.5)
    s.cycle_finished(T + 1, ok=True)
    assert s.due(T + 1) == T + 0.5 + DEBOUNCE


def test_request_makes_a_cycle_due_now() -> None:
    s = finished(Schedule(T), T)
    s.request()
    assert s.due(T + 5) == T + 5


@pytest.mark.parametrize(
    ("failures", "delay"),
    [(1, 30), (2, 60), (3, 120), (4, 240), (5, 480), (6, 960), (7, 1800), (8, 1800), (50, 1800)],
)
def test_backoff_doubles_up_to_thirty_minutes(failures: int, delay: float) -> None:
    assert backoff(failures) == delay


def test_failed_cycles_back_off() -> None:
    s = Schedule(T)
    for n in range(1, 9):
        finished(s, T, ok=False)
        assert s.failures == n
        assert s.due(T) == T + backoff(n)


def test_backoff_overrides_the_active_interval() -> None:
    s = Schedule(T)
    s.client_seen(T)
    for _ in range(4):
        finished(s, T, ok=False)
    assert s.due(T) == T + backoff(4)
    assert s.due(T) > T + ACTIVE_INTERVAL


def test_success_resets_backoff() -> None:
    s = Schedule(T)
    for _ in range(5):
        finished(s, T, ok=False)
    finished(s, T)
    assert s.failures == 0
    assert s.due(T) == T + IDLE_INTERVAL


def test_network_up_resets_backoff_and_runs_now() -> None:
    s = Schedule(T)
    for _ in range(6):
        finished(s, T, ok=False)
    s.network_up()
    assert s.failures == 0
    assert s.due(T + 1) == T + 1


def test_local_change_still_triggers_during_backoff() -> None:
    s = Schedule(T)
    for _ in range(6):
        finished(s, T, ok=False)
    s.local_changed(T + 5)
    assert s.due(T + 5) == T + 5 + DEBOUNCE


def test_backoff_cap_is_thirty_minutes() -> None:
    assert BACKOFF_MAX == 30 * 60


# ---------------------------------------------------------------- the async runner


class Recorder:
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.times: list[float] = []
        self.results: list[bool] = []
        self.gate: asyncio.Event | None = None

    async def __call__(self) -> bool:
        self.times.append(self.clock.elapsed)
        if self.gate is not None:
            await self.gate.wait()
        return self.results.pop(0) if self.results else True


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def recorder(clock: FakeClock) -> Recorder:
    return Recorder(clock)


@pytest.fixture
async def scheduler(clock: FakeClock, recorder: Recorder) -> AsyncIterator[Scheduler]:
    s = Scheduler(recorder, clock)
    task = asyncio.create_task(s.run())
    await settle()
    yield s
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_runs_a_cycle_at_start(scheduler: Scheduler, recorder: Recorder) -> None:
    assert recorder.times == [0]


async def test_idle_cadence_is_five_minutes(
    scheduler: Scheduler, clock: FakeClock, recorder: Recorder
) -> None:
    await clock.advance(IDLE_INTERVAL * 3)
    assert recorder.times == [0, 300, 600, 900]


async def test_active_cadence_is_one_minute(
    scheduler: Scheduler, clock: FakeClock, recorder: Recorder
) -> None:
    scheduler.client_seen()
    await clock.advance(180)
    assert recorder.times == [0, 60, 120, 180]


async def test_cadence_falls_back_to_idle_when_clients_go_away(
    scheduler: Scheduler, clock: FakeClock, recorder: Recorder
) -> None:
    scheduler.client_seen()
    await clock.advance(CLIENT_WINDOW + IDLE_INTERVAL + 60)
    active = [t for t in recorder.times if t <= CLIENT_WINDOW]
    assert active == [0, 60, 120, 180, 240, 300]
    assert recorder.times[len(active) :] == [600]


async def test_local_change_runs_two_seconds_later(
    scheduler: Scheduler, clock: FakeClock, recorder: Recorder
) -> None:
    await clock.advance(10)
    scheduler.local_changed()
    await clock.advance(1.9)
    assert recorder.times == [0]
    await clock.advance(0.1)
    assert recorder.times == [0, 12]


async def test_burst_of_changes_runs_one_cycle(
    scheduler: Scheduler, clock: FakeClock, recorder: Recorder
) -> None:
    await clock.advance(10)
    for _ in range(5):
        scheduler.local_changed()
        await clock.advance(0.5)
    await clock.advance(5)
    assert recorder.times == [0, 14]


async def test_request_runs_immediately(
    scheduler: Scheduler, clock: FakeClock, recorder: Recorder
) -> None:
    await clock.advance(42)
    scheduler.request()
    await settle()
    assert recorder.times == [0, 42]


async def test_network_up_runs_immediately_and_clears_backoff(
    scheduler: Scheduler, clock: FakeClock, recorder: Recorder
) -> None:
    recorder.results = [False, False, False]
    scheduler.request()
    await clock.advance(30 + 60)  # two failed retries
    assert recorder.times == [0, 0, 30, 90]
    assert scheduler.schedule.failures == 3
    await clock.advance(10)
    scheduler.network_up()
    await settle()
    assert recorder.times[-1] == 100
    assert scheduler.schedule.failures == 0


async def test_failures_back_off_exponentially(
    scheduler: Scheduler, clock: FakeClock, recorder: Recorder
) -> None:
    recorder.results = [False] * 10
    scheduler.request()
    await clock.advance(4 * 3600)
    gaps = [b - a for a, b in zip(recorder.times[1:], recorder.times[2:], strict=False)]
    assert gaps[:7] == [30, 60, 120, 240, 480, 960, 1800]
    assert max(gaps) == 1800


async def test_crashing_cycle_counts_as_failure_and_keeps_running(
    clock: FakeClock,
) -> None:
    calls: list[float] = []

    async def boom() -> bool:
        calls.append(clock.elapsed)
        msg = "bug"
        raise RuntimeError(msg)

    s = Scheduler(boom, clock)
    task = asyncio.create_task(s.run())
    await clock.advance(30 + 60)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls == [0, 30, 90]


async def test_run_now_waits_for_a_fresh_cycle(
    scheduler: Scheduler, clock: FakeClock, recorder: Recorder
) -> None:
    await clock.advance(5)
    waiter = asyncio.create_task(scheduler.run_now())
    await settle()
    assert waiter.done()
    assert recorder.times == [0, 5]


async def test_run_now_during_a_cycle_waits_for_the_next_one(
    scheduler: Scheduler, clock: FakeClock, recorder: Recorder
) -> None:
    gate = asyncio.Event()
    recorder.gate = gate
    scheduler.request()
    await settle()
    assert recorder.times == [0, 0]  # second cycle is blocked inside
    waiter = asyncio.create_task(scheduler.run_now())
    await settle()
    assert not waiter.done()
    gate.set()
    await settle()
    assert waiter.done()
    assert len(recorder.times) == 3  # the in-flight cycle could not see the request


async def test_next_run_reports_wall_time(scheduler: Scheduler, clock: FakeClock) -> None:
    assert scheduler.next_run() == START_WALL + timedelta(seconds=IDLE_INTERVAL)
    await clock.advance(100)
    assert scheduler.next_run() == START_WALL + timedelta(seconds=IDLE_INTERVAL)


async def test_next_run_is_now_when_due(scheduler: Scheduler, clock: FakeClock) -> None:
    scheduler.schedule.request()  # without waking the loop
    assert scheduler.next_run() == clock.now()
