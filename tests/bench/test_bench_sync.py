# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Performance budgets (spec §12): plan() on 10 000 items, an engine cycle on 2 000 items."""

from __future__ import annotations

import asyncio
import dataclasses
import statistics
import time
from typing import TYPE_CHECKING

import pytest
from tests.fakes.memory_stores import MemoryLocal, MemoryRemote, make_credential

from passwords_app.store.state import StateStore
from passwords_app.sync.engine import SyncEngine
from passwords_app.sync.plan import BaseEntry, plan
from passwords_app.sync.ports import LocalSnapshot, RemoteItem, RemoteSnapshot, SyncPolicy

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from pytest_benchmark.fixture import BenchmarkFixture

pytestmark = pytest.mark.benchmark

PLAN_BUDGET_S = 0.100
CYCLE_BUDGET_S = 0.300
ROUNDS = 15


def median_seconds(benchmark: BenchmarkFixture, fn: Callable[[], object]) -> float:
    """Median wall time of `fn`, via pytest-benchmark when it is active.

    pytest-benchmark switches itself off under xdist (`-n`), but the budget must hold in
    every run, so fall back to timing the same rounds by hand.
    """
    if not benchmark.disabled:
        benchmark.pedantic(fn, rounds=ROUNDS, warmup_rounds=2)  # type: ignore[no-untyped-call]
        assert benchmark.stats is not None
        return float(benchmark.stats.stats.median)
    benchmark(fn)  # disabled mode: a single plain call, which also serves as warm-up
    fn()
    samples = []
    for _ in range(ROUNDS):
        t = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t)
    return statistics.median(samples)


def test_plan_10k_items_within_budget(benchmark: BenchmarkFixture) -> None:
    n = 10_000
    creds = [
        make_credential(f"{i:08X}-0000-4000-8000-000000000000", title=f"Site {i}") for i in range(n)
    ]
    base = {c.id: BaseEntry(c, "e1") for c in creds}
    # Steady state plus a realistic trickle of work on both sides.
    remote_items = {c.id: RemoteItem(c, "e1") for c in creds}
    local_items = {c.id: c for c in creds}
    for c in creds[:50]:
        edited = dataclasses.replace(c, notes="edited on iPhone")
        remote_items[c.id] = RemoteItem(edited, "e2")
    for c in creds[50:100]:
        local_items[c.id] = dataclasses.replace(c, title="edited on Linux")
    remote = RemoteSnapshot(remote_items)
    local = LocalSnapshot(local_items)
    policy = SyncPolicy()

    result = plan(base, remote, local, policy)
    assert len(result.actions) == 100

    median = median_seconds(benchmark, lambda: plan(base, remote, local, policy))
    assert median < PLAN_BUDGET_S, f"plan() median {median * 1000:.1f} ms"


def test_plan_first_sync_10k_links_within_budget(benchmark: BenchmarkFixture) -> None:
    # First sync with a populated keyring: every item goes through URL normalization.
    n = 10_000
    remote = RemoteSnapshot(
        {
            f"R{i:05d}": RemoteItem(
                make_credential(f"R{i:05d}", url=f"https://www.site{i}.example.com/login"), "e"
            )
            for i in range(n)
        }
    )
    local = LocalSnapshot(
        {f"L{i:05d}": make_credential(f"L{i:05d}", url=f"site{i}.example.com") for i in range(n)}
    )
    policy = SyncPolicy()
    median = median_seconds(benchmark, lambda: plan({}, remote, local, policy))
    # Linking is a one-off; it gets three times the steady-state budget.
    assert median < 3 * PLAN_BUDGET_S, f"first-sync plan() median {median * 1000:.1f} ms"


def test_engine_cycle_2k_unchanged_within_budget(
    benchmark: BenchmarkFixture, tmp_path: Path
) -> None:
    creds = {
        f"{i:08X}": make_credential(f"{i:08X}", title=f"Site {i}", notes="n" * 40)
        for i in range(2000)
    }
    remote = MemoryRemote(creds)
    local = MemoryLocal(creds)
    with StateStore(tmp_path / "state.db", bytes(32)) as state:
        engine = SyncEngine(remote, local, state)
        first = asyncio.run(engine.run_once())
        assert first.linked == 2000

        def cycle() -> None:
            report = asyncio.run(engine.run_once())
            assert report.linked == 0
            assert report.skipped_reason is None

        median = median_seconds(benchmark, cycle)
    assert median < CYCLE_BUDGET_S, f"engine cycle median {median * 1000:.1f} ms"


FIRST_SYNC_BUDGET_S = 1.0


def test_engine_first_sync_2k_within_budget(benchmark: BenchmarkFixture, tmp_path: Path) -> None:
    # Every item is linked and gets a base row: this is where per-row commits would cost
    # one fsync each.
    creds = {f"{i:08X}": make_credential(f"{i:08X}") for i in range(2000)}
    runs = iter(range(10**6))

    def first_sync() -> None:
        path = tmp_path / f"state-{next(runs)}.db"
        with StateStore(path, bytes(32)) as state:
            report = asyncio.run(
                SyncEngine(MemoryRemote(creds), MemoryLocal(creds), state).run_once()
            )
            assert report.linked == 2000

    median = median_seconds(benchmark, first_sync)
    assert median < FIRST_SYNC_BUDGET_S, f"first sync median {median * 1000:.1f} ms"


def test_engine_approved_mass_delete_1k_within_budget(
    benchmark: BenchmarkFixture, tmp_path: Path
) -> None:
    # A confirmed mass deletion writes a trash row per item; those must not cost an fsync each.
    creds = {f"{i:08X}": make_credential(f"{i:08X}") for i in range(2000)}
    runs = iter(range(10**6))

    def apply_mass_delete() -> None:
        remote, local = MemoryRemote(creds), MemoryLocal(creds)
        with StateStore(tmp_path / f"state-{next(runs)}.db", bytes(32)) as state:
            engine = SyncEngine(remote, local, state)
            asyncio.run(engine.run_once())
            for item_id in list(creds)[:1000]:
                remote.remove(item_id)
            assert asyncio.run(engine.run_once()).paused is not None
            report = asyncio.run(engine.resolve_pause(apply=True))
            assert report.deleted_local == 1000

    median = median_seconds(benchmark, apply_mass_delete)
    assert median < FIRST_SYNC_BUDGET_S, f"mass delete median {median * 1000:.1f} ms"
