# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The Wine anisette server runs its helper once per burst of requests, not once per caller."""

from __future__ import annotations

import importlib.util
import threading
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

SERVER = Path(__file__).resolve().parents[3] / "docker" / "anisette" / "server.py"


@pytest.fixture
def server() -> ModuleType:
    spec = importlib.util.spec_from_file_location("anisette_server_under_test", SERVER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_burst_of_callers_costs_one_helper_run(
    server: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs: list[int] = []
    clock = [100.0]

    def run_helper() -> dict[str, str]:
        runs.append(1)
        return {"run": str(len(runs))}

    monkeypatch.setattr(server, "run_helper", run_helper)
    monkeypatch.setattr(server.time, "monotonic", lambda: clock[0])

    answers = [server.fetch() for _ in range(6)]

    assert len(runs) == 1
    assert answers == [{"run": "1"}] * 6


def test_an_answer_older_than_the_window_is_made_again(
    server: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs: list[int] = []
    clock = [100.0]

    def run_helper() -> dict[str, str]:
        runs.append(1)
        return {"run": str(len(runs))}

    monkeypatch.setattr(server, "run_helper", run_helper)
    monkeypatch.setattr(server.time, "monotonic", lambda: clock[0])

    first = server.fetch()
    clock[0] += server.CACHE_SECONDS - 0.1
    assert server.fetch() == first
    clock[0] += 0.2
    assert server.fetch() == {"run": "2"}


def test_a_failed_run_is_not_cached(server: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    outcomes: list[object] = [RuntimeError("helper_failed"), {"ok": "1"}]

    def run_helper() -> dict[str, str]:
        outcome = outcomes.pop(0)
        if isinstance(outcome, RuntimeError):
            raise outcome
        return outcome  # type: ignore[return-value]

    monkeypatch.setattr(server, "run_helper", run_helper)

    with pytest.raises(RuntimeError, match="helper_failed"):
        server.fetch()
    assert server.fetch() == {"ok": "1"}


def test_concurrent_callers_share_one_run(
    server: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = threading.Event()
    release = threading.Event()
    runs: list[int] = []

    def run_helper() -> dict[str, str]:
        runs.append(1)
        started.set()
        release.wait(timeout=5)
        return {"run": "1"}

    monkeypatch.setattr(server, "run_helper", run_helper)
    results: list[dict[str, str]] = []
    threads = [threading.Thread(target=lambda: results.append(server.fetch())) for _ in range(6)]
    for thread in threads:
        thread.start()
    assert started.wait(timeout=5)
    release.set()
    for thread in threads:
        thread.join(timeout=5)

    assert len(runs) == 1
    assert results == [{"run": "1"}] * 6
