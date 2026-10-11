# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from tests.fakes.memory_stores import MemoryLocal, MemoryRemote
from tests.unit.daemon.fake_clock import FakeClock, settle
from tests.unit.daemon.fakes import APPLE_ID, FakeAccount, FakeNotifier

from passwords_app.daemon.controller import Daemon
from passwords_app.store.state import StateStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator
    from pathlib import Path

    from passwords_app.daemon.status import Status

STATE_KEY = bytes(range(32))


@dataclass
class Events:
    statuses: list[Status] = field(default_factory=list)
    items: list[list[str]] = field(default_factory=list)

    @property
    def states(self) -> list[str]:
        return [s.state for s in self.statuses]

    def changed_ids(self) -> set[str]:
        return {i for batch in self.items for i in batch}


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def remote() -> MemoryRemote:
    return MemoryRemote()


@pytest.fixture
def local() -> MemoryLocal:
    return MemoryLocal()


@pytest.fixture
def state(tmp_path: Path) -> Iterator[StateStore]:
    with StateStore(tmp_path / "state.db", STATE_KEY) as store:
        yield store


@pytest.fixture
def account(remote: MemoryRemote) -> FakeAccount:
    """Signed in and joined: the steady state after a completed sign-in."""
    return FakeAccount(remote, apple_id=APPLE_ID, signed_in=True, joined=True)


@pytest.fixture
def notifier() -> FakeNotifier:
    return FakeNotifier()


@pytest.fixture
def events() -> Events:
    return Events()


@pytest.fixture
async def unstarted(  # noqa: PLR0913, PLR0917 - one fixture per collaborator
    account: FakeAccount,
    local: MemoryLocal,
    state: StateStore,
    clock: FakeClock,
    notifier: FakeNotifier,
    events: Events,
) -> AsyncIterator[Daemon]:
    """A wired daemon the test starts itself (after arranging pre-start state)."""
    daemon = Daemon(account=account, local=local, state=state, clock=clock, notifier=notifier)
    daemon.on_status = events.statuses.append
    daemon.on_items = events.items.append
    yield daemon
    await daemon.stop()


@pytest.fixture
async def daemon(unstarted: Daemon) -> Daemon:
    await unstarted.start()
    await settle()
    return unstarted
