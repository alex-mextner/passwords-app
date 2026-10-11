# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Model test: random edits on both sides, outages, and races always converge with no loss.

Every user write gets a globally unique password, so a password names one version. A version
is "lost" if it was visible in a store when a sync cycle looked at it, and at the end is
neither live, nor in trash, nor something a user knowingly edited over or deleted.
"""

from __future__ import annotations

import asyncio
import dataclasses
import shutil
import tempfile
from pathlib import Path
from typing import override

from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule
from tests.fakes.memory_stores import EPOCH, MemoryLocal, MemoryRemote, make_credential

from passwords_app.store.state import StateStore
from passwords_app.sync.engine import SyncEngine
from passwords_app.sync.ports import SyncPolicy

KEY = bytes(range(32))


class SyncModel(RuleBasedStateMachine):
    policy = SyncPolicy(mass_delete_min=10**9)

    def __init__(self) -> None:
        super().__init__()
        self.tmp = Path(tempfile.mkdtemp(prefix="sync-model-"))
        self.state = StateStore(self.tmp / "state.db", KEY)
        self.remote = MemoryRemote()
        self.local = MemoryLocal()
        self.tick = 0
        self.engine = SyncEngine(
            self.remote, self.local, self.state, policy=self.policy, clock=lambda: EPOCH
        )
        self.observed: set[str] = set()
        self.user_removed: set[str] = set()
        # Versions a user edited over: replacing them is intended, so no trash copy is owed.
        self.superseded: set[str] = set()
        # Versions that were the synced base when a user deleted them: these must be in trash.
        self.must_trash: set[str] = set()

    @override
    def teardown(self) -> None:
        self.state.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---------------------------------------------------------------- helpers

    def fresh(self) -> tuple[str, int]:
        self.tick += 1
        return f"fake-v{self.tick}", self.tick

    def run(self) -> None:
        for c in self.local.items.values():
            self.observed.add(c.password)
        for item in self.remote.items.values():
            self.observed.add(item.credential.password)
        report = asyncio.run(self.engine.run_once())
        if report.paused is not None:
            asyncio.run(self.engine.resolve_pause(apply=True))

    def note_delete(self, item_id: str, password: str) -> None:
        self.user_removed.add(password)
        base = self.state.bases().get(item_id)
        if base is not None and base.credential.password == password:
            self.must_trash.add(password)

    # ---------------------------------------------------------------- user actions

    def put(self, item_id: str, side: str, *, same_time: bool) -> None:
        password, tick = self.fresh()
        c = make_credential(item_id, password=password, modified=0 if same_time else 60 * tick)
        if side == "remote":
            self.remote.put(c)
        else:
            self.local.put(c)

    @rule(side=st.sampled_from(["remote", "local"]))
    def create(self, side: str) -> None:
        # Real stores never reuse an id: iCloud and the keyring adapter mint fresh UUIDs.
        self.put(f"N{self.tick + 1}", side, same_time=False)

    @rule(data=st.data(), side=st.sampled_from(["remote", "local"]), same_time=st.booleans())
    def edit(self, data: st.DataObject, side: str, same_time: bool) -> None:
        items = (
            {i: it.credential for i, it in self.remote.items.items()}
            if side == "remote"
            else dict(self.local.items)
        )
        if not items:
            return
        item_id = data.draw(st.sampled_from(sorted(items)))
        self.user_removed.add(items[item_id].password)
        self.superseded.add(items[item_id].password)
        self.put(item_id, side, same_time=same_time)

    @rule(data=st.data(), side=st.sampled_from(["remote", "local"]))
    def delete(self, data: st.DataObject, side: str) -> None:
        if side == "remote":
            if not self.remote.items:
                return
            item_id = data.draw(st.sampled_from(sorted(self.remote.items)))
            self.note_delete(item_id, self.remote.items[item_id].credential.password)
            self.remote.remove(item_id)
        else:
            if not self.local.items:
                return
            item_id = data.draw(st.sampled_from(sorted(self.local.items)))
            self.note_delete(item_id, self.local.items[item_id].password)
            self.local.remove(item_id)

    @rule(data=st.data())
    def restore(self, data: st.DataObject) -> None:
        entries = self.engine.trash()
        if not entries or self.local.locked:
            return
        entry = data.draw(st.sampled_from(entries))
        asyncio.run(self.engine.restore(entry.trash_id))
        # The user took this version out of the trash; from here it is a live item again.
        self.must_trash.discard(entry.credential.password)

    # ---------------------------------------------------------------- sync cycles

    @rule()
    def sync(self) -> None:
        self.run()

    @rule()
    def sync_offline(self) -> None:
        self.remote.offline = True
        self.run()
        self.remote.offline = False

    @rule()
    def sync_locked(self) -> None:
        self.local.lock()
        self.run()
        self.local.unlock()

    @rule(after=st.integers(0, 3))
    def sync_with_outage_mid_cycle(self, after: int) -> None:
        # Let `after` writes through, then the network drops.
        calls = {"n": 0}

        async def flaky(_: str) -> None:
            calls["n"] += 1
            if calls["n"] > after:
                self.remote.offline = True

        self.remote.on_write = flaky
        try:
            self.run()
        finally:
            self.remote.on_write = None
            self.remote.offline = False

    @rule()
    def sync_racing_an_iphone_edit(self) -> None:
        async def iphone(item_id: str) -> None:
            # The iPhone saves the very record the engine is about to write.
            self.remote.on_write = None
            current = self.remote.items.get(item_id)
            if current is not None:
                self.user_removed.add(current.credential.password)
                self.superseded.add(current.credential.password)
                self.put(item_id, "remote", same_time=False)

        self.remote.on_write = iphone
        try:
            self.run()
        finally:
            self.remote.on_write = None

    # ---------------------------------------------------------------- properties

    @invariant()
    def trash_ids_are_unique(self) -> None:
        ids = [e.trash_id for e in self.state.trash()]
        assert len(ids) == len(set(ids))

    @rule()
    def converge_and_check(self) -> None:
        for _ in range(3):
            self.run()
        live_r = {i: it.credential for i, it in self.remote.items.items()}
        live_l = dict(self.local.items)
        assert {i: c.password for i, c in live_r.items()} == {
            i: c.password for i, c in live_l.items()
        }
        assert all(
            dataclasses.replace(live_r[i], created=EPOCH, modified=EPOCH)
            == dataclasses.replace(live_l[i], created=EPOCH, modified=EPOCH)
            for i in live_r
        )
        report = asyncio.run(self.engine.run_once())
        assert dataclasses.astuple(report)[2:10] == (0,) * 8
        assert self.state.pending() is None
        live = {c.password for c in live_l.values()}
        trashed = {e.credential.password for e in self.state.trash()}
        lost = self.observed - live - trashed - self.user_removed
        assert not lost, f"versions lost: {sorted(lost)}"
        missing = self.must_trash - live - trashed - self.superseded
        assert not missing, f"deleted synced versions not in trash: {sorted(missing)}"


SyncModel.TestCase.settings = settings(max_examples=150, stateful_step_count=30, deadline=None)
test_sync_model = SyncModel.TestCase


class GuardedSyncModel(SyncModel):
    """Same model under the real mass-delete guard (paused cycles are approved)."""

    policy = SyncPolicy()


GuardedSyncModel.TestCase.settings = settings(
    max_examples=60, stateful_step_count=30, deadline=None
)
test_guarded_sync_model = GuardedSyncModel.TestCase
