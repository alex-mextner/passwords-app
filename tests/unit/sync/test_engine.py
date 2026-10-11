# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""SyncEngine against the in-memory stores: spec scenarios S12-S18, S20, S24."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from tests.fakes.memory_stores import MemoryLocal, MemoryRemote, make_credential

from passwords_app.store.state import StateStore
from passwords_app.sync.engine import (
    LAST_SYNC_KEY,
    SKIP_AUTH,
    SKIP_LOCAL,
    SKIP_REMOTE,
    NoPendingDeletionsError,
    SyncEngine,
)
from passwords_app.sync.plan import content_key
from passwords_app.sync.ports import (
    AuthRequired,
    ConflictError,
    ItemRejected,
    LocalUnavailable,
    PendingDeletions,
    RejectedLocalItem,
    RemoteUnavailable,
    SyncPolicy,
    UploadFailure,
    upload_failures_message,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from passwords_app.core.model import Credential
    from passwords_app.sync.ports import RemoteSnapshot

KEY = bytes(32)
T0 = datetime(2026, 6, 1, 9, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


class World:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.remote = MemoryRemote()
        self.local = MemoryLocal()
        self.clock = Clock()
        self.state = StateStore(path, KEY)
        self.engine = self.make_engine()

    def make_engine(self, policy: SyncPolicy | None = None) -> SyncEngine:
        return SyncEngine(self.remote, self.local, self.state, policy=policy, clock=self.clock)

    def restart(self) -> None:
        self.state.close()
        self.state = StateStore(self.path, KEY)
        self.engine = self.make_engine()

    def remote_contents(self) -> dict[str, tuple[object, ...]]:
        return {i: content_key(r.credential) for i, r in self.remote.items.items()}

    def local_contents(self) -> dict[str, tuple[object, ...]]:
        return {i: content_key(c) for i, c in self.local.items.items()}

    def converged(self) -> bool:
        return self.remote_contents() == self.local_contents()


@pytest.fixture
def w(tmp_path: Path) -> Iterator[World]:
    world = World(tmp_path / "state.db")
    yield world
    world.state.close()


def at(c: Credential, minutes: int, **changes: Any) -> Credential:
    return dataclasses.replace(c, modified=T0 + timedelta(minutes=minutes), **changes)


async def synced(w: World, *creds: Credential) -> None:
    for c in creds:
        w.remote.put(c)
    report = await w.engine.run_once()
    assert report.skipped_reason is None
    assert w.converged()


# ---------------------------------------------------------------- basic flow


async def test_new_icloud_items_reach_the_keyring(w: World) -> None:
    w.remote.put(make_credential("A"))
    w.remote.put(make_credential("B"))
    report = await w.engine.run_once()
    assert report.created_local == 2
    assert set(w.local.items) == {"A", "B"}
    assert set(w.state.bases()) == {"A", "B"}


async def test_new_keyring_items_reach_icloud_and_record_the_etag(w: World) -> None:
    w.local.put(make_credential("A"))
    report = await w.engine.run_once()
    assert report.created_remote == 1
    assert w.state.bases()["A"].etag == w.remote.etag_of("A")


async def test_second_cycle_is_a_no_op(w: World) -> None:
    w.remote.put(make_credential("A"))
    w.local.put(make_credential("B"))
    await w.engine.run_once()
    w.remote.calls.clear()
    w.local.calls.clear()
    report = await w.engine.run_once()
    counts = dataclasses.astuple(report)[2:10]
    assert counts == (0,) * 8
    assert [op for op, _ in w.remote.calls] == ["fetch"]
    assert [op for op, _ in w.local.calls] == ["fetch"]


async def test_report_times_come_from_the_clock(w: World) -> None:
    report = await w.engine.run_once()
    assert report.started == T0
    assert report.finished == T0


async def test_successful_cycle_records_last_sync(w: World) -> None:
    await w.engine.run_once()
    assert w.state.get(LAST_SYNC_KEY) == T0.isoformat()


async def test_rejected_keyring_items_are_reported_and_left_alone(w: World) -> None:
    bad = RejectedLocalItem("/org/freedesktop/secrets/collection/x/7", "???", "no host")
    w.local.rejected.append(bad)
    report = await w.engine.run_once()
    assert report.rejected == (bad,)
    assert w.remote.items == {}


async def test_edit_on_apple_reaches_linux(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.remote.put(at(a, 5, password="fake-iphone"))
    report = await w.engine.run_once()
    assert report.updated_local == 1
    assert w.local.items["A"].password == "fake-iphone"


async def test_edit_on_linux_reaches_apple(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.put(at(a, 5, notes="from seahorse"))
    report = await w.engine.run_once()
    assert report.updated_remote == 1
    assert w.remote.items["A"].credential.notes == "from seahorse"
    assert w.state.bases()["A"].etag == w.remote.etag_of("A")


async def test_delete_on_apple_removes_locally_into_trash(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.remote.remove("A")
    report = await w.engine.run_once()
    assert report.deleted_local == 1
    assert "A" not in w.local.items
    (entry,) = w.engine.trash()
    assert (entry.credential.id, entry.reason, entry.deleted_at) == ("A", "deleted-in-icloud", T0)


async def test_delete_on_linux_removes_in_icloud_into_trash(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.remove("A")
    report = await w.engine.run_once()
    assert report.deleted_remote == 1
    assert "A" not in w.remote.items
    assert [e.reason for e in w.engine.trash()] == ["deleted-on-linux"]


async def test_delete_on_both_sides_lands_in_trash_once(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.remove("A")
    w.remote.remove("A")
    await w.engine.run_once()
    await w.engine.run_once()
    assert [e.reason for e in w.engine.trash()] == ["deleted-both"]
    assert w.state.bases() == {}


# ---------------------------------------------------------------- S12 / S13 conflicts


async def test_s12_edit_edit_newer_wins_older_in_trash(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    linux = at(a, 1, password="fake-linux")
    iphone = at(a, 2, password="fake-iphone")
    w.local.put(linux)
    w.remote.put(iphone)
    report = await w.engine.run_once()
    assert report.conflicts == 1
    assert w.local.items["A"] == iphone
    assert w.converged()
    (loser,) = w.engine.trash()
    assert (loser.credential, loser.reason) == (linux, "conflict")


async def test_s12_linux_newer_wins(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    iphone = at(a, 1, password="fake-iphone")
    linux = at(a, 2, password="fake-linux")
    w.remote.put(iphone)
    w.local.put(linux)
    await w.engine.run_once()
    assert w.remote.items["A"].credential == linux
    assert [e.credential for e in w.engine.trash()] == [iphone]


async def test_s12_conflict_does_not_repeat_on_next_cycle(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.put(at(a, 1, password="fake-l"))
    w.remote.put(at(a, 2, password="fake-r"))
    await w.engine.run_once()
    report = await w.engine.run_once()
    assert report.conflicts == 0
    assert len(w.engine.trash()) == 1


async def test_s13_edit_on_linux_beats_delete_on_apple(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.remote.remove("A")
    w.local.put(at(a, 3, password="fake-edited"))
    report = await w.engine.run_once()
    assert report.created_remote == 1
    assert w.remote.items["A"].credential.password == "fake-edited"
    assert w.engine.trash() == []


async def test_s13_edit_on_apple_beats_delete_on_linux(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.remove("A")
    w.remote.put(at(a, 3, password="fake-edited"))
    report = await w.engine.run_once()
    assert report.created_local == 1
    assert w.local.items["A"].password == "fake-edited"


async def test_same_edit_on_both_sides_is_not_a_conflict(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.put(at(a, 1, title="same"))
    w.remote.put(at(a, 2, title="same"))
    report = await w.engine.run_once()
    assert report.conflicts == 0
    assert w.engine.trash() == []
    assert w.state.bases()["A"].etag == w.remote.etag_of("A")


# ---------------------------------------------------------------- etag races


async def test_conflicting_write_is_abandoned_and_replanned(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.put(at(a, 1, password="fake-linux"))
    iphone = at(a, 2, password="fake-iphone")

    async def iphone_saves_first(item_id: str) -> None:
        w.remote.on_write = None
        w.remote.put(iphone)
        assert item_id == "A"

    w.remote.on_write = iphone_saves_first
    report = await w.engine.run_once()
    assert report.updated_remote == 0
    assert report.skipped_reason is None
    assert w.remote.items["A"].credential == iphone
    # Next cycle sees both edits: iPhone is newer, the Linux edit is kept in trash.
    report = await w.engine.run_once()
    assert report.conflicts == 1
    assert w.local.items["A"] == iphone
    assert [e.credential.password for e in w.engine.trash()] == ["fake-linux"]


async def test_conflict_on_one_item_does_not_block_others(w: World) -> None:
    a, b = make_credential("A"), make_credential("B")
    await synced(w, a, b)
    w.local.put(at(a, 1, password="fake-a"))
    w.local.put(at(b, 1, password="fake-b"))
    w.remote.fail_next("upsert", ConflictError("raced"))
    report = await w.engine.run_once()
    assert report.updated_remote == 1
    assert w.remote.items["B"].credential.password == "fake-b"
    await w.engine.run_once()
    assert w.converged()


async def test_conflict_on_delete_keeps_the_item(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.remove("A")
    w.remote.fail_next("delete", ConflictError("raced"))
    report = await w.engine.run_once()
    assert report.deleted_remote == 0
    assert "A" in w.remote.items
    assert "A" in w.state.bases()


# ---------------------------------------------------------------- S14 / S15 trash


async def test_s14_restore_puts_item_back_on_both_sides(w: World) -> None:
    a = make_credential("A", title="Bank")
    await synced(w, a)
    w.remote.remove("A")
    await w.engine.run_once()
    (entry,) = w.engine.trash()
    w.clock.advance(days=3)
    new_id = await w.engine.restore(entry.trash_id)
    assert new_id != "A"
    assert w.local.items[new_id].title == "Bank"
    assert w.local.items[new_id].modified == w.clock.now
    assert w.engine.trash() == []
    report = await w.engine.run_once()
    assert report.created_remote == 1
    assert w.remote.items[new_id].credential.title == "Bank"
    assert w.converged()


async def test_s14_restoring_a_conflict_loser_never_overwrites_the_winner(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.put(at(a, 1, password="fake-loser"))
    w.remote.put(at(a, 2, password="fake-winner"))
    await w.engine.run_once()
    (entry,) = w.engine.trash()
    new_id = await w.engine.restore(entry.trash_id)
    await w.engine.run_once()
    assert w.remote.items["A"].credential.password == "fake-winner"
    assert w.remote.items[new_id].credential.password == "fake-loser"


async def test_restore_unknown_trash_id(w: World) -> None:
    with pytest.raises(KeyError):
        await w.engine.restore("missing")


async def test_restore_while_keyring_locked_keeps_the_entry(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.remote.remove("A")
    await w.engine.run_once()
    (entry,) = w.engine.trash()
    w.local.lock()
    with pytest.raises(LocalUnavailable):
        await w.engine.restore(entry.trash_id)
    assert w.engine.trash() == [entry]


async def test_purge_deletes_entry_for_good(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.remove("A")
    await w.engine.run_once()
    (entry,) = w.engine.trash()
    w.engine.purge(entry.trash_id)
    assert w.engine.trash() == []
    with pytest.raises(KeyError):
        w.engine.purge(entry.trash_id)


@pytest.mark.parametrize(
    ("days", "kept"), [(0, True), (89, True), (90, True), (90.01, False), (365, False)]
)
async def test_s15_trash_expires_after_retention(w: World, days: float, kept: bool) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.remote.remove("A")
    await w.engine.run_once()
    w.clock.advance(days=days)
    assert bool(w.engine.trash()) is kept
    await w.engine.run_once()
    assert bool(w.state.trash()) is kept


async def test_s15_retention_is_a_setting(w: World) -> None:
    w.engine = w.make_engine(SyncPolicy(trash_retention=timedelta(days=7)))
    a = make_credential("A")
    await synced(w, a)
    w.remote.remove("A")
    await w.engine.run_once()
    w.clock.advance(days=8)
    await w.engine.run_once()
    assert w.state.trash() == []


# ---------------------------------------------------------------- S16 pause


async def paused_world(w: World, n: int = 20, gone: int = 10) -> PendingDeletions:
    creds = [make_credential(f"I{i:03d}") for i in range(n)]
    await synced(w, *creds)
    for c in creds[:gone]:
        w.remote.remove(c.id)
    report = await w.engine.run_once()
    assert report.paused is not None
    return report.paused


async def test_s16_mass_delete_pauses_and_deletes_nothing(w: World) -> None:
    pending = await paused_world(w)
    assert len(pending.local_ids) == 10
    assert len(w.local.items) == 20
    assert w.engine.trash() == []
    assert w.state.pending() == pending


async def test_s16_pause_persists_across_cycles_and_restarts(w: World) -> None:
    pending = await paused_world(w)
    w.restart()
    report = await w.engine.run_once()
    assert report.paused == pending
    assert len(w.local.items) == 20


async def test_s16_apply_deletes_into_trash(w: World) -> None:
    await paused_world(w)
    report = await w.engine.resolve_pause(apply=True)
    assert report.paused is None
    assert report.deleted_local == 10
    assert len(w.local.items) == 10
    assert len(w.engine.trash()) == 10
    assert w.state.pending() is None
    assert w.converged()


async def test_s16_restore_brings_everything_back(w: World) -> None:
    await paused_world(w)
    report = await w.engine.resolve_pause(apply=False)
    assert report.created_remote == 10
    assert len(w.remote.items) == 20
    assert w.state.pending() is None
    assert w.converged()
    assert (await w.engine.run_once()).paused is None


async def test_resolve_without_pause_is_an_error(w: World) -> None:
    with pytest.raises(NoPendingDeletionsError):
        await w.engine.resolve_pause(apply=True)


async def test_pause_clears_once_the_deletions_disappear(w: World) -> None:
    creds = [make_credential(f"I{i:03d}") for i in range(20)]
    await synced(w, *creds)
    removed = {c.id: w.remote.items[c.id].credential for c in creds[:10]}
    for i in removed:
        w.remote.remove(i)
    await w.engine.run_once()
    for c in removed.values():
        w.remote.put(c)
    report = await w.engine.run_once()
    assert report.paused is None
    assert w.state.pending() is None


async def test_apply_with_keyring_locked_keeps_the_pause(w: World) -> None:
    pending = await paused_world(w)
    w.local.lock()
    report = await w.engine.resolve_pause(apply=True)
    assert report.skipped_reason == SKIP_LOCAL
    assert w.state.pending() == pending


# ---------------------------------------------------------------- S17 locked / S18 offline


async def test_s17_locked_keyring_skips_cycle_and_deletes_nothing(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.lock()
    report = await w.engine.run_once()
    assert report.skipped_reason == SKIP_LOCAL
    assert "A" in w.remote.items
    assert [op for op, _ in w.remote.calls if op != "fetch"] == []
    w.local.unlock()
    assert (await w.engine.run_once()).deleted_remote == 0
    assert "A" in w.remote.items


async def test_s17_keyring_locking_mid_cycle_stops_cleanly(w: World) -> None:
    await synced(w, make_credential("A"))
    w.remote.put(make_credential("B"))
    w.remote.put(make_credential("C"))
    w.local.fail_next("upsert", LocalUnavailable("locked"))
    report = await w.engine.run_once()
    assert report.skipped_reason == SKIP_LOCAL
    assert w.state.bases().keys() == {"A"}
    report = await w.engine.run_once()
    assert report.created_local == 2
    assert w.converged()


async def test_s18_offline_skips_and_keeps_local_edits(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.put(at(a, 1, password="fake-offline-edit"))
    w.local.put(make_credential("NEW"))
    w.remote.offline = True
    report = await w.engine.run_once()
    assert report.skipped_reason == SKIP_REMOTE
    assert w.local.items["A"].password == "fake-offline-edit"
    w.remote.offline = False
    report = await w.engine.run_once()
    assert (report.updated_remote, report.created_remote) == (1, 1)
    assert w.converged()


async def test_s18_outage_mid_cycle_resumes_without_loss(w: World) -> None:
    for i in range(5):
        w.local.put(make_credential(f"L{i}"))
    w.remote.fail_next("upsert", RemoteUnavailable("reset"))
    report = await w.engine.run_once()
    assert report.skipped_reason == SKIP_REMOTE
    report = await w.engine.run_once()
    assert report.created_remote == 5
    assert w.converged()
    assert len(w.remote.items) == 5


async def test_auth_required_is_reported_distinctly(w: World) -> None:
    w.remote.fail_next("fetch", AuthRequired("2fa"))
    report = await w.engine.run_once()
    assert report.skipped_reason == SKIP_AUTH


async def test_auth_required_during_writes(w: World) -> None:
    w.local.put(make_credential("A"))
    w.remote.fail_next("upsert", AuthRequired("2fa"))
    report = await w.engine.run_once()
    assert report.skipped_reason == SKIP_AUTH
    assert w.state.bases() == {}


async def test_skipped_cycle_does_not_record_last_sync(w: World) -> None:
    w.local.lock()
    await w.engine.run_once()
    assert w.state.get(LAST_SYNC_KEY) is None


# ---------------------------------------------------------------- items iCloud refuses


async def test_an_item_icloud_refuses_does_not_stop_the_others(w: World) -> None:
    for item_id in ("A", "B", "C"):
        w.local.put(make_credential(item_id))
    w.remote.reject("B", "another login for this site and account already exists")
    report = await w.engine.run_once()
    assert report.skipped_reason is None
    assert report.created_remote == 2
    assert set(w.remote.items) == {"A", "C"}
    assert w.state.get(LAST_SYNC_KEY) == T0.isoformat()
    (failure,) = report.upload_failures
    assert failure == UploadFailure(
        "B",
        "https://b.example.com",
        "user",
        "another login for this site and account already exists",
        attempts=1,
        retry_at=T0 + SyncPolicy().rejected_retry,
    )
    assert "B" not in w.state.bases()


async def test_a_refused_item_does_not_stop_later_changes(w: World) -> None:
    w.local.put(make_credential("B"))
    w.remote.reject("B")
    await w.engine.run_once()
    w.local.put(make_credential("LATER"))
    report = await w.engine.run_once()
    assert report.skipped_reason is None
    assert "LATER" in w.remote.items


async def test_a_refused_item_is_retried_with_growing_backoff(w: World) -> None:
    w.local.put(make_credential("B"))
    w.remote.reject("B")
    retry = SyncPolicy().rejected_retry

    async def uploads_of_b() -> int:
        w.remote.calls.clear()
        report = await w.engine.run_once()
        assert report.skipped_reason is None
        assert [f.item_id for f in report.upload_failures] == ["B"]
        return w.remote.calls.count(("upsert", "B"))

    assert await uploads_of_b() == 1
    w.clock.advance(seconds=retry.total_seconds() - 1)
    assert await uploads_of_b() == 0  # still waiting: no hammering every cycle
    w.clock.advance(seconds=1)
    assert await uploads_of_b() == 1  # second refusal: the wait doubles
    w.clock.advance(seconds=retry.total_seconds())
    assert await uploads_of_b() == 0
    w.clock.advance(seconds=retry.total_seconds())
    assert await uploads_of_b() == 1
    w.remote.accept("B")
    w.clock.advance(seconds=4 * retry.total_seconds())
    report = await w.engine.run_once()
    assert report.created_remote == 1
    assert report.upload_failures == ()
    assert w.converged()


async def test_backoff_is_capped(w: World) -> None:
    policy = SyncPolicy(
        rejected_retry=timedelta(minutes=1), rejected_retry_max=timedelta(minutes=3)
    )
    w.engine = w.make_engine(policy)
    w.local.put(make_credential("B"))
    w.remote.reject("B")
    waits = []
    for _ in range(4):
        report = await w.engine.run_once()
        (failure,) = report.upload_failures
        waits.append(failure.retry_at - w.clock.now)
        w.clock.now = failure.retry_at
    assert waits == [timedelta(minutes=m) for m in (1, 2, 3, 3)]


async def test_editing_a_refused_item_retries_it_at_once(w: World) -> None:
    b = make_credential("B")
    w.local.put(b)
    w.remote.reject("B")
    await w.engine.run_once()
    w.remote.accept("B")
    w.local.put(at(b, 1, username="someone-else"))
    report = await w.engine.run_once()
    assert report.created_remote == 1
    assert report.upload_failures == ()
    assert w.remote.items["B"].credential.username == "someone-else"


async def test_a_refused_edit_keeps_the_item_linked_and_others_flowing(w: World) -> None:
    a, b = make_credential("A"), make_credential("B")
    await synced(w, a, b)
    w.local.put(at(a, 1, password="fake-a"))
    w.local.put(at(b, 1, password="fake-b"))
    w.remote.reject("A")
    report = await w.engine.run_once()
    assert report.skipped_reason is None
    assert report.updated_remote == 1
    assert w.remote.items["B"].credential.password == "fake-b"
    assert w.state.bases()["A"].credential == a
    assert [f.item_id for f in report.upload_failures] == ["A"]


async def test_the_retry_schedule_survives_a_restart(w: World) -> None:
    w.local.put(make_credential("B"))
    w.remote.reject("B")
    first = await w.engine.run_once()
    w.restart()
    w.remote.calls.clear()
    report = await w.engine.run_once()
    assert ("upsert", "B") not in w.remote.calls
    assert report.upload_failures == first.upload_failures


async def test_a_refused_item_that_was_deleted_is_forgotten(w: World) -> None:
    w.local.put(make_credential("B"))
    w.remote.reject("B")
    await w.engine.run_once()
    w.local.remove("B")
    report = await w.engine.run_once()
    assert report.upload_failures == ()
    w.local.put(make_credential("B"))
    w.remote.calls.clear()
    await w.engine.run_once()
    assert ("upsert", "B") in w.remote.calls  # a fresh start, not the old schedule


async def test_the_rejection_hook_fires_once_per_refused_version(w: World) -> None:
    seen: list[UploadFailure] = []
    w.engine = SyncEngine(w.remote, w.local, w.state, clock=w.clock, on_upload_rejected=seen.append)
    b = make_credential("B")
    w.local.put(b)
    w.remote.reject("B", "duplicate")
    await w.engine.run_once()
    w.clock.advance(days=1)
    await w.engine.run_once()  # refused again: the user already knows
    assert [(f.item_id, f.attempts) for f in seen] == [("B", 1)]
    w.local.put(at(b, 1, password="fake-new"))
    await w.engine.run_once()  # a new version refused: tell the user again
    assert [(f.item_id, f.attempts) for f in seen] == [("B", 1), ("B", 1)]


async def test_item_rejection_from_a_write_does_not_lose_the_trash_copy(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    iphone = at(a, 1, password="fake-iphone")
    linux = at(a, 2, password="fake-linux")
    w.remote.put(iphone)
    w.local.put(linux)
    w.remote.reject("A")
    report = await w.engine.run_once()
    assert report.skipped_reason is None
    assert [e.credential for e in w.engine.trash()] == [iphone]
    assert w.local.items["A"] == linux


def test_upload_failure_message_names_the_login_and_the_way_out() -> None:
    one = UploadFailure("B", "https://b.example", "alice", "duplicate", 1, T0)
    assert upload_failures_message(()) == ""
    message = upload_failures_message((one,))
    assert "alice on https://b.example" in message
    assert "duplicate" in message
    assert "Everything else is syncing" in message
    two = upload_failures_message((one, dataclasses.replace(one, item_id="C")))
    assert two.startswith("iCloud did not accept 2 passwords")


async def test_a_refused_restore_of_a_held_deletion_is_kept_and_retried(w: World) -> None:
    items = [make_credential(f"I{i}") for i in range(6)]
    await synced(w, *items)
    for c in items:
        w.remote.remove(c.id)
    assert (await w.engine.run_once()).paused is not None
    w.remote.reject("I0")
    report = await w.engine.resolve_pause(apply=False)
    assert report.created_remote == 5
    assert [f.item_id for f in report.upload_failures] == ["I0"]
    w.restart()
    report = await w.engine.run_once()
    # The user chose to keep it: a refused upload must not turn into a local deletion.
    assert report.deleted_local == 0
    assert "I0" in w.local.items
    assert w.engine.trash() == []
    w.remote.accept("I0")
    w.clock.advance(seconds=SyncPolicy().rejected_retry.total_seconds())
    report = await w.engine.run_once()
    assert report.created_remote == 1
    assert w.converged()


async def test_item_rejected_is_not_an_outage(w: World) -> None:
    w.local.put(make_credential("A"))
    w.remote.fail_next("upsert", ItemRejected("bad url"))
    report = await w.engine.run_once()
    assert report.skipped_reason is None
    assert not isinstance(ItemRejected("x"), RemoteUnavailable)


# ---------------------------------------------------------------- S20 restart


async def test_s20_restart_creates_no_duplicates(w: World) -> None:
    w.remote.put(make_credential("A"))
    w.local.put(make_credential("B"))
    await w.engine.run_once()
    w.restart()
    report = await w.engine.run_once()
    assert dataclasses.astuple(report)[2:10] == (0,) * 8
    assert len(w.remote.items) == 2
    assert len(w.local.items) == 2


async def test_s20_lost_state_relinks_by_id(w: World, tmp_path: Path) -> None:
    w.remote.put(make_credential("A"))
    w.local.put(make_credential("B"))
    await w.engine.run_once()
    w.state.close()
    w.path = tmp_path / "fresh.db"
    w.state = StateStore(w.path, KEY)
    w.engine = w.make_engine()
    report = await w.engine.run_once()
    assert report.linked == 2
    assert (report.created_local, report.created_remote) == (0, 0)
    assert len(w.remote.items) == 2


async def test_s20_crash_between_write_and_base_is_harmless(w: World) -> None:
    w.local.put(make_credential("A"))
    w.remote.put(make_credential("A"))  # as if the upload landed but the base did not
    report = await w.engine.run_once()
    assert report.linked == 1
    assert len(w.remote.items) == 1


# ---------------------------------------------------------------- S24 first sync


async def test_s24_first_sync_links_existing_seahorse_items(w: World) -> None:
    w.remote.put(
        make_credential(
            "ICLOUD-1",
            url="https://www.example.com/login",
            username="me",
            password="fake-x",
            title="Example",
        )
    )
    w.local.put(
        make_credential("SEAHORSE-1", url="https://example.com", username="me", password="fake-x")
    )
    w.local.put(make_credential("SEAHORSE-2", url="https://only-local.example", username="me"))
    report = await w.engine.run_once()
    assert report.linked == 1
    assert report.created_remote == 1
    assert set(w.local.items) == {"ICLOUD-1", "SEAHORSE-2"}
    assert w.local.items["ICLOUD-1"].title == "Example"
    assert len(w.remote.items) == 2
    assert w.converged()
    assert [(e.credential.id, e.reason) for e in w.engine.trash()] == [("SEAHORSE-1", "conflict")]


async def test_s24_identical_items_link_without_trash(w: World) -> None:
    fields = {"url": "https://example.com", "username": "me", "password": "fake-x"}
    w.remote.put(make_credential("R", **fields))
    w.local.put(make_credential("L", **fields))
    report = await w.engine.run_once()
    assert report.linked == 1
    assert w.engine.trash() == []
    assert set(w.local.items) == {"R"}


async def test_same_id_different_content_without_base_keeps_both(w: World) -> None:
    w.remote.put(make_credential("X", password="fake-remote"))
    w.local.put(make_credential("X", password="fake-local"))
    await w.engine.run_once()
    assert w.converged()
    passwords = sorted(c.password for c in w.local.items.values())
    assert passwords == ["fake-local", "fake-remote"]
    assert w.local.items["X"].password == "fake-remote"
    assert (await w.engine.run_once()).created_remote == 0


async def test_s24_link_interrupted_before_removing_the_old_item_finishes_next_cycle(
    w: World,
) -> None:
    fields = {"url": "https://example.com", "username": "me", "password": "fake-x"}
    w.remote.put(make_credential("R", **fields))
    w.local.put(make_credential("L", **fields))
    w.local.fail_next("delete", LocalUnavailable("locked mid-link"))
    report = await w.engine.run_once()
    assert report.skipped_reason == SKIP_LOCAL
    assert set(w.local.items) == {"R", "L"}
    report = await w.engine.run_once()
    assert report.linked == 1
    assert report.created_remote == 0
    assert set(w.local.items) == {"R"}
    assert set(w.remote.items) == {"R"}


# ---------------------------------------------------------------- races and durability


async def test_unanswered_pause_survives_partial_return_of_items(w: World) -> None:
    pending = await paused_world(w)
    for item_id in pending.local_ids[:5]:
        w.remote.put(make_credential(item_id))
    report = await w.engine.run_once()
    assert report.deleted_local == 0
    assert report.paused == PendingDeletions(pending.local_ids[5:], ())
    assert len(w.local.items) == 20


async def test_keyring_edit_during_slow_icloud_fetch_is_not_overwritten(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.remote.put(at(a, 1, password="fake-iphone"))
    linux = at(a, 2, password="fake-typed-during-fetch")
    real_fetch = w.remote.fetch

    async def slow_fetch() -> RemoteSnapshot:
        snapshot = await real_fetch()
        w.local.put(linux)  # the user saves while iCloud is still answering
        return snapshot

    w.remote.fetch = slow_fetch  # type: ignore[method-assign]
    await w.engine.run_once()
    assert w.local.items["A"] == linux
    assert w.remote.items["A"].credential.password == "fake-typed-during-fetch"
    assert [e.credential.password for e in w.engine.trash()] == ["fake-iphone"]


async def test_keyring_writes_run_before_any_icloud_write(w: World) -> None:
    for i in range(3):
        w.local.put(make_credential(f"A{i}"))
        w.remote.put(make_credential(f"B{i}"))
    w.local.calls.clear()
    local_writes_seen: list[int] = []

    async def note_progress(_: str) -> None:
        local_writes_seen.append(sum(op == "upsert" for op, _ in w.local.calls))

    w.remote.on_write = note_progress
    await w.engine.run_once()
    assert local_writes_seen == [3, 3, 3]


async def test_trash_copy_is_durable_before_the_overwrite(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    w.local.put(at(a, 1, password="fake-loser"))
    w.remote.put(at(a, 2, password="fake-winner"))
    # An unexpected failure on the overwrite rolls back its batch, never the trash copy.
    w.local.fail_next("upsert", RuntimeError("daemon killed"))
    with pytest.raises(RuntimeError):
        await w.engine.run_once()
    w.restart()
    assert [e.credential.password for e in w.engine.trash()] == ["fake-loser"]


async def test_interrupted_link_keeps_the_keyring_version_in_trash(w: World) -> None:
    fields = {"url": "https://example.com", "username": "me", "password": "fake-x"}
    w.remote.put(make_credential("R", **fields, notes="from iPhone"))
    w.local.put(make_credential("L", **fields, notes="only on Linux"))
    w.local.fail_next("upsert", RuntimeError("daemon killed"))
    with pytest.raises(RuntimeError):
        await w.engine.run_once()
    w.restart()
    assert [e.credential.notes for e in w.engine.trash()] == ["only on Linux"]


async def test_edit_during_fork_upload_survives(w: World) -> None:
    w.remote.put(make_credential("X", password="fake-remote"))
    w.local.put(make_credential("X", password="fake-local"))

    async def user_edits_original(_: str) -> None:
        w.remote.on_write = None
        w.local.put(make_credential("X", password="fake-typed-meanwhile", modified=600))

    w.remote.on_write = user_edits_original
    await w.engine.run_once()
    await w.engine.run_once()
    assert w.local.items["X"].password == "fake-typed-meanwhile"
    assert w.remote.items["X"].credential.password == "fake-typed-meanwhile"
    assert w.converged()


async def test_trash_copies_survive_a_failure_on_a_later_item(w: World) -> None:
    # All copies are committed up front, so a crash on any write cannot lose any of them.
    items = [make_credential(f"I{i}") for i in range(4)]
    await synced(w, *items)
    for c in items:
        w.local.put(at(c, 1, password=f"fake-loser-{c.id}"))
        w.remote.put(at(c, 2, password=f"fake-winner-{c.id}"))
    w.local.fail_next("upsert", RuntimeError("daemon killed"))
    with pytest.raises(RuntimeError):
        await w.engine.run_once()
    w.restart()
    assert sorted(e.credential.password for e in w.engine.trash()) == [
        f"fake-loser-I{i}" for i in range(4)
    ]
    await w.engine.run_once()
    assert len(w.engine.trash()) == 4
    assert w.converged()


async def test_rejected_keyring_item_never_causes_an_icloud_delete(w: World) -> None:
    a = make_credential("A")
    await synced(w, a)
    # Seahorse mangled A's attributes: the adapter cannot parse it and reports it rejected.
    w.local.remove("A")
    w.local.rejected.append(RejectedLocalItem("/item/A", "A", "unparsable label"))
    report = await w.engine.run_once()
    assert report.deleted_remote == 0
    assert "A" in w.remote.items
    assert "A" in w.state.bases()
