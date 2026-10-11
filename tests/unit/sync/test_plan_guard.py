# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Mass-delete guard (`max(5, 10%)` per side) and the user's answer to a pause."""

from __future__ import annotations

import pytest
from tests.fakes.memory_stores import make_credential

from passwords_app.sync.plan import (
    BaseEntry,
    CreateLocal,
    CreateRemote,
    DeleteLocal,
    DeleteRemote,
    PauseDecision,
    SyncPlan,
    Trash,
    UpdateLocal,
    plan,
)
from passwords_app.sync.ports import (
    LocalSnapshot,
    PendingDeletions,
    RemoteItem,
    RemoteSnapshot,
    SyncPolicy,
)

POLICY = SyncPolicy()


def ids(n: int, prefix: str = "I") -> list[str]:
    return [f"{prefix}{i:05d}" for i in range(n)]


def world(
    total: int, *, deleted_remote: int = 0, deleted_local: int = 0
) -> tuple[dict[str, BaseEntry], RemoteSnapshot, LocalSnapshot]:
    """`total` synced items; the first `deleted_remote` vanish from iCloud, the next
    `deleted_local` from the keyring."""
    creds = {i: make_credential(i) for i in ids(total)}
    order = sorted(creds)
    gone_remote = set(order[:deleted_remote])
    gone_local = set(order[deleted_remote : deleted_remote + deleted_local])
    base = {i: BaseEntry(c, "e") for i, c in creds.items()}
    remote = RemoteSnapshot(
        {i: RemoteItem(c, "e") for i, c in creds.items() if i not in gone_remote}
    )
    local = LocalSnapshot({i: c for i, c in creds.items() if i not in gone_local})
    return base, remote, local


def deletes(p: SyncPlan) -> tuple[int, int]:
    return (
        sum(isinstance(a, DeleteLocal) for a in p.actions),
        sum(isinstance(a, DeleteRemote) for a in p.actions),
    )


# (items on the side, deletions, paused?) — threshold is max(5, 10% of that side's items)
THRESHOLD_TABLE = [
    (5, 5, False),
    (6, 5, False),
    (6, 6, True),
    (10, 5, False),
    (10, 6, True),
    (49, 5, False),
    (49, 6, True),
    (50, 5, False),
    (50, 6, True),
    (51, 5, False),
    (51, 6, True),
    (60, 6, False),
    (60, 7, True),
    (100, 10, False),
    (100, 11, True),
    (101, 10, False),
    (101, 11, True),
    (250, 25, False),
    (250, 26, True),
    (1000, 100, False),
    (1000, 101, True),
    (2000, 200, False),
    (2000, 201, True),
]


@pytest.mark.parametrize(("items", "count", "paused"), THRESHOLD_TABLE)
def test_icloud_side_deletions_threshold(items: int, count: int, paused: bool) -> None:
    # Items deleted in iCloud become local deletions; the guard counts the keyring's size.
    base, remote, local = world(items, deleted_remote=count)
    result = plan(base, remote, local, POLICY)
    if paused:
        assert deletes(result) == (0, 0)
        assert result.pending is not None
        assert len(result.pending.local_ids) == count
        assert result.pending.remote_ids == ()
        assert not any(isinstance(a, Trash) for a in result.actions)
    else:
        assert deletes(result) == (count, 0)
        assert result.pending is None


@pytest.mark.parametrize(("items", "count", "paused"), THRESHOLD_TABLE)
def test_keyring_side_deletions_threshold(items: int, count: int, paused: bool) -> None:
    base, remote, local = world(items, deleted_local=count)
    result = plan(base, remote, local, POLICY)
    if paused:
        assert deletes(result) == (0, 0)
        assert result.pending == PendingDeletions((), tuple(sorted(ids(items))[:count]))
    else:
        assert deletes(result) == (0, count)
        assert result.pending is None


def test_empty_icloud_snapshot_never_wipes_the_keyring() -> None:
    # The classic disaster: a fetch that returned nothing would read as "everything deleted".
    base, _, local = world(300)
    result = plan(base, RemoteSnapshot({}), local, POLICY)
    assert deletes(result) == (0, 0)
    assert result.pending is not None
    assert len(result.pending.local_ids) == 300


def test_empty_keyring_snapshot_never_wipes_icloud() -> None:
    base, remote, _ = world(300)
    result = plan(base, remote, LocalSnapshot({}), POLICY)
    assert deletes(result) == (0, 0)
    assert result.pending is not None
    assert len(result.pending.remote_ids) == 300


def test_one_side_over_threshold_holds_the_other_sides_deletions_too() -> None:
    base, remote, local = world(100, deleted_remote=20, deleted_local=3)
    result = plan(base, remote, local, POLICY)
    assert deletes(result) == (0, 0)
    assert result.pending is not None
    assert (len(result.pending.local_ids), len(result.pending.remote_ids)) == (20, 3)


def test_both_sides_under_threshold_delete_normally() -> None:
    # Each side's threshold uses that side's current size: 91 items -> up to 9 deletions.
    base, remote, local = world(100, deleted_remote=9, deleted_local=9)
    result = plan(base, remote, local, POLICY)
    assert deletes(result) == (9, 9)
    assert result.pending is None


def test_pause_still_applies_non_delete_work() -> None:
    base, remote, local = world(20, deleted_remote=10)
    new = make_credential("NEW-REMOTE")
    remote = RemoteSnapshot({**remote.items, "NEW-REMOTE": RemoteItem(new, "n")})
    result = plan(base, remote, local, POLICY)
    assert result.pending is not None
    assert result.actions == (CreateLocal(new, "n"),)


def test_both_sides_deleted_is_not_counted_by_the_guard() -> None:
    # Nothing is deleted from any store when both sides already agree it is gone.
    base, _, _ = world(10)
    result = plan(base, RemoteSnapshot({}), LocalSnapshot({}), POLICY)
    assert result.pending is None
    assert sum(isinstance(a, Trash) for a in result.actions) == 10


@pytest.mark.parametrize(
    ("minimum", "ratio", "items", "count", "paused"),
    [
        (0, 0.0, 10, 1, True),
        (0, 0.5, 10, 5, False),
        (0, 0.5, 10, 6, True),
        (20, 0.0, 100, 20, False),
        (20, 0.0, 100, 21, True),
        (1_000_000, 0.1, 100, 100, False),
    ],
)
def test_policy_controls_the_threshold(
    minimum: int, ratio: float, items: int, count: int, paused: bool
) -> None:
    policy = SyncPolicy(mass_delete_min=minimum, mass_delete_ratio=ratio)
    base, remote, local = world(items, deleted_remote=count)
    assert (plan(base, remote, local, policy).pending is not None) is paused


def test_approved_deletions_go_through_with_their_trash() -> None:
    base, remote, local = world(20, deleted_remote=10)
    pending = plan(base, remote, local, POLICY).pending
    assert pending is not None
    result = plan(base, remote, local, POLICY, decision=PauseDecision(pending, apply=True))
    assert result.pending is None
    assert deletes(result) == (10, 0)
    assert sum(isinstance(a, Trash) for a in result.actions) == 10


def test_approval_covers_only_the_deletions_the_user_saw() -> None:
    base, remote, local = world(100, deleted_remote=20)
    pending = plan(base, remote, local, POLICY).pending
    assert pending is not None
    # Meanwhile 11 more items vanished from the keyring: still over the guard on their own.
    _, _, local2 = world(100, deleted_remote=20, deleted_local=11)
    result = plan(base, remote, local2, POLICY, decision=PauseDecision(pending, apply=True))
    assert deletes(result) == (20, 0)
    assert result.pending is not None
    assert result.pending.local_ids == ()
    assert len(result.pending.remote_ids) == 11


def test_restore_recreates_items_on_the_side_that_lost_them() -> None:
    base, remote, local = world(30, deleted_remote=8, deleted_local=8)
    pending = plan(base, remote, local, POLICY).pending
    assert pending is not None
    result = plan(base, remote, local, POLICY, decision=PauseDecision(pending, apply=False))
    assert result.pending is None
    assert deletes(result) == (0, 0)
    recreated_remote = {a.item_id for a in result.actions if isinstance(a, CreateRemote)}
    recreated_local = {a.item_id for a in result.actions if isinstance(a, CreateLocal)}
    assert recreated_remote == set(pending.local_ids)
    assert recreated_local == set(pending.remote_ids)
    assert not any(isinstance(a, Trash) for a in result.actions)


def test_restore_does_not_touch_deletions_that_appeared_after_the_pause() -> None:
    base, remote, local = world(100, deleted_remote=20)
    pending = plan(base, remote, local, POLICY).pending
    assert pending is not None
    _, _, local2 = world(100, deleted_remote=20, deleted_local=2)
    result = plan(base, remote, local2, POLICY, decision=PauseDecision(pending, apply=False))
    assert deletes(result) == (0, 2)
    assert result.pending is None


def test_restore_of_an_item_edited_meanwhile_keeps_the_edit() -> None:
    base, remote, local = world(20, deleted_remote=10)
    pending = plan(base, remote, local, POLICY).pending
    assert pending is not None
    edited_id = pending.local_ids[0]
    edited = make_credential(edited_id, password="fake-edited", modified=60)
    local2 = LocalSnapshot({**local.items, edited_id: edited})
    result = plan(base, remote, local2, POLICY, decision=PauseDecision(pending, apply=False))
    assert CreateRemote(edited) in result.actions


def test_pending_lists_are_sorted_for_stable_storage() -> None:
    base, remote, local = world(40, deleted_remote=10, deleted_local=10)
    pending = plan(base, remote, local, POLICY).pending
    assert pending is not None
    assert list(pending.local_ids) == sorted(pending.local_ids)
    assert list(pending.remote_ids) == sorted(pending.remote_ids)


def test_edits_alongside_a_pause_still_flow() -> None:
    base, remote, local = world(20, deleted_remote=10)
    keep = max(local.items)
    changed = make_credential(keep, password="fake-changed", modified=5)
    remote = RemoteSnapshot({**remote.items, keep: RemoteItem(changed, "x")})
    result = plan(base, remote, local, POLICY)
    assert UpdateLocal(changed, "x") in result.actions


def test_unanswered_pause_keeps_holding_even_below_the_threshold() -> None:
    # Half of the vanished items came back: the rest is now under the guard, but the user
    # never answered, so nothing may be deleted.
    base, remote, local = world(20, deleted_remote=10)
    pending = plan(base, remote, local, POLICY).pending
    assert pending is not None
    returned = pending.local_ids[:5]
    remote2 = RemoteSnapshot(
        {**remote.items, **{i: RemoteItem(base[i].credential, "e") for i in returned}}
    )
    result = plan(base, remote2, local, POLICY, held=pending)
    assert deletes(result) == (0, 0)
    assert result.pending == PendingDeletions(pending.local_ids[5:], ())


def test_held_pause_does_not_block_unrelated_new_deletions() -> None:
    base, remote, local = world(20, deleted_remote=10)
    pending = plan(base, remote, local, POLICY).pending
    assert pending is not None
    back = {i: RemoteItem(base[i].credential, "e") for i in pending.local_ids[:5]}
    remote2 = RemoteSnapshot({**remote.items, **back})
    kept = max(remote2.items)
    local2 = LocalSnapshot({i: c for i, c in local.items.items() if i != kept})
    result = plan(base, remote2, local2, POLICY, held=pending)
    assert deletes(result) == (0, 1)
    assert result.pending == PendingDeletions(pending.local_ids[5:], ())


def test_held_pause_dissolves_once_every_item_is_back() -> None:
    base, remote, local = world(20, deleted_remote=10)
    pending = plan(base, remote, local, POLICY).pending
    assert pending is not None
    full = RemoteSnapshot({i: RemoteItem(b.credential, "e") for i, b in base.items()})
    result = plan(base, full, local, POLICY, held=pending)
    assert result.pending is None
    assert result.actions == ()
