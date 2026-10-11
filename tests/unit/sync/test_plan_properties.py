# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Planner invariants over random three-way worlds (hypothesis)."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.fakes.memory_stores import make_credential

from passwords_app.sync.plan import (
    BaseEntry,
    CreateLocal,
    CreateRemote,
    DeleteLocal,
    DeleteRemote,
    ForkLocal,
    Link,
    Trash,
    UpdateLocal,
    UpdateRemote,
    content_key,
    plan,
)
from passwords_app.sync.ports import LocalSnapshot, RemoteItem, RemoteSnapshot, SyncPolicy

if TYPE_CHECKING:
    from passwords_app.core.model import Credential

# Version 0 is the synced base; 1-3 are later edits. None means "absent on that side".
version = st.one_of(st.none(), st.integers(0, 3))
cell = st.tuples(st.booleans(), version, version, st.integers(0, 3), st.integers(0, 3))
worlds = st.dictionaries(st.sampled_from([f"ID{i:02d}" for i in range(24)]), cell, max_size=24)

POLICY = SyncPolicy()

type World = dict[str, tuple[bool, int | None, int | None, int, int]]
NO_GUARD = SyncPolicy(mass_delete_min=10**9)


def cred(item_id: str, v: int, minute: int) -> Credential:
    return make_credential(item_id, password=f"fake-v{v}", modified=60 * minute + v)


def build(
    world: World,
) -> tuple[dict[str, BaseEntry], RemoteSnapshot, LocalSnapshot]:
    base: dict[str, BaseEntry] = {}
    remote: dict[str, RemoteItem] = {}
    local: dict[str, Credential] = {}
    for item_id, (has_base, r, loc, rt, lt) in world.items():
        if has_base:
            base[item_id] = BaseEntry(cred(item_id, 0, 0), "e0")
        if r is not None:
            remote[item_id] = RemoteItem(cred(item_id, r, rt), f"e{r}")
        if loc is not None:
            local[item_id] = cred(item_id, loc, lt)
    return base, RemoteSnapshot(remote), LocalSnapshot(local)


def changed(c: Credential | None, b: BaseEntry | None) -> bool:
    return c is not None and (b is None or content_key(c) != content_key(b.credential))


@given(worlds)
def test_plan_is_deterministic(world: World) -> None:
    base, remote, local = build(world)
    assert plan(base, remote, local, POLICY) == plan(base, remote, local, POLICY)


@given(worlds)
def test_a_changed_version_is_never_destroyed_without_a_trash_copy(
    world: World,
) -> None:
    base, remote, local = build(world)
    result = plan(base, remote, local, NO_GUARD)
    trashed = {content_key(a.credential) for a in result.actions if isinstance(a, Trash)}
    forked = {content_key(a.credential) for a in result.actions if isinstance(a, ForkLocal)}
    for a in result.actions:
        b = base.get(a.item_id)
        if isinstance(a, (UpdateLocal, DeleteLocal)):
            old = local.items.get(a.item_id)
            new_key = content_key(a.credential) if isinstance(a, UpdateLocal) else None
            if changed(old, b) and old is not None and content_key(old) != new_key:
                assert content_key(old) in trashed | forked or _copy_exists(old, local)
        if isinstance(a, (UpdateRemote, DeleteRemote)):
            item = remote.items.get(a.item_id)
            old_r = item.credential if item else None
            new_key = content_key(a.credential) if isinstance(a, UpdateRemote) else None
            if changed(old_r, b) and old_r is not None and content_key(old_r) != new_key:
                assert content_key(old_r) in trashed


def _copy_exists(c: Credential, local: LocalSnapshot) -> bool:
    return any(
        other.id != c.id and content_key(other) == content_key(c) for other in local.items.values()
    )


@given(worlds)
def test_deletions_only_follow_an_unchanged_base(
    world: World,
) -> None:
    base, remote, local = build(world)
    for a in plan(base, remote, local, NO_GUARD).actions:
        if isinstance(a, DeleteLocal):
            b = base[a.item_id]
            assert a.item_id not in remote.items
            assert content_key(local.items[a.item_id]) == content_key(b.credential)
        if isinstance(a, DeleteRemote):
            b = base[a.item_id]
            assert a.item_id not in local.items
            assert content_key(remote.items[a.item_id].credential) == content_key(b.credential)
            assert a.etag == remote.items[a.item_id].etag


@given(worlds)
def test_trash_precedes_the_write_it_protects(
    world: World,
) -> None:
    base, remote, local = build(world)
    seen_write: set[str] = set()
    for a in plan(base, remote, local, NO_GUARD).actions:
        if isinstance(a, Trash):
            assert a.item_id not in seen_write
        elif isinstance(a, (UpdateLocal, UpdateRemote, DeleteLocal, DeleteRemote, Link)):
            seen_write.add(a.item_id)


@given(worlds)
def test_remote_writes_are_conditional_on_the_fetched_etag(
    world: World,
) -> None:
    base, remote, local = build(world)
    for a in plan(base, remote, local, NO_GUARD).actions:
        if isinstance(a, UpdateRemote):
            assert a.etag == remote.items[a.item_id].etag
        if isinstance(a, CreateRemote):
            assert a.item_id not in remote.items


@given(worlds)
def test_every_item_on_either_side_gets_at_most_one_write_per_store(
    world: World,
) -> None:
    base, remote, local = build(world)
    local_writes: dict[str, int] = {}
    remote_writes: dict[str, int] = {}
    for a in plan(base, remote, local, NO_GUARD).actions:
        if isinstance(a, (CreateLocal, UpdateLocal, DeleteLocal, ForkLocal)):
            local_writes[a.item_id] = local_writes.get(a.item_id, 0) + 1
        if isinstance(a, (CreateRemote, UpdateRemote, DeleteRemote)):
            remote_writes[a.item_id] = remote_writes.get(a.item_id, 0) + 1
    assert all(n == 1 for n in local_writes.values())
    assert all(n == 1 for n in remote_writes.values())


@given(worlds)
def test_guard_never_lets_a_held_deletion_through(
    world: World,
) -> None:
    policy = SyncPolicy(mass_delete_min=1, mass_delete_ratio=0.0)
    base, remote, local = build(world)
    result = plan(base, remote, local, policy)
    deletions = [a for a in result.actions if isinstance(a, (DeleteLocal, DeleteRemote))]
    if result.pending is not None:
        assert deletions == []
        held = len(result.pending.local_ids) + len(result.pending.remote_ids)
        assert held > 1
    else:
        assert len([a for a in deletions if isinstance(a, DeleteLocal)]) <= 1
        assert len([a for a in deletions if isinstance(a, DeleteRemote)]) <= 1


@given(worlds)
def test_unguarded_and_guarded_plans_agree_on_everything_but_deletions(
    world: World,
) -> None:
    base, remote, local = build(world)
    free = plan(base, remote, local, NO_GUARD)
    guarded = plan(base, remote, local, SyncPolicy(mass_delete_min=0, mass_delete_ratio=0.0))
    held = (
        set()
        if guarded.pending is None
        else {
            *guarded.pending.local_ids,
            *guarded.pending.remote_ids,
        }
    )
    assert [a for a in free.actions if a.item_id not in held] == list(guarded.actions)


@settings(max_examples=50)
@given(worlds)
def test_content_key_equality_matches_content_hash_equality(
    world: World,
) -> None:
    _, remote, local = build(world)
    creds = [i.credential for i in remote.items.values()] + list(local.items.values())
    for a in creds:
        for b in creds:
            assert (content_key(a) == content_key(b)) == (a.content_hash() == b.content_hash())


text = st.text(max_size=8)
credentials = st.builds(
    lambda u, n, p, t, no, o, alt, g: make_credential(
        "X", username=n, url=u, password=p, title=t, notes=no, otpauth=o, alt_urls=alt, group=g
    ),
    st.sampled_from(["https://a.example", "https://b.example"]),
    text,
    text,
    st.none() | text,
    st.none() | text,
    st.none() | text,
    st.lists(text, max_size=2).map(tuple),
    st.none() | text,
)


@given(credentials, credentials)
def test_content_key_agrees_with_content_hash_for_arbitrary_fields(
    a: Credential, b: Credential
) -> None:
    assert (content_key(a) == content_key(b)) == (a.content_hash() == b.content_hash())


@given(credentials)
def test_content_key_ignores_id_and_timestamps(a: Credential) -> None:
    moved = dataclasses.replace(a, id="OTHER", modified=a.modified.replace(year=2030))
    assert content_key(moved) == content_key(a)


@given(worlds)
def test_an_items_icloud_write_is_its_last_action(world: World) -> None:
    # The engine relies on this: a lost etag race abandons the item with nothing left over.
    base, remote, local = build(world)
    actions = plan(base, remote, local, NO_GUARD).actions
    for n, a in enumerate(actions):
        if isinstance(a, (CreateRemote, UpdateRemote, DeleteRemote)):
            assert all(later.item_id != a.item_id for later in actions[n + 1 :])


@given(worlds)
def test_every_keyring_write_precedes_every_icloud_write(world: World) -> None:
    # The engine relies on this: keyring writes are unconditional, so they must not wait
    # behind network round trips while the user keeps editing.
    base, remote, local = build(world)
    kinds = [
        "local"
        if isinstance(a, (CreateLocal, UpdateLocal, DeleteLocal, ForkLocal, Link))
        else "remote"
        if isinstance(a, (CreateRemote, UpdateRemote, DeleteRemote))
        else "state"
        for a in plan(base, remote, local, NO_GUARD).actions
    ]
    writes = [k for k in kinds if k != "state"]
    assert writes == sorted(writes)


@given(worlds)
def test_trash_of_a_linked_keyring_item_precedes_the_link(world: World) -> None:
    base, remote, local = build(world)
    actions = plan(base, remote, local, NO_GUARD).actions
    for n, a in enumerate(actions):
        if isinstance(a, Link) and a.local_id != a.item_id:
            trashed = [t for t in actions if isinstance(t, Trash) and t.item_id == a.local_id]
            assert all(actions.index(t) < n for t in trashed)
