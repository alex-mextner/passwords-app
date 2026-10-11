# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Records iCloud now reads as part of another login (`RemoteSnapshot.merged`).

Apple keeps a login used on several websites as one record per website; once those records
read as one login, the ids of the absorbed records leave the snapshot. That is not a deletion:
the keyring copy goes away without a mass-delete pause and, when the merged login still holds
everything it had, without a trash entry.
"""

from __future__ import annotations

import dataclasses

from tests.fakes.memory_stores import make_credential

from passwords_app.sync.plan import BaseEntry, DeleteLocal, DropBase, Trash, UpdateLocal, plan
from passwords_app.sync.ports import LocalSnapshot, RemoteItem, RemoteSnapshot, SyncPolicy

POLICY = SyncPolicy()


def _sites(n: int) -> list[str]:
    return [f"https://site{i}.example.com" for i in range(n)]


def _world(n: int) -> tuple[dict[str, BaseEntry], RemoteSnapshot, LocalSnapshot, list[str]]:
    """`n` synced records of one login, one per site; iCloud now reads them as one login."""
    sites = _sites(n)
    ids = [f"R{i:03d}" for i in range(n)]
    records = [
        make_credential(i, url=url, username="kim", password="same")
        for i, url in zip(ids, sites, strict=True)
    ]
    merged_login = dataclasses.replace(records[0], alt_urls=tuple(sites[1:]))
    base = {c.id: BaseEntry(c, "e") for c in records}
    remote = RemoteSnapshot(
        {ids[0]: RemoteItem(merged_login, "e2")}, merged=dict.fromkeys(ids[1:], ids[0])
    )
    local = LocalSnapshot({c.id: c for c in records})
    return base, remote, local, ids


def test_absorbed_records_leave_the_keyring_without_pause_or_trash() -> None:
    base, remote, local, ids = _world(40)
    p = plan(base, remote, local, POLICY)
    assert p.pending is None
    deleted = {a.item_id for a in p.actions if isinstance(a, DeleteLocal)}
    assert deleted == set(ids[1:])
    assert not [a for a in p.actions if isinstance(a, Trash)]
    updated = [a for a in p.actions if isinstance(a, UpdateLocal)]
    assert [a.credential.alt_urls for a in updated] == [tuple(_sites(40)[1:])]


def test_a_local_edit_of_an_absorbed_record_is_kept_in_trash() -> None:
    base, remote, local, ids = _world(2)
    edited = dataclasses.replace(local.items[ids[1]], notes="only here")
    local = LocalSnapshot({**local.items, ids[1]: edited})
    p = plan(base, remote, local, POLICY)
    assert [a for a in p.actions if isinstance(a, Trash)] == [Trash(edited, "conflict")]
    assert DeleteLocal(ids[1]) in p.actions


def test_an_absorbed_record_gone_from_the_keyring_only_drops_its_base() -> None:
    base, remote, local, ids = _world(2)
    local = LocalSnapshot({ids[0]: local.items[ids[0]]})
    p = plan(base, remote, local, POLICY)
    assert DropBase(ids[1]) in p.actions
    assert not [a for a in p.actions if isinstance(a, Trash | DeleteLocal)]


def test_an_unsynced_keyring_copy_of_an_absorbed_record_is_removed() -> None:
    """A keyring that outlived its sync state (a reinstall) holds the record without a base."""
    base, remote, local, ids = _world(2)
    base = {ids[0]: base[ids[0]]}
    p = plan(base, remote, local, POLICY)
    assert DeleteLocal(ids[1]) in p.actions
    assert not [a for a in p.actions if isinstance(a, Trash)]


def test_an_unedited_copy_leaves_without_trash_after_iphone_changes() -> None:
    """The records changed on the iPhone as they joined; the keyring copy holds no edit."""
    base, remote, local, ids = _world(2)
    login = remote.items[ids[0]].credential
    remote = RemoteSnapshot(
        {ids[0]: RemoteItem(dataclasses.replace(login, password="new"), "e3")},
        merged=remote.merged,
    )
    p = plan(base, remote, local, POLICY)
    assert DeleteLocal(ids[1]) in p.actions
    assert not [a for a in p.actions if isinstance(a, Trash) and a.item_id == ids[1]]


def test_a_restored_version_of_an_absorbed_record_is_kept_in_trash() -> None:
    """The user restored this record's older version; the login it joined does not hold it."""
    base, remote, local, ids = _world(2)
    login = remote.items[ids[0]].credential
    remote = RemoteSnapshot(
        {ids[0]: RemoteItem(dataclasses.replace(login, password="new"), "e3")},
        merged=remote.merged,
    )
    p = plan(base, remote, local, POLICY, restored=frozenset({ids[1]}))
    assert Trash(local.items[ids[1]], "conflict") in p.actions
