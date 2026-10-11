# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Spec §5 table, cell by cell and field by field."""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from tests.fakes.memory_stores import make_credential

from passwords_app.sync.plan import (
    BaseEntry,
    CreateLocal,
    CreateRemote,
    DeleteLocal,
    DeleteRemote,
    DropBase,
    Link,
    MergeLocal,
    SetBase,
    Trash,
    UpdateLocal,
    UpdateRemote,
    plan,
)
from passwords_app.sync.ports import LocalSnapshot, RemoteItem, RemoteSnapshot, SyncPolicy

if TYPE_CHECKING:
    from passwords_app.core.model import Credential
    from passwords_app.sync.plan import SyncPlan

POLICY = SyncPolicy()

# Two distinct non-default values per content field, so "both sides changed the same field
# differently" is expressible for every field.
FIELD_VALUES: dict[str, tuple[Any, Any]] = {
    "url": ("https://login.example.org", "https://accounts.example.net"),
    "username": ("alice@example.org", "bob@example.org"),
    "password": ("fake-value-alpha", "fake-value-beta"),
    "title": ("Work mail", "Personal mail"),
    "notes": ("first note", "second note"),
    "otpauth": ("otpauth://totp/A?issuer=A", "otpauth://totp/B?issuer=B"),
    "alt_urls": (("https://a.example.org",), ("https://b.example.org", "https://c.example.org")),
    "group": ("GROUP-FAMILY", "GROUP-WORK"),
}
FIELDS = sorted(FIELD_VALUES)

BASE = make_credential("ITEM", modified=0)


def edit(c: Credential, *, modified: int, **changes: Any) -> Credential:
    return dataclasses.replace(
        c, modified=make_credential(c.id, modified=modified).modified, **changes
    )


def run(
    base: Credential | None,
    remote: Credential | None,
    local: Credential | None,
    *,
    base_etag: str = "e1",
    remote_etag: str = "e1",
) -> SyncPlan:
    bases = {} if base is None else {base.id: BaseEntry(base, base_etag)}
    remote_items = {} if remote is None else {remote.id: RemoteItem(remote, remote_etag)}
    local_items = {} if local is None else {local.id: local}
    return plan(bases, RemoteSnapshot(remote_items), LocalSnapshot(local_items), POLICY)


# ---------------------------------------------------------------- based cells


def test_unchanged_everywhere_is_a_no_op() -> None:
    result = run(BASE, BASE, BASE)
    assert result.actions == ()
    assert result.pending is None


def test_unchanged_but_remote_etag_moved_refreshes_base_only() -> None:
    result = run(BASE, BASE, BASE, remote_etag="e2")
    assert result.actions == (SetBase(BASE, "e2"),)


@pytest.mark.parametrize("side", ["remote", "local", "both"])
def test_timestamp_only_change_is_not_a_change(side: str) -> None:
    touched = edit(BASE, modified=500)
    remote = touched if side in {"remote", "both"} else BASE
    local = touched if side in {"local", "both"} else BASE
    assert run(BASE, remote, local).actions == ()


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value", [0, 1])
def test_remote_field_change_updates_local(field: str, value: int) -> None:
    remote = edit(BASE, modified=10, **{field: FIELD_VALUES[field][value]})
    result = run(BASE, remote, BASE, remote_etag="e2")
    assert result.actions == (UpdateLocal(remote, "e2"),)


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value", [0, 1])
def test_local_field_change_updates_remote_conditionally(field: str, value: int) -> None:
    local = edit(BASE, modified=10, **{field: FIELD_VALUES[field][value]})
    result = run(BASE, BASE, local, remote_etag="e7")
    assert result.actions == (UpdateRemote(local, "e7"),)


@pytest.mark.parametrize("field", FIELDS)
def test_local_change_with_older_modified_still_propagates(field: str) -> None:
    # Clocks on different machines disagree; with only one side changed, timestamps are
    # irrelevant and the edit must win.
    base = edit(BASE, modified=1000)
    local = edit(base, modified=5, **{field: FIELD_VALUES[field][0]})
    result = run(base, base, local)
    assert result.actions == (UpdateRemote(local, "e1"),)


@pytest.mark.parametrize("field", FIELDS)
def test_field_cleared_to_default_counts_as_change(field: str) -> None:
    filled = edit(BASE, modified=1, **{field: FIELD_VALUES[field][0]})
    default = make_credential("ITEM", modified=2)
    if field in {"url", "username", "password"}:
        # Required fields have no "cleared" state in this table; the default IS a value.
        default = dataclasses.replace(default, **{field: getattr(BASE, field)})
    result = run(filled, filled, default)
    assert result.actions == (UpdateRemote(default, "e1"),)


@pytest.mark.parametrize("field", FIELDS)
def test_same_change_on_both_sides_only_refreshes_base(field: str) -> None:
    remote = edit(BASE, modified=10, **{field: FIELD_VALUES[field][0]})
    local = edit(BASE, modified=20, **{field: FIELD_VALUES[field][0]})
    result = run(BASE, remote, local, remote_etag="e2")
    assert result.actions == (SetBase(remote, "e2"),)


@pytest.mark.parametrize("field", FIELDS)
def test_conflict_remote_newer_wins_and_local_goes_to_trash(field: str) -> None:
    local = edit(BASE, modified=10, **{field: FIELD_VALUES[field][0]})
    remote = edit(BASE, modified=20, **{field: FIELD_VALUES[field][1]})
    result = run(BASE, remote, local, remote_etag="e2")
    assert result.actions == (Trash(local, "conflict"), UpdateLocal(remote, "e2"))


@pytest.mark.parametrize("field", FIELDS)
def test_conflict_local_newer_wins_and_remote_goes_to_trash(field: str) -> None:
    remote = edit(BASE, modified=10, **{field: FIELD_VALUES[field][0]})
    local = edit(BASE, modified=20, **{field: FIELD_VALUES[field][1]})
    result = run(BASE, remote, local, remote_etag="e2")
    assert result.actions == (Trash(remote, "conflict"), UpdateRemote(local, "e2"))


@pytest.mark.parametrize("field", FIELDS)
def test_conflict_tie_goes_to_icloud(field: str) -> None:
    remote = edit(BASE, modified=10, **{field: FIELD_VALUES[field][0]})
    local = edit(BASE, modified=10, **{field: FIELD_VALUES[field][1]})
    result = run(BASE, remote, local, remote_etag="e2")
    assert result.actions == (Trash(local, "conflict"), UpdateLocal(remote, "e2"))


@pytest.mark.parametrize("delta_ms", [1, 999, 1000, 86_400_000])
def test_conflict_winner_is_decided_by_any_positive_time_difference(delta_ms: int) -> None:
    remote = edit(BASE, modified=10, password="fake-r")
    local = dataclasses.replace(
        BASE, password="fake-l", modified=remote.modified + timedelta(milliseconds=delta_ms)
    )
    result = run(BASE, remote, local)
    assert result.actions == (Trash(remote, "conflict"), UpdateRemote(local, "e1"))


@pytest.mark.parametrize(
    ("remote_field", "local_field"), [(a, b) for a in FIELDS for b in FIELDS if a != b]
)
def test_edits_to_different_fields_are_a_whole_item_conflict(
    remote_field: str, local_field: str
) -> None:
    # Field-level merge would silently combine two versions nobody wrote; the spec keeps
    # whole versions and trashes the loser so the user can pick.
    remote = edit(BASE, modified=30, **{remote_field: FIELD_VALUES[remote_field][0]})
    local = edit(BASE, modified=20, **{local_field: FIELD_VALUES[local_field][1]})
    result = run(BASE, remote, local, remote_etag="e2")
    assert result.actions == (Trash(local, "conflict"), UpdateLocal(remote, "e2"))


def test_remote_deleted_local_unchanged_deletes_local_and_trashes_base() -> None:
    result = run(BASE, None, BASE)
    assert result.actions == (Trash(BASE, "deleted-in-icloud"), DeleteLocal(BASE.id))


def test_local_deleted_remote_unchanged_deletes_remote_with_its_etag() -> None:
    result = run(BASE, BASE, None, remote_etag="e9")
    assert result.actions == (Trash(BASE, "deleted-on-linux"), DeleteRemote(BASE.id, "e9"))


def test_deleted_on_both_sides_trashes_base_and_drops_it() -> None:
    result = run(BASE, None, None)
    assert result.actions == (Trash(BASE, "deleted-both"), DropBase(BASE.id))


@pytest.mark.parametrize("field", FIELDS)
def test_edit_beats_remote_delete(field: str) -> None:
    local = edit(BASE, modified=10, **{field: FIELD_VALUES[field][0]})
    result = run(BASE, None, local)
    assert result.actions == (CreateRemote(local),)


@pytest.mark.parametrize("field", FIELDS)
def test_edit_beats_local_delete(field: str) -> None:
    remote = edit(BASE, modified=10, **{field: FIELD_VALUES[field][0]})
    result = run(BASE, remote, None, remote_etag="e3")
    assert result.actions == (CreateLocal(remote, "e3"),)


@pytest.mark.parametrize("side", ["remote", "local"])
def test_timestamp_only_touch_does_not_beat_a_delete(side: str) -> None:
    touched = edit(BASE, modified=99)
    if side == "local":
        result = run(BASE, None, touched)
        assert result.actions == (Trash(BASE, "deleted-in-icloud"), DeleteLocal(BASE.id))
    else:
        result = run(BASE, touched, None, remote_etag="e4")
        assert result.actions == (Trash(BASE, "deleted-on-linux"), DeleteRemote(BASE.id, "e4"))


# ---------------------------------------------------------------- unbased cells


def test_nothing_anywhere_plans_nothing() -> None:
    assert run(None, None, None).actions == ()


def test_new_remote_item_is_created_locally_with_its_etag() -> None:
    remote = make_credential("NEW")
    assert run(None, remote, None, remote_etag="e5").actions == (CreateLocal(remote, "e5"),)


def test_new_local_item_is_created_remotely() -> None:
    local = make_credential("NEW")
    assert run(None, None, local).actions == (CreateRemote(local),)


def test_same_id_on_both_sides_with_equal_content_is_linked() -> None:
    remote = make_credential("SAME", modified=5)
    local = edit(remote, modified=9)
    assert run(None, remote, local, remote_etag="e6").actions == (Link("SAME", remote, "e6"),)


@pytest.mark.parametrize("field", FIELDS)
def test_same_id_with_different_content_newer_local_wins(field: str) -> None:
    # iCloud Keychain keeps one login per site and username, so a fork copy could never
    # be uploaded (#71): the newer version keeps the id, the other goes to trash.
    remote = make_credential("SAME", modified=5)
    local = edit(remote, modified=9, **{field: FIELD_VALUES[field][0]})
    result = run(None, remote, local, remote_etag="e6")
    assert result.actions == (Trash(remote, "conflict"), UpdateRemote(local, "e6"))


@pytest.mark.parametrize("local_modified", [3, 5])
def test_same_id_with_different_content_newer_or_tied_icloud_wins(local_modified: int) -> None:
    remote = make_credential("SAME", modified=5)
    local = edit(remote, modified=local_modified, password="fake-mine")
    result = run(None, remote, local, remote_etag="e6")
    assert result.actions == (Trash(local, "conflict"), UpdateLocal(remote, "e6"))


def _twin(of: Credential, item_id: str, *, modified: int, **changes: Any) -> Credential:
    """A keyring login with `of`'s site and username under another id."""
    return edit(dataclasses.replace(of, id=item_id), modified=modified, **changes)


def test_newer_keyring_duplicate_of_a_synced_login_replaces_it_in_the_keyring() -> None:
    synced = make_credential("A", modified=5)
    dup = _twin(synced, "B", modified=9, password="fake-newer")
    result = plan(
        {"A": BaseEntry(synced, "e1")},
        RemoteSnapshot({"A": RemoteItem(synced, "e1")}),
        LocalSnapshot({"A": synced, "B": dup}),
        POLICY,
    )
    winner = dataclasses.replace(dup, id="A")
    assert result.actions == (
        Trash(synced, "conflict"),
        MergeLocal("B", winner),
        UpdateRemote(winner, "e1"),
    )


def test_a_merge_whose_upload_failed_is_uploaded_by_the_next_cycle() -> None:
    synced = make_credential("A", modified=5)
    winner = edit(synced, modified=9, password="fake-newer")
    result = plan(
        {"A": BaseEntry(synced, "e1")},
        RemoteSnapshot({"A": RemoteItem(synced, "e1")}),
        LocalSnapshot({"A": winner}),
        POLICY,
    )
    assert result.actions == (UpdateRemote(winner, "e1"),)


@pytest.mark.parametrize("dup_modified", [3, 5])
def test_older_or_tied_keyring_duplicate_goes_to_trash(dup_modified: int) -> None:
    synced = make_credential("A", modified=5)
    dup = _twin(synced, "B", modified=dup_modified, password="fake-older")
    result = plan(
        {"A": BaseEntry(synced, "e1")},
        RemoteSnapshot({"A": RemoteItem(synced, "e1")}),
        LocalSnapshot({"A": synced, "B": dup}),
        POLICY,
    )
    assert result.actions == (Trash(dup, "conflict"), DeleteLocal("B"))
    assert result.pending is None


def test_keyring_duplicate_of_a_new_icloud_login_is_merged_on_first_sync() -> None:
    phone = make_credential("A", modified=5)
    seahorse = _twin(phone, "B", modified=9, username=phone.username.upper(), password="fake-x")
    result = plan(
        {},
        RemoteSnapshot({"A": RemoteItem(phone, "e1")}),
        LocalSnapshot({"B": seahorse}),
        POLICY,
    )
    winner = dataclasses.replace(seahorse, id="A")
    assert result.actions == (
        Trash(phone, "conflict"),
        MergeLocal("B", winner),
        UpdateRemote(winner, "e1"),
    )


def test_older_keyring_duplicate_of_a_new_icloud_login_yields_to_it() -> None:
    phone = make_credential("A", modified=9)
    seahorse = _twin(phone, "B", modified=5, password="fake-x")
    result = plan(
        {},
        RemoteSnapshot({"A": RemoteItem(phone, "e1")}),
        LocalSnapshot({"B": seahorse}),
        POLICY,
    )
    assert set(result.actions) == {
        Trash(seahorse, "conflict"),
        DeleteLocal("B"),
        CreateLocal(phone, "e1"),
    }


def test_logins_on_another_path_are_not_duplicates() -> None:
    synced = make_credential("A", modified=5)
    other = _twin(synced, "B", modified=9, url=synced.url + "/admin", password="fake-x")
    result = plan(
        {"A": BaseEntry(synced, "e1")},
        RemoteSnapshot({"A": RemoteItem(synced, "e1")}),
        LocalSnapshot({"A": synced, "B": other}),
        POLICY,
    )
    assert result.actions == (CreateRemote(other),)


def test_a_second_duplicate_waits_while_the_first_is_merged() -> None:
    synced = make_credential("A", modified=5)
    first = _twin(synced, "B", modified=9, password="fake-b")
    second = _twin(synced, "C", modified=7, password="fake-c")
    result = plan(
        {"A": BaseEntry(synced, "e1")},
        RemoteSnapshot({"A": RemoteItem(synced, "e1")}),
        LocalSnapshot({"A": synced, "B": first, "C": second}),
        POLICY,
    )
    winner = dataclasses.replace(first, id="A")
    assert result.actions == (
        Trash(synced, "conflict"),
        MergeLocal("B", winner),
        UpdateRemote(winner, "e1"),
    )


@pytest.mark.parametrize("dup_modified", [3, 9])
def test_a_twin_moved_to_another_site_in_the_keyring_is_not_merged(dup_modified: int) -> None:
    synced = make_credential("A", modified=5)
    moved = edit(synced, modified=6, url="https://new.example.com")
    dup = _twin(synced, "B", modified=dup_modified, password="fake-b")
    result = plan(
        {"A": BaseEntry(synced, "e1")},
        RemoteSnapshot({"A": RemoteItem(synced, "e1")}),
        LocalSnapshot({"A": moved, "B": dup}),
        POLICY,
    )
    assert set(result.actions) == {UpdateRemote(moved, "e1"), CreateRemote(dup)}


def test_a_written_default_port_picks_the_twin_icloud_keeps_apart() -> None:
    plain = make_credential("A", modified=5, url="https://x.example.com")
    with_port = make_credential("B", modified=5, url="https://x.example.com:443")
    dup = _twin(with_port, "C", modified=9, password="fake-c")
    result = plan(
        {"A": BaseEntry(plain, "e1"), "B": BaseEntry(with_port, "e2")},
        RemoteSnapshot({"A": RemoteItem(plain, "e1"), "B": RemoteItem(with_port, "e2")}),
        LocalSnapshot({"A": plain, "B": with_port, "C": dup}),
        POLICY,
    )
    winner = dataclasses.replace(dup, id="B")
    assert result.actions == (
        Trash(with_port, "conflict"),
        MergeLocal("C", winner),
        UpdateRemote(winner, "e2"),
    )


def test_a_duplicate_never_replaces_a_login_the_user_restored() -> None:
    synced = make_credential("A", modified=5)
    restored = edit(synced, modified=1, password="fake-restored")
    dup = _twin(synced, "B", modified=9, password="fake-b")
    result = plan(
        {"A": BaseEntry(synced, "e1")},
        RemoteSnapshot({"A": RemoteItem(synced, "e1")}),
        LocalSnapshot({"A": restored, "B": dup}),
        POLICY,
        restored=frozenset({"A"}),
    )
    assert set(result.actions) == {
        Trash(dup, "conflict"),
        DeleteLocal("B"),
        UpdateRemote(restored, "e1"),
    }


def test_a_duplicate_waits_while_icloud_has_an_edit_of_its_twin() -> None:
    # Merged now, a duplicate equal to the old base would look unchanged next cycle and be
    # overwritten by iCloud's edit without a trash copy.
    synced = make_credential("A", modified=1, password="fake-x")
    mine = edit(synced, modified=10, password="fake-y")
    theirs = edit(synced, modified=20, password="fake-z")
    dup = _twin(synced, "B", modified=30)
    result = plan(
        {"A": BaseEntry(synced, "e1")},
        RemoteSnapshot({"A": RemoteItem(theirs, "e2")}),
        LocalSnapshot({"A": mine, "B": dup}),
        POLICY,
    )
    assert all(a.item_id == "A" for a in result.actions)
    assert result.actions == (Trash(mine, "conflict"), UpdateLocal(theirs, "e2"))


def test_a_restored_duplicate_replaces_its_twin_even_when_older() -> None:
    phone = make_credential("A", modified=9)
    restored = _twin(phone, "B", modified=1, password="fake-restored")
    result = plan(
        {},
        RemoteSnapshot({"A": RemoteItem(phone, "e1")}),
        LocalSnapshot({"B": restored}),
        POLICY,
        restored=frozenset({"B"}),
    )
    winner = dataclasses.replace(restored, id="A")
    assert result.actions == (
        Trash(phone, "conflict"),
        MergeLocal("B", winner),
        UpdateRemote(winner, "e1"),
    )


# ---------------------------------------------------------------- whole-plan properties


def test_actions_come_in_id_order() -> None:
    ids = ["C", "A", "B"]
    remote = {i: RemoteItem(make_credential(i), "e") for i in ids}
    result = plan({}, RemoteSnapshot(remote), LocalSnapshot({}), POLICY)
    assert [a.item_id for a in result.actions] == ["A", "B", "C"]


def test_independent_items_are_planned_independently() -> None:
    a = make_credential("A")
    b = make_credential("B")
    b2 = edit(b, modified=10, password="fake-new")
    c = make_credential("C")
    result = plan(
        {"A": BaseEntry(a, "e"), "B": BaseEntry(b, "e"), "C": BaseEntry(c, "e")},
        RemoteSnapshot({"A": RemoteItem(a, "e"), "B": RemoteItem(b2, "f")}),
        LocalSnapshot({"A": a, "B": b, "C": c}),
        POLICY,
    )
    assert result.actions == (
        UpdateLocal(b2, "f"),
        Trash(c, "deleted-in-icloud"),
        DeleteLocal("C"),
    )


def test_a_fork_copy_left_by_an_older_version_is_merged_back() -> None:
    # Releases before #71 kept a same-id conflict as a keyring-only copy iCloud refuses.
    remote = make_credential("SAME", modified=5, notes="from the iPhone")
    copy = make_credential("SAME", modified=9, notes="mine")
    copy = dataclasses.replace(copy, id="FORK")
    result = plan(
        {"SAME": BaseEntry(remote, "e1")},
        RemoteSnapshot({"SAME": RemoteItem(remote, "e1")}),
        LocalSnapshot({"SAME": remote, "FORK": copy}),
        POLICY,
    )
    winner = dataclasses.replace(copy, id="SAME")
    assert result.actions == (
        Trash(remote, "conflict"),
        MergeLocal("FORK", winner),
        UpdateRemote(winner, "e1"),
    )
