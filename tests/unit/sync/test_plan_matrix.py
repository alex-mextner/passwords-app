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
    ForkLocal,
    Link,
    SetBase,
    Trash,
    UpdateLocal,
    UpdateRemote,
    fork_id,
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
def test_same_id_with_different_content_keeps_both(field: str) -> None:
    remote = make_credential("SAME", modified=5)
    local = edit(remote, modified=9, **{field: FIELD_VALUES[field][0]})
    result = run(None, remote, local, remote_etag="e6")
    copy = dataclasses.replace(local, id=fork_id("SAME", local))
    assert result.actions == (
        ForkLocal(copy, "SAME"),
        UpdateLocal(remote, "e6"),
        CreateRemote(copy),
    )
    assert copy.id != "SAME"


def test_fork_id_is_deterministic_and_content_bound() -> None:
    a = make_credential("X", password="fake-one")
    b = make_credential("X", password="fake-two")
    assert fork_id("X", a) == fork_id("X", a)
    assert fork_id("X", a) != fork_id("X", b)
    assert fork_id("X", a) != fork_id("Y", a)
    assert fork_id("X", a) == fork_id("X", a).upper()


def test_fork_is_not_repeated_when_the_copy_already_exists_locally() -> None:
    # A cycle that crashed after saving the copy must not save it again.
    remote = make_credential("SAME", modified=5)
    local = make_credential("SAME", modified=9, password="fake-mine")
    copy = dataclasses.replace(local, id=fork_id("SAME", local))
    result = plan(
        {},
        RemoteSnapshot({"SAME": RemoteItem(remote, "e1")}),
        LocalSnapshot({"SAME": local, copy.id: copy}),
        POLICY,
    )
    assert not any(isinstance(a, ForkLocal) for a in result.actions)
    assert set(result.actions) == {UpdateLocal(remote, "e1"), CreateRemote(copy)}


def test_fork_is_not_repeated_when_the_copy_already_reached_icloud() -> None:
    remote = make_credential("SAME", modified=5)
    local = make_credential("SAME", modified=9, password="fake-mine")
    copy = dataclasses.replace(local, id=fork_id("SAME", local))
    result = plan(
        {copy.id: BaseEntry(copy, "c1")},
        RemoteSnapshot({"SAME": RemoteItem(remote, "e1"), copy.id: RemoteItem(copy, "c1")}),
        LocalSnapshot({"SAME": local, copy.id: copy}),
        POLICY,
    )
    assert result.actions == (UpdateLocal(remote, "e1"),)


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


def test_edited_fork_from_an_interrupted_cycle_does_not_vouch_for_the_original() -> None:
    remote = make_credential("SAME", modified=5)
    local = make_credential("SAME", modified=9, password="fake-mine")
    fork = dataclasses.replace(local, id=fork_id("SAME", local), notes="edited since")
    result = plan(
        {},
        RemoteSnapshot({"SAME": RemoteItem(remote, "e1")}),
        LocalSnapshot({"SAME": local, fork.id: fork}),
        POLICY,
    )
    assert Trash(local, "conflict") in result.actions
    assert result.actions.index(Trash(local, "conflict")) < result.actions.index(
        UpdateLocal(remote, "e1")
    )


def test_a_fork_left_by_a_cancelled_cycle_is_uploaded_not_linked_back() -> None:
    # #17: the cycle saved the copy and overwrote the original with iCloud's version, then
    # was cancelled before its base updates committed. The copy shares site, account and
    # password with iCloud's version, but linking them would put it back in trash.
    remote = make_credential("SAME", modified=5, notes="from the iPhone")
    local = make_credential("SAME", modified=9, notes="mine")
    copy = dataclasses.replace(local, id=fork_id("SAME", local))
    result = plan(
        {},
        RemoteSnapshot({"SAME": RemoteItem(remote, "e1")}),
        LocalSnapshot({"SAME": remote, copy.id: copy}),
        POLICY,
    )
    assert set(result.actions) == {Link("SAME", remote, "e1"), CreateRemote(copy)}
