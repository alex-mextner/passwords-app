# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The in-memory stores behave like the real ones where the engine can tell the difference."""

from __future__ import annotations

import asyncio

import pytest
from tests.fakes.memory_stores import MemoryLocal, MemoryRemote, make_credential

from passwords_app.sync.ports import (
    AuthRequired,
    ConflictError,
    ItemRejected,
    LocalUnavailable,
    RemoteUnavailable,
)


async def call_remote(remote: MemoryRemote, op: str) -> None:
    if op == "fetch":
        await remote.fetch()
    elif op == "upsert":
        await remote.upsert(make_credential("B"), None)
    else:
        await remote.delete("A", None)


async def call_local(local: MemoryLocal, op: str) -> None:
    if op == "fetch":
        await local.fetch()
    elif op == "upsert":
        await local.upsert(make_credential("B"))
    else:
        await local.delete("A")


# ---------------------------------------------------------------- MemoryRemote


async def test_remote_create_requires_absent_record() -> None:
    remote = MemoryRemote()
    etag = await remote.upsert(make_credential("A"), None)
    assert remote.etag_of("A") == etag
    with pytest.raises(ConflictError):
        await remote.upsert(make_credential("A"), None)


async def test_remote_update_is_conditional_on_etag() -> None:
    remote = MemoryRemote()
    first = remote.put(make_credential("A"))
    second = await remote.upsert(make_credential("A", title="t"), first)
    assert second != first
    with pytest.raises(ConflictError):
        await remote.upsert(make_credential("A", title="u"), first)
    assert remote.items["A"].credential.title == "t"


async def test_remote_update_of_missing_record_conflicts() -> None:
    with pytest.raises(ConflictError):
        await MemoryRemote().upsert(make_credential("A"), "etag-1")


async def test_remote_delete_is_conditional() -> None:
    remote = MemoryRemote()
    etag = remote.put(make_credential("A"))
    with pytest.raises(ConflictError):
        await remote.delete("A", "stale")
    await remote.delete("A", etag)
    assert "A" not in remote.items
    with pytest.raises(ConflictError):
        await remote.delete("A", etag)


async def test_remote_snapshot_is_detached_from_later_edits() -> None:
    remote = MemoryRemote({"A": make_credential("A")})
    snap = await remote.fetch()
    remote.put(make_credential("B"))
    assert set(snap.items) == {"A"}


async def test_remote_device_edit_changes_the_etag() -> None:
    remote = MemoryRemote({"A": make_credential("A")})
    before = remote.etag_of("A")
    remote.put(make_credential("A", title="iPhone"))
    assert remote.etag_of("A") != before


@pytest.mark.parametrize("op", ["fetch", "upsert", "delete"])
async def test_remote_offline_fails_every_operation(op: str) -> None:
    remote = MemoryRemote({"A": make_credential("A")})
    remote.offline = True
    with pytest.raises(RemoteUnavailable):
        await call_remote(remote, op)
    assert "A" in remote.items


async def test_remote_injected_faults_fire_the_requested_number_of_times() -> None:
    remote = MemoryRemote()
    remote.fail_next("fetch", AuthRequired("2fa"), times=2)
    for _ in range(2):
        with pytest.raises(AuthRequired):
            await remote.fetch()
    await remote.fetch()


async def test_remote_faults_are_per_operation() -> None:
    remote = MemoryRemote()
    remote.fail_next("delete", ConflictError("x"))
    await remote.fetch()
    await remote.upsert(make_credential("A"), None)
    with pytest.raises(ConflictError):
        await remote.delete("A", None)


async def test_remote_records_calls_in_order() -> None:
    remote = MemoryRemote()
    await remote.fetch()
    await remote.upsert(make_credential("A"), None)
    await remote.delete("A", None)
    assert remote.calls == [("fetch", None), ("upsert", "A"), ("delete", "A")]


async def test_remote_on_write_runs_before_the_etag_check() -> None:
    remote = MemoryRemote({"A": make_credential("A")})
    etag = remote.etag_of("A")

    async def race(item_id: str) -> None:
        remote.put(make_credential(item_id, title="raced"))

    remote.on_write = race
    with pytest.raises(ConflictError):
        await remote.upsert(make_credential("A", title="mine"), etag)
    assert remote.items["A"].credential.title == "raced"


async def test_remote_rejects_one_item_until_it_is_accepted() -> None:
    remote = MemoryRemote()
    remote.reject("A", "duplicate login")
    with pytest.raises(ItemRejected, match="duplicate login"):
        await remote.upsert(make_credential("A"), None)
    await remote.upsert(make_credential("B"), None)
    assert set(remote.items) == {"B"}
    remote.accept("A")
    await remote.upsert(make_credential("A"), None)
    assert set(remote.items) == {"A", "B"}


async def test_remote_with_unique_logins_refuses_a_second_login_for_a_site_and_user() -> None:
    remote = MemoryRemote({"A": make_credential("A", url="https://x.example", username="al")})
    twin = make_credential("B", url="https://X.example", username="AL")
    await remote.upsert(twin, None)  # off by default: only ids collide
    remote.remove("B")
    remote.unique_logins = True
    with pytest.raises(ItemRejected, match="another login"):
        await remote.upsert(twin, None)
    etag = remote.etag_of("A")
    await remote.upsert(make_credential("A", url="https://x.example", username="AL"), etag)
    await remote.upsert(make_credential("C", url="https://x.example", username="bo"), None)
    assert set(remote.items) == {"A", "C"}


# ---------------------------------------------------------------- MemoryLocal


@pytest.mark.parametrize("op", ["fetch", "upsert", "delete"])
async def test_locked_collection_fails_every_operation(op: str) -> None:
    local = MemoryLocal({"A": make_credential("A")})
    local.lock()
    with pytest.raises(LocalUnavailable):
        await call_local(local, op)
    local.unlock()
    assert set((await local.fetch()).items) == {"A"}


async def test_local_delete_of_missing_item_is_a_no_op() -> None:
    local = MemoryLocal()
    await local.delete("missing")
    assert local.items == {}


async def test_local_snapshot_carries_rejected_items() -> None:
    from passwords_app.sync.ports import RejectedLocalItem  # noqa: PLC0415

    local = MemoryLocal()
    bad = RejectedLocalItem("/item/1", "label", "no host")
    local.rejected.append(bad)
    assert (await local.fetch()).rejected == (bad,)


async def test_change_notifications_cover_external_and_engine_writes() -> None:
    local = MemoryLocal()
    changes = local.changes()
    waiter = asyncio.ensure_future(anext(changes))
    await asyncio.sleep(0)
    local.put(make_credential("A"))
    await asyncio.wait_for(waiter, 1)
    waiter = asyncio.ensure_future(anext(changes))
    await asyncio.sleep(0)
    await local.delete("A")
    await asyncio.wait_for(waiter, 1)
    await changes.aclose()


async def test_closed_listener_stops_receiving() -> None:
    local = MemoryLocal()
    changes = local.changes()
    waiter = asyncio.ensure_future(anext(changes))
    await asyncio.sleep(0)
    local.put(make_credential("A"))
    await waiter
    await changes.aclose()
    local.put(make_credential("B"))  # must not fail with a dangling queue


def test_make_credential_takes_modified_as_seconds_after_epoch() -> None:
    c = make_credential("X", modified=90)
    assert (c.modified - c.created).total_seconds() == 90
