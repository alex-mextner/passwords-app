# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Daemon behavior without D-Bus: startup states, items, trash, cycles, alerts."""

from __future__ import annotations

import asyncio
import threading
from contextlib import aclosing
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from dbus_fast import Variant
from tests.fakes.memory_stores import MemoryLocal, MemoryRemote, make_credential
from tests.unit.daemon.fake_clock import FakeClock, settle
from tests.unit.daemon.otp_fixtures import otpauth_uri

from passwords_app.daemon.controller import ACCOUNT_KEY, FETCH_ATTEMPTS, MSG_CRASH, Daemon
from passwords_app.daemon.echo import ECHO_WINDOW
from passwords_app.daemon.errors import (
    AuthRequiredError,
    InvalidError,
    LockedError,
    NotFoundError,
    UnavailableError,
)
from passwords_app.daemon.items import parse_edit
from passwords_app.daemon.scheduler import BACKOFF_FIRST, DEBOUNCE, DEBOUNCE_MAX, IDLE_INTERVAL
from passwords_app.daemon.status import (
    MSG_AUTH,
    MSG_LOCAL,
    MSG_NOT_JOINED,
    MSG_OFFLINE,
    MSG_SESSION_UNREADABLE,
    MSG_SIGNED_OUT,
)
from passwords_app.sync.engine import UPLOAD_FAILURES_KEY
from passwords_app.sync.plan import BaseEntry
from passwords_app.sync.ports import (
    AuthRequired,
    LocalUnavailable,
    PendingDeletions,
    RejectedLocalItem,
)
from passwords_app.sync.remote_icloud import DUPLICATE_LOGIN

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from tests.unit.daemon.conftest import Events
    from tests.unit.daemon.fakes import FakeAccount, FakeNotifier

    from passwords_app.core.model import Credential
    from passwords_app.store.state import StateStore
    from passwords_app.sync.ports import LocalSnapshot


def s(value: str) -> Variant:
    return Variant("s", value)


def new_login(**extra: Variant) -> dict[str, Variant]:
    return {"url": s("https://new.example.com"), "username": s("neo"), "password": s("pw"), **extra}


# ---------------------------------------------------------------- startup


async def test_start_runs_a_first_cycle(
    remote: MemoryRemote, local: MemoryLocal, unstarted: Daemon
) -> None:
    remote.put(make_credential("A"))
    await unstarted.start()
    await settle()
    assert set(local.items) == {"A"}
    assert unstarted.status().state == "idle"
    assert unstarted.status().last_sync is not None


async def test_signed_out_start_never_touches_icloud(
    account: FakeAccount, remote: MemoryRemote, local: MemoryLocal, unstarted: Daemon
) -> None:
    account.signed_in = account.joined = False
    account.apple_id = None
    local.put(make_credential("L"))
    await unstarted.start()
    await settle()
    status = unstarted.status()
    assert (status.state, status.message, status.apple_id) == ("signed-out", MSG_SIGNED_OUT, "")
    assert remote.calls == []
    assert [c.id for c in await unstarted.list_items()] == ["L"]
    assert status.next_sync is None


async def test_signed_in_but_not_joined_requires_sign_in(
    account: FakeAccount, remote: MemoryRemote, unstarted: Daemon
) -> None:
    account.joined = False
    await unstarted.start()
    await settle()
    assert (unstarted.status().state, unstarted.status().message) == (
        "signin-required",
        MSG_NOT_JOINED,
    )
    assert unstarted.status().apple_id == "alice@example.com"
    assert unstarted.status().join_pending
    assert remote.calls == []


async def test_a_signed_in_start_without_network_comes_up_offline_and_retries(
    account: FakeAccount,
    remote: MemoryRemote,
    local: MemoryLocal,
    clock: FakeClock,
    unstarted: Daemon,
) -> None:
    account.remote_store_error = UnavailableError("Can't reach Apple: no route to host")
    remote.put(make_credential("A"))
    await unstarted.start()  # the daemon still comes up and answers
    await settle()
    assert (unstarted.status().state, unstarted.status().message) == ("offline", MSG_OFFLINE)
    account.remote_store_error = None
    await clock.advance(BACKOFF_FIRST)
    assert unstarted.status().state == "idle"
    assert "A" in local.items


async def test_a_session_apple_rejects_at_start_asks_to_sign_in(
    account: FakeAccount, unstarted: Daemon
) -> None:
    account.remote_store_error = AuthRequiredError("Apple wants the password again")
    await unstarted.start()
    await settle()
    assert (unstarted.status().state, unstarted.status().message) == ("signin-required", MSG_AUTH)
    assert not unstarted.status().join_pending  # joined already: only a full sign-in helps


async def test_account_calls_run_off_the_event_loop(account: FakeAccount, daemon: Daemon) -> None:
    assert account.calls
    assert threading.get_ident() not in account.threads


async def test_bases_of_another_apple_id_are_forgotten_at_start(
    state: StateStore, local: MemoryLocal, remote: MemoryRemote, unstarted: Daemon
) -> None:
    # The keyring mirrors an old account; the new account's iCloud has none of its items.
    old = make_credential("OLD")
    local.put(old)
    state.set_base(BaseEntry(old, "etag-old"))
    state.set(ACCOUNT_KEY, "someone-else@example.com")
    await unstarted.start()
    await settle()
    assert "OLD" in local.items  # not read as "deleted in iCloud"
    assert "OLD" in remote.items  # uploaded to the new account instead
    assert state.get(ACCOUNT_KEY) == "alice@example.com"


async def test_same_apple_id_keeps_bases(
    state: StateStore, local: MemoryLocal, remote: MemoryRemote, unstarted: Daemon
) -> None:
    gone = make_credential("GONE")
    local.put(gone)
    state.set_base(BaseEntry(gone, "etag-x"))
    state.set(ACCOUNT_KEY, "alice@example.com")
    await unstarted.start()
    await settle()
    assert "GONE" not in local.items  # deleted in iCloud -> deleted locally
    assert [e.reason for e in unstarted.trash()] == ["deleted-in-icloud"]


async def test_persisted_pause_is_reported_at_start(
    state: StateStore, remote: MemoryRemote, local: MemoryLocal, unstarted: Daemon
) -> None:
    state.set(ACCOUNT_KEY, "alice@example.com")
    for i in range(6):
        c = make_credential(f"P{i}")
        local.put(c)
        state.set_base(BaseEntry(c, "e"))
    state.set_pending(PendingDeletions(tuple(f"P{i}" for i in range(6)), ()))
    remote.offline = True
    await unstarted.start()
    await settle()
    status = unstarted.status()
    assert status.state == "offline"  # the first cycle could not re-plan
    assert status.pending_local == tuple(f"P{i}" for i in range(6))


# ---------------------------------------------------------------- items


async def test_list_is_sorted_by_display_name(local: MemoryLocal, daemon: Daemon) -> None:
    local.put(make_credential("1", url="https://zeta.example.com"))
    local.put(make_credential("2", url="https://alpha.example.com"))
    local.put(make_credential("3", url="https://mid.example.com", title="Beta"))
    await daemon.sync_now()
    assert [c.id for c in await daemon.list_items()] == ["2", "3", "1"]


async def test_get_returns_the_full_credential(local: MemoryLocal, daemon: Daemon) -> None:
    c = make_credential("A", otpauth=otpauth_uri())
    local.put(c)
    await daemon.sync_now()
    assert await daemon.get("A") == c


async def test_get_unknown_is_not_found(daemon: Daemon) -> None:
    with pytest.raises(NotFoundError):
        await daemon.get("NOPE")


async def test_save_creates_locally_then_uploads_after_debounce(
    remote: MemoryRemote, local: MemoryLocal, clock: FakeClock, daemon: Daemon, events: Events
) -> None:
    new_id = await daemon.save(parse_edit(new_login()))
    assert new_id == new_id.upper()
    assert len(new_id) == 36
    assert local.items[new_id].username == "neo"
    assert new_id in events.changed_ids()
    assert new_id not in remote.items
    await clock.advance(DEBOUNCE)
    assert remote.items[new_id].credential.username == "neo"


async def test_save_update_changes_only_given_fields(
    local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    local.put(make_credential("A", title="Old", notes="keep"))
    await clock.advance(DEBOUNCE)
    await daemon.save(parse_edit({"id": s("A"), "title": s("New")}))
    c = local.items["A"]
    assert (c.title, c.notes) == ("New", "keep")
    assert c.modified == clock.now()


async def test_save_unknown_id_is_not_found(local: MemoryLocal, daemon: Daemon) -> None:
    with pytest.raises(NotFoundError):
        await daemon.save(parse_edit({"id": s("MISSING"), "title": s("x")}))
    assert ("upsert", "MISSING") not in local.calls


async def test_save_without_changes_does_not_write(local: MemoryLocal, daemon: Daemon) -> None:
    local.put(make_credential("A", title="Same"))
    await daemon.sync_now()
    local.calls.clear()
    assert await daemon.save(parse_edit({"id": s("A"), "title": s("Same")})) == "A"
    assert [op for op, _ in local.calls if op == "upsert"] == []


async def test_a_partial_save_keeps_a_password_changed_moments_ago_elsewhere(
    local: MemoryLocal, daemon: Daemon
) -> None:
    before, after = "old", "new"
    local.put(make_credential("A", password=before))
    await daemon.get("A")  # cached
    local.put(make_credential("A", password=after))  # Seahorse; its signal is on the way
    await daemon.save(parse_edit({"id": s("A"), "title": s("Renamed")}))
    assert (local.items["A"].title, local.items["A"].password) == ("Renamed", after)


async def test_delete_trashes_the_keyring_s_current_content(
    local: MemoryLocal, daemon: Daemon
) -> None:
    before, after = "old", "new"
    local.put(make_credential("A", password=before))
    await daemon.get("A")  # cached
    local.put(make_credential("A", password=after))  # Seahorse; its signal is on the way
    await daemon.delete("A")
    (entry,) = daemon.trash()
    assert entry.credential.password == after  # Restore must bring back what was deleted


async def test_save_invalid_content_is_rejected(local: MemoryLocal, daemon: Daemon) -> None:
    with pytest.raises(InvalidError):
        await daemon.save(parse_edit(new_login(url=s("mailto:x@example.com"))))
    assert len(local.items) == 0


async def test_locked_keyring_refuses_reads_and_writes(local: MemoryLocal, daemon: Daemon) -> None:
    local.put(make_credential("A"))
    local.lock()  # the change notification drops the cached snapshot
    await settle()
    with pytest.raises(LockedError):
        await daemon.list_items()
    with pytest.raises(LockedError):
        await daemon.get("A")
    with pytest.raises(LockedError):
        await daemon.save(parse_edit(new_login()))
    with pytest.raises(LockedError):
        await daemon.match("https://a.example.com")


async def test_unlock_makes_items_available_again(local: MemoryLocal, daemon: Daemon) -> None:
    local.put(make_credential("A"))
    local.lock()
    await settle()
    with pytest.raises(LockedError):
        await daemon.list_items()
    local.unlock()
    assert [c.id for c in await daemon.list_items()] == ["A"]


async def test_delete_moves_to_trash_and_deletes_in_icloud(
    remote: MemoryRemote, local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    remote.put(make_credential("A"))
    await daemon.sync_now()
    await daemon.delete("A")
    assert "A" not in local.items
    assert [(e.credential.id, e.reason) for e in daemon.trash()] == [("A", "deleted-on-linux")]
    await clock.advance(DEBOUNCE)
    assert "A" not in remote.items
    assert len(daemon.trash()) == 1  # the cycle's own trash entry deduplicates


async def test_delete_while_signed_out_is_still_restorable(
    account: FakeAccount, local: MemoryLocal, unstarted: Daemon
) -> None:
    account.signed_in = account.joined = False
    local.put(make_credential("A"))
    await unstarted.start()
    await settle()
    await unstarted.delete("A")
    (entry,) = unstarted.trash()
    restored = await unstarted.restore(entry.trash_id)
    assert local.items[restored].url == "https://a.example.com"


async def test_delete_unknown_is_not_found(daemon: Daemon) -> None:
    with pytest.raises(NotFoundError):
        await daemon.delete("NOPE")


def trashed_ids(daemon: Daemon) -> list[str]:
    return [e.credential.id for e in daemon.trash()]


async def test_deleting_from_a_locked_keyring_is_refused_before_anything_is_trashed(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A"))
    await daemon.get("A")  # cached
    local.lock()  # its signal has not reached the daemon yet
    with pytest.raises(LockedError):
        await daemon.delete("A")
    assert trashed_ids(daemon) == []


async def test_a_delete_the_locked_keyring_refused_leaves_no_ghost_once_it_is_readable(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A"))
    original = local.delete

    async def lock_first(item_id: str, *, expected: str | None = None) -> None:
        local.lock()  # between the delete's read and its write
        await original(item_id, expected=expected)

    local.delete = lock_first  # type: ignore[method-assign]
    with pytest.raises(LockedError):
        await daemon.delete("A")
    assert trashed_ids(daemon) == ["A"]  # unknown yet whether the delete went through
    local.unlock()
    daemon.keyring_lock_changed()
    await daemon.list_items()
    assert "A" in local.items
    assert trashed_ids(daemon) == []  # a ghost entry would restore as a duplicate of A


async def test_a_refused_delete_on_a_readable_keyring_leaves_no_trash_entry(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A"))
    local.fail_next("delete", LocalUnavailable("refused"))
    with pytest.raises(LockedError):
        await daemon.delete("A")
    assert "A" in local.items
    assert trashed_ids(daemon) == []


def lose_the_reply(local: MemoryLocal, *, then_lock: bool) -> None:
    """The keyring deletes, but the daemon only sees an error (and maybe a lock)."""
    original = local.delete

    async def delete_then_fail(item_id: str, *, expected: str | None = None) -> None:
        await original(item_id, expected=expected)
        if then_lock:
            local.lock()
        msg = "the reply was lost"
        raise LocalUnavailable(msg)

    local.delete = delete_then_fail  # type: ignore[method-assign]


async def test_a_delete_that_failed_after_removing_the_item_keeps_its_trash_entry(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A"))
    lose_the_reply(local, then_lock=False)
    with pytest.raises(LockedError):
        await daemon.delete("A")
    assert "A" not in local.items
    assert trashed_ids(daemon) == ["A"]  # its only copy


async def test_a_lost_reply_then_a_lock_keeps_the_trash_entry(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A"))
    lose_the_reply(local, then_lock=True)
    with pytest.raises(LockedError):
        await daemon.delete("A")
    local.unlock()
    daemon.keyring_lock_changed()
    await daemon.list_items()
    assert "A" not in local.items
    assert trashed_ids(daemon) == ["A"]


async def test_a_read_older_than_a_failed_delete_does_not_settle_it(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A"))
    await settle()
    daemon.keyring_lock_changed()  # nothing cached
    original = local.fetch
    read_done, release = asyncio.Event(), asyncio.Event()

    async def slow_fetch() -> LocalSnapshot:
        snapshot = await original()  # still shows A
        read_done.set()
        await release.wait()
        return snapshot

    local.fetch = slow_fetch  # type: ignore[method-assign]
    reader = asyncio.create_task(daemon.list_items())
    await read_done.wait()
    local.fetch = original  # type: ignore[method-assign]
    lose_the_reply(local, then_lock=True)
    with pytest.raises(LockedError):
        await daemon.delete("A")
    release.set()
    assert [c.id for c in await reader] == ["A"]
    assert trashed_ids(daemon) == ["A"]  # A is gone: the entry is its only copy


async def test_item_events_name_exactly_the_changed_ids(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, events: Events
) -> None:
    remote.put(make_credential("A"))
    remote.put(make_credential("B"))
    await daemon.sync_now()
    events.items.clear()
    remote.put(make_credential("B", title="edited on iPhone", modified=10))
    remote.remove("A")
    await daemon.sync_now()
    assert events.changed_ids() == {"A", "B"}


async def test_no_item_event_when_nothing_changed(daemon: Daemon, events: Events) -> None:
    await daemon.sync_now()
    events.items.clear()
    await daemon.sync_now()
    assert events.items == []


# ---------------------------------------------------------------- trash


async def test_trash_restore_keeps_the_free_id_and_uploads(
    remote: MemoryRemote, local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    # Its own id lets iCloud move the record out of Recently Deleted instead of duplicating it.
    remote.put(make_credential("A"))
    await daemon.sync_now()
    remote.remove("A")
    await daemon.sync_now()
    (entry,) = daemon.trash()
    assert entry.reason == "deleted-in-icloud"
    restored_id = await daemon.restore(entry.trash_id)
    assert restored_id == "A"
    assert "A" in local.items
    assert daemon.trash() == []
    await clock.advance(DEBOUNCE)
    assert "A" in remote.items


async def test_restore_unknown_is_not_found(daemon: Daemon) -> None:
    with pytest.raises(NotFoundError):
        await daemon.restore("nope")


async def test_restore_into_a_locked_keyring_keeps_the_entry(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A"))
    await daemon.sync_now()
    await daemon.delete("A")
    (entry,) = daemon.trash()
    local.lock()
    with pytest.raises(LockedError):
        await daemon.restore(entry.trash_id)
    assert [e.trash_id for e in daemon.trash()] == [entry.trash_id]


async def test_restore_over_a_login_edited_meanwhile_asks_to_retry(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A", password="fake-old"))
    await daemon.sync_now()
    await daemon.delete("A")
    (entry,) = daemon.trash()
    local.put(make_credential("B", url=make_credential("A").url, password="fake-live"))

    async def seahorse_edits_the_twin(_: str) -> None:
        local.on_write = None
        local.put(make_credential("B", url=make_credential("A").url, password="fake-typed"))

    local.on_write = seahorse_edits_the_twin
    with pytest.raises(UnavailableError, match="changed while it was being restored"):
        await daemon.restore(entry.trash_id)
    assert local.items["B"].password == "fake-typed"
    assert entry.trash_id in [e.trash_id for e in daemon.trash()]


async def test_purge(local: MemoryLocal, daemon: Daemon, events: Events) -> None:
    local.put(make_credential("A"))
    await daemon.sync_now()
    await daemon.delete("A")
    (entry,) = daemon.trash()
    daemon.purge(entry.trash_id)
    assert daemon.trash() == []
    assert events.statuses[-1].trash_count == 0
    with pytest.raises(NotFoundError):
        daemon.purge(entry.trash_id)


# ---------------------------------------------------------------- cycles and status


async def test_sync_now_applies_remote_changes_before_returning(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon
) -> None:
    remote.put(make_credential("NEW"))
    await daemon.sync_now()
    assert "NEW" in local.items


async def test_cycle_publishes_syncing_then_idle(daemon: Daemon, events: Events) -> None:
    events.statuses.clear()
    await daemon.sync_now()
    assert events.states[0] == "syncing"
    assert events.states[-1] == "idle"


async def test_sync_now_while_signed_out_is_auth_required(
    account: FakeAccount, unstarted: Daemon
) -> None:
    account.signed_in = account.joined = False
    await unstarted.start()
    with pytest.raises(AuthRequiredError):
        await unstarted.sync_now()


async def test_offline_then_network_up(
    remote: MemoryRemote, local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    remote.offline = True
    await daemon.sync_now()
    status = daemon.status()
    assert (status.state, status.message) == ("offline", MSG_OFFLINE)
    remote.offline = False
    remote.put(make_credential("BACK"))
    daemon.scheduler.network_up()
    await settle()
    assert daemon.status().state == "idle"
    assert "BACK" in local.items


async def test_offline_retries_with_backoff(
    remote: MemoryRemote, clock: FakeClock, daemon: Daemon
) -> None:
    remote.offline = True
    await daemon.sync_now()
    fetches = remote.calls.count(("fetch", None))
    await clock.advance(BACKOFF_FIRST)
    assert remote.calls.count(("fetch", None)) == fetches + 1


async def test_auth_expiry_alerts_once_and_clears_on_recovery(
    remote: MemoryRemote, clock: FakeClock, daemon: Daemon, notifier: FakeNotifier
) -> None:
    remote.fail_next("fetch", AuthRequired("token expired"), times=3)
    for _ in range(3):
        await daemon.sync_now()
    assert (daemon.status().state, daemon.status().message) == ("signin-required", MSG_AUTH)
    assert notifier.topics() == ["signin"]
    await daemon.sync_now()
    assert daemon.status().state == "idle"
    assert notifier.closed == ["signin"]


async def test_locked_keyring_cycle_is_an_error_without_deletions(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon
) -> None:
    remote.put(make_credential("A"))
    await daemon.sync_now()
    local.lock()
    await daemon.sync_now()
    assert (daemon.status().state, daemon.status().message) == ("error", MSG_LOCAL)
    assert "A" in remote.items


async def test_unlocking_resumes_syncing_without_waiting_out_the_backoff(
    local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    local.lock()
    for _ in range(4):  # the backoff is now minutes, far past the debounce
        await daemon.sync_now()
    assert daemon.status().message == MSG_LOCAL
    local.unlock()  # an unlock changes no item, so no item signal follows
    daemon.keyring_lock_changed()
    await clock.advance(DEBOUNCE)
    assert daemon.status().state == "idle"


async def test_crashing_engine_reports_error(remote: MemoryRemote, daemon: Daemon) -> None:
    remote.fail_next("fetch", RuntimeError("bug in a store"))
    await daemon.sync_now()
    assert (daemon.status().state, daemon.status().message) == ("error", MSG_CRASH)
    await daemon.sync_now()
    assert daemon.status().state == "idle"


async def mass_delete_setup(remote: MemoryRemote, daemon: Daemon, n: int = 8) -> None:
    for i in range(n):
        remote.put(make_credential(f"M{i}"))
    await daemon.sync_now()
    for i in range(n):
        remote.remove(f"M{i}")
    await daemon.sync_now()


async def test_mass_delete_pauses_and_alerts_once(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, notifier: FakeNotifier
) -> None:
    await mass_delete_setup(remote, daemon)
    status = daemon.status()
    assert status.state == "paused"
    assert len(status.pending_local) == 8
    assert "8 passwords" in status.message
    assert len(local.items) == 8  # nothing deleted yet
    await daemon.sync_now()
    assert notifier.topics() == ["pause"]


async def test_resolve_pause_apply(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, notifier: FakeNotifier
) -> None:
    await mass_delete_setup(remote, daemon)
    await daemon.resolve_pause(apply=True)
    assert daemon.status().state == "idle"
    assert len(local.items) == 0
    assert len(daemon.trash()) == 8
    assert notifier.closed == ["pause"]


async def test_resolve_pause_restore(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon
) -> None:
    await mass_delete_setup(remote, daemon)
    await daemon.resolve_pause(apply=False)
    assert daemon.status().state == "idle"
    assert len(local.items) == 8
    assert len(remote.items) == 8


async def test_resolve_pause_without_pause_is_invalid(daemon: Daemon) -> None:
    with pytest.raises(InvalidError):
        await daemon.resolve_pause(apply=True)


async def test_rejected_items_notify_once_per_new_item(
    local: MemoryLocal, daemon: Daemon, notifier: FakeNotifier
) -> None:
    local.rejected.append(RejectedLocalItem("/item/1", "weird label", "no website"))
    await daemon.sync_now()
    await daemon.sync_now()
    assert notifier.topics() == ["rejected"]
    assert "weird label" in notifier.shown[0][2]
    local.rejected.append(RejectedLocalItem("/item/2", "another", "no website"))
    await daemon.sync_now()
    assert notifier.topics() == ["rejected", "rejected"]
    assert "another" in notifier.shown[1][2]
    assert "weird label" not in notifier.shown[1][2]


async def test_many_rejected_items_are_summarized(
    local: MemoryLocal, daemon: Daemon, notifier: FakeNotifier
) -> None:
    local.rejected.extend(RejectedLocalItem(f"/i/{i}", f"label {i}", "x") for i in range(9))
    await daemon.sync_now()
    _, summary, body = notifier.shown[0]
    assert summary.startswith("9 keyring items")
    assert "and 4 more" in body


# ---------------------------------------------------------------- logins iCloud refuses


def twin(password: str = "pw-A") -> Credential:
    """A keyring login iCloud refuses (another login has its site and username, #71)."""
    return make_credential(
        "A", url="https://www.example.com/login", username="bob", password=password
    )


async def test_a_refused_login_leaves_the_status_idle_with_the_reason(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon
) -> None:
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    await daemon.sync_now()
    status = daemon.status()
    assert status.state == "idle"
    assert status.message.startswith(
        f"iCloud did not accept the password for bob on https://www.example.com/login: "
        f"{DUPLICATE_LOGIN}."
    )


async def test_a_refused_login_is_announced_once_per_version(  # noqa: PLR0913, PLR0917 - fixtures
    remote: MemoryRemote,
    local: MemoryLocal,
    clock: FakeClock,
    daemon: Daemon,
    notifier: FakeNotifier,
    events: Events,
) -> None:
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    await daemon.sync_now()
    body = (
        "Another password for this website and username already exists. The password for bob "
        "stays on this computer only; everything else keeps syncing. Edit or delete it to fix "
        "this."
    )
    assert notifier.shown == [("refused:A", "Couldn't save “example.com” to iCloud", body)]
    # Still waiting, then retried after the backoff and refused again: not news.
    await daemon.sync_now()
    await clock.advance(daemon.policy.rejected_retry.total_seconds() + 1)
    await daemon.sync_now()
    assert remote.calls.count(("upsert", "A")) >= 2
    assert notifier.topics() == ["refused:A"]
    # An edited version that iCloud refuses too is a new refusal.
    local.put(twin(password="edited"))
    await daemon.sync_now()
    assert notifier.topics() == ["refused:A", "refused:A"]
    assert notifier.closed == []
    assert events.statuses[-1].message.startswith("iCloud did not accept")


async def test_the_refusal_is_withdrawn_once_icloud_takes_the_login(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, notifier: FakeNotifier
) -> None:
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    await daemon.sync_now()
    remote.accept("A")
    local.put(twin(password="fixed"))  # an edit retries at once
    await daemon.sync_now()
    assert "A" in remote.items
    assert notifier.closed == ["refused:A"]
    assert (daemon.status().state, daemon.status().message) == ("idle", "")


async def test_the_refusal_is_withdrawn_once_the_login_is_deleted(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, notifier: FakeNotifier
) -> None:
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    await daemon.sync_now()
    await daemon.delete("A")
    await daemon.sync_now()
    assert notifier.closed == ["refused:A"]
    assert daemon.status().message == ""


async def test_an_outage_does_not_withdraw_a_refusal(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, notifier: FakeNotifier
) -> None:
    # An interrupted cycle did not look at every login, so it cannot know the refusal is over.
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    await daemon.sync_now()
    remote.offline = True
    await daemon.sync_now()
    assert daemon.status().state == "offline"
    assert notifier.closed == []
    remote.offline = False
    await daemon.sync_now()
    assert notifier.topics() == ["refused:A"]
    assert daemon.status().message.startswith("iCloud did not accept")


async def test_signing_out_withdraws_refusals(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, notifier: FakeNotifier
) -> None:
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    await daemon.sync_now()
    await daemon.sign_out()
    assert notifier.closed == ["refused:A"]


async def test_a_refusal_from_a_crashed_cycle_is_announced_once(  # noqa: PLR0913, PLR0917 - fixtures
    remote: MemoryRemote,
    local: MemoryLocal,
    state: StateStore,
    daemon: Daemon,
    notifier: FakeNotifier,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The crash loses the cycle's refusal schedule, so the next cycle refuses afresh: that
    # refusal is the one announced, not both.
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    real_set = state.set

    def crash_on_schedule(key: str, value: str) -> None:
        if key == UPLOAD_FAILURES_KEY:
            monkeypatch.setattr(state, "set", real_set)
            msg = "bug while saving the schedule"
            raise RuntimeError(msg)
        real_set(key, value)

    monkeypatch.setattr(state, "set", crash_on_schedule)
    await daemon.sync_now()
    assert daemon.status().message == MSG_CRASH
    assert notifier.shown == []
    await daemon.sync_now()
    assert notifier.topics() == ["refused:A"]


async def test_a_refused_login_carries_the_reason_as_its_sync_problem(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, events: Events
) -> None:
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    local.put(make_credential("B"))
    await daemon.get("A")  # a fresh read: clients have seen both logins before the cycle
    events.items.clear()
    await daemon.sync_now()
    assert daemon.sync_problem("A") == DUPLICATE_LOGIN
    assert daemon.sync_problem("B") == ""
    assert daemon.sync_problem("unknown") == ""
    # Nothing in the keyring changed: the event is about the refusal alone.
    assert events.items == [["A"]]
    events.items.clear()
    await daemon.sync_now()  # still refused, same reason: not news
    assert events.items == []


async def test_the_sync_problem_clears_when_icloud_takes_the_login(
    remote: MemoryRemote,
    local: MemoryLocal,
    clock: FakeClock,
    daemon: Daemon,
    events: Events,
) -> None:
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    await daemon.sync_now()
    events.items.clear()
    remote.accept("A")
    await clock.advance(daemon.policy.rejected_retry.total_seconds() + 1)
    await daemon.sync_now()
    assert "A" in remote.items
    assert daemon.sync_problem("A") == ""
    assert events.changed_ids() == {"A"}


async def test_the_sync_problem_of_a_deleted_login_is_forgotten(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon
) -> None:
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    await daemon.sync_now()
    await daemon.delete("A")
    await daemon.sync_now()
    assert daemon.sync_problem("A") == ""


async def test_an_outage_keeps_the_sync_problem(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, events: Events
) -> None:
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    await daemon.sync_now()
    events.items.clear()
    remote.offline = True
    await daemon.sync_now()
    assert daemon.sync_problem("A") == DUPLICATE_LOGIN
    assert events.items == []


async def test_signing_out_clears_sync_problems(
    remote: MemoryRemote, local: MemoryLocal, daemon: Daemon, events: Events
) -> None:
    remote.reject("A", DUPLICATE_LOGIN)
    local.put(twin())
    await daemon.sync_now()
    events.items.clear()
    await daemon.sign_out()
    assert daemon.sync_problem("A") == ""
    assert events.changed_ids() == {"A"}


async def test_external_keyring_change_syncs_after_debounce(
    remote: MemoryRemote, local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    await clock.advance(10)
    local.put(make_credential("SEAHORSE"))
    await clock.advance(DEBOUNCE - 0.5)
    assert "SEAHORSE" not in remote.items
    await clock.advance(0.5)
    assert "SEAHORSE" in remote.items


async def test_status_counts_and_times(
    remote: MemoryRemote, clock: FakeClock, daemon: Daemon
) -> None:
    remote.put(make_credential("A"))
    remote.put(make_credential("B"))
    await daemon.sync_now()
    status = daemon.status()
    assert status.item_count == 2
    assert status.trash_count == 0
    assert status.last_sync == clock.now()
    # The cycle's own keyring writes are not local changes: no follow-up cycle.
    assert status.next_sync == clock.now() + timedelta(seconds=IDLE_INTERVAL)
    await clock.advance(DEBOUNCE)
    assert daemon.status().next_sync == clock.now() + timedelta(seconds=IDLE_INTERVAL - DEBOUNCE)


# ---------------------------------------------------------------- own keyring writes


async def test_own_keyring_writes_do_not_schedule_another_cycle(
    remote: MemoryRemote, local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    remote.put(make_credential("A"))
    remote.put(make_credential("B"))
    await daemon.sync_now()
    assert set(local.items) == {"A", "B"}
    fetches = remote.calls.count(("fetch", None))
    await clock.advance(DEBOUNCE_MAX + 1)
    assert remote.calls.count(("fetch", None)) == fetches


async def test_own_keyring_deletion_does_not_schedule_another_cycle(
    remote: MemoryRemote, local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    for i in range(5):
        remote.put(make_credential(f"K{i}"))
    remote.put(make_credential("GONE"))
    await daemon.sync_now()
    await clock.advance(DEBOUNCE_MAX + 1)
    remote.remove("GONE")
    await daemon.sync_now()
    assert "GONE" not in local.items
    fetches = remote.calls.count(("fetch", None))
    await clock.advance(DEBOUNCE_MAX + 1)
    assert remote.calls.count(("fetch", None)) == fetches


async def test_user_edit_right_after_a_cycle_still_syncs(
    remote: MemoryRemote, local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    remote.put(make_credential("A"))
    await daemon.sync_now()
    # Seahorse edits the item the cycle has just written.
    local.put(make_credential("A", notes="edited in Seahorse", modified=60))
    await clock.advance(DEBOUNCE)
    assert remote.items["A"].credential.notes == "edited in Seahorse"


async def test_user_edit_during_a_cycle_still_syncs(
    remote: MemoryRemote, local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    remote.put(make_credential("A"))
    remote.put(make_credential("B"))
    original = local.upsert

    async def upsert_then_user_edit(credential: Credential, *, expected: str | None = None) -> None:
        await original(credential, expected=expected)
        if credential.id == "B":  # the user adds an item while the cycle is still writing
            local.put(make_credential("NEW"))

    local.upsert = upsert_then_user_edit  # type: ignore[method-assign]
    await daemon.sync_now()
    assert "NEW" not in remote.items
    await clock.advance(DEBOUNCE)
    assert "NEW" in remote.items


async def test_change_signal_after_the_echo_window_syncs(
    remote: MemoryRemote, local: MemoryLocal, clock: FakeClock, daemon: Daemon
) -> None:
    remote.put(make_credential("A"))
    await daemon.sync_now()
    await clock.advance(ECHO_WINDOW)
    fetches = remote.calls.count(("fetch", None))
    local._notify()  # a late signal: no longer attributable to the cycle
    await clock.advance(DEBOUNCE)
    assert remote.calls.count(("fetch", None)) == fetches + 1


# ---------------------------------------------------------------- keyring locking


async def test_lock_change_drops_cached_passwords(local: MemoryLocal, daemon: Daemon) -> None:
    local.put(make_credential("A"))
    await daemon.get("A")  # cached
    local.lock()
    daemon.keyring_lock_changed()
    with pytest.raises(LockedError):
        await daemon.get("A")


async def test_a_read_racing_a_lock_never_hands_out_its_result(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A"))
    daemon.keyring_lock_changed()  # nothing cached
    original = local.fetch
    passed_lock_check, release = asyncio.Event(), asyncio.Event()

    async def slow_fetch() -> LocalSnapshot:
        snapshot = await original()  # the keyring was still unlocked here
        passed_lock_check.set()
        await release.wait()
        return snapshot

    local.fetch = slow_fetch  # type: ignore[method-assign]
    reader = asyncio.create_task(daemon.get("A"))
    await passed_lock_check.wait()
    local.lock()
    daemon.keyring_lock_changed()
    local.fetch = original  # type: ignore[method-assign]
    release.set()
    with pytest.raises(LockedError):
        await reader
    with pytest.raises(LockedError):
        await daemon.get("A")


async def test_a_keyring_that_keeps_flipping_refuses_the_read(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A"))
    daemon.keyring_lock_changed()
    original = local.fetch

    async def flipping_fetch() -> LocalSnapshot:
        snapshot = await original()
        daemon.keyring_lock_changed()  # locked and unlocked again during every read
        return snapshot

    local.fetch = flipping_fetch  # type: ignore[method-assign]
    local.calls.clear()
    with pytest.raises(LockedError):
        await daemon.get("A")
    assert local.calls.count(("fetch", None)) == FETCH_ATTEMPTS


async def test_a_read_older_than_a_save_never_replaces_the_saved_item(
    local: MemoryLocal, unstarted: Daemon, events: Events
) -> None:
    # The keyring's change signal for a write may arrive long after the write returned:
    # hold every signal back, so only the save itself can mark the older read as stale.
    signals, deliver = local.changes, asyncio.Event()

    async def late_changes() -> AsyncGenerator[None]:
        async with aclosing(signals()) as inner:
            async for _ in inner:
                await deliver.wait()
                yield

    local.changes = late_changes  # type: ignore[method-assign]
    local.put(make_credential("A", title="Original"))
    await unstarted.start()
    await settle()
    daemon = unstarted
    daemon.keyring_lock_changed()  # nothing cached
    original = local.fetch
    read_done, release = asyncio.Event(), asyncio.Event()

    async def slow_fetch() -> LocalSnapshot:
        snapshot = await original()
        read_done.set()
        await release.wait()
        return snapshot

    local.fetch = slow_fetch  # type: ignore[method-assign]
    reader = asyncio.create_task(daemon.get("A"))
    await read_done.wait()
    local.fetch = original  # type: ignore[method-assign]
    await daemon.save(parse_edit({"id": s("A"), "title": s("New title")}))
    announced = len(events.items)
    release.set()
    assert (await reader).title == "Original"  # it started before the save
    assert events.items[announced:] == []  # announcing it would revert A in every client
    await daemon.save(parse_edit({"id": s("A"), "notes": s("added later")}))
    assert (local.items["A"].title, local.items["A"].notes) == ("New title", "added later")


async def test_a_read_older_than_a_change_signal_is_not_cached(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("A", title="Original"))
    await settle()
    daemon.keyring_lock_changed()
    original = local.fetch
    read_done, release = asyncio.Event(), asyncio.Event()

    async def slow_fetch() -> LocalSnapshot:
        snapshot = await original()
        read_done.set()
        await release.wait()
        return snapshot

    local.fetch = slow_fetch  # type: ignore[method-assign]
    reader = asyncio.create_task(daemon.get("A"))
    await read_done.wait()
    local.fetch = original  # type: ignore[method-assign]
    local.put(make_credential("A", title="Edited in Seahorse"))  # signals a change
    await settle()
    release.set()
    await reader
    assert (await daemon.get("A")).title == "Edited in Seahorse"


# ---------------------------------------------------------------- match and codes


async def test_match_ranks_exact_host_first_and_excludes_others(
    local: MemoryLocal, daemon: Daemon
) -> None:
    local.put(make_credential("SITE", url="https://example.com", title="A site"))
    local.put(make_credential("EXACT", url="https://login.example.com", title="Z exact"))
    local.put(make_credential("OTHER", url="https://example.org"))
    local.put(make_credential("LOOK", url="https://example.com.evil.test"))
    local.put(make_credential("HTTPS", url="https://plain.example.net"))
    await daemon.sync_now()
    assert [c.id for c in await daemon.match("https://login.example.com/signin")] == [
        "EXACT",
        "SITE",
    ]
    assert await daemon.match("http://plain.example.net/") == []  # no https -> http downgrade
    assert await daemon.match("not a url") == []


async def test_match_uses_alt_urls(local: MemoryLocal, daemon: Daemon) -> None:
    local.put(make_credential("A", url="https://a.example.com", alt_urls=("https://b.test",)))
    await daemon.sync_now()
    assert [c.id for c in await daemon.match("https://b.test/login")] == ["A"]


@pytest.mark.parametrize(
    ("unix", "code", "left"),
    [
        (59, "94287082", 1),
        (1_111_111_109, "07081804", 1),
        (1_111_111_111, "14050471", 29),
        (1_234_567_890, "89005924", 0 + 30 - 1_234_567_890 % 30),
        (2_000_000_000, "69279037", 30 - 2_000_000_000 % 30),
    ],
)
async def test_codes_follow_rfc_6238(  # noqa: PLR0913, PLR0917 - fixtures + parameters
    local: MemoryLocal, clock: FakeClock, daemon: Daemon, unix: int, code: str, left: int
) -> None:
    local.put(make_credential("T", otpauth=otpauth_uri(digits="8")))
    clock.set_wall(datetime.fromtimestamp(unix, UTC))
    assert await daemon.code("T") == (code, left)


async def test_code_for_item_without_otp_is_not_found(local: MemoryLocal, daemon: Daemon) -> None:
    local.put(make_credential("A"))
    with pytest.raises(NotFoundError):
        await daemon.code("A")


async def test_code_with_broken_setup_is_invalid(local: MemoryLocal, daemon: Daemon) -> None:
    local.put(make_credential("A", otpauth="otpauth://totp/x?issuer=nothing"))
    with pytest.raises(InvalidError):
        await daemon.code("A")


async def test_client_calls_switch_to_the_active_cadence(
    remote: MemoryRemote, clock: FakeClock, daemon: Daemon
) -> None:
    fetches = remote.calls.count(("fetch", None))
    daemon.touch()
    await clock.advance(120)
    assert remote.calls.count(("fetch", None)) == fetches + 2


async def test_stop_is_idempotent(daemon: Daemon) -> None:
    await daemon.stop()
    await daemon.stop()


def test_status_message_for_signed_out_default(
    account: FakeAccount,
    local: MemoryLocal,
    state: StateStore,
    clock: FakeClock,
    notifier: FakeNotifier,
) -> None:
    d = Daemon(account=account, local=local, state=state, clock=clock, notifier=notifier)
    assert (d.status().state, d.status().message) == ("signed-out", MSG_SIGNED_OUT)


async def test_unreadable_saved_session_is_explained_not_just_signed_out(
    account: FakeAccount, unstarted: Daemon
) -> None:
    account.signed_in = account.joined = False
    account.apple_id = None
    account.session_unreadable = True
    await unstarted.start()
    status = unstarted.status()
    assert (status.state, status.message) == ("signed-out", MSG_SESSION_UNREADABLE)
    with pytest.raises(AuthRequiredError, match="Sign in again"):
        await unstarted.sync_now()


async def test_status_is_not_answered_before_the_saved_account_was_read(unstarted: Daemon) -> None:
    """The bus name is taken before start(): an early GetStatus must not get the default."""
    waiting = asyncio.ensure_future(unstarted.until_started())
    await asyncio.sleep(0)
    assert not waiting.done()
    await unstarted.start()
    await asyncio.wait_for(waiting, timeout=1)
