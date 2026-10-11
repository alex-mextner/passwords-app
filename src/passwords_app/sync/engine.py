# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Executes sync plans against the two stores and keeps state.db truthful.

The engine refuses to plan from anything less than two complete snapshots: a locked keyring
or a failed iCloud fetch skips the cycle, because the planner reads "missing" as "deleted".
Each write is followed by its base update, and a conditional write that loses a race only
abandons that item; the next cycle re-plans it from fresh data.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING, assert_never

from passwords_app.core.model import TrashEntry
from passwords_app.sync.plan import (
    BaseEntry,
    CreateLocal,
    CreateRemote,
    DeleteLocal,
    DeleteRemote,
    DropBase,
    ForkLocal,
    Link,
    PauseDecision,
    SetBase,
    SyncPlan,
    Trash,
    UpdateLocal,
    UpdateRemote,
    plan,
    trash_id,
)
from passwords_app.sync.ports import (
    AuthRequired,
    ConflictError,
    LocalUnavailable,
    RemoteUnavailable,
    SyncPolicy,
    SyncReport,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from passwords_app.store.state import StateStore
    from passwords_app.sync.plan import Action
    from passwords_app.sync.ports import (
        LocalSnapshot,
        LocalStore,
        RemoteSnapshot,
        RemoteStore,
    )

LAST_SYNC_KEY = "last-sync"

# `SyncReport.skipped_reason` values; the daemon maps them to its status state.
SKIP_LOCAL = "local-unavailable"
SKIP_REMOTE = "remote-unavailable"
SKIP_AUTH = "auth-required"


def utcnow() -> datetime:
    return datetime.now(UTC)


class NoPendingDeletionsError(LookupError):
    """`resolve_pause` was called while nothing is paused."""


class _Abort(Exception):  # noqa: N818 - internal control flow, never escapes the engine
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class SyncEngine:
    def __init__(
        self,
        remote: RemoteStore,
        local: LocalStore,
        state: StateStore,
        *,
        policy: SyncPolicy | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._remote = remote
        self._local = local
        self._state = state
        self._policy = policy if policy is not None else SyncPolicy()
        self._clock = clock

    # ------------------------------------------------------------------ cycles

    async def run_once(self) -> SyncReport:
        """Run one sync cycle; never raises for store outages (they become `skipped_reason`)."""
        return await self._cycle(None)

    async def resolve_pause(self, *, apply: bool) -> SyncReport:
        """Answer a mass-delete pause: apply the held deletions, or restore the items."""
        pending = self._state.pending()
        if pending is None:
            msg = "no deletions are waiting for a decision"
            raise NoPendingDeletionsError(msg)
        return await self._cycle(PauseDecision(pending, apply=apply))

    async def _cycle(self, decision: PauseDecision | None) -> SyncReport:
        started = self._clock()
        self._state.purge_older_than(started - self._policy.trash_retention)
        try:
            # iCloud first: its fetch is the slow one, and the keyring snapshot must be as
            # fresh as possible because keyring writes cannot be made conditional.
            remote = await self._fetch_remote()
            local = await self._fetch_local()
        except _Abort as abort:
            return SyncReport(started, self._clock(), skipped_reason=abort.reason)

        sync_plan = plan(
            self._state.bases(),
            remote,
            local,
            self._policy,
            decision=decision,
            held=None if decision is not None else self._state.pending(),
        )
        counts, skipped = await self._execute(sync_plan, started)
        if skipped is None:
            # Pending is replaced only after a complete pass, so an interrupted cycle keeps
            # the user's open decision instead of silently forgetting it.
            self._state.set_pending(sync_plan.pending)
            if sync_plan.pending is None:
                self._state.set(LAST_SYNC_KEY, started.isoformat())
        return SyncReport(
            started,
            self._clock(),
            created_local=counts["created_local"],
            updated_local=counts["updated_local"],
            deleted_local=counts["deleted_local"],
            created_remote=counts["created_remote"],
            updated_remote=counts["updated_remote"],
            deleted_remote=counts["deleted_remote"],
            conflicts=counts["conflicts"],
            linked=counts["linked"],
            skipped_reason=skipped,
            paused=sync_plan.pending,
            rejected=tuple(local.rejected),
        )

    async def _fetch_local(self) -> LocalSnapshot:
        try:
            return await self._local.fetch()
        except LocalUnavailable as exc:
            raise _Abort(SKIP_LOCAL) from exc

    async def _fetch_remote(self) -> RemoteSnapshot:
        try:
            return await self._remote.fetch()
        except AuthRequired as exc:
            raise _Abort(SKIP_AUTH) from exc
        except RemoteUnavailable as exc:
            raise _Abort(SKIP_REMOTE) from exc

    async def _execute(self, sync_plan: SyncPlan, now: datetime) -> tuple[Counter[str], str | None]:
        counts: Counter[str] = Counter()
        copies = [a for a in sync_plan.actions if isinstance(a, Trash)]
        writes = [a for a in sync_plan.actions if not isinstance(a, Trash)]
        # Every trash copy is committed before any store write that could destroy its
        # original; if the cycle then stops, the copies are idempotent (stable trash ids).
        # Base updates share one transaction: a lost one is re-derived by the next cycle.
        with self._state.transaction():
            for copy in copies:
                await self._apply(copy, now, counts)
        with self._state.transaction():
            for action in writes:
                skip = await self._apply_write(action, now, counts)
                if skip is not None:
                    return counts, skip
        return counts, None

    async def _apply_write(self, action: Action, now: datetime, counts: Counter[str]) -> str | None:
        """Apply one store write; return the skip reason that ends the cycle, if any."""
        try:
            await self._apply(action, now, counts)
        except ConflictError:
            # The planner puts an item's iCloud write last in its group, so a lost
            # race leaves nothing of that item pending; the next cycle re-plans it.
            return None
        except LocalUnavailable:
            return SKIP_LOCAL
        except AuthRequired:
            return SKIP_AUTH
        except RemoteUnavailable:
            return SKIP_REMOTE
        return None

    async def _apply(self, action: Action, now: datetime, counts: Counter[str]) -> None:
        match action:
            case Trash() | CreateLocal() | UpdateLocal() | DeleteLocal() | ForkLocal():
                await self._apply_local(action, now, counts)
            case _:
                await self._apply_remote(action, counts)

    async def _apply_local(
        self,
        action: Trash | CreateLocal | UpdateLocal | DeleteLocal | ForkLocal,
        now: datetime,
        counts: Counter[str],
    ) -> None:
        state = self._state
        match action:
            case Trash(credential, reason):
                entry = TrashEntry(trash_id(credential, reason), credential, now, reason)
                if state.add_trash(entry) and reason == "conflict":
                    counts["conflicts"] += 1
            case CreateLocal(credential, etag):
                await self._local.upsert(credential)
                state.set_base(BaseEntry(credential, etag))
                counts["created_local"] += 1
            case UpdateLocal(credential, etag):
                await self._local.upsert(credential)
                state.set_base(BaseEntry(credential, etag))
                counts["updated_local"] += 1
            case DeleteLocal(item_id):
                await self._local.delete(item_id)
                state.drop_base(item_id)
                counts["deleted_local"] += 1
            case ForkLocal(credential, _):
                await self._local.upsert(credential)
                counts["created_local"] += 1
            case _:
                assert_never(action)

    async def _apply_remote(
        self,
        action: CreateRemote | UpdateRemote | DeleteRemote | Link | SetBase | DropBase,
        counts: Counter[str],
    ) -> None:
        state = self._state
        match action:
            case CreateRemote(credential):
                etag = await self._remote.upsert(credential, None)
                state.set_base(BaseEntry(credential, etag))
                counts["created_remote"] += 1
            case UpdateRemote(credential, etag):
                new_etag = await self._remote.upsert(credential, etag)
                state.set_base(BaseEntry(credential, new_etag))
                counts["updated_remote"] += 1
            case DeleteRemote(item_id, etag):
                await self._remote.delete(item_id, etag)
                state.drop_base(item_id)
                counts["deleted_remote"] += 1
            case Link(local_id, credential, etag):
                if local_id != credential.id:
                    # Write before delete: a crash in between leaves a duplicate, never a loss.
                    await self._local.upsert(credential)
                    await self._local.delete(local_id)
                state.set_base(BaseEntry(credential, etag))
                counts["linked"] += 1
            case SetBase(credential, etag):
                state.set_base(BaseEntry(credential, etag))
            case DropBase(item_id):
                state.drop_base(item_id)
            case _:
                assert_never(action)

    # ------------------------------------------------------------------ trash

    def trash(self) -> list[TrashEntry]:
        """Trash entries still inside the retention window, newest first."""
        return self._state.trash(since=self._clock() - self._policy.trash_retention)

    async def restore(self, trash_id: str) -> str:
        """Put a trashed version back into the keyring; the next cycle uploads it.

        A deleted item comes back under its own id while that id is free on this side, so
        the upload recovers the record iCloud keeps in Recently Deleted rather than adding a
        duplicate next to it. A conflict loser, or an item whose id is live again, gets a
        fresh id: its original id belongs to another version that must not be overwritten.
        """
        entry = self._state.get_trash(trash_id)
        if entry is None:
            raise KeyError(trash_id)
        now = self._clock()
        item_id = entry.credential.id
        if entry.reason == "conflict" or await self._id_taken(item_id):
            item_id = str(uuid.uuid4()).upper()
        restored = dataclasses.replace(entry.credential, id=item_id, modified=now)
        await self._local.upsert(restored)
        self._state.remove_trash(trash_id)
        return restored.id

    async def _id_taken(self, item_id: str) -> bool:
        """Whether `item_id` names a live item here: one in the keyring or synced with iCloud."""
        if item_id in self._state.bases():
            return True
        return item_id in (await self._local.fetch()).items

    def purge(self, trash_id: str) -> None:
        """Delete a trash entry for good."""
        if not self._state.remove_trash(trash_id):
            raise KeyError(trash_id)
