# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Executes sync plans against the two stores and keeps state.db truthful.

The engine refuses to plan from anything less than two complete snapshots: a locked keyring
or a failed iCloud fetch skips the cycle, because the planner reads "missing" as "deleted".
Each write is followed by its base update, and a conditional write that loses a race only
abandons that item; the next cycle re-plans it from fresh data. An upload iCloud refuses
for that item alone (`ItemRejected`) is set aside the same way and retried on its own
backoff schedule, so one bad login never holds up the rest or reads as an outage.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING, assert_never

from passwords_app.core.model import TrashEntry
from passwords_app.core.urls import login_identity
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
    content_key,
    plan,
    trash_id,
)
from passwords_app.sync.ports import (
    AuthRequired,
    ConflictError,
    ItemRejected,
    LocalUnavailable,
    RemoteUnavailable,
    SyncPolicy,
    SyncReport,
    UploadFailure,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from passwords_app.core.model import Credential, TrashReason
    from passwords_app.store.state import StateStore
    from passwords_app.sync.plan import Action
    from passwords_app.sync.ports import (
        LocalSnapshot,
        LocalStore,
        RemoteSnapshot,
        RemoteStore,
    )

LAST_SYNC_KEY = "last-sync"
UPLOAD_FAILURES_KEY = "upload-failures"

# `SyncReport.skipped_reason` values; the daemon maps them to its status state.
SKIP_LOCAL = "local-unavailable"
SKIP_REMOTE = "remote-unavailable"
SKIP_AUTH = "auth-required"


def utcnow() -> datetime:
    return datetime.now(UTC)


def _trash_entry(credential: Credential, reason: TrashReason, now: datetime) -> TrashEntry:
    return TrashEntry(trash_id(credential, reason), credential, now, reason)


class NoPendingDeletionsError(LookupError):
    """`resolve_pause` was called while nothing is paused."""


class _Abort(Exception):  # noqa: N818 - internal control flow, never escapes the engine
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclasses.dataclass(frozen=True, slots=True)
class _Refusal:
    failure: UploadFailure
    content: str  # content hash of the refused version: an edit makes it a new upload


class _Refusals:
    """Uploads iCloud refused, and when each may be tried again; persisted in state.db."""

    def __init__(
        self,
        state: StateStore,
        policy: SyncPolicy,
        now: datetime,
        notify: Callable[[UploadFailure], None] | None,
    ) -> None:
        self._state = state
        self._policy = policy
        self._now = now
        self._notify = notify
        raw = state.get(UPLOAD_FAILURES_KEY)
        self._known: dict[str, _Refusal] = {} if raw is None else _decode_refusals(raw)
        self._seen: dict[str, UploadFailure] = {}  # refused or still waiting this cycle

    @property
    def current(self) -> tuple[UploadFailure, ...]:
        return tuple(self._seen[i] for i in sorted(self._seen))

    def waiting(self, credential: Credential) -> bool:
        """Whether this exact version was refused and its retry time has not come yet."""
        known = self._known.get(credential.id)
        if known is None or known.content != credential.content_hash():
            return False
        if self._now < known.failure.retry_at:
            self._seen[credential.id] = known.failure
            return True
        return False

    def refused(self, credential: Credential, reason: str) -> None:
        content = credential.content_hash()
        known = self._known.get(credential.id)
        attempts = known.failure.attempts + 1 if known and known.content == content else 1
        wait = min(
            self._policy.rejected_retry * 2 ** min(attempts - 1, 20),
            self._policy.rejected_retry_max,
        )
        failure = UploadFailure(
            credential.id,
            credential.url,
            credential.username,
            reason,
            attempts,
            self._now + wait,
        )
        self._known[credential.id] = _Refusal(failure, content)
        self._seen[credential.id] = failure
        if attempts == 1 and self._notify is not None:
            # Once per refused version: the retries of a known refusal are not news.
            self._notify(failure)

    def accepted(self, item_id: str) -> None:
        self._known.pop(item_id, None)

    def save(self, *, complete: bool) -> None:
        """Persist the schedule; a complete pass forgets items that no longer need uploading."""
        if complete:
            self._known = {i: r for i, r in self._known.items() if i in self._seen}
        if self._known:
            self._state.set(UPLOAD_FAILURES_KEY, _encode_refusals(self._known))
        else:
            self._state.delete(UPLOAD_FAILURES_KEY)


def _encode_refusals(refusals: dict[str, _Refusal]) -> str:
    return json.dumps(
        {
            item_id: {
                "content": r.content,
                "url": r.failure.url,
                "username": r.failure.username,
                "reason": r.failure.reason,
                "attempts": r.failure.attempts,
                "retry_at": r.failure.retry_at.isoformat(),
            }
            for item_id, r in refusals.items()
        },
        sort_keys=True,
    )


def _decode_refusals(raw: str) -> dict[str, _Refusal]:
    return {
        item_id: _Refusal(
            UploadFailure(
                item_id,
                r["url"],
                r["username"],
                r["reason"],
                r["attempts"],
                datetime.fromisoformat(r["retry_at"]),
            ),
            r["content"],
        )
        for item_id, r in json.loads(raw).items()
    }


class SyncEngine:
    def __init__(  # noqa: PLR0913 - the stores, the state, and two optional seams
        self,
        remote: RemoteStore,
        local: LocalStore,
        state: StateStore,
        *,
        policy: SyncPolicy | None = None,
        clock: Callable[[], datetime] = utcnow,
        on_upload_rejected: Callable[[UploadFailure], None] | None = None,
    ) -> None:
        """`on_upload_rejected` is called once for each version iCloud refuses to store."""
        self._remote = remote
        self._local = local
        self._state = state
        self._policy = policy if policy is not None else SyncPolicy()
        self._clock = clock
        self._on_upload_rejected = on_upload_rejected

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
        refusals = _Refusals(self._state, self._policy, started, self._on_upload_rejected)
        counts, skipped = await self._execute(sync_plan, started, refusals)
        refusals.save(complete=skipped is None)
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
            upload_failures=refusals.current,
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

    async def _execute(
        self, sync_plan: SyncPlan, now: datetime, refusals: _Refusals
    ) -> tuple[Counter[str], str | None]:
        counts: Counter[str] = Counter()
        copies = [a for a in sync_plan.actions if isinstance(a, Trash)]
        writes = [a for a in sync_plan.actions if not isinstance(a, Trash)]
        # Every trash copy is committed before any store write that could destroy its
        # original; if the cycle then stops, the copies are idempotent (stable trash ids).
        # Base updates share one transaction: a lost one is re-derived by the next cycle.
        with self._state.transaction():
            for copy in copies:
                await self._apply_local(copy, now, counts)
        with self._state.transaction():
            for action in writes:
                skip = await self._apply_write(action, now, counts, refusals)
                if skip is not None:
                    return counts, skip
        return counts, None

    async def _apply_write(
        self, action: Action, now: datetime, counts: Counter[str], refusals: _Refusals
    ) -> str | None:
        """Apply one store write; return the skip reason that ends the cycle, if any."""
        try:
            match action:
                case Trash() | CreateLocal() | UpdateLocal() | DeleteLocal() | ForkLocal():
                    await self._apply_local(action, now, counts)
                case _:
                    await self._apply_remote(action, counts, refusals)
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

    async def _apply_local(
        self,
        action: Trash | CreateLocal | UpdateLocal | DeleteLocal | ForkLocal,
        now: datetime,
        counts: Counter[str],
    ) -> None:
        state = self._state
        match action:
            case Trash(credential, reason):
                entry = _trash_entry(credential, reason, now)
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
        refusals: _Refusals,
    ) -> None:
        state = self._state
        match action:
            case CreateRemote(credential):
                if await self._upload(credential, None, refusals):
                    counts["created_remote"] += 1
            case UpdateRemote(credential, etag):
                if await self._upload(credential, etag, refusals):
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

    async def _upload(self, credential: Credential, etag: str | None, refusals: _Refusals) -> bool:
        """Write `credential` to iCloud; False when iCloud refuses it (now or still waiting)."""
        if not refusals.waiting(credential):
            try:
                new_etag = await self._remote.upsert(credential, etag)
            except ItemRejected as exc:
                # Like a lost race, only this item is abandoned and the next cycle plans the
                # same upload; the schedule decides when it runs.
                refusals.refused(credential, str(exc))
            else:
                refusals.accepted(credential.id)
                self._state.set_base(BaseEntry(credential, new_etag))
                return True
        if etag is None:
            # A creation means iCloud lacks the item while the keyring keeps it (a new item,
            # an edit that beat a delete, a held deletion the user restored). With no base,
            # every later cycle plans it as keyring-only, so a refused restore stays an
            # upload to retry instead of turning into a local deletion.
            self._state.drop_base(credential.id)
        return False

    # ------------------------------------------------------------------ trash

    def trash(self) -> list[TrashEntry]:
        """Trash entries still inside the retention window, newest first."""
        return self._state.trash(since=self._clock() - self._policy.trash_retention)

    async def restore(self, trash_id: str) -> str:
        """Put a trashed version back into the keyring; the next cycle uploads it.

        iCloud Keychain keeps one login per site and username, so a version whose twin is
        live in the keyring (a conflict loser and its winner, or the login saved again since)
        cannot come back next to it: it replaces the twin in place, as the current version of
        that login, and the displaced version goes to trash so nothing is lost. Without a
        twin the copy gets a fresh id: the original id may be tombstoned in iCloud, and
        reusing it would collide with Apple's Recently Deleted record.
        """
        entry = self._state.get_trash(trash_id)
        if entry is None:
            raise KeyError(trash_id)
        now = self._clock()
        twin = self._live_twin(entry.credential, (await self._local.fetch()).items)
        if twin is None:
            restored = dataclasses.replace(
                entry.credential, id=str(uuid.uuid4()).upper(), modified=now
            )
            await self._local.upsert(restored)
        elif content_key(twin) == content_key(entry.credential):
            restored = twin
        else:
            restored = dataclasses.replace(entry.credential, id=twin.id, modified=now)
            # Committed before the overwrite and kept even if the write fails: a failed
            # write may still have landed (a lost reply), and then this is the only copy.
            self._state.add_trash(_trash_entry(twin, "conflict", now))
            await self._local.upsert(restored)
            with self._state.transaction():
                self._mark_restored_as_edit(twin, restored)
                self._state.remove_trash(trash_id)
            return restored.id
        self._state.remove_trash(trash_id)
        return restored.id

    def _mark_restored_as_edit(self, displaced: Credential, restored: Credential) -> None:
        """Make the planner see the restore as an edit of `displaced` into `restored`.

        Restoring the version both sides last agreed on would otherwise read as "no change
        in the keyring", and a pending iCloud edit of the login would overwrite it unseen.
        Recording the displaced version as the agreed one makes the restore compete like
        any keyring edit: newer wins, the loser goes to trash.
        """
        base = self._state.bases().get(restored.id)
        if base is not None and content_key(base.credential) == content_key(restored):
            self._state.set_base(BaseEntry(displaced, base.etag))

    def _live_twin(self, version: Credential, live: Mapping[str, Credential]) -> Credential | None:
        """Return the keyring login iCloud would see as the same login as `version`, if any."""
        identity = login_identity(version)
        if identity is None:
            return None
        twins = [c for c in live.values() if login_identity(c) == identity]
        if len(twins) <= 1:
            return twins[0] if twins else None
        # Several keyring logins share the identity (Seahorse duplicates, or iCloud logins
        # that differ only in what a Credential does not carry). Prefer the one whose written
        # port matches too (`:443` next to a portless login are two keychain logins), then the
        # version's own login, then the one iCloud already has.
        exact = login_identity(version, exact_port=True)
        synced = self._state.bases().keys()
        return min(
            twins,
            key=lambda c: (
                login_identity(c, exact_port=True) != exact,
                c.id != version.id,
                c.id not in synced,
                c.id,
            ),
        )

    def purge(self, trash_id: str) -> None:
        """Delete a trash entry for good."""
        if not self._state.remove_trash(trash_id):
            raise KeyError(trash_id)
