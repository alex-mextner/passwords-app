# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Pure three-way planner: spec §5 turned into an ordered list of actions.

`plan()` compares, per item id, the last synced version (base) with the current remote
(iCloud) and local (keyring) views and decides what the engine must write. It does no I/O,
so every rule in the spec table is testable as a plain function call.

Write actions carry their own base update: the engine records the new base only after the
store write succeeded, so a failed write leaves the base untouched and the next cycle
re-plans the same item from the truth instead of from a half-applied plan.
"""

from __future__ import annotations

import dataclasses
import hashlib
import operator
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from passwords_app.core.model import Credential, TrashReason
from passwords_app.core.urls import link_host, login_identity, site_key
from passwords_app.sync.ports import PendingDeletions

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from passwords_app.core.urls import LoginIdentity
    from passwords_app.sync.ports import LocalSnapshot, RemoteItem, RemoteSnapshot, SyncPolicy


@dataclass(frozen=True, slots=True)
class BaseEntry:
    """The version both sides agreed on at the end of the last successful sync of an item."""

    credential: Credential
    etag: str | None


@dataclass(frozen=True, slots=True)
class CreateLocal:
    """Copy a remote item into the keyring; base := (credential, etag)."""

    credential: Credential
    etag: str | None

    @property
    def item_id(self) -> str:
        return self.credential.id


@dataclass(frozen=True, slots=True)
class UpdateLocal:
    """Overwrite the keyring item with the remote version; base := (credential, etag)."""

    credential: Credential
    etag: str | None

    @property
    def item_id(self) -> str:
        return self.credential.id


@dataclass(frozen=True, slots=True)
class DeleteLocal:
    """Remove the keyring item; the base is dropped."""

    item_id: str


@dataclass(frozen=True, slots=True)
class MergeLocal:
    """Move the keyring item `local_id` onto `credential.id`, its twin's id; base untouched.

    iCloud Keychain keeps one login per site and username, so a newer keyring duplicate of
    a login can only reach iCloud as that login's new version: written over the twin in the
    keyring, then uploaded by an `UpdateRemote` that records the base; a failed upload is
    planned again next cycle from the keyring version.
    """

    local_id: str
    credential: Credential

    @property
    def item_id(self) -> str:
        return self.credential.id


@dataclass(frozen=True, slots=True)
class CreateRemote:
    """Create the item in iCloud (no etag condition); base := (credential, new etag)."""

    credential: Credential

    @property
    def item_id(self) -> str:
        return self.credential.id


@dataclass(frozen=True, slots=True)
class UpdateRemote:
    """Overwrite the iCloud record if it still has `etag`; base := (credential, new etag)."""

    credential: Credential
    etag: str | None

    @property
    def item_id(self) -> str:
        return self.credential.id


@dataclass(frozen=True, slots=True)
class DeleteRemote:
    """Delete the iCloud record if it still has `etag`; the base is dropped."""

    item_id: str
    etag: str | None


@dataclass(frozen=True, slots=True)
class Link:
    """Adopt `credential` (remote) as the synced version of the local item `local_id`.

    When the ids differ, the keyring item is re-keyed: the remote credential is written
    locally and the item under `local_id` removed. base := (credential, etag).
    """

    local_id: str
    credential: Credential
    etag: str | None

    @property
    def item_id(self) -> str:
        return self.credential.id


@dataclass(frozen=True, slots=True)
class Trash:
    """Keep a removed or overwritten version for restore."""

    credential: Credential
    reason: TrashReason

    @property
    def item_id(self) -> str:
        return self.credential.id


@dataclass(frozen=True, slots=True)
class SetBase:
    """Record agreement without writing to either store."""

    credential: Credential
    etag: str | None

    @property
    def item_id(self) -> str:
        return self.credential.id


@dataclass(frozen=True, slots=True)
class DropBase:
    item_id: str


type Action = (
    CreateLocal
    | UpdateLocal
    | DeleteLocal
    | MergeLocal
    | CreateRemote
    | UpdateRemote
    | DeleteRemote
    | Link
    | Trash
    | SetBase
    | DropBase
)


_KEYRING_WRITES = (CreateLocal, UpdateLocal, DeleteLocal, MergeLocal, Link)


@dataclass(frozen=True, slots=True)
class SyncPlan:
    """Actions in execution order.

    Per item, `Trash` precedes the write it protects and an iCloud write comes last. Every
    keyring write precedes every iCloud write.
    """

    actions: tuple[Action, ...]
    pending: PendingDeletions | None = None


@dataclass(frozen=True, slots=True)
class PauseDecision:
    """The user's answer to a mass-delete pause: apply the held deletions or undo them."""

    pending: PendingDeletions
    apply: bool


type ContentKey = tuple[object, ...]

# Equal content keys <=> equal `Credential.content_hash()` (same fields, no id/timestamps),
# but at a fraction of the cost: hashing 30 000 credentials alone would blow the
# 100 ms budget for a 10 000-item plan. Derived from the dataclass so a new field cannot
# be forgotten here.
_CONTENT_FIELDS = tuple(
    f.name for f in dataclasses.fields(Credential) if f.name not in {"id", "created", "modified"}
)
content_key: Callable[[Credential], ContentKey] = operator.attrgetter(*_CONTENT_FIELDS)

type _Side = Literal["local", "remote"]


def trash_id(credential: Credential, reason: TrashReason) -> str:
    """Stable id of a trash entry, so re-running a half-applied cycle does not duplicate it."""
    digest = hashlib.sha256(
        f"{credential.id}\0{credential.content_hash()}\0{reason}".encode()
    ).hexdigest()
    return digest[:32]


def _link_key(c: Credential) -> tuple[str, str, str] | None:
    host = link_host(c.url)
    return (host, c.username, c.password) if host else None


def _remote_candidates(
    base: Mapping[str, BaseEntry],
    remote: Mapping[str, RemoteItem],
    local: Mapping[str, Credential],
) -> dict[tuple[str, str, str], deque[str]]:
    """Unsynced remote item ids by link key, in id order."""
    candidates: dict[tuple[str, str, str], deque[str]] = {}
    for rid in sorted(remote):
        if rid in base:
            continue
        same_id_local = local.get(rid)
        # A remote item already copied under its own id with identical content is a link
        # that stopped before removing the old keyring item; finishing it avoids a duplicate.
        if same_id_local is not None and content_key(same_id_local) != content_key(
            remote[rid].credential
        ):
            continue
        key = _link_key(remote[rid].credential)
        if key is not None:
            candidates.setdefault(key, deque()).append(rid)
    return candidates


def _link_pairs(
    base: Mapping[str, BaseEntry],
    remote: Mapping[str, RemoteItem],
    local: Mapping[str, Credential],
) -> list[tuple[str, str]]:
    """Pair unsynced local items with unsynced remote items describing the same login."""
    local_new = sorted(i for i in local if i not in base and i not in remote)
    if not local_new:
        return []
    candidates = _remote_candidates(base, remote, local)
    if not candidates:
        return []
    pairs: list[tuple[str, str]] = []
    for lid in local_new:
        key = _link_key(local[lid])
        matches = candidates.get(key) if key is not None else None
        if matches:
            pairs.append((lid, matches.popleft()))
    return pairs


def _login_twins(remote: Mapping[str, RemoteItem]) -> dict[LoginIdentity, list[str]]:
    """Group iCloud item ids by the identity iCloud Keychain keeps one login of."""
    twins: dict[LoginIdentity, list[str]] = {}
    for rid in sorted(remote):
        identity = login_identity(remote[rid].credential)
        if identity is not None:
            twins.setdefault(identity, []).append(rid)
    return twins


def _only_twin(dup: Credential, ids: list[str], remote: Mapping[str, RemoteItem]) -> str | None:
    """Pick the one iCloud login among `ids` that `dup` collides with, else None.

    `login_identity` treats a written default port as none, so `https://x` and
    `https://x:443` share it while iCloud keeps them apart: the written port decides, and an
    item matching none or several of them is no one's duplicate.
    """
    if len(ids) == 1:
        return ids[0]
    exact = login_identity(dup, exact_port=True)
    same = [i for i in ids if login_identity(remote[i].credential, exact_port=True) == exact]
    return same[0] if len(same) == 1 else None


def _covered(record: Credential, login: Credential) -> bool:
    """Whether `login` holds everything `record` has: account, password, sites, metadata."""
    sites = {site_key(u) for u in (login.url, *login.alt_urls)}
    return (
        (record.username, record.password) == (login.username, login.password)
        and all(site_key(u) in sites for u in (record.url, *record.alt_urls))
        and all(
            mine in (None, "", theirs)
            for mine, theirs in (
                (record.title, login.title),
                (record.notes, login.notes),
                (record.otpauth, login.otpauth),
            )
        )
    )


def _too_many(policy: SyncPolicy, count: int, items: int) -> bool:
    return count > max(policy.mass_delete_min, policy.mass_delete_ratio * items)


def _keyring_writes_first(groups: list[tuple[Action, ...]]) -> tuple[Action, ...]:
    # Keyring writes run before any iCloud round trip: a conditional keyring write that
    # loses to a fresh edit only postpones its item, but every round trip before it widens
    # that window. The sort is stable and moves whole groups, so dependencies inside a
    # group are kept.
    groups.sort(key=lambda group: not any(isinstance(a, _KEYRING_WRITES) for a in group))
    return tuple(a for group in groups for a in group)


class _Planner:
    def __init__(
        self,
        base: Mapping[str, BaseEntry],
        remote: Mapping[str, RemoteItem],
        local: Mapping[str, Credential],
        decision: PauseDecision | None,
    ) -> None:
        self.base = base
        self.remote = remote
        self.local = local
        none = frozenset[str]()
        restore = decision if decision is not None and not decision.apply else None
        approve = decision if decision is not None and decision.apply else None
        self.restore_local = frozenset(restore.pending.local_ids) if restore else none
        self.restore_remote = frozenset(restore.pending.remote_ids) if restore else none
        self.approved_local = frozenset(approve.pending.local_ids) if approve else none
        self.approved_remote = frozenset(approve.pending.remote_ids) if approve else none
        self.local_incomplete = False
        # Items the user restored from trash over their live login since the last sync.
        self.restored = none
        # Each group is one item's actions; deletions are tagged so the guard can hold them.
        self.groups: list[tuple[tuple[Action, ...], _Side | None, str]] = []

    def emit(self, item_id: str, *actions: Action, deletes: _Side | None = None) -> None:
        self.groups.append((actions, deletes, item_id))

    def merge_duplicates(self, settled: set[str]) -> None:
        """Resolve new keyring logins that duplicate an iCloud login's site and username.

        iCloud refuses a second login for the same site and username, so uploading one would
        fail forever (#71): the newer version takes the iCloud login's id and the other goes
        to trash. Every id resolved here is added to `settled` and skipped for this cycle.
        """
        new = {
            lid: identity
            for lid in sorted(self.local)
            if lid not in self.base and lid not in self.remote and lid not in settled
            if (identity := login_identity(self.local[lid])) is not None
        }
        # Indexing every iCloud login costs a URL parse each: only when a candidate exists.
        twins = _login_twins(self.remote) if new else {}
        for lid, identity in new.items():
            twin = self._twin(lid, identity, twins)
            if twin is None:
                continue
            settled.add(lid)
            if twin not in settled:
                # Otherwise another duplicate replaced the twin this cycle; this one waits.
                self.merge(lid, twin, settled)

    def _twin(
        self, lid: str, identity: LoginIdentity, twins: Mapping[LoginIdentity, list[str]]
    ) -> str | None:
        """Return the iCloud login the new keyring item `lid` duplicates, if it should merge."""
        ids = twins.get(identity)
        twin = _only_twin(self.local[lid], ids, self.remote) if ids else None
        if twin is None:
            return None
        held = self.local.get(twin)
        # A twin deleted on this side is about to be deleted in iCloud too, and one edited
        # to another site no longer collides: either way the duplicate uploads on its own.
        if held is None:
            return None if twin in self.base else twin
        return twin if login_identity(held) == identity else None

    def merge(self, lid: str, rid: str, settled: set[str]) -> None:
        dup = self.local[lid]
        item = self.remote[rid]
        current = self.local.get(rid) or item.credential
        # A login the user restored from trash is their explicit choice and stays.
        dup_wins = lid in self.restored or (
            rid not in self.restored and dup.modified > current.modified
        )
        if not dup_wins or content_key(dup) == content_key(current):
            # Ties go to the login iCloud already holds, as in `both_changed`.
            self.emit(lid, Trash(dup, "conflict"), DeleteLocal(lid))
        elif self._quiet(rid):
            settled.add(rid)
            winner = dataclasses.replace(dup, id=rid)
            # Separate groups: the upload must not sit between the keyring writes.
            self.emit(rid, Trash(current, "conflict"), MergeLocal(lid, winner))
            self.emit(rid, UpdateRemote(winner, item.etag))
        # Otherwise the twin's own versions are resolved first; the duplicate waits.

    def _quiet(self, rid: str) -> bool:
        """Whether `current` in `merge` is the only version of `rid` the upload replaces."""
        b = self.base.get(rid)
        if b is None:
            return rid not in self.local
        return content_key(self.remote[rid].credential) == content_key(b.credential)

    def link(self, lid: str, rid: str) -> None:
        item = self.remote[rid]
        loc = self.local[lid]
        if content_key(loc) == content_key(item.credential):
            self.emit(rid, Link(lid, item.credential, item.etag))
        else:
            # The iCloud record is the fuller copy (title, notes, codes); the keyring item
            # differs only in what Seahorse-style entry could not express, kept in trash.
            self.emit(rid, Trash(loc, "conflict"), Link(lid, item.credential, item.etag))

    def unbased(self, item_id: str, item: RemoteItem | None, loc: Credential | None) -> None:
        if item is not None and loc is not None:
            if content_key(item.credential) == content_key(loc):
                self.emit(item_id, Link(item_id, item.credential, item.etag))
            else:
                # Both sides created the id: iCloud fits one login per site and username,
                # so the newer version wins as for an edit on both sides (#71).
                self.both_changed(item_id, item, loc, local_wins=False)
        elif item is not None:
            self.emit(item_id, CreateLocal(item.credential, item.etag))
        elif loc is not None:
            self.emit(item_id, CreateRemote(loc))

    def based(
        self, item_id: str, b: BaseEntry, item: RemoteItem | None, loc: Credential | None
    ) -> None:
        bkey = content_key(b.credential)
        if item is None:
            if loc is None:
                self.emit(item_id, Trash(b.credential, "deleted-both"), DropBase(item_id))
            elif (
                content_key(loc) != bkey
                or item_id in self.restore_local
                or item_id in self.restored
            ):
                # Edit beats delete (or the user chose to restore the held deletion).
                self.emit(item_id, CreateRemote(loc))
            else:
                self.emit(
                    item_id,
                    Trash(b.credential, "deleted-in-icloud"),
                    DeleteLocal(item_id),
                    deletes="local",
                )
            return
        rkey = content_key(item.credential)
        if loc is None:
            if rkey != bkey or item_id in self.restore_remote:
                self.emit(item_id, CreateLocal(item.credential, item.etag))
            elif self.local_incomplete:
                # A keyring item that failed to parse may be this one: absent is not deleted.
                return
            else:
                self.emit(
                    item_id,
                    Trash(b.credential, "deleted-on-linux"),
                    DeleteRemote(item_id, item.etag),
                    deletes="remote",
                )
            return
        self.both_present(item_id, b, item, loc)

    def absorb(self, merged: Mapping[str, str]) -> frozenset[str]:
        """Retire every record `merged` names that left the snapshot; return their ids."""
        gone = sorted(
            (
                (item_id, self.remote[into])
                for item_id, into in merged.items()
                if item_id not in self.remote and into in self.remote
            ),
            key=operator.itemgetter(0),
        )
        for item_id, into in gone:
            self.absorbed(item_id, into, self.local.get(item_id))
        return frozenset(item_id for item_id, _ in gone)

    def absorbed(self, item_id: str, into: RemoteItem, loc: Credential | None) -> None:
        """Retire `item_id`, a record iCloud now reads as part of the login `into`.

        Not a deletion (see `RemoteSnapshot.merged`), so the mass-delete guard does not
        hold it. A keyring copy goes to trash unless `into` holds all of it or it holds no
        edit iCloud never saw (it equals the base and the user did not restore it).
        """
        b = self.base.get(item_id)
        if loc is None:
            if b is not None:
                self.emit(item_id, DropBase(item_id))
            return
        unedited = (
            b is not None
            and content_key(b.credential) == content_key(loc)
            and item_id not in self.restored
        )
        if unedited or _covered(loc, into.credential):
            self.emit(item_id, DeleteLocal(item_id))
        else:
            self.emit(item_id, Trash(loc, "conflict"), DeleteLocal(item_id))

    def both_present(self, item_id: str, b: BaseEntry, item: RemoteItem, loc: Credential) -> None:
        bkey = content_key(b.credential)
        rkey = content_key(item.credential)
        lkey = content_key(loc)
        remote_changed = rkey != bkey
        # A restore is the user's explicit choice: it counts as a keyring edit against any
        # iCloud edit, even when it brought back the version both sides last agreed on.
        restored = item_id in self.restored
        local_changed = lkey != bkey or (restored and remote_changed)
        if not remote_changed and not local_changed:
            if item.etag != b.etag:
                self.emit(item_id, SetBase(item.credential, item.etag))
        elif not local_changed:
            self.emit(item_id, UpdateLocal(item.credential, item.etag))
        elif not remote_changed:
            self.emit(item_id, UpdateRemote(loc, item.etag))
        else:
            self.both_changed(item_id, item, loc, local_wins=restored)

    def both_changed(
        self, item_id: str, item: RemoteItem, loc: Credential, *, local_wins: bool
    ) -> None:
        """Resolve an edit on both sides; `local_wins` overrides the newer-wins rule."""
        if content_key(item.credential) == content_key(loc):
            self.emit(item_id, SetBase(item.credential, item.etag))
        elif local_wins or loc.modified > item.credential.modified:
            self.emit(item_id, Trash(item.credential, "conflict"), UpdateRemote(loc, item.etag))
        else:
            # Ties go to iCloud: it is the copy every other device already sees.
            self.emit(item_id, Trash(loc, "conflict"), UpdateLocal(item.credential, item.etag))

    def _deleting(self, side: _Side, approved: frozenset[str]) -> list[str]:
        """Ids of this side's deletion groups that the user has not approved."""
        return [i for _, s, i in self.groups if s == side and i not in approved]

    def _holds(
        self,
        policy: SyncPolicy,
        held: PendingDeletions | None,
        local_ids: list[str],
        remote_ids: list[str],
    ) -> tuple[list[str], list[str]]:
        if _too_many(policy, len(local_ids), len(self.local)) or _too_many(
            policy, len(remote_ids), len(self.remote)
        ):
            return local_ids, remote_ids
        if held is not None:
            was_local, was_remote = frozenset(held.local_ids), frozenset(held.remote_ids)
            return [i for i in local_ids if i in was_local], [
                i for i in remote_ids if i in was_remote
            ]
        return [], []

    def guarded(self, policy: SyncPolicy, held: PendingDeletions | None) -> SyncPlan:
        """Flatten the groups, holding unapproved deletions when there are too many.

        Deletions held by an earlier, still unanswered pause stay held whatever the count
        is now: only the user releases them, even if some of the items came back meanwhile.
        """
        local_ids = self._deleting("local", self.approved_local)
        remote_ids = self._deleting("remote", self.approved_remote)
        hold_local, hold_remote = self._holds(policy, held, local_ids, remote_ids)
        hold = {("local", i) for i in hold_local} | {("remote", i) for i in hold_remote}
        kept = [
            g for g, side, item_id in self.groups if side is None or (side, item_id) not in hold
        ]
        actions = _keyring_writes_first(kept)
        if not hold:
            return SyncPlan(actions)
        return SyncPlan(actions, PendingDeletions(tuple(hold_local), tuple(hold_remote)))


def plan(  # noqa: PLR0913 - the pause state is part of what decides deletions
    base: Mapping[str, BaseEntry],
    remote: RemoteSnapshot,
    local: LocalSnapshot,
    policy: SyncPolicy,
    *,
    decision: PauseDecision | None = None,
    held: PendingDeletions | None = None,
    restored: frozenset[str] = frozenset(),
) -> SyncPlan:
    """Decide every action for one cycle (spec §5), holding mass deletions back.

    `held` is an unanswered earlier pause: those deletions stay held. `decision` carries the
    user's answer to a pause: approved deletions bypass the guard; restored ones become
    re-creations from the side that still has the item. `restored` names keyring logins the
    user restored from trash: each wins against an iCloud edit, whose version goes to trash.
    """
    planner = _Planner(base, remote.items, local.items, decision)
    planner.local_incomplete = bool(local.rejected)
    planner.restored = restored
    absorbed = planner.absorb(remote.merged)
    unabsorbed = {i: c for i, c in local.items.items() if i not in absorbed}
    settled: set[str] = set(absorbed)
    for lid, rid in _link_pairs(base, remote.items, unabsorbed):
        planner.link(lid, rid)
        settled.add(lid)
        settled.add(rid)
    planner.merge_duplicates(settled)

    for item_id in sorted(base.keys() | remote.items.keys() | local.items.keys()):
        if item_id in settled:
            continue
        b = base.get(item_id)
        item = remote.items.get(item_id)
        loc = local.items.get(item_id)
        if b is None:
            planner.unbased(item_id, item, loc)
        else:
            planner.based(item_id, b, item, loc)

    return planner.guarded(policy, held)
