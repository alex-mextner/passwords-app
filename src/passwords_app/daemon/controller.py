# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The daemon's behavior, independent of D-Bus: items, trash, sync cycles, status, sign-in.

The daemon is the only writer of the synced keyring collection besides the user's own tools,
so every write it makes (app/browser `Save`/`Delete`, trash restore, a sync cycle) runs under
one lock: an app edit can never interleave with a cycle that planned from older data and
overwrite it. Items are served from the last complete keyring snapshot; a locked or
unreachable keyring drops that snapshot so no password is handed out while it is locked.

Account changes are guarded the same way: signing out, or signing in to a different Apple ID,
forgets the per-item sync bases. Otherwise the next cycle would read every item missing from
the new account as "deleted in iCloud" and remove it from the keyring.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from dbus_fast import Variant

from passwords_app.core.model import Credential, TrashEntry
from passwords_app.core.otp import OtpError, code_at, parse_otpauth
from passwords_app.core.urls import MatchKind, link_host, match
from passwords_app.daemon.account import STEP_CODE, STEP_DONE
from passwords_app.daemon.echo import Echo, WriteJournal, settled
from passwords_app.daemon.errors import (
    AuthRequiredError,
    InvalidError,
    LockedError,
    NotFoundError,
    UnavailableError,
)
from passwords_app.daemon.items import apply_edit
from passwords_app.daemon.scheduler import Scheduler
from passwords_app.daemon.status import (
    MSG_NOT_JOINED,
    MSG_SESSION_UNREADABLE,
    MSG_SIGNED_OUT,
    Status,
    outcome,
    paused_message,
)
from passwords_app.sync.engine import LAST_SYNC_KEY, NoPendingDeletionsError, SyncEngine
from passwords_app.sync.plan import content_key, trash_id
from passwords_app.sync.ports import (
    AuthRequired,
    ConflictError,
    LocalUnavailable,
    RemoteUnavailable,
    SyncPolicy,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Mapping, Sequence

    from passwords_app.core.model import TrashReason
    from passwords_app.daemon.account import AccountInfo, AccountPort, RecoveryDevice
    from passwords_app.daemon.items import ItemEdit
    from passwords_app.daemon.notify import Notifier
    from passwords_app.daemon.scheduler import Clock
    from passwords_app.store.state import StateStore
    from passwords_app.sync.ports import (
        LocalSnapshot,
        LocalStore,
        RemoteSnapshot,
        RemoteStore,
        SyncReport,
        SyncState,
        UploadFailure,
    )

ACCOUNT_KEY = "apple-id"
WATCH_RETRY_SECONDS = 30.0
MAX_LISTED_REJECTS = 5
# Notification topic prefix for a login iCloud refused; one notification per login.
REFUSED_TOPIC = "refused:"
# Reads retried when the keyring's lock state changes while they are in flight.
FETCH_ATTEMPTS = 3
_CODE = re.compile(r"[0-9]{6}")

MSG_CODE_DEVICE = "Enter the 6-digit verification code shown on your iPhone, iPad, or Mac."
MSG_CODE_SMS = "Enter the 6-digit verification code sent to your phone by text message."
MSG_DEVICE = (
    "Confirm with a device passcode. Apple keeps your keychain keys sealed with the screen "
    "passcode of each of your devices; entering one device's passcode lets this computer join."
)
MSG_DONE = "This computer is now part of your iCloud Keychain."
MSG_CRASH = "Sync failed unexpectedly. Details are in the system journal."

_log = logging.getLogger(__name__)


def new_item_id() -> str:
    return str(uuid.uuid4()).upper()


def _sort_key(c: Credential) -> tuple[str, str, str]:
    return ((c.title or link_host(c.url) or c.url).casefold(), c.username.casefold(), c.id)


def _refusal_notice(failure: UploadFailure) -> tuple[str, str]:
    """Return the notification summary and body for a login iCloud refused to store."""
    reason = failure.reason.rstrip(".")
    if reason[1:2].islower():  # leave "iCloud …" as is
        reason = reason[:1].upper() + reason[1:]
    who = f"The password for {failure.username}" if failure.username else "This password"
    summary = f"Couldn't save “{link_host(failure.url) or failure.url}” to iCloud"
    body = (
        f"{reason}. {who} stays on this computer only; everything else keeps syncing. "
        "Edit or delete it to fix this."
    )
    return summary, body


@dataclass(frozen=True, slots=True)
class SignInStep:
    step: str
    destination: str
    message: str

    def to_dbus(self) -> dict[str, Variant]:
        return {
            "step": Variant("s", self.step),
            "destination": Variant("s", self.destination),
            "message": Variant("s", self.message),
        }


class CachingLocal:
    """`LocalStore` that remembers the last complete snapshot until anything changes.

    Reads run outside the daemon's write lock, so a read can overlap a write, a change
    signal or a lock. Its result is cached only if nothing was invalidated meanwhile (an
    older picture must not replace a newer one), and is not even returned across a lock.

    While a sync cycle journals (see `begin_journal`) the cycle's own first read and its
    writes are recorded, so the daemon can recognize the keyring's change signals for them.
    """

    def __init__(self, inner: LocalStore) -> None:
        self._inner = inner
        self.snapshot: LocalSnapshot | None = None
        self._generation = 0
        self._lock_generation = 0
        self._journal: WriteJournal | None = None
        self._journal_task: asyncio.Task[object] | None = None

    def begin_journal(self) -> WriteJournal:
        """Journal the calling task's reads and every write until `end_journal`."""
        self._journal = WriteJournal()
        self._journal_task = asyncio.current_task()
        return self._journal

    def end_journal(self) -> None:
        self._journal = self._journal_task = None

    def invalidate(self) -> None:
        """Drop the snapshot; a read already in flight will not cache its older result."""
        self.snapshot = None
        self._generation += 1

    def lock_changed(self) -> None:
        """Drop the snapshot, and the result of any read that started before this call.

        A read in flight may have passed the keyring's lock check just before it locked;
        its result must neither be cached nor returned.
        """
        self.invalidate()
        self._lock_generation += 1

    async def fetch(self) -> LocalSnapshot:
        for _ in range(FETCH_ATTEMPTS):
            generation, lock_generation = self._generation, self._lock_generation
            try:
                snapshot = await self._inner.fetch()
            except LocalUnavailable:
                self.snapshot = None
                raise
            if lock_generation != self._lock_generation:
                continue
            if generation == self._generation:
                self.snapshot = snapshot
            if self._journal is not None and asyncio.current_task() is self._journal_task:
                self._journal.read(snapshot)
            return snapshot
        self.snapshot = None
        msg = "the keyring kept locking and unlocking during the read"
        raise LocalUnavailable(msg)

    async def upsert(self, credential: Credential, *, expected: str | None = None) -> None:
        # Before and after: a read starting while the write is under way may miss it.
        self.invalidate()
        try:
            await self._inner.upsert(credential, expected=expected)
        finally:
            self.invalidate()
        if self._journal is not None:
            self._journal.upserted(credential)

    async def delete(self, item_id: str, *, expected: str | None = None) -> None:
        self.invalidate()
        try:
            await self._inner.delete(item_id, expected=expected)
        finally:
            self.invalidate()
        if self._journal is not None:
            self._journal.deleted(item_id)

    def changes(self) -> AsyncIterator[None]:
        return self._inner.changes()


class AccountRemote:
    """`RemoteStore` of the signed-in account; `AuthRequired` while there is none.

    The account's store is opened on first use, not at sign-in or startup: opening it may
    need the network, so a daemon that starts before the network is up still comes up, and
    its cycles report "offline" and retry like any cycle that cannot reach iCloud.
    """

    def __init__(self) -> None:
        self._open: Callable[[], RemoteStore] | None = None
        self._target: RemoteStore | None = None

    @property
    def signed_in(self) -> bool:
        return self._open is not None

    def use(self, open_store: Callable[[], RemoteStore] | None) -> None:
        """Switch to the account whose store `open_store` opens (blocking); None: signed out."""
        self._open, self._target = open_store, None

    async def _store(self) -> RemoteStore:
        if self._target is None:
            if self._open is None:
                msg = "not signed in to iCloud"
                raise AuthRequired(msg)
            try:
                self._target = await asyncio.to_thread(self._open)
            except AuthRequiredError as exc:
                raise AuthRequired(str(exc)) from exc
            except UnavailableError as exc:
                raise RemoteUnavailable(str(exc)) from exc
        return self._target

    async def fetch(self) -> RemoteSnapshot:
        return await (await self._store()).fetch()

    async def upsert(self, credential: Credential, etag: str | None) -> str:
        return await (await self._store()).upsert(credential, etag)

    async def delete(self, item_id: str, etag: str | None) -> None:
        await (await self._store()).delete(item_id, etag)


class Daemon:
    def __init__(  # noqa: PLR0913 - the composition root hands over every collaborator
        self,
        *,
        account: AccountPort,
        local: LocalStore,
        state: StateStore,
        clock: Clock,
        notifier: Notifier,
        policy: SyncPolicy | None = None,
    ) -> None:
        self._account = account
        self._local = CachingLocal(local)
        self._remote = AccountRemote()
        self._store = state
        self._clock = clock
        self._notifier = notifier
        self._policy = policy or SyncPolicy()
        self._engine = SyncEngine(
            self._remote,
            self._local,
            state,
            policy=self._policy,
            clock=clock.now,
            on_upload_rejected=self._upload_refused,
        )
        self.scheduler = Scheduler(self._cycle, clock)
        self._lock = asyncio.Lock()
        self._signin_lock = asyncio.Lock()
        self._state: SyncState = "signed-out"
        self._message = MSG_SIGNED_OUT
        self._apple_id = ""
        # Signed in, password and code done, only the device passcode is missing.
        self._join_pending = False
        self._published: dict[str, tuple[object, ...]] | None = None
        self._announced: LocalSnapshot | None = None
        self._awaiting_code: str | None = None
        self._devices: set[str] = set()
        self._rejected_seen: frozenset[str] = frozenset()
        # Logins iCloud refused during the engine call in progress; announced after it.
        self._refused: dict[str, UploadFailure] = {}
        # Why iCloud refuses each login it has not stored yet (the item dicts' sync_problem).
        self._problems: dict[str, str] = {}
        self._alerts: set[str] = set()
        self._tasks: list[asyncio.Task[None]] = []
        # The keyring content the last cycle left behind (see echo.py), and the pending
        # comparison of a change signal against it.
        self._echo: Echo | None = None
        self._echo_check: asyncio.Task[None] | None = None
        self._recheck = False
        # Trash entries of failed deletes that may or may not have happened (see `delete`).
        self._unsettled_trash: dict[str, TrashEntry] = {}
        self.on_status: Callable[[Status], None] | None = None
        self.on_items: Callable[[list[str]], None] | None = None
        # The bus name is taken before `start()` has read the account, so a client answered in
        # that gap would be told the construction default ("signed out") as if it were true.
        self._started = asyncio.Event()

    # ------------------------------------------------------------------ lifecycle

    async def until_started(self) -> None:
        """Return once `start()` has adopted the saved account state."""
        await self._started.wait()

    async def start(self) -> None:
        info = await asyncio.to_thread(self._account.status)
        await self._adopt(info)
        self._tasks = [
            asyncio.create_task(self.scheduler.run(), name="scheduler"),
            asyncio.create_task(self._watch_local(), name="keyring-watch"),
        ]
        self._started.set()

    async def stop(self) -> None:
        tasks = [*self._tasks, *([self._echo_check] if self._echo_check else [])]
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks = []
        self._echo_check = None

    def close(self) -> None:
        """Release state.db (after `stop`)."""
        self._store.close()

    @property
    def policy(self) -> SyncPolicy:
        return self._policy

    # ------------------------------------------------------------------ status

    def status(self) -> Status:
        snapshot = self._local.snapshot
        count = len(snapshot.items) if snapshot else len(self._published or {})
        last = self._store.get(LAST_SYNC_KEY)
        pending = self._store.pending()
        signed_in = self._remote.signed_in
        return Status(
            state=self._state,
            apple_id=self._apple_id,
            item_count=count,
            trash_count=len(self._engine.trash()),
            last_sync=datetime.fromisoformat(last) if last else None,
            next_sync=self.scheduler.next_run() if signed_in else None,
            message=self._message,
            pending_local=pending.local_ids if pending and signed_in else (),
            pending_remote=pending.remote_ids if pending and signed_in else (),
            join_pending=self._join_pending,
        )

    def _set(self, state: SyncState, message: str, *, join_pending: bool = False) -> None:
        self._state, self._message, self._join_pending = state, message, join_pending
        self._publish()

    def _publish(self) -> None:
        if self.on_status is not None:
            self.on_status(self.status())

    def touch(self) -> None:
        """Note a client call (app, browser host, CLI): keep the faster sync cadence."""
        self.scheduler.client_seen()

    def keyring_lock_changed(self) -> None:
        """Forget the keyring snapshot: a collection (un)locked, or the keyring changed hands.

        No cached password is handed out after a lock, not even one a read in flight fetched
        just before it: the next request reads the keyring again and gets `LockedError`
        while it stays locked. Like an item change, it also schedules a cycle: after an
        unlock, syncing resumes now rather than when the locked cycles' backoff runs out.
        """
        self._local.lock_changed()
        self.scheduler.local_changed()

    # ------------------------------------------------------------------ account

    async def _adopt(self, info: AccountInfo) -> None:
        """Make the daemon match the account's state (after start or a sign-in step)."""
        self._apple_id = info.apple_id or ""
        if not (info.signed_in and info.joined):
            self._remote.use(None)
            if info.signed_in:
                self._set("signin-required", MSG_NOT_JOINED, join_pending=True)
            else:
                self._set(
                    "signed-out",
                    MSG_SESSION_UNREADABLE if info.session_unreadable else MSG_SIGNED_OUT,
                )
            return
        async with self._lock:
            self._forget_other_account(self._apple_id)
            self._remote.use(self._account.remote_store)
        pending = self._store.pending()
        if pending is not None:
            self._set("paused", paused_message(pending))
        else:
            self._set("idle", "")

    def _forget_other_account(self, apple_id: str) -> None:
        if self._store.get(ACCOUNT_KEY) != apple_id:
            self._forget_bases()
            self._store.set(ACCOUNT_KEY, apple_id)

    def _forget_bases(self) -> None:
        with self._store.transaction():
            for item_id in self._store.bases():
                self._store.drop_base(item_id)
            self._store.set_pending(None)

    async def _step(self, step: str, destination: str) -> SignInStep:
        if step == STEP_CODE:
            self._awaiting_code = destination
            message = MSG_CODE_SMS if destination == "sms" else MSG_CODE_DEVICE
            return SignInStep(step, destination, message)
        self._awaiting_code = None
        await self._adopt(await asyncio.to_thread(self._account.status))
        if step == STEP_DONE:
            self.scheduler.request()
            return SignInStep(step, "", MSG_DONE)
        return SignInStep(step, "", MSG_DEVICE)

    async def sign_in_start(self, apple_id: str, password: str) -> SignInStep:
        apple_id = apple_id.strip()
        if not apple_id or not password:
            msg = "Enter your Apple Account email or phone number and its password."
            raise InvalidError(msg)
        async with self._signin_lock:
            self._awaiting_code = None
            self._devices = set()
            step = await asyncio.to_thread(self._account.sign_in, apple_id, password)
            return await self._step(step, "trusted-device")

    async def sign_in_code(self, code: str) -> SignInStep:
        code = code.replace(" ", "").replace("-", "")
        async with self._signin_lock:
            if self._awaiting_code is None:
                msg = "No sign-in is waiting for a verification code. Start signing in first."
                raise InvalidError(msg)
            if not _CODE.fullmatch(code):
                msg = "The verification code has 6 digits."
                raise InvalidError(msg)
            step = await asyncio.to_thread(self._account.submit_code, code)
            return await self._step(step, self._awaiting_code)

    async def sign_in_request_sms(self) -> SignInStep:
        async with self._signin_lock:
            if self._awaiting_code is None:
                msg = "No sign-in is waiting for a verification code. Start signing in first."
                raise InvalidError(msg)
            step = await asyncio.to_thread(self._account.request_sms)
            return await self._step(step, "sms")

    async def recovery_devices(self) -> list[RecoveryDevice]:
        async with self._signin_lock:
            info = await asyncio.to_thread(self._account.status)
            if not info.signed_in:
                msg = "Sign in with your Apple Account first."
                raise AuthRequiredError(msg)
            devices = await asyncio.to_thread(self._account.recovery_devices)
            self._devices = {d.id for d in devices}
            return devices

    async def join(self, device_id: str, passcode: str) -> SignInStep:
        if not device_id or not passcode:
            msg = "Choose a device and enter its passcode."
            raise InvalidError(msg)
        async with self._signin_lock:
            # Each wrong passcode spends one of that device's few attempts, so only a device
            # the user just picked from the list is ever tried.
            if device_id not in self._devices:
                msg = "Choose one of your devices from the list first."
                raise InvalidError(msg)
            step = await asyncio.to_thread(self._account.join, device_id, passcode)
            return await self._step(step, "")

    async def sign_out(self) -> None:
        async with self._signin_lock, self._lock:
            await asyncio.to_thread(self._account.sign_out)
            self._remote.use(None)
            self._awaiting_code = None
            self._devices = set()
            self._forget_bases()
            self._store.delete(ACCOUNT_KEY)
            self._apple_id = ""
        for topic in list(self._alerts):
            await self._withdraw(topic)
        self._set_problems({})
        self._set("signed-out", MSG_SIGNED_OUT)

    # ------------------------------------------------------------------ cycles

    async def _cycle(self) -> bool:
        if not self._remote.signed_in:
            with contextlib.suppress(LockedError):
                await self._items()
            self._publish()
            return True
        async with self._lock:
            self._set("syncing", "")
            journal = self._local.begin_journal()
            # A crashed call saved no refusal, so the next one reports the same ones again.
            self._refused.clear()
            try:
                report = await self._engine.run_once()
            except Exception:  # noqa: BLE001 - a daemon must outlive any bug in one cycle
                _log.exception("sync cycle failed")
                self._echo = None
                self._set("error", MSG_CRASH)
                return False
            finally:
                self._local.end_journal()
            after = await self._refresh()
            self._echo = settled(journal, after, self._clock.monotonic())
            refused = self._take_refused()
        await self._after(report, refused)
        return report.skipped_reason is None

    def _upload_refused(self, failure: UploadFailure) -> None:
        self._refused[failure.item_id] = failure

    def _take_refused(self) -> list[UploadFailure]:
        """Return this engine call's refusals; taken under the lock, before another call runs."""
        refused, self._refused = list(self._refused.values()), {}
        return refused

    async def _after(self, report: SyncReport, refused: Sequence[UploadFailure]) -> None:
        state, message = outcome(report)
        self._note_problems(report)
        self._set(state, message)
        if state == "paused":
            await self._alert("pause", "Passwords sync is paused", message)
        else:
            await self._withdraw("pause")
        if state == "signin-required":
            await self._alert("signin", "Sign in to iCloud again", message)
        else:
            await self._withdraw("signin")
        await self._report_rejected(report)
        await self._report_refused(report, refused)

    async def _report_refused(self, report: SyncReport, refused: Sequence[UploadFailure]) -> None:
        """One notification per refused version; withdrawn once iCloud no longer refuses it."""
        for failure in refused:
            topic = REFUSED_TOPIC + failure.item_id
            self._alerts.add(topic)
            await self._notifier.notify(topic, *_refusal_notice(failure))
        if report.skipped_reason is not None:
            return  # an interrupted cycle did not look at every login
        waiting = {REFUSED_TOPIC + f.item_id for f in report.upload_failures}
        for topic in sorted(self._alerts):
            if topic.startswith(REFUSED_TOPIC) and topic not in waiting:
                await self._withdraw(topic)

    def sync_problem(self, item_id: str) -> str:
        """Why iCloud refuses to store this login; "" while it syncs."""
        return self._problems.get(item_id, "")

    def _note_problems(self, report: SyncReport) -> None:
        problems = {f.item_id: f.reason for f in report.upload_failures}
        if report.skipped_reason is not None:
            # An interrupted cycle did not look at every login: it can add refusals, not end them.
            problems = self._problems | problems
        self._set_problems(problems)

    def _set_problems(self, problems: dict[str, str]) -> None:
        """Replace the refusals; clients hear of each login whose sync_problem changed."""
        previous, self._problems = self._problems, problems
        changed = sorted(
            i for i in previous.keys() | problems.keys() if previous.get(i) != problems.get(i)
        )
        if changed and self.on_items is not None:
            self.on_items(changed)

    async def _report_rejected(self, report: SyncReport) -> None:
        refs = frozenset(r.ref for r in report.rejected)
        fresh = [r for r in report.rejected if r.ref not in self._rejected_seen]
        self._rejected_seen = refs
        if not fresh:
            return
        lines = [f"“{r.label}”: {r.reason}" for r in fresh[:MAX_LISTED_REJECTS]]
        if len(fresh) > MAX_LISTED_REJECTS:
            lines.append(f"and {len(fresh) - MAX_LISTED_REJECTS} more")
        noun = "item" if len(fresh) == 1 else "items"
        await self._notifier.notify(
            "rejected",
            f"{len(fresh)} keyring {noun} can't sync",
            "Rename them as “username @ example.com” in Passwords and Keys.\n" + "\n".join(lines),
        )

    async def _alert(self, topic: str, summary: str, body: str) -> None:
        if topic not in self._alerts:
            self._alerts.add(topic)
            await self._notifier.notify(topic, summary, body)

    async def _withdraw(self, topic: str) -> None:
        if topic in self._alerts:
            self._alerts.discard(topic)
            await self._notifier.close(topic)

    async def _watch_local(self) -> None:
        while True:
            try:
                async for _ in self._local.changes():
                    self._local_signal()
            except Exception:  # noqa: BLE001 - best-effort watch; periodic cycles still run
                _log.warning("keyring change watch failed; retrying", exc_info=True)
            await self._clock.sleep(WATCH_RETRY_SECONDS)

    def _local_signal(self) -> None:
        self._local.invalidate()
        echo = self._echo
        if not self._lock.locked() and (echo is None or not echo.active(self._clock.monotonic())):
            self.scheduler.local_changed()
            return
        # A cycle may be writing right now (its echo is not known yet) or has just written:
        # compare the keyring with what it left behind once nothing else holds the lock.
        self._recheck = True
        if self._echo_check is None or self._echo_check.done():
            self._echo_check = asyncio.create_task(self._check_echo(), name="keyring-echo")

    async def _check_echo(self) -> None:
        while self._recheck:
            self._recheck = False  # signals arriving during the comparison ask for another
            async with self._lock:
                own = await self._is_echo()
            if not own:
                self._recheck = False
                self.scheduler.local_changed()
                return

    async def _is_echo(self) -> bool:
        """Whether the keyring holds exactly what the last cycle left in it (lock held)."""
        echo = self._echo
        if echo is None or not echo.active(self._clock.monotonic()):
            return False
        try:
            snapshot = await self._local.fetch()
        except LocalUnavailable:
            return False
        return echo.matches(snapshot, self._clock.monotonic())

    async def _refresh(self) -> LocalSnapshot | None:
        try:
            return await self._snapshot()
        except LockedError:
            return None

    async def _snapshot(self, *, fresh: bool = False) -> LocalSnapshot:
        snapshot = None if fresh else self._local.snapshot
        if snapshot is None:
            try:
                snapshot = await self._local.fetch()
            except LocalUnavailable as exc:
                raise LockedError(str(exc)) from exc
        # Only the cached snapshot is current: `CachingLocal` caches a read only if nothing
        # invalidated the cache while it ran. An older read is still answered, but must not
        # settle a failed delete (the delete invalidated after it started) or be announced
        # (clients would see items revert).
        if snapshot is self._local.snapshot:
            if self._unsettled_trash:
                self._settle_trash(snapshot.items)
            if snapshot is not self._announced:
                # Also covers snapshots the engine fetched during a cycle (Seahorse edits).
                self._announced = snapshot
                self._announce(snapshot.items)
        return snapshot

    async def _items(self, *, fresh: bool = False) -> Mapping[str, Credential]:
        return (await self._snapshot(fresh=fresh)).items

    async def _find(self, item_id: str, *, fresh: bool = False) -> Credential:
        item = (await self._items(fresh=fresh)).get(item_id)
        if item is None and not fresh:
            # The cached snapshot may predate an item created a moment ago (the keyring's
            # change signal is still in flight); only a fresh read can say it is missing.
            item = (await self._items(fresh=True)).get(item_id)
        if item is None:
            msg = "No password with this id."
            raise NotFoundError(msg)
        return item

    async def _current(self, item_id: str) -> Credential:
        """Read the item as the keyring holds it now, for an edit or delete to start from.

        Not from the cache: Seahorse may have changed it a moment ago, and a new password
        is signalled only by a file poll (seconds later). A partial Save merged into the
        cached copy would write the old password back; a Delete would trash the old one.
        """
        return await self._find(item_id, fresh=True)

    def _announce(self, items: Mapping[str, Credential]) -> None:
        current = {i: (*content_key(c), c.modified) for i, c in items.items()}
        previous, self._published = self._published, current
        if previous is None or self.on_items is None:
            return
        changed = sorted(
            {i for i in current if previous.get(i) != current[i]}
            | (previous.keys() - current.keys())
        )
        if changed:
            self.on_items(changed)

    async def list_items(self) -> list[Credential]:
        return sorted((await self._items()).values(), key=_sort_key)

    async def get(self, item_id: str) -> Credential:
        return await self._find(item_id)

    async def save(self, edit: ItemEdit) -> str:
        async with self._lock:
            existing = None if edit.item_id is None else await self._current(edit.item_id)
            credential = apply_edit(edit, existing, new_id=new_item_id(), now=self._clock.now())
            if credential is not existing:
                await self._write(credential)
                await self._refresh()
        self.scheduler.local_changed()
        self._publish()
        return credential.id

    async def _write(self, credential: Credential) -> None:
        try:
            await self._local.upsert(credential)
        except LocalUnavailable as exc:
            raise LockedError(str(exc)) from exc
        except ValueError as exc:
            msg = "The keyring cannot store this item."
            raise InvalidError(msg) from exc

    async def delete(self, item_id: str) -> None:
        async with self._lock:
            item = await self._current(item_id)
            # Trash first: a crash between the two steps keeps a restorable copy.
            reason: TrashReason = "deleted-on-linux"
            entry = TrashEntry(trash_id(item, reason), item, self._clock.now(), reason)
            self._unsettled_trash.pop(entry.trash_id, None)  # this attempt decides anew
            self._store.add_trash(entry)
            try:
                await self._local.delete(item_id)
            except LocalUnavailable as exc:
                # A refusal and a lost reply look alike, so the entry stays until a read
                # shows which one it was; this one may not get through a locked keyring.
                self._unsettled_trash[entry.trash_id] = entry
                await self._refresh()
                raise LockedError(str(exc)) from exc
            await self._refresh()
        self.scheduler.local_changed()
        self._publish()

    def _settle_trash(self, items: Mapping[str, Credential]) -> None:
        """Settle failed deletes against a keyring read that started after them.

        An item still there was never deleted: its entry would be a ghost that Restore turns
        into a duplicate. An item that is gone was deleted after all (its reply was lost):
        the entry is its only copy and stays.
        """
        for key, entry in self._unsettled_trash.items():
            if entry.credential.id in items:
                self._store.remove_trash(key)
        self._unsettled_trash.clear()

    # ------------------------------------------------------------------ trash

    def trash(self) -> list[TrashEntry]:
        return self._engine.trash()

    async def restore(self, trash_id_: str) -> str:
        async with self._lock:
            try:
                new_id = await self._engine.restore(trash_id_)
            except KeyError:
                msg = "No deleted password with this id."
                raise NotFoundError(msg) from None
            except LocalUnavailable as exc:
                raise LockedError(str(exc)) from exc
            except ConflictError:
                msg = "The password was changed while it was being restored. Try again."
                raise UnavailableError(msg) from None
            await self._refresh()
        self.scheduler.local_changed()
        self._publish()
        return new_id

    def purge(self, trash_id_: str) -> None:
        try:
            self._engine.purge(trash_id_)
        except KeyError:
            msg = "No deleted password with this id."
            raise NotFoundError(msg) from None
        self._publish()

    # ------------------------------------------------------------------ sync control

    def _require_account(self) -> None:
        if not self._remote.signed_in:
            raise AuthRequiredError(self._message or MSG_SIGNED_OUT)

    async def sync_now(self) -> None:
        self._require_account()
        await self.scheduler.run_now()

    async def resolve_pause(self, *, apply: bool) -> None:
        self._require_account()
        async with self._lock:
            self._refused.clear()
            try:
                report = await self._engine.resolve_pause(apply=apply)
            except NoPendingDeletionsError:
                msg = "Nothing is waiting for a decision."
                raise InvalidError(msg) from None
            await self._refresh()
            refused = self._take_refused()
        await self._after(report, refused)

    # ------------------------------------------------------------------ browser helpers

    async def match(self, url: str) -> list[Credential]:
        ranked: list[tuple[int, tuple[str, str, str], Credential]] = []
        for c in (await self._items()).values():
            kind = match(url, c)
            if kind is not MatchKind.NONE:
                ranked.append((0 if kind is MatchKind.EXACT_HOST else 1, _sort_key(c), c))
        ranked.sort(key=lambda r: (r[0], r[1]))
        return [c for *_, c in ranked]

    async def code(self, item_id: str) -> tuple[str, int]:
        item = await self.get(item_id)
        if item.otpauth is None:
            msg = "This password has no verification code."
            raise NotFoundError(msg)
        try:
            params = parse_otpauth(item.otpauth)
        except OtpError:
            msg = "This password's verification code setup is not valid."
            raise InvalidError(msg) from None
        return code_at(params, self._clock.now())
