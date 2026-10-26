# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The daemon's status: what `GetStatus` returns and `StatusChanged` broadcasts.

`outcome()` is the single place that turns a sync report into a user-visible state, so the
app, the CLI and the notifications all agree on what "offline" or "paused" means.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dbus_fast import Variant

from passwords_app.daemon.items import to_ms
from passwords_app.sync.engine import SKIP_AUTH, SKIP_LOCAL, SKIP_REMOTE
from passwords_app.sync.ports import upload_failures_message

if TYPE_CHECKING:
    from datetime import datetime

    from passwords_app.sync.ports import PendingDeletions, SyncReport, SyncState

MSG_SIGNED_OUT = "Not signed in to iCloud."
MSG_SESSION_UNREADABLE = (
    "The saved iCloud sign-in cannot be opened on this computer: it was made on another "
    "computer, or this computer's keyring was reset. Sign in again."
)
MSG_NOT_JOINED = (
    "Finish signing in: confirm with a device passcode so this computer can join your "
    "iCloud Keychain."
)
MSG_AUTH = "Apple needs you to sign in again before passwords can sync."
MSG_OFFLINE = "Can't reach iCloud right now. Passwords will sync when the connection is back."
MSG_LOCAL = 'The "iCloud Passwords" keyring is locked or unavailable. Unlock it to sync.'


@dataclass(frozen=True, slots=True)
class Status:
    state: SyncState
    apple_id: str = ""
    item_count: int = 0
    trash_count: int = 0
    last_sync: datetime | None = None
    next_sync: datetime | None = None
    message: str = ""
    pending_local: tuple[str, ...] = field(default=())
    pending_remote: tuple[str, ...] = field(default=())
    # The Apple Account is signed in (password and code done); only the device passcode is
    # missing, so a client continues at that step instead of asking for the password again.
    join_pending: bool = False

    def to_dbus(self) -> dict[str, Variant]:
        return {
            "state": Variant("s", self.state),
            "apple_id": Variant("s", self.apple_id),
            "item_count": Variant("u", self.item_count),
            "trash_count": Variant("u", self.trash_count),
            "last_sync": Variant("x", 0 if self.last_sync is None else to_ms(self.last_sync)),
            "next_sync": Variant("x", 0 if self.next_sync is None else to_ms(self.next_sync)),
            "message": Variant("s", self.message),
            "pending_local_deletions": Variant("as", list(self.pending_local)),
            "pending_remote_deletions": Variant("as", list(self.pending_remote)),
            "join_pending": Variant("b", self.join_pending),
        }


def paused_message(pending: PendingDeletions) -> str:
    count = len(pending.local_ids) + len(pending.remote_ids)
    noun = "password" if count == 1 else "passwords"
    return f"Sync paused: {count} {noun} would be deleted. Choose Apply deletions or Restore them."


def outcome(report: SyncReport) -> tuple[SyncState, str]:
    """Return the state and message a finished cycle leaves the daemon in."""
    match report.skipped_reason:
        case None:
            pass
        case reason if reason == SKIP_AUTH:
            return "signin-required", MSG_AUTH
        case reason if reason == SKIP_REMOTE:
            return "offline", MSG_OFFLINE
        case reason if reason == SKIP_LOCAL:
            return "error", MSG_LOCAL
        case _:
            return "error", "Sync was skipped."
    if report.paused is not None:
        return "paused", paused_message(report.paused)
    # Logins iCloud refused wait alone while everything else syncs: not an outage.
    return "idle", upload_failures_message(report.upload_failures)
