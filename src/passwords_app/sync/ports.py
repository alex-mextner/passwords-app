# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Contracts between the sync engine and the two stores it reconciles.

The engine only ever sees these shapes, so the iCloud client, the Secret Service adapter, and
the in-memory fakes used by tests are interchangeable. A store that cannot give a complete,
trustworthy view MUST raise (`RemoteUnavailable` / `LocalUnavailable`) rather than return a
partial snapshot: the engine reads "missing" as "deleted".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, Sequence

    from passwords_app.core.model import Credential


class SyncError(Exception):
    """Base for every error the engine understands."""


class RemoteUnavailable(SyncError):  # noqa: N818 - spec §5 contract name, used by every store
    """iCloud could not be read or written completely (network, server, protocol)."""


class AuthRequired(RemoteUnavailable):
    """Apple needs an interactive sign-in (2FA or password) before sync can continue."""


class LocalUnavailable(SyncError):  # noqa: N818 - spec §5 contract name, used by every store
    """The keyring collection is locked, missing, or unreachable."""


class ConflictError(SyncError):
    """A conditional write lost a race: the record changed since it was fetched."""


class ItemRejected(SyncError):  # noqa: N818 - named like the other store outcomes
    """iCloud refused to store this one item (e.g. another login has its site and account).

    Nothing is wrong with the connection or the other items, so the engine sets this item
    aside and retries it on its own schedule instead of ending the cycle.
    """


@dataclass(frozen=True, slots=True)
class RemoteItem:
    credential: Credential
    etag: str | None


@dataclass(frozen=True, slots=True)
class RemoteSnapshot:
    items: Mapping[str, RemoteItem]


@dataclass(frozen=True, slots=True)
class RejectedLocalItem:
    """A keyring item in the synced collection that cannot become a Credential."""

    ref: str
    label: str
    reason: str


@dataclass(frozen=True, slots=True)
class LocalSnapshot:
    items: Mapping[str, Credential]
    rejected: tuple[RejectedLocalItem, ...] = ()


class RemoteStore(Protocol):
    async def fetch(self) -> RemoteSnapshot: ...

    async def upsert(self, credential: Credential, etag: str | None) -> str:
        """Create (etag None) or overwrite-if-unchanged; return the new etag.

        Raises `ItemRejected` when iCloud will not store this credential at all.
        """
        ...

    async def delete(self, item_id: str, etag: str | None) -> None: ...


class LocalStore(Protocol):
    async def fetch(self) -> LocalSnapshot: ...

    async def upsert(self, credential: Credential) -> None: ...

    async def delete(self, item_id: str) -> None: ...

    def changes(self) -> AsyncIterator[None]:
        """Yield once per external change notification (debouncing is the caller's job)."""
        ...


@dataclass(frozen=True, slots=True)
class SyncPolicy:
    trash_retention: timedelta = timedelta(days=90)
    mass_delete_min: int = 5
    mass_delete_ratio: float = 0.10
    # An item iCloud refused is retried after `rejected_retry`, doubling per refusal up to
    # `rejected_retry_max`; an edit to the item retries it at once.
    rejected_retry: timedelta = timedelta(minutes=2)
    rejected_retry_max: timedelta = timedelta(hours=6)


@dataclass(frozen=True, slots=True)
class PendingDeletions:
    """Deletions held back by the mass-delete guard until the user decides."""

    local_ids: tuple[str, ...]
    remote_ids: tuple[str, ...]


SyncState = Literal[
    "signed-out", "syncing", "idle", "paused", "offline", "signin-required", "error"
]


@dataclass(frozen=True, slots=True)
class UploadFailure:
    """A keyring item iCloud refused to store; only this item waits for `retry_at`."""

    item_id: str
    url: str
    username: str
    reason: str
    attempts: int
    retry_at: datetime


def upload_failures_message(failures: Sequence[UploadFailure]) -> str:
    """Return the status line for items iCloud refused; "" when there are none."""
    if not failures:
        return ""
    first = failures[0]
    who = f"{first.username} on {first.url}" if first.username else first.url
    if len(failures) == 1:
        return (
            f"iCloud did not accept the password for {who}: {first.reason}. "
            "Everything else is syncing; edit or delete this password to fix it."
        )
    return (
        f"iCloud did not accept {len(failures)} passwords (first: {who}: {first.reason}). "
        "Everything else is syncing; edit or delete them to fix it."
    )


@dataclass(frozen=True, slots=True)
class SyncReport:
    started: datetime
    finished: datetime
    created_local: int = 0
    updated_local: int = 0
    deleted_local: int = 0
    created_remote: int = 0
    updated_remote: int = 0
    deleted_remote: int = 0
    conflicts: int = 0
    linked: int = 0
    skipped_reason: str | None = None
    paused: PendingDeletions | None = None
    rejected: tuple[RejectedLocalItem, ...] = field(default=())
    upload_failures: tuple[UploadFailure, ...] = field(default=())
