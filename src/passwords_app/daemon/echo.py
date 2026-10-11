# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Tell the keyring's echo of a sync cycle's own writes apart from a user's edit.

The Secret Service signals every change to the collection, including the ones a cycle just
made, and those signals carry no item ids. Without a filter each cycle that writes to the
keyring would schedule one more cycle (and one more iCloud fetch) 2 s later.

A cycle records the keyring it read first and every write it made. If the keyring it reads
back afterwards is exactly that plus its writes, nobody else touched it, and that content
becomes the expected echo for a short window: a change signal that leaves the keyring with
this content changed nothing worth syncing. Anything else (an item a user edits, adds or
deletes, even right after the cycle) differs and is synced as usual.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from passwords_app.core.model import Credential
    from passwords_app.sync.ports import LocalSnapshot, RejectedLocalItem

# Covers gnome-keyring's signals and the keyring file watch (polled every 2 s).
ECHO_WINDOW = 10.0

type Fingerprint = tuple[frozenset[tuple[str, str]], frozenset[RejectedLocalItem]]


def fingerprint(snapshot: LocalSnapshot) -> Fingerprint:
    """Reduce a snapshot to its user-visible content: (id, content hash) pairs, rejects."""
    return (
        frozenset((item_id, c.content_hash()) for item_id, c in snapshot.items.items()),
        frozenset(snapshot.rejected),
    )


@dataclass(slots=True)
class WriteJournal:
    """What one cycle first read from the keyring, and what it wrote there afterwards."""

    before: LocalSnapshot | None = None
    # item id -> content hash written, or None for a deletion
    writes: dict[str, str | None] = field(default_factory=dict[str, str | None])

    def read(self, snapshot: LocalSnapshot) -> None:
        if self.before is None:
            self.before = snapshot

    def upserted(self, credential: Credential) -> None:
        self.writes[credential.id] = credential.content_hash()

    def deleted(self, item_id: str) -> None:
        self.writes[item_id] = None

    def expected(self) -> Fingerprint | None:
        """Predict the keyring after the cycle, unless someone else changed it (None: no read)."""
        if self.before is None:
            return None
        items = {item_id: c.content_hash() for item_id, c in self.before.items.items()}
        for item_id, content in self.writes.items():
            if content is None:
                items.pop(item_id, None)
            else:
                items[item_id] = content
        return frozenset(items.items()), frozenset(self.before.rejected)


@dataclass(frozen=True, slots=True)
class Echo:
    """The keyring content a cycle left behind, and until when signals may be its echo."""

    content: Fingerprint
    until: float

    def active(self, now: float) -> bool:
        return now < self.until

    def matches(self, snapshot: LocalSnapshot, now: float) -> bool:
        return self.active(now) and fingerprint(snapshot) == self.content


def settled(journal: WriteJournal, after: LocalSnapshot | None, now: float) -> Echo | None:
    """Return the echo to expect after a cycle; None if the keyring changed under it."""
    expected = journal.expected()
    if expected is None or after is None or fingerprint(after) != expected:
        return None
    return Echo(expected, now + ECHO_WINDOW)
