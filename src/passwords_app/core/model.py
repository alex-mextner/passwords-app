# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Canonical password record shared by every layer (iCloud, keyring, daemon, app, browser).

`Credential.content_hash()` is the single definition of "this item changed": it covers every
user-visible field and deliberately ignores `id` and timestamps, so the same login seen
through two stores compares equal even before the stores agree on bookkeeping.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal


def _require_aware(name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        msg = f"{name} must be timezone-aware"
        raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class Credential:
    """One website login. Immutable; derive edits with `dataclasses.replace`."""

    id: str
    url: str
    username: str
    password: str
    created: datetime
    modified: datetime
    title: str | None = None
    notes: str | None = None
    otpauth: str | None = None
    alt_urls: tuple[str, ...] = ()
    group: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            msg = "id must be non-empty"
            raise ValueError(msg)
        if not self.url:
            msg = "url must be non-empty"
            raise ValueError(msg)
        _require_aware("created", self.created)
        _require_aware("modified", self.modified)

    def content_hash(self) -> str:
        """SHA-256 of the user-visible content (no id, no timestamps)."""
        canonical = json.dumps(
            {
                "url": self.url,
                "username": self.username,
                "password": self.password,
                "title": self.title,
                "notes": self.notes,
                "otpauth": self.otpauth,
                "alt_urls": list(self.alt_urls),
                "group": self.group,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()


TrashReason = Literal["deleted-in-icloud", "deleted-on-linux", "deleted-both", "conflict"]


@dataclass(frozen=True, slots=True)
class TrashEntry:
    """A credential removed from either side (or a conflict loser), kept for restore."""

    trash_id: str
    credential: Credential
    deleted_at: datetime
    reason: TrashReason

    def __post_init__(self) -> None:
        _require_aware("deleted_at", self.deleted_at)

    def expires_at(self, retention: timedelta) -> datetime:
        return self.deleted_at + retention
