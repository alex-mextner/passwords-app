# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Typed views of the daemon's D-Bus dictionaries (see the interface XML for the keys).

Parsing is strict about types but tolerant about absent optional keys, so a newer daemon that
adds keys keeps working and a malformed reply fails loudly instead of rendering garbage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, cast

import idna

from passwords_app.core.urls import link_host

if TYPE_CHECKING:
    from collections.abc import Mapping

type Wire = Mapping[str, object]


class ReplyError(ValueError):
    """The daemon sent a dictionary that does not match the interface contract."""


def _str(d: Wire, key: str, *, default: str = "") -> str:
    value = d.get(key, default)
    if not isinstance(value, str):
        msg = f"{key} must be a string"
        raise ReplyError(msg)
    return value


def _bool(d: Wire, key: str) -> bool:
    value = d.get(key, False)
    if not isinstance(value, bool):
        msg = f"{key} must be a boolean"
        raise ReplyError(msg)
    return value


def _int(d: Wire, key: str) -> int:
    value = d.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{key} must be an integer"
        raise ReplyError(msg)
    return value


def _strs(d: Wire, key: str) -> tuple[str, ...]:
    value = d.get(key, [])
    if not isinstance(value, list | tuple) or not all(
        isinstance(v, str) for v in cast("list[object]", value)
    ):
        msg = f"{key} must be a list of strings"
        raise ReplyError(msg)
    return tuple(cast("list[str]", value))


def from_unix_ms(ms: int) -> datetime | None:
    """Daemon timestamps are unix milliseconds; 0 means "never"."""
    return None if ms <= 0 else datetime.fromtimestamp(ms / 1000, tz=UTC)


def to_unix_ms(at: datetime) -> int:
    return round(at.timestamp() * 1000)


def display_host(url: str) -> str:
    """Human host for `url` (IDN decoded, no `www.`), or the raw text when it has no host."""
    host = link_host(url)
    if not host:
        return url.strip()
    try:
        # The core normalizes with UTS #46 (non-transitional, so "faß.de" keeps its ß); the
        # stdlib codec implements IDNA 2003 and rejects such labels.
        return idna.decode(host)
    except idna.IDNAError:
        return host


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class Item:
    """One login as listed by the daemon; `password`/`otpauth` are None unless fetched by Get."""

    id: str
    url: str
    username: str = ""
    title: str = ""
    notes: str = ""
    group: str = ""
    alt_urls: tuple[str, ...] = ()
    created: datetime = _EPOCH
    modified: datetime = _EPOCH
    has_code: bool = False
    password: str | None = field(default=None, repr=False)
    otpauth: str | None = field(default=None, repr=False)

    @classmethod
    def from_wire(cls, d: Wire) -> Item:
        item_id = _str(d, "id")
        if not item_id:
            msg = "item without id"
            raise ReplyError(msg)
        password = _str(d, "password") if "password" in d else None
        otpauth = _str(d, "otpauth") if "otpauth" in d else None
        return cls(
            id=item_id,
            url=_str(d, "url"),
            username=_str(d, "username"),
            title=_str(d, "title"),
            notes=_str(d, "notes"),
            group=_str(d, "group"),
            alt_urls=_strs(d, "alt_urls"),
            created=from_unix_ms(_int(d, "created")) or _EPOCH,
            modified=from_unix_ms(_int(d, "modified")) or _EPOCH,
            has_code=_bool(d, "has_code") or bool(otpauth),
            password=password,
            otpauth=otpauth or None,
        )

    @property
    def host(self) -> str:
        return display_host(self.url)

    @property
    def display_title(self) -> str:
        """Title as Apple shows it: the user's title, else the website."""
        return self.title.strip() or self.host or self.url


class TrashReason(StrEnum):
    DELETED_IN_ICLOUD = "deleted-in-icloud"
    DELETED_ON_LINUX = "deleted-on-linux"
    DELETED_BOTH = "deleted-both"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class TrashEntry:
    trash_id: str
    reason: TrashReason
    deleted_at: datetime
    expires_at: datetime
    item: Item

    @classmethod
    def from_wire(cls, d: Wire) -> TrashEntry:
        trash_id = _str(d, "trash_id")
        if not trash_id:
            msg = "trash entry without trash_id"
            raise ReplyError(msg)
        raw_item = d.get("item")
        if not isinstance(raw_item, dict):
            msg = "trash entry without item"
            raise ReplyError(msg)
        reason_text = _str(d, "reason")
        try:
            reason = TrashReason(reason_text)
        except ValueError:
            reason = TrashReason.UNKNOWN
        deleted_at = from_unix_ms(_int(d, "deleted_at")) or _EPOCH
        return cls(
            trash_id=trash_id,
            reason=reason,
            deleted_at=deleted_at,
            expires_at=from_unix_ms(_int(d, "expires_at")) or deleted_at,
            item=Item.from_wire(cast("Wire", raw_item)),
        )


class SyncState(StrEnum):
    SIGNED_OUT = "signed-out"
    SYNCING = "syncing"
    IDLE = "idle"
    PAUSED = "paused"
    OFFLINE = "offline"
    SIGNIN_REQUIRED = "signin-required"
    ERROR = "error"
    # The app could not reach the daemon at all; never sent on the wire.
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class Status:
    state: SyncState
    apple_id: str = ""
    item_count: int = 0
    trash_count: int = 0
    last_sync: datetime | None = None
    next_sync: datetime | None = None
    message: str = ""
    pending_local_deletions: tuple[str, ...] = ()
    pending_remote_deletions: tuple[str, ...] = ()

    @classmethod
    def from_wire(cls, d: Wire) -> Status:
        state_text = _str(d, "state")
        try:
            state = SyncState(state_text)
        except ValueError:
            state = SyncState.ERROR
        if state is SyncState.UNREACHABLE:
            state = SyncState.ERROR
        return cls(
            state=state,
            apple_id=_str(d, "apple_id"),
            item_count=_int(d, "item_count"),
            trash_count=_int(d, "trash_count"),
            last_sync=from_unix_ms(_int(d, "last_sync")),
            next_sync=from_unix_ms(_int(d, "next_sync")),
            message=_str(d, "message"),
            pending_local_deletions=_strs(d, "pending_local_deletions"),
            pending_remote_deletions=_strs(d, "pending_remote_deletions"),
        )

    @property
    def pending_deletions(self) -> int:
        return len(self.pending_local_deletions) + len(self.pending_remote_deletions)


class StepKind(StrEnum):
    CODE = "code"
    DEVICE = "device"
    DONE = "done"


@dataclass(frozen=True, slots=True)
class SignInStep:
    step: StepKind
    destination: str = ""
    message: str = ""

    @classmethod
    def from_wire(cls, d: Wire) -> SignInStep:
        try:
            step = StepKind(_str(d, "step"))
        except ValueError as exc:
            msg = "unknown sign-in step"
            raise ReplyError(msg) from exc
        return cls(step=step, destination=_str(d, "destination"), message=_str(d, "message"))


@dataclass(frozen=True, slots=True)
class RecoveryDevice:
    id: str
    name: str
    model: str
    serial: str

    @classmethod
    def from_wire(cls, d: Wire) -> RecoveryDevice:
        device_id = _str(d, "id")
        if not device_id:
            msg = "device without id"
            raise ReplyError(msg)
        return cls(
            id=device_id,
            name=_str(d, "name"),
            model=_str(d, "model"),
            serial=_str(d, "serial"),
        )


@dataclass(frozen=True, slots=True)
class Draft:
    """Fields the user edits; turned into a Save() dictionary by `to_wire`."""

    url: str
    username: str = ""
    password: str = field(default="", repr=False)
    title: str = ""
    notes: str = ""
    otpauth: str = field(default="", repr=False)
    alt_urls: tuple[str, ...] = ()
    group: str = ""
    id: str = ""

    @classmethod
    def from_item(cls, item: Item) -> Draft:
        return cls(
            id=item.id,
            url=item.url,
            username=item.username,
            password=item.password or "",
            title=item.title,
            notes=item.notes,
            otpauth=item.otpauth or "",
            alt_urls=item.alt_urls,
            group=item.group,
        )

    def to_wire(self) -> dict[str, object]:
        """Every editable key, so an update never silently keeps a field the user cleared."""
        return {
            "id": self.id,
            "url": self.url.strip(),
            "username": self.username,
            "password": self.password,
            "title": self.title.strip(),
            "notes": self.notes,
            "otpauth": self.otpauth.strip(),
            "alt_urls": [u.strip() for u in self.alt_urls if u.strip()],
            "group": self.group,
        }
