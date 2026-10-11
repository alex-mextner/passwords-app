# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`Credential` <-> the a{sv} item dicts of `io.github.alex_mextner.Passwords1`.

Secrets leave the daemon only through `item_dict(..., secrets=True)`, which the service calls
for `Get` alone. `Save` input is checked in two steps: `parse_edit` validates the dict's shape
(known keys, D-Bus types) and `apply_edit` validates content against the item it changes.
Every dict carries every key; `None` travels as "" so clients never branch on presence.
Error messages name the offending key and never quote the value.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from dbus_fast import Variant

from passwords_app.core.model import Credential
from passwords_app.core.otp import OtpError, parse_otpauth
from passwords_app.core.urls import normalize_url
from passwords_app.daemon.errors import InvalidError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import timedelta

    from passwords_app.core.model import TrashEntry

_STRING, _STRING_ARRAY, _INT64, _BOOLEAN = "s", "as", "x", "b"

# Key -> D-Bus signature, as documented in the interface XML.
ITEM_KEYS: Mapping[str, str] = {
    "id": _STRING,
    "url": _STRING,
    "username": _STRING,
    "title": _STRING,
    "notes": _STRING,
    "alt_urls": _STRING_ARRAY,
    "group": _STRING,
    "created": _INT64,
    "modified": _INT64,
    "has_code": _BOOLEAN,
    "sync_problem": _STRING,
    "password": _STRING,
    "otpauth": _STRING,
}
# Clients may echo a dict from Get back into Save; these are the daemon's bookkeeping.
_READ_ONLY = frozenset({"created", "modified", "has_code", "sync_problem"})
_OPTIONAL_TEXT = ("title", "notes", "group", "otpauth")


def to_ms(dt: datetime) -> int:
    """Unix milliseconds (truncated), as the interface's `x` timestamps."""
    delta = dt.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1000 + delta.microseconds // 1000


def from_ms(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, UTC)


def item_dict(
    c: Credential, *, secrets: bool = False, sync_problem: str = ""
) -> dict[str, Variant]:
    """`sync_problem` is why iCloud refused to store this version ("" while it syncs)."""
    item = {
        "id": Variant("s", c.id),
        "url": Variant("s", c.url),
        "username": Variant("s", c.username),
        "title": Variant("s", c.title or ""),
        "notes": Variant("s", c.notes or ""),
        "alt_urls": Variant("as", list(c.alt_urls)),
        "group": Variant("s", c.group or ""),
        "created": Variant("x", to_ms(c.created)),
        "modified": Variant("x", to_ms(c.modified)),
        "has_code": Variant("b", c.otpauth is not None),
        "sync_problem": Variant("s", sync_problem),
    }
    if secrets:
        item["password"] = Variant("s", c.password)
        item["otpauth"] = Variant("s", c.otpauth or "")
    return item


def trash_dict(entry: TrashEntry, retention: timedelta) -> dict[str, Variant]:
    return {
        "trash_id": Variant("s", entry.trash_id),
        "reason": Variant("s", entry.reason),
        "deleted_at": Variant("x", to_ms(entry.deleted_at)),
        "expires_at": Variant("x", to_ms(entry.expires_at(retention))),
        "item": Variant("a{sv}", item_dict(entry.credential)),
    }


@dataclass(frozen=True, slots=True)
class ItemEdit:
    """A shape-checked Save request: the target id (None = create) and the fields it sets."""

    item_id: str | None
    fields: Mapping[str, str | tuple[str, ...]]


def parse_edit(raw: Mapping[str, Variant]) -> ItemEdit:
    fields: dict[str, str | tuple[str, ...]] = {}
    item_id: str | None = None
    for key, variant in raw.items():
        expected = ITEM_KEYS.get(key)
        if expected is None:
            # The key itself may be a mistyped secret; never echo it.
            msg = "the item has an unknown key"
            raise InvalidError(msg)
        if variant.signature != expected:
            msg = f"{key} must have D-Bus type {expected}"
            raise InvalidError(msg)
        if key in _READ_ONLY:
            continue
        value = variant.value
        if key == "id":
            item_id = value or None
        elif key == "alt_urls":
            fields[key] = tuple(value)
        else:
            fields[key] = value
    return ItemEdit(item_id, fields)


def _url(raw: str, key: str) -> str:
    try:
        return normalize_url(raw)
    except ValueError:
        msg = f"{key} is not a web address"
        raise InvalidError(msg) from None


def _alt_urls(raw: tuple[str, ...]) -> tuple[str, ...]:
    urls = [_url(u, "alt_urls") for u in raw if u.strip()]
    return tuple(dict.fromkeys(urls))


def _check_otpauth(uri: str) -> None:
    try:
        parse_otpauth(uri)
    except OtpError:
        msg = "the verification code setup (otpauth) is not a valid TOTP link"
        raise InvalidError(msg) from None


def _text(fields: Mapping[str, str | tuple[str, ...]], key: str) -> str | None:
    value = fields.get(key)
    return value if isinstance(value, str) else None


def _required(fields: Mapping[str, str | tuple[str, ...]], key: str, current: str | None) -> str:
    value = _text(fields, key)
    if value is None:
        if current is None:
            msg = f"{key} is required"
            raise InvalidError(msg)
        return current
    if not value:
        msg = f"{key} must not be empty"
        raise InvalidError(msg)
    return value


def _optional(
    fields: Mapping[str, str | tuple[str, ...]], key: str, current: str | None
) -> str | None:
    value = _text(fields, key)
    return current if value is None else (value or None)


def _resolved_url(fields: Mapping[str, str | tuple[str, ...]], current: str | None) -> str:
    url = _text(fields, "url")
    return _required(fields, "url", current) if url is None else _url(url, "url")


def _resolved_otpauth(
    fields: Mapping[str, str | tuple[str, ...]], current: str | None
) -> str | None:
    otpauth = _optional(fields, "otpauth", current)
    if otpauth is not None and "otpauth" in fields:
        _check_otpauth(otpauth)
    return otpauth


def _resolved_alt_urls(
    fields: Mapping[str, str | tuple[str, ...]], current: tuple[str, ...]
) -> tuple[str, ...]:
    alt = fields.get("alt_urls")
    return _alt_urls(alt) if isinstance(alt, tuple) else current


def _created(
    fields: Mapping[str, str | tuple[str, ...]], *, new_id: str, now: datetime
) -> Credential:
    otpauth = _resolved_otpauth(fields, None)
    return Credential(
        id=new_id,
        url=_resolved_url(fields, None),
        username=_optional(fields, "username", "") or "",
        password=_required(fields, "password", None),
        created=now,
        modified=now,
        title=_optional(fields, "title", None),
        notes=_optional(fields, "notes", None),
        otpauth=otpauth,
        alt_urls=_resolved_alt_urls(fields, ()),
        group=_optional(fields, "group", None),
    )


def _edited(fields: Mapping[str, str | tuple[str, ...]], existing: Credential) -> Credential:
    """`existing` with `fields` applied; `modified` is left for the caller to bump."""
    otpauth = _resolved_otpauth(fields, existing.otpauth)
    return dataclasses.replace(
        existing,
        url=_resolved_url(fields, existing.url),
        username=_optional(fields, "username", existing.username) or "",
        password=_required(fields, "password", existing.password),
        title=_optional(fields, "title", existing.title),
        notes=_optional(fields, "notes", existing.notes),
        otpauth=otpauth,
        alt_urls=_resolved_alt_urls(fields, existing.alt_urls),
        group=_optional(fields, "group", existing.group),
    )


def apply_edit(
    edit: ItemEdit, existing: Credential | None, *, new_id: str, now: datetime
) -> Credential:
    """Return the credential `edit` produces; `existing` is the item with `edit.item_id`."""
    if existing is None:
        return _created(edit.fields, new_id=new_id, now=now)
    if existing.id != edit.item_id:
        msg = "existing credential does not match the edited id"
        raise ValueError(msg)
    edited = _edited(edit.fields, existing)
    if edited.content_hash() == existing.content_hash():
        return existing
    return dataclasses.replace(edited, modified=now)
