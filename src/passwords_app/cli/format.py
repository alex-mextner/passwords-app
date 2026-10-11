# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Plain-text rendering of daemon replies (already unwrapped to Python values).

Pure functions of their inputs and an explicit `now`, so every wording and table layout is
tested without a terminal. Passwords appear only in `item_detail(..., reveal=True)`; TOTP
seeds are never rendered, only the current code.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    type Plain = dict[str, Any]

MASK = "••••••••"
STATE_LABELS = {
    "signed-out": "Signed out",
    "syncing": "Syncing…",
    "idle": "Up to date",
    "paused": "Paused — waiting for your decision",
    "offline": "Offline",
    "signin-required": "Sign-in required",
    "error": "Error",
}
REASONS = {
    "deleted-in-icloud": "deleted on an Apple device",
    "deleted-on-linux": "deleted on this computer",
    "deleted-both": "deleted everywhere",
    "conflict": "replaced by a newer edit",
}
_MINUTE = 60
_HOUR = 3600
_DAY = 86400


def _from_ms(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, UTC)


def relative(ms: int, now: datetime, *, never: str = "never") -> str:
    """'just now', '5 min ago', 'in 2 h', '3 days ago' ...; `never` for 0."""
    if ms == 0:
        return never
    delta = (_from_ms(ms) - now).total_seconds()
    seconds = abs(delta)
    if seconds < _MINUTE:
        return "just now" if delta <= 0 else "in a moment"
    if seconds < _HOUR:
        span = f"{int(seconds // _MINUTE)} min"
    elif seconds < _DAY:
        span = f"{int(seconds // _HOUR)} h"
    else:
        days = int(seconds // _DAY)
        span = f"{days} day" + ("" if days == 1 else "s")
    return f"in {span}" if delta > 0 else f"{span} ago"


def host(url: str) -> str:
    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return url


def display_name(item: Plain) -> str:
    return str(item.get("title") or host(str(item.get("url", ""))))


def status_text(status: Plain, now: datetime) -> str:
    state = str(status["state"])
    lines = [f"Passwords:  {STATE_LABELS.get(state, state)}"]
    if status.get("apple_id"):
        lines.append(f"Account:    {status['apple_id']}")
    trash = int(status.get("trash_count", 0))
    items = f"Items:      {status.get('item_count', 0)}"
    if trash:
        items += f" ({trash} recently deleted)"
    lines.append(items)
    if state != "signed-out":
        lines.append(f"Last sync:  {relative(int(status.get('last_sync', 0)), now)}")
        if int(status.get("next_sync", 0)):
            lines.append(f"Next sync:  {relative(int(status['next_sync']), now)}")
    if status.get("message"):
        lines.extend(("", str(status["message"])))
    local = list(status.get("pending_local_deletions", []))
    remote = list(status.get("pending_remote_deletions", []))
    if local or remote:
        held = (
            f"Held back: {len(local)} deletion(s) in this computer's keyring, "
            f"{len(remote)} in iCloud."
        )
        choice = (
            "Run `passwords-app resolve apply` to delete them, "
            "or `passwords-app resolve restore` to bring them back."
        )
        lines.extend(("", held, choice))
    elif state == "signed-out":
        lines.extend(("", "Run `passwords-app signin` to connect your iCloud Keychain."))
    elif state == "signin-required":
        lines.extend(("", "Run `passwords-app signin` to sign in again."))
    return "\n".join(lines)


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    body = [list(r) for r in rows]
    widths = [
        max(len(h), *(len(r[i]) for r in body)) if body else len(h) for i, h in enumerate(headers)
    ]

    def line(cells: Sequence[str]) -> str:
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths, strict=True)).rstrip()

    return "\n".join([line(headers), *(line(r) for r in body)])


def filter_items(items: Iterable[Plain], query: str) -> list[Plain]:
    needle = query.casefold().strip()
    if not needle:
        return list(items)
    return [
        i
        for i in items
        if any(needle in str(i.get(k, "")).casefold() for k in ("title", "url", "username", "id"))
        or any(needle in u.casefold() for u in i.get("alt_urls", []))
    ]


def items_table(items: Sequence[Plain]) -> str:
    if not items:
        return "No passwords."
    rows = [
        (
            display_name(i),
            str(i.get("username") or "—"),
            host(str(i.get("url", ""))),
            "code" if i.get("has_code") else "",
            str(i["id"]),
        )
        for i in items
    ]
    return _table(("NAME", "USERNAME", "WEBSITE", "2FA", "ID"), rows)


def item_detail(item: Plain, *, reveal: bool, code: tuple[str, int] | None, now: datetime) -> str:
    password = str(item.get("password", "")) if reveal else MASK
    lines = [
        display_name(item),
        f"  Website:   {item.get('url', '')}",
        f"  Username:  {item.get('username') or '—'}",
        f"  Password:  {password}",
    ]
    if code is not None:
        lines.append(f"  Code:      {code[0]} ({code[1]} s left)")
    alt = list(item.get("alt_urls", []))
    if alt:
        lines.append(f"  Also used on: {', '.join(alt)}")
    if item.get("group"):
        lines.append(f"  Shared group: {item['group']}")
    if item.get("notes"):
        notes = str(item["notes"]).splitlines() or [""]
        lines.append(f"  Notes:     {notes[0]}")
        lines.extend(f"             {n}" for n in notes[1:])
    lines.append(f"  Modified:  {relative(int(item.get('modified', 0)), now)}")
    lines.append(f"  ID:        {item['id']}")
    return "\n".join(lines)


def trash_table(entries: Sequence[Plain], now: datetime) -> str:
    if not entries:
        return "Recently Deleted is empty."
    rows: list[tuple[str, ...]] = []
    for e in entries:
        item = e["item"]
        days_left = max(0, int((_from_ms(int(e["expires_at"])) - now).total_seconds() // _DAY))
        rows.append(
            (
                display_name(item),
                str(item.get("username") or "—"),
                REASONS.get(str(e["reason"]), str(e["reason"])),
                relative(int(e["deleted_at"]), now),
                f"{days_left} days",
                str(e["trash_id"]),
            )
        )
    return _table(("NAME", "USERNAME", "WHY", "DELETED", "KEPT FOR", "TRASH ID"), rows)
