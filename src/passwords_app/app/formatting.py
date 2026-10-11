# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""User-facing text for dates, counts and sync states (translated, plural-aware).

Dates use one translatable pattern per month instead of strftime: Russian needs the genitive
month ("10 октября"), which strftime's locale tables do not give portably.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timedelta, tzinfo
from enum import StrEnum

from passwords_app.app.i18n import _, ngettext, pgettext
from passwords_app.app.records import Status, SyncState, TrashReason

# What a hidden password looks like; the length never hints at the real one.
MASK = "•" * 12


def _n_(message: str) -> str:
    """Mark for extraction; translated at use time so a language switch takes effect."""
    return message


_MONTH_PATTERNS = (
    _n_("January {day}, {year}"),
    _n_("February {day}, {year}"),
    _n_("March {day}, {year}"),
    _n_("April {day}, {year}"),
    _n_("May {day}, {year}"),
    _n_("June {day}, {year}"),
    _n_("July {day}, {year}"),
    _n_("August {day}, {year}"),
    _n_("September {day}, {year}"),
    _n_("October {day}, {year}"),
    _n_("November {day}, {year}"),
    _n_("December {day}, {year}"),
)


def _local(at: datetime, tz: tzinfo | None) -> datetime:
    return at.astimezone(tz)


def clock(at: datetime, tz: tzinfo | None = None) -> str:
    local = _local(at, tz)
    return f"{local.hour:02d}:{local.minute:02d}"


def calendar_date(at: datetime, tz: tzinfo | None = None) -> str:
    local = _local(at, tz)
    return _(_MONTH_PATTERNS[local.month - 1]).format(day=local.day, year=local.year)


def date_time(
    at: datetime, now: datetime, tz: tzinfo | None = None, *, in_sentence: bool = False
) -> str:
    """`Today at 14:05`, `Yesterday at 09:30`, else the calendar date.

    `in_sentence` gives the lowercase forms for use after other words ("Last synced …").
    """
    day = _local(at, tz).date()
    today = _local(now, tz).date()
    if day == today:
        pattern = _("today at {time}") if in_sentence else _("Today at {time}")
        return pattern.format(time=clock(at, tz))
    if day == today - timedelta(days=1):
        pattern = _("yesterday at {time}") if in_sentence else _("Yesterday at {time}")
        return pattern.format(time=clock(at, tz))
    return calendar_date(at, tz)


def ago(at: datetime, now: datetime, tz: tzinfo | None = None) -> str:
    """Coarse relative time for sync status: `just now`, `5 minutes ago`, `3 hours ago`."""
    seconds = (now - at).total_seconds()
    if seconds < 60:  # noqa: PLR2004 - one minute
        return _("just now")
    minutes = int(seconds // 60)
    if minutes < 60:  # noqa: PLR2004 - one hour
        return ngettext("{n} minute ago", "{n} minutes ago", minutes).format(n=minutes)
    hours = minutes // 60
    if hours < 24:  # noqa: PLR2004 - one day
        return ngettext("{n} hour ago", "{n} hours ago", hours).format(n=hours)
    return date_time(at, now, tz, in_sentence=True)


def days_left(expires_at: datetime, now: datetime) -> int:
    """Whole days until purge, rounded up so "expires in 3 h" still reads as 1 day."""
    return max(0, math.ceil((expires_at - now).total_seconds() / 86400))


def days_left_text(days: int) -> str:
    if days <= 0:
        return _("Removed today")
    return ngettext("{n} day left", "{n} days left", days).format(n=days)


def reason_text(reason: TrashReason) -> str:
    texts = {
        TrashReason.DELETED_ON_LINUX: _("Deleted on this computer"),
        TrashReason.DELETED_IN_ICLOUD: _("Deleted on another device"),
        TrashReason.DELETED_BOTH: _("Deleted everywhere"),
        TrashReason.CONFLICT: _("Replaced by a newer edit"),
    }
    return texts.get(reason, pgettext("why an item is in Deleted", "Deleted"))


def status_title(status: Status, *, refused: bool = False) -> str:
    """Short label for the header button; `refused`: iCloud refuses some password."""
    if refused and status.state is SyncState.IDLE:
        return _("Not All Synced")
    titles = {
        SyncState.IDLE: _("Synced"),
        SyncState.SYNCING: _("Syncing…"),
        SyncState.PAUSED: _("Sync Paused"),
        SyncState.OFFLINE: _("Offline"),
        SyncState.SIGNIN_REQUIRED: _("Sign-In Required"),
        SyncState.SIGNED_OUT: _("Not Signed In"),
        SyncState.ERROR: _("Sync Error"),
        SyncState.UNREACHABLE: _("Service Not Running"),
    }
    return titles[status.state]


def status_icon(status: Status, *, refused: bool = False) -> str:
    if refused and status.state is SyncState.IDLE:
        return "dialog-warning-symbolic"
    icons = {
        SyncState.IDLE: "pa-synced-symbolic",
        SyncState.SYNCING: "pa-syncing-symbolic",
        SyncState.PAUSED: "pa-paused-symbolic",
        SyncState.OFFLINE: "pa-offline-symbolic",
        SyncState.SIGNIN_REQUIRED: "dialog-password-symbolic",
        SyncState.SIGNED_OUT: "avatar-default-symbolic",
        SyncState.ERROR: "pa-error-symbolic",
        SyncState.UNREACHABLE: "dialog-warning-symbolic",
    }
    return icons[status.state]


# The daemon's wording for refusals it knows (sync.remote_icloud.DUPLICATE_LOGIN), so the
# app can show them translated; any other reason is shown as the daemon wrote it.
_SYNC_PROBLEMS = {
    "another password for this website and username already exists": _n_(
        "Another password for this website and username already exists."
    ),
}


def sync_problem_text(problem: str) -> str:
    """Say why iCloud refuses to store a password, from the item's sync_problem."""
    known = _SYNC_PROBLEMS.get(problem)
    if known is not None:
        return _(known)
    return problem if problem.endswith(".") else f"{problem}."


def status_detail(  # noqa: PLR0911 - one early return per sync state reads as the spec's table
    status: Status, now: datetime, tz: tzinfo | None = None
) -> str:
    """One sentence for the status popover; the daemon's own message wins when it has one."""
    if status.message:
        return status.message
    if status.state is SyncState.UNREACHABLE:
        return _("The Passwords background service is not running.")
    if status.state is SyncState.SIGNED_OUT:
        return _("Sign in with your Apple Account to sync passwords with iCloud Keychain.")
    if status.state is SyncState.SIGNIN_REQUIRED:
        return _("Apple asks you to sign in again before syncing can continue.")
    if status.state is SyncState.PAUSED:
        return pause_title(status)
    if status.last_sync is None:
        return _("Not synced yet")
    return _("Last synced {when}").format(when=ago(status.last_sync, now, tz))


def pause_title(status: Status) -> str:
    n = status.pending_deletions
    return ngettext(
        "Sync paused: {n} password would be deleted",
        "Sync paused: {n} passwords would be deleted",
        n,
    ).format(n=n)


class Copied(StrEnum):
    PASSWORD = "password"  # noqa: S105  # nosec B105 - a kind of value, not a secret
    USERNAME = "username"
    CODE = "code"


def copied_text(what: Copied, delay: int) -> str:
    """Toast after a copy; `delay` is the auto-clear time in seconds (0 = never)."""
    if what is Copied.PASSWORD:
        if delay:
            return _("Password copied · clears in {n} s").format(n=delay)
        return _("Password copied")
    if what is Copied.CODE:
        if delay:
            return _("Verification code copied · clears in {n} s").format(n=delay)
        return _("Verification code copied")
    return _("User name copied")


def passwords_count(n: int) -> str:
    return ngettext("{n} password", "{n} passwords", n).format(n=n)


# The daemon's WrongPasscode text is English and may carry the attempts left on that device
# ("… 9 attempts left …"); only the number is taken from it, the sentence is the app's own.
_ATTEMPTS_LEFT = re.compile(r"(\d+)\s+attempts?\s+left", re.IGNORECASE)


def wrong_passcode_text(daemon_message: str) -> str:
    match = _ATTEMPTS_LEFT.search(daemon_message)
    if match is None:
        return _("Wrong passcode.")
    n = int(match.group(1))
    return ngettext(
        "Wrong passcode. {n} attempt left on this device.",
        "Wrong passcode. {n} attempts left on this device.",
        n,
    ).format(n=n)
