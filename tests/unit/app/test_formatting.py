# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""User-facing dates, relative times, trash countdowns and sync-status text (English)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st

from passwords_app.app import i18n
from passwords_app.app.formatting import (
    ago,
    calendar_date,
    clock,
    date_time,
    days_left,
    days_left_text,
    passwords_count,
    pause_title,
    reason_text,
    status_detail,
    status_icon,
    status_title,
    sync_problem_text,
    wrong_passcode_text,
)
from passwords_app.app.records import Status, SyncState, TrashReason

NOW = datetime(2026, 10, 10, 14, 5, 30, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _english() -> None:
    i18n.setup(["en"])


# ---------------------------------------------------------------- dates


def test_clock_is_zero_padded_24h() -> None:
    assert clock(datetime(2026, 1, 2, 9, 3, tzinfo=UTC), UTC) == "09:03"
    assert clock(datetime(2026, 1, 2, 23, 59, 59, tzinfo=UTC), UTC) == "23:59"


def test_clock_converts_to_the_given_zone() -> None:
    plus3 = timezone(timedelta(hours=3))
    assert clock(datetime(2026, 1, 2, 22, 30, tzinfo=UTC), plus3) == "01:30"


@pytest.mark.parametrize(
    ("month", "text"),
    [
        (1, "January 5, 2026"),
        (2, "February 5, 2026"),
        (3, "March 5, 2026"),
        (4, "April 5, 2026"),
        (5, "May 5, 2026"),
        (6, "June 5, 2026"),
        (7, "July 5, 2026"),
        (8, "August 5, 2026"),
        (9, "September 5, 2026"),
        (10, "October 5, 2026"),
        (11, "November 5, 2026"),
        (12, "December 5, 2026"),
    ],
)
def test_calendar_date_every_month(month: int, text: str) -> None:
    assert calendar_date(datetime(2026, month, 5, 12, tzinfo=UTC), UTC) == text


def test_calendar_date_uses_local_day() -> None:
    minus5 = timezone(timedelta(hours=-5))
    assert calendar_date(datetime(2026, 1, 1, 2, tzinfo=UTC), minus5) == "December 31, 2025"


@pytest.mark.parametrize(
    ("at", "text"),
    [
        (NOW, "Today at 14:05"),
        (datetime(2026, 10, 10, 0, 0, tzinfo=UTC), "Today at 00:00"),
        (datetime(2026, 10, 9, 23, 59, tzinfo=UTC), "Yesterday at 23:59"),
        (datetime(2026, 10, 9, 0, 0, tzinfo=UTC), "Yesterday at 00:00"),
        (datetime(2026, 10, 8, 23, 59, tzinfo=UTC), "October 8, 2026"),
        (datetime(2025, 10, 10, 14, 5, tzinfo=UTC), "October 10, 2025"),
    ],
)
def test_date_time(at: datetime, text: str) -> None:
    assert date_time(at, NOW, UTC) == text


def test_date_time_today_depends_on_zone() -> None:
    at = datetime(2026, 10, 9, 22, 0, tzinfo=UTC)
    now = datetime(2026, 10, 10, 1, 0, tzinfo=UTC)
    assert date_time(at, now, UTC) == "Yesterday at 22:00"
    assert date_time(at, now, timezone(timedelta(hours=3))) == "Today at 01:00"


# ---------------------------------------------------------------- ago


@pytest.mark.parametrize(
    ("delta", "text"),
    [
        (timedelta(seconds=-10), "just now"),
        (timedelta(0), "just now"),
        (timedelta(seconds=59), "just now"),
        (timedelta(seconds=59.999), "just now"),
        (timedelta(seconds=60), "1 minute ago"),
        (timedelta(seconds=119), "1 minute ago"),
        (timedelta(minutes=2), "2 minutes ago"),
        (timedelta(minutes=59, seconds=59), "59 minutes ago"),
        (timedelta(hours=1), "1 hour ago"),
        (timedelta(hours=2, minutes=59), "2 hours ago"),
        (timedelta(hours=23, minutes=59), "23 hours ago"),
        (timedelta(hours=24), "yesterday at 14:05"),
        (timedelta(days=3), "October 7, 2026"),
    ],
)
def test_ago_thresholds(delta: timedelta, text: str) -> None:
    assert ago(NOW - delta, NOW, UTC) == text


# ---------------------------------------------------------------- trash countdown


@pytest.mark.parametrize(
    ("delta", "days"),
    [
        (timedelta(days=30), 30),
        (timedelta(days=29, hours=1), 30),
        (timedelta(hours=3), 1),
        (timedelta(seconds=1), 1),
        (timedelta(0), 0),
        (timedelta(days=-2), 0),
    ],
)
def test_days_left_rounds_up_and_never_goes_negative(delta: timedelta, days: int) -> None:
    assert days_left(NOW + delta, NOW) == days


@given(st.timedeltas(min_value=timedelta(days=-400), max_value=timedelta(days=400)))
def test_days_left_bounds(delta: timedelta) -> None:
    days = days_left(NOW + delta, NOW)
    assert days >= 0
    assert days * 86400 >= delta.total_seconds()
    assert days == 0 or (days - 1) * 86400 < delta.total_seconds()


@pytest.mark.parametrize(
    ("days", "text"),
    [(-1, "Removed today"), (0, "Removed today"), (1, "1 day left"), (30, "30 days left")],
)
def test_days_left_text(days: int, text: str) -> None:
    assert days_left_text(days) == text


@pytest.mark.parametrize(
    ("reason", "text"),
    [
        (TrashReason.DELETED_ON_LINUX, "Deleted on this computer"),
        (TrashReason.DELETED_IN_ICLOUD, "Deleted on another device"),
        (TrashReason.DELETED_BOTH, "Deleted everywhere"),
        (TrashReason.CONFLICT, "Replaced by a newer edit"),
        (TrashReason.UNKNOWN, "Deleted"),
    ],
)
def test_reason_text(reason: TrashReason, text: str) -> None:
    assert reason_text(reason) == text


# ---------------------------------------------------------------- sync status


@pytest.mark.parametrize(
    ("state", "title"),
    [
        (SyncState.IDLE, "Synced"),
        (SyncState.SYNCING, "Syncing…"),
        (SyncState.PAUSED, "Sync Paused"),
        (SyncState.OFFLINE, "Offline"),
        (SyncState.SIGNIN_REQUIRED, "Sign-In Required"),
        (SyncState.SIGNED_OUT, "Not Signed In"),
        (SyncState.ERROR, "Sync Error"),
        (SyncState.UNREACHABLE, "Service Not Running"),
    ],
)
def test_status_title(state: SyncState, title: str) -> None:
    assert status_title(Status(state)) == title


def test_every_state_has_a_distinct_symbolic_icon() -> None:
    icons = [status_icon(Status(state)) for state in SyncState]
    assert all(icon.endswith("-symbolic") for icon in icons)
    assert len(set(icons)) == len(SyncState)


def test_refused_passwords_turn_synced_into_a_warning() -> None:
    idle = Status(SyncState.IDLE)
    assert status_title(idle, refused=True) == "Not All Synced"
    assert status_icon(idle, refused=True) == "dialog-warning-symbolic"
    assert status_icon(idle, refused=True) != status_icon(idle)


@pytest.mark.parametrize("state", [s for s in SyncState if s is not SyncState.IDLE])
def test_other_states_keep_their_title_and_icon_while_passwords_are_refused(
    state: SyncState,
) -> None:
    status = Status(state)
    assert status_title(status, refused=True) == status_title(status)
    assert status_icon(status, refused=True) == status_icon(status)


def test_sync_problem_text_translates_known_reasons_and_passes_others_through() -> None:
    from passwords_app.sync.remote_icloud import DUPLICATE_LOGIN  # noqa: PLC0415

    assert sync_problem_text(DUPLICATE_LOGIN) == (
        "Another password for this website and username already exists."
    )
    other = "iCloud Keychain cannot store this login: not a website address"
    assert sync_problem_text(other) == f"{other}."


@pytest.mark.parametrize("state", list(SyncState))
def test_daemon_message_wins_in_every_state(state: SyncState) -> None:
    status = Status(state, message="Apple's servers are busy", last_sync=NOW)
    assert status_detail(status, NOW, UTC) == "Apple's servers are busy"


@pytest.mark.parametrize(
    ("status", "text"),
    [
        (Status(SyncState.UNREACHABLE), "The Passwords background service is not running."),
        (
            Status(SyncState.SIGNED_OUT, last_sync=NOW),
            "Sign in with your Apple Account to sync passwords with iCloud Keychain.",
        ),
        (
            Status(SyncState.SIGNIN_REQUIRED),
            "Apple asks you to sign in again before syncing can continue.",
        ),
        (
            Status(SyncState.PAUSED, pending_local_deletions=("a",), last_sync=NOW),
            "Sync paused: 1 password would be deleted",
        ),
        (Status(SyncState.IDLE), "Not synced yet"),
        (Status(SyncState.ERROR), "Not synced yet"),
        (Status(SyncState.IDLE, last_sync=NOW - timedelta(seconds=5)), "Last synced just now"),
        (
            Status(SyncState.OFFLINE, last_sync=NOW - timedelta(minutes=5)),
            "Last synced 5 minutes ago",
        ),
        (
            Status(SyncState.SYNCING, last_sync=NOW - timedelta(days=1, hours=1)),
            "Last synced yesterday at 13:05",
        ),
    ],
)
def test_status_detail(status: Status, text: str) -> None:
    assert status_detail(status, NOW, UTC) == text


@pytest.mark.parametrize(
    ("local", "remote", "text"),
    [
        ((), (), "Sync paused: 0 passwords would be deleted"),
        (("a",), (), "Sync paused: 1 password would be deleted"),
        ((), ("b",), "Sync paused: 1 password would be deleted"),
        (("a", "b"), ("c",), "Sync paused: 3 passwords would be deleted"),
    ],
)
def test_pause_title_counts_both_directions(
    local: tuple[str, ...], remote: tuple[str, ...], text: str
) -> None:
    status = Status(
        SyncState.PAUSED, pending_local_deletions=local, pending_remote_deletions=remote
    )
    assert pause_title(status) == text


@pytest.mark.parametrize(
    ("n", "text"),
    [(0, "0 passwords"), (1, "1 password"), (2, "2 passwords"), (5000, "5000 passwords")],
)
def test_passwords_count(n: int, text: str) -> None:
    assert passwords_count(n) == text


# ---------------------------------------------------------------- wrong passcode


@pytest.mark.parametrize(
    ("daemon", "expected"),
    [
        ("Wrong passcode. 9 attempts left on this device.",) * 2,
        ("Wrong passcode. 1 attempt left on this device.",) * 2,
        ("the passcode was not accepted", "Wrong passcode."),
        ("", "Wrong passcode."),
    ],
)
def test_wrong_passcode_text(daemon: str, expected: str) -> None:
    assert wrong_passcode_text(daemon) == expected
