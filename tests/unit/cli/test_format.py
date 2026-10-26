# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Rendering of status, item lists, item details and Recently Deleted."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from passwords_app.cli import format as fmt

NOW = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
HIDDEN = "hidden-value-for-format-tests"


def ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def ago(**kw: float) -> int:
    return ms(NOW - timedelta(**kw))


def ahead(**kw: float) -> int:
    return ms(NOW + timedelta(**kw))


def item(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "ID-1",
        "url": "https://mail.example.com/login",
        "username": "alice",
        "title": "",
        "notes": "",
        "alt_urls": [],
        "group": "",
        "created": ago(days=10),
        "modified": ago(hours=3),
        "has_code": False,
    }
    base.update(fields)
    return base


def status(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "state": "idle",
        "apple_id": "alice@example.com",
        "item_count": 12,
        "trash_count": 0,
        "last_sync": ago(minutes=5),
        "next_sync": ahead(minutes=4),
        "message": "",
        "pending_local_deletions": [],
        "pending_remote_deletions": [],
    }
    base.update(fields)
    return base


# ---------------------------------------------------------------- relative times


@pytest.mark.parametrize(
    ("when", "text"),
    [
        (0, "never"),
        (ago(seconds=5), "just now"),
        (ago(seconds=59), "just now"),
        (ago(minutes=1), "1 min ago"),
        (ago(minutes=59), "59 min ago"),
        (ago(hours=1), "1 h ago"),
        (ago(hours=23, minutes=59), "23 h ago"),
        (ago(days=1), "1 day ago"),
        (ago(days=89), "89 days ago"),
        (ahead(seconds=30), "in a moment"),
        (ahead(minutes=4, seconds=30), "in 4 min"),
        (ahead(hours=2), "in 2 h"),
        (ahead(days=3), "in 3 days"),
    ],
)
def test_relative(when: int, text: str) -> None:
    assert fmt.relative(when, NOW) == text


def test_relative_custom_never() -> None:
    assert fmt.relative(0, NOW, never="not scheduled") == "not scheduled"


# ---------------------------------------------------------------- names


@pytest.mark.parametrize(
    ("fields", "name"),
    [
        ({"title": "Work mail"}, "Work mail"),
        ({"title": ""}, "mail.example.com"),
        ({"url": "http://192.168.1.1:8080/admin"}, "192.168.1.1"),
        ({"url": "https://[::1]:8443"}, "::1"),
        ({"url": "https://xn--e1afmkfd.xn--p1ai"}, "xn--e1afmkfd.xn--p1ai"),
    ],
)
def test_display_name(fields: dict[str, Any], name: str) -> None:
    assert fmt.display_name(item(**fields)) == name


# ---------------------------------------------------------------- status


def test_idle_status() -> None:
    text = fmt.status_text(status(), NOW)
    assert "Passwords:  Up to date" in text
    assert "Account:    alice@example.com" in text
    assert "Items:      12" in text
    assert "Last sync:  5 min ago" in text
    assert "Next sync:  in 4 min" in text


def test_trash_count_is_mentioned_only_when_non_zero() -> None:
    assert "recently deleted" not in fmt.status_text(status(), NOW)
    assert "Items:      12 (3 recently deleted)" in fmt.status_text(status(trash_count=3), NOW)


def test_never_synced() -> None:
    assert "Last sync:  never" in fmt.status_text(status(last_sync=0, next_sync=0), NOW)


def test_signed_out_points_to_signin_and_hides_sync_times() -> None:
    text = fmt.status_text(
        status(state="signed-out", apple_id="", last_sync=0, next_sync=0, message="Not signed in"),
        NOW,
    )
    assert "Signed out" in text
    assert "Account" not in text
    assert "Last sync" not in text
    assert "passwords-app signin" in text


def test_signin_required_points_to_signin() -> None:
    text = fmt.status_text(status(state="signin-required", message="Apple needs you"), NOW)
    assert "Sign-in required" in text
    assert "Apple needs you" in text
    assert "passwords-app signin" in text
    assert "sign in again" in text


def test_a_sign_in_waiting_for_the_passcode_says_it_needs_only_that() -> None:
    text = fmt.status_text(
        status(state="signin-required", message="Finish signing in", join_pending=True), NOW
    )
    assert "passwords-app signin" in text
    assert "asks only for a device passcode" in text
    assert "sign in again" not in text


def test_paused_lists_held_back_deletions_and_both_choices() -> None:
    text = fmt.status_text(
        status(
            state="paused",
            pending_local_deletions=["A", "B"],
            pending_remote_deletions=["C"],
            message="Sync paused: 3 passwords would be deleted.",
        ),
        NOW,
    )
    assert "Paused" in text
    assert "2 deletion(s) in this computer's keyring, 1 in iCloud" in text
    assert "passwords-app resolve apply" in text
    assert "passwords-app resolve restore" in text


@pytest.mark.parametrize(
    ("state", "label"),
    [
        ("syncing", "Syncing…"),
        ("offline", "Offline"),
        ("error", "Error"),
        ("something-new", "something-new"),
    ],
)
def test_state_labels(state: str, label: str) -> None:
    assert f"Passwords:  {label}" in fmt.status_text(status(state=state), NOW)


# ---------------------------------------------------------------- lists


def test_empty_list() -> None:
    assert fmt.items_table([]) == "No passwords."


def test_items_table_columns_align() -> None:
    rows = [
        item(id="A", title="Short"),
        item(id="B-LONGER", url="https://a-much-longer-host.example.com", username=""),
        item(id="C", has_code=True),
    ]
    lines = fmt.items_table(rows).splitlines()
    assert lines[0].split() == ["NAME", "USERNAME", "WEBSITE", "2FA", "ID"]
    starts = {line.index(line.split()[-1]) for line in lines}
    assert len(starts) == 1  # the ID column starts at the same offset on every row
    assert "—" in lines[2]  # empty username
    assert "code" in lines[3]


def test_items_table_has_no_secrets() -> None:
    assert HIDDEN not in fmt.items_table([item(password=HIDDEN)])


@pytest.mark.parametrize(
    ("query", "ids"),
    [
        ("", ["A", "B", "C"]),
        ("mail", ["A"]),
        ("MAIL", ["A"]),
        ("bob", ["B"]),
        ("Bank", ["C"]),
        ("shop.example.org", ["B"]),
        ("nothing", []),
        ("CAROL", ["C"]),
        ("example", ["A", "B", "C"]),
        ("  bob  ", ["B"]),
    ],
)
def test_filter_items(query: str, ids: list[str]) -> None:
    items = [
        item(id="A", url="https://mail.example.com"),
        item(
            id="B",
            url="https://shop.example.net",
            username="bob",
            alt_urls=["https://shop.example.org"],
        ),
        item(id="C", url="https://x.example.com", title="My Bank", username="carol"),
    ]
    assert [i["id"] for i in fmt.filter_items(items, query)] == ids


# ---------------------------------------------------------------- details


def test_detail_masks_the_password_by_default() -> None:
    text = fmt.item_detail(item(password=HIDDEN), reveal=False, code=None, now=NOW)
    assert HIDDEN not in text
    assert fmt.MASK in text


def test_detail_reveals_on_request() -> None:
    text = fmt.item_detail(item(password=HIDDEN), reveal=True, code=None, now=NOW)
    assert f"Password:  {HIDDEN}" in text


def test_detail_shows_the_code_never_the_seed() -> None:
    text = fmt.item_detail(
        item(has_code=True, otpauth="otpauth://totp/x?issuer=y"),
        reveal=True,
        code=("123456", 17),
        now=NOW,
    )
    assert "Code:      123456 (17 s left)" in text
    assert "otpauth" not in text


def test_detail_optional_fields() -> None:
    text = fmt.item_detail(
        item(
            title="Mail",
            alt_urls=["https://a.example.com", "https://b.example.com"],
            group="Family",
            notes="first\nsecond",
        ),
        reveal=False,
        code=None,
        now=NOW,
    )
    lines = text.splitlines()
    assert lines[0] == "Mail"
    assert "Also used on: https://a.example.com, https://b.example.com" in text
    assert "Shared group: Family" in text
    assert "  Notes:     first" in lines
    assert "             second" in lines
    assert "Modified:  3 h ago" in text
    assert "ID:        ID-1" in text


def test_detail_omits_empty_optional_fields() -> None:
    text = fmt.item_detail(item(), reveal=False, code=None, now=NOW)
    for absent in ("Also used on", "Shared group", "Notes", "Code"):
        assert absent not in text


# ---------------------------------------------------------------- trash


def entry(reason: str = "deleted-in-icloud", days_ago: float = 1, **fields: Any) -> dict[str, Any]:
    deleted = NOW - timedelta(days=days_ago)
    return {
        "trash_id": "T" * 32,
        "reason": reason,
        "deleted_at": ms(deleted),
        "expires_at": ms(deleted + timedelta(days=90)),
        "item": item(**fields),
    }


def test_empty_trash() -> None:
    assert fmt.trash_table([], NOW) == "Recently Deleted is empty."


@pytest.mark.parametrize(
    ("reason", "why"),
    [
        ("deleted-in-icloud", "deleted on an Apple device"),
        ("deleted-on-linux", "deleted on this computer"),
        ("deleted-both", "deleted everywhere"),
        ("conflict", "replaced by a newer edit"),
        ("future-reason", "future-reason"),
    ],
)
def test_trash_reasons_are_explained(reason: str, why: str) -> None:
    assert why in fmt.trash_table([entry(reason)], NOW)


@pytest.mark.parametrize(
    ("days_ago", "left"), [(0, "90 days"), (1, "89 days"), (89.5, "0 days"), (95, "0 days")]
)
def test_trash_days_left(days_ago: float, left: str) -> None:
    assert left in fmt.trash_table([entry(days_ago=days_ago)], NOW)


def test_trash_table_shows_ids_for_restore() -> None:
    table = fmt.trash_table([entry()], NOW)
    assert "T" * 32 in table
    assert table.splitlines()[0].split()[-2:] == ["TRASH", "ID"]


def test_no_text_mentions_escrow() -> None:
    texts = [fmt.status_text(status(state=s), NOW) for s in fmt.STATE_LABELS]
    texts += list(fmt.REASONS.values())
    assert all("escrow" not in t.lower() for t in texts)
