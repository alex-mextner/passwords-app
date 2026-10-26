# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Status dict layout and the report -> state mapping."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from passwords_app.daemon import status
from passwords_app.daemon.status import (
    MSG_AUTH,
    MSG_LOCAL,
    MSG_OFFLINE,
    Status,
    outcome,
    paused_message,
)
from passwords_app.sync.engine import SKIP_AUTH, SKIP_LOCAL, SKIP_REMOTE
from passwords_app.sync.ports import (
    PendingDeletions,
    RejectedLocalItem,
    SyncReport,
    UploadFailure,
    upload_failures_message,
)

T0 = datetime(2026, 5, 1, tzinfo=UTC)


def report(**kwargs: object) -> SyncReport:
    return SyncReport(T0, T0, **kwargs)  # type: ignore[arg-type]


def test_status_dict_has_every_key_with_the_documented_type() -> None:
    d = Status("idle").to_dbus()
    assert {k: v.signature for k, v in d.items()} == {
        "state": "s",
        "apple_id": "s",
        "item_count": "u",
        "trash_count": "u",
        "last_sync": "x",
        "next_sync": "x",
        "message": "s",
        "pending_local_deletions": "as",
        "pending_remote_deletions": "as",
        "join_pending": "b",
    }


def test_never_synced_is_zero() -> None:
    d = Status("signed-out").to_dbus()
    assert d["last_sync"].value == 0
    assert d["next_sync"].value == 0


def test_values_are_carried() -> None:
    d = Status(
        "paused",
        apple_id="alice@example.com",
        item_count=12,
        trash_count=3,
        last_sync=T0,
        next_sync=datetime(2026, 5, 1, 0, 1, tzinfo=UTC),
        message="m",
        pending_local=("A",),
        pending_remote=("B", "C"),
        join_pending=True,
    ).to_dbus()
    assert {k: v.value for k, v in d.items()} == {
        "state": "paused",
        "apple_id": "alice@example.com",
        "item_count": 12,
        "trash_count": 3,
        "last_sync": 1_777_593_600_000,
        "next_sync": 1_777_593_660_000,
        "message": "m",
        "pending_local_deletions": ["A"],
        "pending_remote_deletions": ["B", "C"],
        "join_pending": True,
    }


@pytest.mark.parametrize(
    ("reason", "state", "message"),
    [
        (SKIP_AUTH, "signin-required", MSG_AUTH),
        (SKIP_REMOTE, "offline", MSG_OFFLINE),
        (SKIP_LOCAL, "error", MSG_LOCAL),
    ],
)
def test_skipped_cycles_map_to_states(reason: str, state: str, message: str) -> None:
    assert outcome(report(skipped_reason=reason)) == (state, message)


def test_unknown_skip_reason_is_an_error_not_idle() -> None:
    assert outcome(report(skipped_reason="something-new"))[0] == "error"


def test_a_clean_cycle_is_idle() -> None:
    assert outcome(report(created_local=3)) == ("idle", "")


def test_rejected_items_alone_do_not_change_the_state() -> None:
    rejected = (RejectedLocalItem("/x", "label", "why"),)
    assert outcome(report(rejected=rejected)) == ("idle", "")


def refused(item_id: str = "A") -> UploadFailure:
    return UploadFailure(item_id, "https://example.com", "bob", "why", 1, T0)


def test_logins_icloud_refused_stay_idle_and_explain_why() -> None:
    # Only those logins wait; the rest synced, so this is not an outage (#82).
    failures = (refused("A"), refused("B"))
    assert outcome(report(upload_failures=failures)) == (
        "idle",
        upload_failures_message(failures),
    )


def test_a_pause_wins_over_refused_logins() -> None:
    # The pause needs a decision; the refusal is shown again by the next cycle.
    pending = PendingDeletions(("A",), ())
    state, _ = outcome(report(paused=pending, upload_failures=(refused(),)))
    assert state == "paused"


def test_an_outage_wins_over_refused_logins() -> None:
    assert outcome(report(skipped_reason=SKIP_REMOTE, upload_failures=(refused(),))) == (
        "offline",
        MSG_OFFLINE,
    )


def test_a_paused_cycle_is_paused() -> None:
    pending = PendingDeletions(("A", "B"), ("C",))
    state, message = outcome(report(paused=pending))
    assert state == "paused"
    assert "3 passwords" in message


def test_skip_wins_over_pause() -> None:
    # A cycle interrupted mid-way must report the outage, not a stale pause.
    pending = PendingDeletions(("A",), ())
    assert outcome(report(paused=pending, skipped_reason=SKIP_REMOTE))[0] == "offline"


@pytest.mark.parametrize(
    ("local", "remote", "text"),
    [(1, 0, "1 password would"), (0, 2, "2 passwords would"), (5, 6, "11 passwords would")],
)
def test_paused_message_counts_both_sides(local: int, remote: int, text: str) -> None:
    pending = PendingDeletions(
        tuple(f"L{i}" for i in range(local)), tuple(f"R{i}" for i in range(remote))
    )
    assert text in paused_message(pending)


def test_messages_never_mention_escrow() -> None:
    texts = [v for k, v in vars(status).items() if k.startswith("MSG_")]
    assert texts
    assert all("escrow" not in t.lower() for t in texts)
