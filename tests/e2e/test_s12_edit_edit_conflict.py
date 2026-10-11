# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S12: the same password edited on the iPhone and on Linux while they could not sync.

The newer edit wins on both sides; the other one is not lost: it waits in Recently Deleted
(reason "conflict"), from where the user can restore it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from tests.e2e.apple import login
from tests.e2e.stack import SurfaceTimeoutError, pump, wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack

ON_IPHONE = "FAKE-edited-on-the-iphone"
ON_LINUX = "FAKE-edited-in-seahorse"


def _conflicting_edits(stack: Stack, newer: str) -> tuple[str, str]:
    """Edit contoso on both sides while the daemon is stopped; returns (winner, loser)."""
    seeded = stack.seeded["contoso"]
    item = stack.keyring.by_id(seeded.id)
    assert item is not None
    stack.stop_daemon()  # e.g. the laptop was asleep while both edits happened

    def edit_on_iphone() -> None:
        stack.apple.edit(seeded.id, password=ON_IPHONE)

    def edit_on_linux() -> None:
        stack.keyring.set_secret(item.path, ON_LINUX)

    older, newest = (
        (edit_on_linux, edit_on_iphone) if newer == "iphone" else (edit_on_iphone, edit_on_linux)
    )
    older()
    pump(2.5)  # timestamps are whole seconds on the keyring side
    newest()
    stack.start_daemon()
    return (ON_IPHONE, ON_LINUX) if newer == "iphone" else (ON_LINUX, ON_IPHONE)


@pytest.mark.parametrize("newer", ["iphone", "linux"])
def test_s12_newer_edit_wins_and_the_other_is_kept(stack: Stack, newer: str) -> None:
    seeded = stack.seeded["contoso"]
    winner, _ = _conflicting_edits(stack, newer)

    def converged() -> bool:
        held = stack.apple.get(seeded.id)
        local = stack.keyring.by_id(seeded.id)
        return bool(held and local and held.password == winner and local.secret == winner)

    wait_until(converged, what=f"both sides on the {newer} edit")
    entry = wait_until(lambda: stack.trash_entry(seeded.id, "conflict"), what="conflict entry")
    assert entry["item"]["username"] == seeded.username
    app = stack.app
    wait_until(lambda: app.detail_shows(seeded.id, password=winner), what="app shows the winner")
    app.section("deleted")
    wait_until(
        lambda: [e.reason for e in app.trash() if e.item.id == seeded.id] == ["conflict"],
        what="the losing version in the app's Deleted view",
    )
    assert len(stack.apple.logins()) == len(stack.seeded)
    stack.assert_no_duplicates()


@pytest.mark.xfail(
    strict=True,
    raises=(SurfaceTimeoutError, AssertionError),
    reason="#66: restoring a login whose site and username exist leaves sync 'offline'",
)
def test_s12_restoring_the_conflict_loser_reaches_icloud(stack: Stack) -> None:
    seeded = stack.seeded["contoso"]
    _winner, loser = _conflicting_edits(stack, "iphone")
    entry = wait_until(lambda: stack.trash_entry(seeded.id, "conflict"), what="conflict entry")

    restored_id = stack.daemon.call("Restore", "s", entry["trash_id"])
    wait_until(
        lambda: (i := stack.keyring.by_id(restored_id)) and i.secret == loser,
        what="the restored version in the keyring",
    )
    # Later changes keep flowing to iCloud, and the status does not claim to be offline.
    later = login("https://news.tailspin.example", "reader", "FAKE-made-after-restore")
    stack.keyring.create(f"{later.username} @ news.tailspin.example", later.password)
    wait_until(
        lambda: stack.apple.find(later.url, later.username), what="a later Linux change in iCloud"
    )
    assert stack.daemon.status()["state"] != "offline"
