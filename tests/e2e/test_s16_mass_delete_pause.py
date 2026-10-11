# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S16: deleting many passwords at once pauses sync instead of deleting them on the other
side; the app shows a banner, and the user applies the deletions or restores the passwords.

13 logins, 7 deleted: more than max(5, 10 %), so the guard trips (spec §5).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from tests.e2e.apple import login
from tests.e2e.proof import capture_app
from tests.e2e.stack import stays, wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack

    from passwords_app.core.model import Credential

SCENARIO = "s16-mass-delete"
EXTRA = 10
DELETED = 7


@pytest.fixture
def bulk(stack: Stack) -> list[Credential]:
    """Ten more logins on the iPhone before the first sync; returns the seven to delete."""
    extra = [
        stack.apple.create(
            login(f"https://shop{n}.example", f"buyer{n}", "-".join(("FAKE", "bulk", str(n))))
        )
        for n in range(EXTRA)
    ]
    stack.start_daemon()
    assert len(stack.keyring.items()) == len(stack.seeded) + EXTRA
    return extra[:DELETED]


def _paused(stack: Stack, side: str) -> bool:
    status = stack.daemon.status()
    return status["state"] == "paused" and len(status[f"pending_{side}_deletions"]) == DELETED


@pytest.mark.stack(daemon=False)
def test_s16_mass_delete_on_iphone_pauses_then_apply_deletes_into_trash(
    stack: Stack, bulk: list[Credential]
) -> None:
    app = stack.app
    for cred in bulk:
        stack.apple.delete(cred.id)

    wait_until(lambda: _paused(stack, "local"), what="sync paused with 7 pending deletions")
    banner = app.pause_banner
    wait_until(banner.get_revealed, what="the pause banner")
    assert banner.get_title() == "Sync paused: 7 passwords would be deleted"
    assert app.status_title() == "Sync Paused"
    # Several cycles later still nothing is deleted on Linux.
    stays(lambda: all(stack.keyring.by_id(c.id) for c in bulk), seconds=5, what="keyring intact")
    capture_app(app, SCENARIO)

    app.resolve_pause("apply")
    wait_until(
        lambda: all(stack.keyring.by_id(c.id) is None for c in bulk), what="deleted in keyring"
    )
    wait_until(
        lambda: all(stack.trash_entry(c.id, "deleted-in-icloud") for c in bulk), what="trash"
    )
    wait_until(lambda: not banner.get_revealed(), what="banner gone")
    assert stack.daemon.status()["state"] == "idle"
    app.section("deleted")
    wait_until(lambda: {c.id for c in bulk} <= {e.item.id for e in app.trash()}, what="Deleted")
    capture_app(app, f"{SCENARIO}-applied")


@pytest.mark.stack(daemon=False)
def test_s16_the_list_shows_the_passwords_while_paused(
    stack: Stack, bulk: list[Credential]
) -> None:
    app = stack.app
    wait_until(lambda: len(app.items()) == len(stack.seeded) + EXTRA, what="the app loaded")
    for cred in bulk:
        stack.apple.delete(cred.id)
    wait_until(lambda: _paused(stack, "local"), what="sync paused")
    # Nothing was deleted, so the user still sees all their passwords, not a spinner.
    wait_until(lambda: app.list_view_shown() == "items", what="the list showing passwords")
    assert len(app.titles()) == len(stack.seeded) + EXTRA


@pytest.mark.stack(daemon=False)
def test_s16_mass_delete_on_iphone_restore_brings_them_back_on_both_sides(
    stack: Stack, bulk: list[Credential]
) -> None:
    app = stack.app
    for cred in bulk:
        stack.apple.delete(cred.id)
    wait_until(lambda: _paused(stack, "local"), what="sync paused")

    app.resolve_pause("restore")

    def restored_in_icloud() -> bool:
        live = {(c.url, c.username, c.password) for c in stack.apple.logins().values()}
        return all((c.url, c.username, c.password) in live for c in bulk)

    wait_until(restored_in_icloud, what="the seven back in iCloud")
    assert all(stack.keyring_login(c.url, c.username) for c in bulk)
    wait_until(lambda: stack.daemon.status()["state"] == "idle", what="sync resumed")
    wait_until(lambda: not app.pause_banner.get_revealed(), what="banner gone")
    stack.assert_no_duplicates()
    assert len(stack.apple.logins()) == len(stack.seeded) + EXTRA


@pytest.mark.stack(daemon=False)
def test_s16_mass_delete_in_seahorse_pauses_and_icloud_keeps_them(
    stack: Stack, bulk: list[Credential]
) -> None:
    for cred in bulk:
        item = stack.keyring.by_id(cred.id)
        assert item is not None
        stack.keyring.delete(item.path)

    wait_until(lambda: _paused(stack, "remote"), what="sync paused with 7 remote deletions")
    stays(lambda: all(stack.apple.get(c.id) for c in bulk), seconds=5, what="iCloud intact")
    app = stack.app
    wait_until(app.pause_banner.get_revealed, what="the pause banner")

    app.resolve_pause("apply")
    wait_until(lambda: all(stack.apple.get(c.id) is None for c in bulk), what="deleted in iCloud")
    assert all(stack.trash_entry(c.id, "deleted-on-linux") for c in bulk)
