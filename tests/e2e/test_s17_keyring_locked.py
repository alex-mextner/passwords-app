# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S17: a locked keyring is never read as "empty": no password is deleted anywhere while it
is locked, the status says why, and sync catches up once it is unlocked."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.e2e.apple import login
from tests.e2e.stack import stays, wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack


def test_s17_locked_keyring_deletes_nothing_and_resumes_on_unlock(stack: Stack) -> None:
    app = stack.app
    seeded = stack.seeded
    stack.keyring.lock_everything()
    # Meanwhile the iPhone keeps working.
    gone = seeded["contoso"]
    stack.apple.delete(gone.id)
    added = stack.apple.create(
        login("https://news.tailspin.example", "reader", "FAKE-while-locked")
    )

    status = wait_until(
        lambda: (s := stack.daemon.status())["state"] == "error" and "locked" in s["message"] and s,
        what="status 'error: keyring locked'",
    )
    assert "Unlock it to sync" in status["message"]
    wait_until(lambda: app.status_title() == "Sync Error", what="app status")
    # Several cycles: iCloud loses nothing (the locked keyring was not taken for "all deleted").
    kept = {seeded["northwind"].id, seeded["woodgrove"].id, added.id}
    stays(lambda: kept <= set(stack.apple.logins()), seconds=6, what="iCloud intact")
    assert stack.daemon.trash() == []

    stack.keyring.unlock_login()
    wait_until(lambda: stack.keyring_matches(added), what="the new login after unlock")
    wait_until(lambda: stack.keyring.by_id(gone.id) is None, what="the delete after unlock")
    wait_until(lambda: stack.daemon.status()["state"] == "idle", what="status idle")
    assert kept == set(stack.apple.logins())
    assert all(stack.keyring_matches(seeded[k]) for k in ("northwind", "woodgrove"))
    assert stack.trash_entry(gone.id, "deleted-in-icloud") is not None
