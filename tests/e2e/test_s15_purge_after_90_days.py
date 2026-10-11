# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S15: Recently Deleted keeps a password for 90 days, then purges it (the daemon's wall clock
is moved forward; nothing else is faked)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.e2e.stack import stays, wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack


def test_s15_trash_is_kept_89_days_and_purged_after_90(stack: Stack) -> None:
    seeded = stack.seeded["contoso"]
    app = stack.app
    app.delete(seeded.id)
    wait_until(lambda: stack.trash_entry(seeded.id, "deleted-on-linux"), what="trash entry")
    wait_until(lambda: stack.apple.get(seeded.id) is None, what="deleted in iCloud")

    stack.days_later(89)
    stack.daemon.sync_now()
    stays(lambda: stack.trash_entry(seeded.id), seconds=4, what="the entry on day 89")
    assert stack.daemon.status()["trash_count"] == 1

    stack.days_later(91)
    stack.daemon.sync_now()
    wait_until(lambda: stack.trash_entry(seeded.id) is None, what="purged on day 91")
    assert stack.daemon.status()["trash_count"] == 0
    app.section("deleted")
    wait_until(lambda: not app.trash(), what="the app's Deleted view empty")
    # Purging Recently Deleted touches nothing that is still live.
    others = [c for k, c in stack.seeded.items() if k != "contoso"]
    assert set(stack.apple.logins()) == {c.id for c in others}
    assert all(stack.keyring_matches(c) for c in others)
