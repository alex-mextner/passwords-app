# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S9: a password deleted in Seahorse is deleted in iCloud and kept in Recently Deleted."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack


def test_s09_seahorse_delete_reaches_icloud_and_trash(stack: Stack) -> None:
    seeded = stack.seeded["contoso"]
    item = stack.keyring.by_id(seeded.id)
    assert item is not None
    stack.keyring.delete(item.path)

    wait_until(lambda: stack.apple.get(seeded.id) is None, what="record deleted in iCloud")
    entry = wait_until(lambda: stack.trash_entry(seeded.id, "deleted-on-linux"), what="trash")
    assert entry["item"]["url"] == seeded.url
    app = stack.app
    assert app.item(seeded.id) is None
    app.section("deleted")
    wait_until(lambda: seeded.id in {e.item.id for e in app.trash()}, what="the app's Deleted view")
    others = [c for k, c in stack.seeded.items() if k != "contoso"]
    assert set(stack.apple.logins()) == {c.id for c in others}
