# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S6: a password deleted in the app is deleted in iCloud and the keyring, and kept in
Recently Deleted (reason: deleted on this computer)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import NORTHWIND
from tests.e2e.browsers import no_fill_offered
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack


def test_s06_delete_in_app_deletes_in_icloud_and_keeps_trash(
    stack: Stack, site: SiteServer
) -> None:
    seeded = stack.seeded["northwind"]
    app = stack.app
    app.delete(seeded.id)

    wait_until(lambda: stack.apple.get(seeded.id) is None, what="record deleted in iCloud")
    wait_until(lambda: stack.keyring.by_id(seeded.id) is None, what="keyring item deleted")
    entry = wait_until(lambda: stack.trash_entry(seeded.id, "deleted-on-linux"), what="trash")
    assert entry["item"]["username"] == seeded.username
    app.section("deleted")
    wait_until(
        lambda: [e.reason for e in app.trash() if e.item.id == seeded.id] == ["deleted-on-linux"],
        what="the entry in the app's Deleted view",
    )
    no_fill_offered(stack.firefox, site.url(NORTHWIND))
    others = [c for k, c in stack.seeded.items() if k != "northwind"]
    assert set(stack.apple.logins()) == {c.id for c in others}
