# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S3: a password deleted on the iPhone leaves the keyring, the app and the browsers, and
waits in Recently Deleted (reason: deleted in iCloud)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import NORTHWIND
from tests.e2e.browsers import no_fill_offered
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack


def test_s03_delete_on_apple_removes_everywhere_and_keeps_it_in_trash(
    stack: Stack, site: SiteServer
) -> None:
    seeded = stack.seeded["northwind"]
    app = stack.app
    assert app.item(seeded.id) is not None

    stack.apple.delete(seeded.id)

    wait_until(lambda: stack.keyring.by_id(seeded.id) is None, what="keyring item removed")
    wait_until(lambda: app.item(seeded.id) is None, what="row removed from the app")
    entry = wait_until(
        lambda: stack.trash_entry(seeded.id, "deleted-in-icloud"), what="trash entry"
    )
    assert entry["item"]["url"] == seeded.url
    assert entry["expires_at"] - entry["deleted_at"] == 90 * 86_400_000
    app.section("deleted")
    wait_until(
        lambda: [e.reason for e in app.trash() if e.item.id == seeded.id] == ["deleted-in-icloud"],
        what="the entry in the app's Deleted view",
    )
    assert "Northwind Mail" in app.deleted_titles()
    for browser in (stack.firefox, stack.chromium):
        no_fill_offered(browser, site.url(NORTHWIND))
    # The other logins are untouched on both sides.
    others = {k: v for k, v in stack.seeded.items() if k != "northwind"}
    assert set(stack.apple.logins()) == {c.id for c in others.values()}
    assert all(stack.keyring_matches(c) for c in others.values())
