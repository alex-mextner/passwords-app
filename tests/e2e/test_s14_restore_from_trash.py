# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S14: a password deleted on the iPhone is restored from the app's Deleted view and comes
back on both sides (and in the browsers)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import NORTHWIND
from tests.e2e.browsers import fill
from tests.e2e.proof import capture_app, capture_page
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack

SCENARIO = "s14-restore-from-trash"


def test_s14_restore_brings_the_password_back_on_both_sides(stack: Stack, site: SiteServer) -> None:
    seeded = stack.seeded["northwind"]
    app = stack.app
    stack.apple.delete(seeded.id)
    entry = wait_until(
        lambda: stack.trash_entry(seeded.id, "deleted-in-icloud"), what="trash entry"
    )
    wait_until(lambda: stack.keyring.by_id(seeded.id) is None, what="gone from the keyring")

    app.restore(entry["trash_id"])

    def back_in_icloud() -> list[str]:
        return [
            c.id
            for c in stack.apple.logins().values()
            if (c.url, c.username, c.password) == (seeded.url, seeded.username, seeded.password)
        ]

    (restored_id,) = wait_until(back_in_icloud, what="the login back in iCloud")
    local = stack.keyring.by_id(restored_id)
    assert local is not None
    assert local.secret == seeded.password
    assert stack.trash_entry(seeded.id) is None
    wait_until(lambda: app.detail_shows(restored_id, password=seeded.password), what="app")
    capture_app(app, SCENARIO)
    for browser in (stack.firefox, stack.chromium):
        assert fill(browser, site.url(NORTHWIND)) == (seeded.username, seeded.password)
        capture_page(browser, SCENARIO)
    stack.assert_no_duplicates()
