# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S5: a password edited in the app is edited in iCloud (same record) and in the keyring."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import NORTHWIND
from tests.e2e.browsers import fill
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack

NEW_SECRET = "FAKE-edited-in-the-app"


def test_s05_edit_in_app_reaches_icloud_and_keyring(stack: Stack, site: SiteServer) -> None:
    seeded = stack.seeded["northwind"]
    app = stack.app
    app.edit(seeded.id, password=NEW_SECRET, title="Northwind Webmail")

    def on_phone() -> bool:
        held = stack.apple.get(seeded.id)
        return held is not None and (held.password, held.title) == (
            NEW_SECRET,
            "Northwind Webmail",
        )

    wait_until(on_phone, what="the edit in iCloud")
    held = stack.apple.get(seeded.id)
    assert held is not None
    assert (held.url, held.username) == (seeded.url, seeded.username)
    item = wait_until(
        lambda: (i := stack.keyring.by_id(seeded.id)) and i.secret == NEW_SECRET and i,
        what="the edit in the keyring",
    )
    assert item.label == "Northwind Webmail — alex.doe@example.com"
    assert fill(stack.firefox, site.url(NORTHWIND)) == (seeded.username, NEW_SECRET)
    stack.assert_no_duplicates()
    assert len(stack.apple.logins()) == len(stack.seeded)
