# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S2: a password and title changed on the iPhone change on Linux: keyring, app, browsers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import NORTHWIND
from tests.e2e.browsers import fill
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack

NEW_SECRET = "FAKE-northwind-changed-on-iphone"


def test_s02_edit_on_apple_reaches_keyring_app_and_both_browsers(
    stack: Stack, site: SiteServer
) -> None:
    seeded = stack.seeded["northwind"]
    app = stack.app
    wait_until(lambda: app.detail_shows(seeded.id, password=seeded.password), what="app before")

    edited = stack.apple.edit(seeded.id, password=NEW_SECRET, title="NW Mail")

    item = wait_until(lambda: stack.keyring_matches(edited), what="new password in the keyring")
    assert item.label == "NW Mail — alex.doe@example.com"
    wait_until(
        lambda: app.detail_shows(seeded.id, password=NEW_SECRET, title="NW Mail"),
        what="the edit in the app",
    )
    assert "Northwind Mail" not in app.titles()
    for browser in (stack.firefox, stack.chromium):
        assert fill(browser, site.url(NORTHWIND)) == (seeded.username, NEW_SECRET)
    stack.assert_no_duplicates()
    assert len(stack.apple.logins()) == len(stack.seeded)
