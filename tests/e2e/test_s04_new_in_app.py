# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S4: a password created in the app reaches iCloud (decrypted on the iPhone side), the
keyring and the browsers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import FABRIKAM
from tests.e2e.browsers import fill
from tests.e2e.proof import capture_app, capture_page, overlay_shot
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack

SCENARIO = "s04-new-in-app"
NEW_SECRET = "FAKE-created-in-the-app"


def test_s04_new_in_app_reaches_icloud_keyring_and_browsers(stack: Stack, site: SiteServer) -> None:
    app = stack.app
    url = site.origin(FABRIKAM)
    app.new_password(url, "lee.park@example.com", NEW_SECRET, title="Fabrikam (app)")

    on_phone = wait_until(
        lambda: stack.apple.find(url, "lee.park@example.com"), what="the login in iCloud"
    )
    assert on_phone.password == NEW_SECRET
    assert on_phone.title == "Fabrikam (app)"
    # Linux and the iPhone agree on the item's identity.
    assert stack.keyring_matches(on_phone) is not None
    (listed,) = stack.daemon.find(url, "lee.park@example.com")
    assert listed["id"] == on_phone.id
    wait_until(lambda: app.detail_shows(on_phone.id, password=NEW_SECRET), what="app detail")
    capture_app(app, SCENARIO)
    for browser in (stack.firefox, stack.chromium):
        shot = overlay_shot(browser, SCENARIO, "dropdown")
        assert fill(browser, site.url(FABRIKAM), at_dropdown=shot) == (
            "lee.park@example.com",
            NEW_SECRET,
        )
        capture_page(browser, SCENARIO)
    stack.assert_no_duplicates()
