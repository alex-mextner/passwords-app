# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S11: a login saved from Chrome (Chromium with the same extension) lands in iCloud, the
keyring and the app; a changed password saved from Chrome updates the same item."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import FABRIKAM, NORTHWIND
from tests.e2e.browsers import sign_up_and_save
from tests.e2e.proof import capture_app, capture_page
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack

SCENARIO = "s11-save-from-chrome"
NEW_SECRET = "FAKE-saved-from-chromium"
CHANGED_SECRET = "FAKE-changed-in-chromium"
USER = "chrome.user@example.com"


def test_s11_chromium_save_reaches_icloud_keyring_and_app(stack: Stack, site: SiteServer) -> None:
    app = stack.app
    sign_up_and_save(stack.chromium, site.url(FABRIKAM), USER, NEW_SECRET)
    capture_page(stack.chromium, SCENARIO)
    url = site.origin(FABRIKAM)
    on_phone = wait_until(lambda: stack.apple.find(url, USER), what="the login in iCloud")
    assert on_phone.password == NEW_SECRET
    assert stack.keyring_matches(on_phone) is not None
    wait_until(lambda: app.detail_shows(on_phone.id, password=NEW_SECRET), what="app detail")
    capture_app(app, SCENARIO)
    stack.assert_no_duplicates()


def test_s11_chromium_password_change_updates_the_same_item(stack: Stack, site: SiteServer) -> None:
    seeded = stack.seeded["northwind"]
    sign_up_and_save(stack.chromium, site.url(NORTHWIND), seeded.username, CHANGED_SECRET)

    def on_phone() -> bool:
        held = stack.apple.get(seeded.id)
        return held is not None and held.password == CHANGED_SECRET

    wait_until(on_phone, what="the changed password in iCloud (same record)")
    wait_until(
        lambda: (i := stack.keyring.by_id(seeded.id)) and i.secret == CHANGED_SECRET,
        what="the changed password in the keyring",
    )
    assert len(stack.apple.logins()) == len(stack.seeded)
    stack.assert_no_duplicates()
