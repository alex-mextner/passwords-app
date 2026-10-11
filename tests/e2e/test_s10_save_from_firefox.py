# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S10: a login saved from Firefox's "Save password?" prompt lands in iCloud (and decrypts
there to the same password), in the keyring and in the app."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import FABRIKAM
from tests.e2e.browsers import fill, sign_up_and_save
from tests.e2e.proof import Video, capture_app, capture_page
from tests.e2e.stack import pump, wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack

SCENARIO = "s10-save-from-firefox"
NEW_SECRET = "FAKE-saved-from-firefox"
USER = "new.user@example.com"


def test_s10_firefox_save_reaches_icloud_keyring_and_app(stack: Stack, site: SiteServer) -> None:
    app = stack.app
    video = Video(SCENARIO, stack.root / "video")
    firefox = video.browser(stack.firefox)
    sign_up_and_save(firefox, site.url(FABRIKAM), USER, NEW_SECRET)
    firefox.hold(1.5)
    capture_page(stack.firefox, SCENARIO)

    url = site.origin(FABRIKAM)
    on_phone = wait_until(lambda: stack.apple.find(url, USER), what="the login in iCloud")
    assert on_phone.password == NEW_SECRET
    record = stack.cloudkit.record(on_phone.id)
    assert record is not None
    assert record.fields  # stored encrypted; `find` decrypted it with the zone keys
    assert stack.keyring_matches(on_phone) is not None
    video.end_browser(firefox)

    video.start_app(app)
    wait_until(lambda: app.detail_shows(on_phone.id, password=NEW_SECRET), what="app detail")
    pump(2.0)
    capture_app(app, SCENARIO)
    video.stop_app()

    # Firefox now offers it back on the next visit, from the same store.
    replay = video.browser(stack.firefox)
    assert fill(replay, site.url(FABRIKAM)) == (USER, NEW_SECRET)
    video.end_browser(replay)
    video.finish()
    stack.assert_no_duplicates()
