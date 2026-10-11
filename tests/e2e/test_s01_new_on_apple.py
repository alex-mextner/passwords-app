# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S1: a password created on the iPhone shows up in the keyring, the app and both browsers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import FABRIKAM
from tests.e2e.apple import login
from tests.e2e.browsers import fill
from tests.e2e.proof import Video, capture_app, capture_page, dropdown_shot
from tests.e2e.stack import pump, wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack

SCENARIO = "s01-new-on-apple"


def test_s01_new_on_apple_reaches_keyring_app_and_both_browsers(
    stack: Stack, site: SiteServer
) -> None:
    app = stack.app
    video = Video(SCENARIO, stack.root / "video")
    video.start_app(app)
    pump(1.5)  # the "before" picture: no Fabrikam login anywhere on Linux
    assert "Fabrikam Accounts" not in app.titles()
    cred = stack.apple.create(
        login(
            site.origin(FABRIKAM),
            "dana.ray@example.com",
            "Fabrikam-Fictional-11",
            title="Fabrikam Accounts",
        )
    )

    item = wait_until(lambda: stack.keyring_matches(cred), what="the login in the keyring")
    assert item.label == "Fabrikam Accounts — dana.ray@example.com"
    assert item.attributes["xdg:schema"] == "io.github.alex_mextner.Passwords"
    wait_until(
        lambda: app.detail_shows(cred.id, password=cred.password, title="Fabrikam Accounts"),
        what="the login in the app",
    )
    assert "Fabrikam Accounts" in app.titles()
    pump(1.5)
    capture_app(app, SCENARIO)
    video.stop_app()

    for browser in (stack.firefox, stack.chromium):
        page = video.browser(browser)
        shot = dropdown_shot(browser, SCENARIO, page)
        assert fill(page, site.url(FABRIKAM), at_dropdown=shot) == (cred.username, cred.password)
        capture_page(browser, SCENARIO)
        video.end_browser(page)
    video.finish()

    # Nothing else moved: the iPhone still holds what it created, and Linux holds it once.
    held = stack.apple.get(cred.id)
    assert held is not None
    assert (held.url, held.username, held.password, held.title) == (
        cred.url,
        cred.username,
        cred.password,
        cred.title,
    )
    stack.assert_no_duplicates()
