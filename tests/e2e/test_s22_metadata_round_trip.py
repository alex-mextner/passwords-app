# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S22: title, notes and additional websites survive the round trip iPhone → Linux → iPhone:
in the keyring attributes, in the app, as a browser match, and after edits on Linux."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import FABRIKAM
from tests.e2e.apple import login
from tests.e2e.browsers import fill
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack

NOTES = "Fictional note: badge #42\nsecond line ✓"


def test_s22_title_notes_and_alt_urls_round_trip(stack: Stack, site: SiteServer) -> None:
    cred = stack.apple.create(
        login(
            "https://intranet.tailspin.example",
            "kim.lee",
            "FAKE-round-trip",
            title="Tailspin Intranet",
            notes=NOTES,
            alt_urls=(site.origin(FABRIKAM), "https://vpn.tailspin.example"),
        )
    )
    item = wait_until(lambda: stack.keyring_matches(cred), what="the login in the keyring")
    assert item.label == "Tailspin Intranet — kim.lee"
    assert item.attributes["notes"] == NOTES
    assert item.attributes["alt-urls"].split("\n") == list(cred.alt_urls)

    app = stack.app
    wait_until(
        lambda: app.detail_shows(
            cred.id, title="Tailspin Intranet", notes=NOTES, alt_urls=cred.alt_urls
        ),
        what="title, notes and websites in the app",
    )
    # An additional website is a website: the browser offers the login there.
    assert fill(stack.firefox, site.url(FABRIKAM)) == ("kim.lee", cred.password)

    # Linux → iPhone: edit notes and title in the app; the websites stay as they were.
    app.edit(cred.id, title="Tailspin Portal", notes="Edited on Linux")

    def on_phone() -> bool:
        held = stack.apple.get(cred.id)
        return held is not None and (held.title, held.notes, held.alt_urls) == (
            "Tailspin Portal",
            "Edited on Linux",
            cred.alt_urls,
        )

    wait_until(on_phone, what="the app's edit in iCloud's sidecar")
    held = stack.apple.get(cred.id)
    assert held is not None
    assert held.password == cred.password
