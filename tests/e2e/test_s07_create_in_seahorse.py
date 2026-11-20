# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S7: a password added in Seahorse ("Passwords and Keys", label `user @ host`) reaches
iCloud, and the keyring item is adopted (our schema, an id, the standard label)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.e2e.proof import capture_app
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack

SCENARIO = "s07-create-in-seahorse"
NEW_SECRET = "FAKE-typed-into-seahorse"


def test_s07_seahorse_item_reaches_icloud_and_the_app(stack: Stack) -> None:
    app = stack.app
    stack.keyring.create("bob @ intranet.example", NEW_SECRET)

    on_phone = wait_until(
        lambda: stack.apple.find("https://intranet.example", "bob"), what="the login in iCloud"
    )
    assert on_phone.password == NEW_SECRET
    adopted = wait_until(lambda: stack.keyring_matches(on_phone), what="the adopted item")
    assert adopted.attributes["xdg:schema"] == "io.github.alex_mextner.Passwords"
    assert adopted.label == "intranet.example — bob"
    wait_until(lambda: app.detail_shows(on_phone.id, password=NEW_SECRET), what="app detail")
    capture_app(app, SCENARIO)
    stack.assert_no_duplicates()
    assert len(stack.keyring.items()) == len(stack.seeded) + 1
