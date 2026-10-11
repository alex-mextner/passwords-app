# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S8: a password changed (and an item renamed) in Seahorse is changed in iCloud."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack

NEW_SECRET = "FAKE-changed-in-seahorse"


def test_s08_seahorse_password_change_reaches_icloud(stack: Stack) -> None:
    seeded = stack.seeded["contoso"]
    item = stack.keyring.by_id(seeded.id)
    assert item is not None
    stack.keyring.set_secret(item.path, NEW_SECRET)

    def on_phone() -> bool:
        held = stack.apple.get(seeded.id)
        return held is not None and held.password == NEW_SECRET

    wait_until(on_phone, what="the new password in iCloud")
    app = stack.app
    wait_until(lambda: app.detail_shows(seeded.id, password=NEW_SECRET), what="app detail")
    stack.assert_no_duplicates()


def test_s08_seahorse_rename_becomes_the_title_in_icloud(stack: Stack) -> None:
    seeded = stack.seeded["woodgrove"]
    item = stack.keyring.by_id(seeded.id)
    assert item is not None
    stack.keyring.rename(item.path, "Woodgrove Bank — sam.lee")

    def on_phone() -> bool:
        held = stack.apple.get(seeded.id)
        return held is not None and held.title == "Woodgrove Bank"

    wait_until(on_phone, what="the new title in iCloud")
    held = stack.apple.get(seeded.id)
    assert held is not None
    assert held.password == seeded.password
