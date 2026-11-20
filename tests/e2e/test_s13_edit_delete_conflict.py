# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S13: deleted on one side, edited on the other while they could not sync: the edit wins
(spec §5), so the edited password ends up on both sides instead of disappearing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack

EDITED = "FAKE-edit-beats-delete"


def test_s13_delete_on_iphone_edit_on_linux_recreates_in_icloud(stack: Stack) -> None:
    seeded = stack.seeded["contoso"]
    item = stack.keyring.by_id(seeded.id)
    assert item is not None
    stack.stop_daemon()
    stack.apple.delete(seeded.id)
    stack.keyring.set_secret(item.path, EDITED)
    stack.start_daemon()

    def back_in_icloud() -> bool:
        return any(
            (c.url, c.username, c.password) == (seeded.url, seeded.username, EDITED)
            for c in stack.apple.logins().values()
        )

    wait_until(back_in_icloud, what="the edited login recreated in iCloud")
    local = stack.keyring_login(seeded.url, seeded.username)
    assert local is not None
    assert local.secret == EDITED
    app = stack.app
    assert local.id is not None
    wait_until(lambda: app.detail_shows(local.id, password=EDITED), what="app shows the edit")
    stack.assert_no_duplicates()


def test_s13_delete_on_linux_edit_on_iphone_recreates_in_keyring(stack: Stack) -> None:
    seeded = stack.seeded["contoso"]
    item = stack.keyring.by_id(seeded.id)
    assert item is not None
    stack.stop_daemon()
    stack.keyring.delete(item.path)
    stack.apple.edit(seeded.id, password=EDITED)
    stack.start_daemon()

    local = wait_until(
        lambda: (
            (i := stack.keyring_login(seeded.url, seeded.username)) and i.secret == EDITED and i
        ),
        what="the edited login recreated in the keyring",
    )
    held = stack.apple.get(seeded.id)
    assert held is not None
    assert held.password == EDITED
    assert local.id == seeded.id
    stack.assert_no_duplicates()
