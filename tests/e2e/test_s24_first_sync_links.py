# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S24: the first sync links passwords already in the keyring (typed in Seahorse before
signing in) to the same logins in iCloud instead of duplicating them; the rest is uploaded."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack


def _login_key(url: str, username: str) -> tuple[str | None, str]:
    return urlsplit(url).hostname, username


@pytest.mark.stack(signed_in=False, daemon=True)
def test_s24_first_sync_links_existing_seahorse_items(stack: Stack) -> None:
    # Installed, not signed in yet: the daemon made the "iCloud Passwords" keyring and waits.
    assert stack.daemon.status()["state"] == "signed-out"
    stack.stop_daemon()
    northwind = stack.seeded["northwind"]
    # The user already kept two of these passwords in Seahorse, plus one iCloud lacks.
    stack.keyring.create("alex.doe@example.com @ login.northwind.example", northwind.password)
    stack.keyring.create(
        f"{stack.seeded['contoso'].username} @ portal.contoso.example",
        stack.seeded["contoso"].password,
    )
    stack.keyring.create("kim @ intranet.example", "FAKE-only-on-linux")

    stack.sign_in()
    stack.start_daemon()

    wait_until(
        lambda: stack.apple.find("https://intranet.example", "kim"), what="Linux-only uploaded"
    )
    wait_until(
        lambda: all(stack.keyring.by_id(c.id) for c in stack.seeded.values()),
        what="every iCloud login mirrored",
    )
    # Linked, not duplicated: one keyring item per login, carrying the iCloud record's id.
    assert len(stack.keyring.items()) == len(stack.seeded) + 1
    assert len(stack.apple.logins()) == len(stack.seeded) + 1
    assert all(i.id for i in stack.keyring.items())
    # A Seahorse entry has no title or notes, so the fuller iCloud record wins the link and
    # the keyring version is kept in Recently Deleted instead of being dropped.
    trash = stack.daemon.trash()
    assert {e["reason"] for e in trash} <= {"conflict"}
    linked = {_login_key(c.url, c.username) for c in (northwind, stack.seeded["contoso"])}
    assert {_login_key(e["item"]["url"], e["item"]["username"]) for e in trash} <= linked
    app = stack.app
    assert len(app.items()) == len(stack.seeded) + 1
