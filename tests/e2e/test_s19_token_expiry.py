# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S19: an expired iCloud token is renewed silently (sync just continues); when Apple wants a
second factor, the status becomes "signin-required", the app asks to sign in, and nothing is
deleted anywhere."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.e2e.apple import login
from tests.e2e.stack import stays, wait_until

if TYPE_CHECKING:
    from tests.e2e.stack import Stack


def test_s19_expired_token_is_refreshed_silently(stack: Stack) -> None:
    app = stack.app
    refreshes = stack.services.count("/setup/settings")
    stack.services.expire_token()
    added = stack.apple.create(
        login("https://news.tailspin.example", "reader", "FAKE-after-expiry")
    )

    wait_until(lambda: stack.keyring_matches(added), what="sync continuing with a new token")
    assert stack.services.count("/setup/settings") > refreshes
    assert stack.services.count("/gsa") == 0  # no password re-login was needed
    assert stack.daemon.status()["state"] == "idle"
    assert not app.signin_banner.get_revealed()


def test_s19_second_factor_needed_means_signin_required(stack: Stack) -> None:
    app = stack.app
    stack.services.settings_unauthorized = True  # the stored mmeAuthToken expired too
    stack.services.second_factor = "trusted"  # and Apple wants a code from a trusted device
    stack.services.expire_token()

    status = wait_until(
        lambda: (s := stack.daemon.status())["state"] == "signin-required" and s,
        what="status signin-required",
    )
    assert status["message"]
    assert stack.services.count("/gsa") >= 1  # it tried the saved password first
    wait_until(app.signin_banner.get_revealed, what="the sign-in banner")
    assert app.signin_banner.get_title() == "Sign in to iCloud to keep your passwords in sync"
    assert app.status_title() == "Sign-In Required"
    # Nothing is deleted on either side while signed out of iCloud.
    stays(
        lambda: all(stack.keyring_matches(c) for c in stack.seeded.values()),
        seconds=4,
        what="keyring intact",
    )
    assert set(stack.apple.logins()) == {c.id for c in stack.seeded.values()}
    assert stack.daemon.trash() == []
