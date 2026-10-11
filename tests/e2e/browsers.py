# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""What a person does in Firefox or Chromium, through the real extension and native host.

The browsers, the test site (one loopback port for every fictional host) and the `Page` API
come from tests/browser/e2e_support.py; here they reach the real daemon instead of a fake.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.browser.e2e_support import assert_no_overlay, overlay_rect, value, wait_overlay
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.browser.e2e_support import Page


def fill(page: Page, url: str, *, at_dropdown: Callable[[], None] | None = None) -> tuple[str, str]:
    """Open `url`, focus the user name field, pick the first entry the dropdown offers;
    returns what the page's fields then hold. `at_dropdown` runs while the dropdown shows."""
    page.goto(url)
    page.click("#email")
    wait_overlay(page, "dropdown", timeout=30)
    if at_dropdown is not None:
        at_dropdown()
    page.press("Enter")
    wait_until(lambda: value(page, "#password"), what=f"password filled in {page.name}")
    return value(page, "#email"), value(page, "#password")


def no_fill_offered(page: Page, url: str) -> None:
    page.goto(url)
    page.click("#email")
    assert_no_overlay(page, "dropdown", settle=4.0)


def fill_code(page: Page, url: str, *, at_dropdown: Callable[[], None] | None = None) -> str:
    """The one-time-code page: pick the entry, return the six digits it typed."""
    page.goto(url)
    page.click("#d1")
    wait_overlay(page, "dropdown", timeout=30)
    if at_dropdown is not None:
        at_dropdown()
    page.press("Enter")
    wait_until(lambda: value(page, "#d6"), what=f"code filled in {page.name}")
    return "".join(value(page, f"#d{i}") for i in range(1, 7))


def sign_up_and_save(page: Page, url: str, username: str, password: str) -> None:
    """Log in with a new login, then accept the extension's "Save password?" prompt."""
    page.goto(url)
    page.type("#email", username)
    page.type("#password", password)
    page.click("#submit")
    wait_until(
        lambda: page.js("return location.pathname") == "/welcome.html",
        what=f"welcome page in {page.name}",
    )
    rect = wait_overlay(page, "save-prompt", timeout=30)
    # The prompt's primary button sits at the card's bottom right; a real mouse click.
    page.click_at(rect["x"] + rect["width"] - 40, rect["y"] + rect["height"] - 26)
    wait_until(
        lambda: overlay_rect(page, "save-prompt") is None,
        what=f"save prompt closed in {page.name}",
    )
