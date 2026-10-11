# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Browser-independent e2e scenarios; each test module runs them in one real browser.

Every interaction goes through real input (WebDriver / CDP), so the extension sees trusted
events exactly as with a person at the keyboard. Screenshots land in docs/proof/browser/.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from tests.browser.conftest import ALEX, OPS, OTP_SEED, SAM
from tests.browser.e2e_support import (
    FABRIKAM,
    LOOKALIKE,
    NORTHWIND,
    PROOF,
    SQUAT,
    Page,
    SiteServer,
    assert_no_overlay,
    compress_proof,
    overlay_rect,
    value,
    wait_overlay,
    wait_until,
)

from passwords_app.core.otp import code_at, parse_otpauth

if TYPE_CHECKING:
    from tests.browser.conftest import Vault

APPLE_STYLE = re.compile(r"^[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}$")


def _shot(page: Page, scene: str) -> None:
    raw = PROOF / f"{page.name}-{scene}.raw.png"
    page.screenshot(raw)
    if raw.exists():  # a FrameRecorder keeps scenes to itself
        compress_proof(raw, PROOF / f"{page.name}-{scene}.png")


def _events_for(page: Page, field: str) -> list[str]:
    events = page.js("return window.__events") or []
    return [e[0] for e in events if e[1] == field]


def _click_save(page: Page) -> None:
    """Click the prompt's primary button (bottom right of the card) with the real mouse."""
    rect = wait_overlay(page, "save-prompt")
    page.click_at(rect["x"] + rect["width"] - 40, rect["y"] + rect["height"] - 26)


def _current_codes() -> set[str]:
    params = parse_otpauth(f"otpauth://totp/Northwind:alex?secret={OTP_SEED}&issuer=Northwind")
    now = datetime.now(UTC)
    return {code_at(params, now + timedelta(seconds=s))[0] for s in (-30, 0, 30)}


def fill_first_candidate(page: Page, site: SiteServer, vault: Vault) -> None:
    page.goto(site.url(NORTHWIND))
    page.click("#email")
    wait_overlay(page, "dropdown")
    _shot(page, "dropdown")
    page.press("Enter")
    wait_until(lambda: value(page, "#password"), what="password filled")
    assert value(page, "#email") == ALEX[0]
    assert value(page, "#password") == ALEX[1]
    # The page's own listeners saw the fill like typing: input then change, on both fields.
    assert _events_for(page, "email")[-2:] == ["input", "change"]
    assert _events_for(page, "password")[-2:] == ["input", "change"]
    assert overlay_rect(page, "dropdown") is None
    assert "Get" in vault.calls()


def keyboard_picks_second(page: Page, site: SiteServer, vault: Vault) -> None:
    del vault
    page.goto(site.url(NORTHWIND))
    page.click("#password")
    wait_overlay(page, "dropdown")
    page.press("ArrowDown")
    page.press("Enter")
    wait_until(lambda: value(page, "#password"), what="password filled")
    assert (value(page, "#email"), value(page, "#password")) == OPS


def escape_closes_without_filling(page: Page, site: SiteServer, vault: Vault) -> None:
    page.goto(site.url(NORTHWIND))
    page.click("#email")
    wait_overlay(page, "dropdown")
    page.press("Escape")
    wait_until(lambda: overlay_rect(page, "dropdown") is None, what="dropdown closed")
    assert value(page, "#password") == ""
    assert "Get" not in vault.calls()


def otp_fill(page: Page, site: SiteServer, vault: Vault) -> None:
    page.goto(site.url(NORTHWIND, "/otp.html"))
    page.click("#d1")
    wait_overlay(page, "dropdown")
    _shot(page, "otp")
    page.press("Enter")
    wait_until(lambda: value(page, "#d6"), what="code filled")
    code = "".join(value(page, f"#d{i}") for i in range(1, 7))
    assert code in _current_codes()
    assert "GetCode" in vault.calls()
    assert "Get" not in vault.calls()


def save_new_login(page: Page, site: SiteServer, vault: Vault) -> None:
    page.goto(site.url(FABRIKAM))
    page.type("#email", "new.user@example.com")
    page.type("#password", "Brand-New-Fictional-42")
    page.click("#submit")
    wait_until(lambda: page.js("return location.pathname") == "/welcome.html", what="welcome")
    wait_overlay(page, "save-prompt")
    _shot(page, "save-prompt")
    _click_save(page)
    origin = site.origin(FABRIKAM)
    wait_until(
        lambda: (
            (origin, "new.user@example.com", "Brand-New-Fictional-42")
            in [i[:3] for i in vault.items()]
        ),
        what="saved item",
    )
    assert overlay_rect(page, "save-prompt") is None


def update_changed_password(page: Page, site: SiteServer, vault: Vault) -> None:
    page.goto(site.url(FABRIKAM))
    page.type("#email", SAM[0])
    page.type("#password", "fb-New-Fictional-4")
    page.click("#submit")
    wait_until(lambda: page.js("return location.pathname") == "/welcome.html", what="welcome")
    wait_overlay(page, "save-prompt")
    _shot(page, "update-prompt")
    _click_save(page)
    wait_until(
        lambda: (vault.fabrikam, SAM[0], "fb-New-Fictional-4", vault.sam) in vault.items(),
        what="updated item",
    )
    assert len([i for i in vault.items() if i[1] == SAM[0]]) == 1


def unchanged_login_is_not_offered(page: Page, site: SiteServer, vault: Vault) -> None:
    fill_first_candidate(page, site, vault)
    page.click("#submit")
    wait_until(lambda: page.js("return location.pathname") == "/welcome.html", what="welcome")
    assert_no_overlay(page, "save-prompt")


def generator_then_save(page: Page, site: SiteServer, vault: Vault) -> None:
    page.goto(site.url(FABRIKAM, "/signup.html"))
    page.type("#email", "generated@example.com")
    page.click("#new-password")
    wait_overlay(page, "dropdown")
    _shot(page, "generator")
    page.press("Enter")
    wait_until(lambda: value(page, "#new-password"), what="generated password")
    generated = value(page, "#new-password")
    assert APPLE_STYLE.match(generated), generated
    assert value(page, "#confirm-password") == generated
    page.click("#submit")
    wait_until(lambda: page.js("return location.pathname") == "/welcome.html", what="welcome")
    _click_save(page)
    wait_until(
        lambda: (
            (site.origin(FABRIKAM), "generated@example.com", generated)
            in [i[:3] for i in vault.items()]
        ),
        what="saved generated password",
    )


def popup_search_and_fill(page: Page, site: SiteServer, vault: Vault) -> None:
    del vault
    page.goto(site.url(NORTHWIND))
    page.click("#email")  # the tab the popup acts on was just used
    page.press("Escape")
    page.open_popup()
    wait_until(
        lambda: page.js("return document.querySelectorAll('#list li').length") == 2,
        what="popup list",
    )
    page.element_screenshot("body", PROOF / f"{page.name}-popup.png")
    page.type("#search", "ops")
    wait_until(
        lambda: page.js("return document.querySelectorAll('#list li').length") == 1, what="search"
    )
    page.element_screenshot("body", PROOF / f"{page.name}-popup-search.png")
    page.click("#list li .fill")
    page.back_to_page()
    wait_until(lambda: value(page, "#password"), what="popup fill")
    assert (value(page, "#email"), value(page, "#password")) == OPS


def _expect_no_fill(page: Page, url: str, vault: Vault) -> None:
    page.goto(url)
    page.click("#email")
    assert_no_overlay(page, "dropdown")
    page.click("#password")
    assert_no_overlay(page, "dropdown", settle=1.0)
    assert value(page, "#password") == ""
    # The daemon was asked and said no; no password was ever requested.
    assert "Get" not in vault.calls()


def no_fill_on_lookalike(page: Page, site: SiteServer, vault: Vault) -> None:
    _expect_no_fill(page, site.url(LOOKALIKE), vault)
    _expect_no_fill(page, site.url(SQUAT), vault)
    _shot(page, "lookalike-no-dropdown")


def no_fill_on_http_downgrade(page: Page, site: SiteServer, vault: Vault) -> None:
    # Same host and port as the saved https login, only the scheme differs.
    url = site.url(NORTHWIND, scheme="http")
    _expect_no_fill(page, url, vault)
    assert page.js("return location.protocol") == "http:"


def no_fill_in_third_party_frame(page: Page, site: SiteServer, vault: Vault) -> None:
    page.goto(site.url(FABRIKAM, f"/embed.html?src={site.url(NORTHWIND)}"))
    time.sleep(1.0)  # frame load
    rect = page.js(
        "const r = document.getElementById('frame').getBoundingClientRect();"
        "return {x: r.x, y: r.y};"
    )
    # Click the framed email field (first field, ~150 px into the frame).
    page.click_at(rect["x"] + 60, rect["y"] + 150)
    time.sleep(2.0)  # time for a host round-trip, had the background asked
    # The frame's own document is out of reach from here; the daemon log is not: a refused
    # frame never even triggers a Match, let alone a Get.
    assert "Match" not in vault.calls()
    assert "Get" not in vault.calls()
