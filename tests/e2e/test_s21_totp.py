# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""S21: a verification code set up on the iPhone is shown in the app (live code) and filled by
both browsers into a split one-time-code form; the codes match an independent TOTP."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tests.browser.e2e_support import FABRIKAM
from tests.e2e.apple import login
from tests.e2e.browsers import fill_code
from tests.e2e.data import OTP_SECRET, current_codes
from tests.e2e.proof import capture_app, capture_page, overlay_shot
from tests.e2e.stack import wait_until

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer
    from tests.e2e.stack import Stack

SCENARIO = "s21-totp"


def test_s21_code_from_iphone_shown_in_app_and_filled_in_browsers(
    stack: Stack, site: SiteServer
) -> None:
    otpauth = f"otpauth://totp/Fabrikam:dana?secret={OTP_SECRET}&issuer=Fabrikam"
    cred = stack.apple.create(
        login(
            site.origin(FABRIKAM),
            "dana",
            "FAKE-with-a-code",
            title="Fabrikam 2FA",
            otpauth=otpauth,
        )
    )
    wait_until(lambda: stack.keyring_matches(cred), what="the login in the keyring")
    local = stack.keyring.by_id(cred.id)
    assert local is not None
    assert "otpauth" in local.attributes
    code, seconds_left = stack.daemon.get_code(cred.id)
    assert code in current_codes(otpauth)
    assert 0 < seconds_left <= 30

    app = stack.app
    wait_until(lambda: app.detail_shows(cred.id, has_code=True), what="app detail with a code")
    detail = app.window.detail
    wait_until(lambda: re.fullmatch(r"\d{6}", detail.code or ""), what="code in the app")
    assert detail.code in current_codes(otpauth)
    assert detail.code_label.get_text() == f"{detail.code[:3]} {detail.code[3:]}"
    capture_app(app, SCENARIO)

    for browser in (stack.firefox, stack.chromium):
        shot = overlay_shot(browser, SCENARIO, "dropdown")
        assert fill_code(browser, site.url(FABRIKAM, "/otp.html"), at_dropdown=shot) in (
            current_codes(otpauth)
        )
        capture_page(browser, SCENARIO)
