# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
# Every password here is a fictional test value.
"""The fictional accounts the scenarios work with."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from tests.browser.e2e_support import NORTHWIND
from tests.e2e.apple import login

from passwords_app.core.otp import code_at, parse_otpauth

if TYPE_CHECKING:
    from tests.browser.e2e_support import SiteServer

    from passwords_app.core.model import Credential

OTP_SECRET = "JBSWY3DPEHPK3PXP"


def seed(site: SiteServer) -> dict[str, Credential]:
    """What the iPhone already holds when a scenario starts."""
    return {
        "northwind": login(
            site.origin(NORTHWIND),
            "alex.doe@example.com",
            "Northwind-Fictional-01",
            title="Northwind Mail",
        ),
        "contoso": login(
            "https://portal.contoso.example", "j.smith", "Contoso-Fictional-02", title="Contoso"
        ),
        "woodgrove": login("https://bank.woodgrove.example", "sam.lee", "Woodgrove-Fictional-03"),
    }


def current_codes(otpauth: str) -> set[str]:
    """The codes valid around now (one period either side), computed independently."""
    params = parse_otpauth(otpauth)
    now = datetime.now(UTC)
    return {code_at(params, now + timedelta(seconds=s))[0] for s in (-30, 0, 30)}
