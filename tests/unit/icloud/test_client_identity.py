# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Which client identity goes to which Apple endpoint (the whole fix for ec=-80045)."""

from __future__ import annotations

from passwords_app.icloud import const
from passwords_app.icloud.auth import icloud as icloud_auth
from passwords_app.icloud.escrow.srp import EscrowRecovery
from passwords_app.icloud.transport import cloudkit


def test_grandslam_login_delegates_and_escrow_claim_the_anisette_platform() -> None:
    for info in (
        const.GSA_CLIENT_INFO,
        icloud_auth.LOGIN_DELEGATES_CLIENT_INFO,
        EscrowRecovery.ESCROW_MME_CLIENT_INFO,
    ):
        assert info.startswith(const.WINDOWS_PLATFORM)


def test_account_settings_is_asked_as_a_windows_client_first_then_as_a_mac() -> None:
    assert "Mac OS X" in icloud_auth.ICLOUD_CLIENT_INFO
    assert const.WINDOWS_PLATFORM not in icloud_auth.ICLOUD_CLIENT_INFO
    assert icloud_auth.ACCOUNT_SETTINGS_CLIENT_INFOS == (
        ("Windows", icloud_auth.LOGIN_DELEGATES_CLIENT_INFO),
        ("Mac", icloud_auth.ICLOUD_CLIENT_INFO),
    )


def test_cloudkit_claims_the_anisette_platform() -> None:
    assert cloudkit.CK_MME_CLIENT_INFO.startswith(const.WINDOWS_PLATFORM)
