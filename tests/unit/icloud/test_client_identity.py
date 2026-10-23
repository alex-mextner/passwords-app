# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Which client identity goes to which Apple endpoint (the whole fix for ec=-80045)."""

from __future__ import annotations

from passwords_app.icloud import const
from passwords_app.icloud.auth import icloud as icloud_auth
from passwords_app.icloud.escrow.srp import EscrowRecovery


def test_grandslam_login_delegates_and_escrow_claim_the_anisette_platform() -> None:
    for info in (
        const.GSA_CLIENT_INFO,
        icloud_auth.LOGIN_DELEGATES_CLIENT_INFO,
        EscrowRecovery.ESCROW_MME_CLIENT_INFO,
    ):
        assert info.startswith(const.WINDOWS_PLATFORM)


def test_account_settings_keeps_the_mac_identity() -> None:
    assert "Mac OS X" in icloud_auth.ICLOUD_CLIENT_INFO
    assert const.WINDOWS_PLATFORM not in icloud_auth.ICLOUD_CLIENT_INFO
