# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`ICloudAccount.load()` against the real `passwords_app.icloud.account`, unmocked.

The adapter tests use a stand-in module; this one checks the names and shapes the adapter
relies on in the real one (shipped by the iCloud client work). Until that module is on the
branch, the test is skipped rather than faked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from passwords_app.daemon.account import AccountInfo, ICloudAccount

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration


def test_load_wires_the_real_account(tmp_path: Path) -> None:
    real = pytest.importorskip(
        "passwords_app.icloud.account",
        reason="passwords_app.icloud.account ships with the iCloud client PR (Task A, #8)",
    )
    for name in ("Account", "AccountError", "WrongCode", "WrongPasscode", "SignInRequired"):
        assert hasattr(real, name), name
    account = ICloudAccount.load(tmp_path / "config", "http://127.0.0.1:9")
    # A fresh config directory: nobody signed in, and nothing touched the network.
    assert account.status() == AccountInfo(apple_id=None, signed_in=False, joined=False)
