# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The anisette client names a server Apple accepts when it cannot reach one."""

from __future__ import annotations

from typing import Any, override

import pytest
import requests

from passwords_app.icloud.auth.anisette import Anisette, AnisetteError
from passwords_app.icloud.const import DEFAULT_ANISETTE_URL


class _Down(requests.Session):
    @override
    def get(self, url: str | bytes, **_kwargs: Any) -> requests.Response:
        msg = "connection refused"
        raise requests.ConnectionError(msg)


def test_the_default_is_the_local_windows_adi_server_not_the_android_one() -> None:
    assert DEFAULT_ANISETTE_URL == "http://localhost:6970"


def test_unreachable_server_error_names_the_local_server_and_what_apple_accepts() -> None:
    with pytest.raises(AnisetteError) as caught:
        Anisette("http://127.0.0.1:6970", http=_Down()).headers()
    text = str(caught.value)
    assert "passwords-app install" in text
    assert "passwords-app-anisette-windows" in text
    assert "Windows or macOS ADI" in text
    assert "-80045" in text
    assert "PASSWORDS_APP_ANISETTE_URL" in text
