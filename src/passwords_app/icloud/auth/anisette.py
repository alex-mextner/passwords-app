# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Anisette client: machine validation data from a local anisette server.

Apple's auth wants X-Apple-I-MD / X-Apple-I-MD-M on every call. The one-time password inside is
valid for a short while, so a burst of CloudKit calls (a sync pages through many zones) reuses
one answer for a few seconds instead of asking the anisette server before every request.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING, Protocol

import requests

from passwords_app.icloud.const import DEFAULT_ANISETTE_URL
from passwords_app.icloud.errors import AppleError
from passwords_app.icloud.values import is_dict

if TYPE_CHECKING:
    from collections.abc import Callable

# Well inside the OTP's validity, short enough that a slow sync never sends a stale one.
REUSE_SECONDS = 10.0


class AnisetteError(AppleError):
    pass


class AnisetteSource(Protocol):
    def headers(self) -> dict[str, str]: ...


class Anisette:
    # Header keys an anisette server may return; we forward exactly these.
    _KEYS = (
        "X-Apple-I-MD",
        "X-Apple-I-MD-M",
        "X-Apple-I-MD-RINFO",
        "X-Apple-I-MD-LU",
        "X-Apple-I-SRL-NO",
        "X-Mme-Device-Id",
        "X-Apple-I-Client-Time",
        "X-Apple-I-TimeZone",
        "X-Apple-Locale",
    )

    def __init__(
        self,
        url: str | None = None,
        *,
        http: requests.Session | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = (
            url or os.environ.get("PASSWORDS_APP_ANISETTE_URL") or DEFAULT_ANISETTE_URL
        ).rstrip("/")
        # The anisette server is local plain HTTP; a session still saves the connect per call.
        self._http = http or requests.Session()
        self._clock = clock
        self._cached: dict[str, str] | None = None
        self._fetched_at = 0.0

    def headers(self) -> dict[str, str]:
        now = self._clock()
        if self._cached is not None and now - self._fetched_at < REUSE_SECONDS:
            return dict(self._cached)
        fresh = self._fetch()
        self._cached, self._fetched_at = fresh, now
        return dict(fresh)

    def _fetch(self) -> dict[str, str]:
        try:
            resp = self._http.get(self.url, timeout=5)
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as e:
            msg = (
                f"Could not get anisette data from {self.url}: {e}\n"
                "Start one, e.g.: docker run -d -p 6969:6969 dadoum/anisette-server:latest\n"
                "or set PASSWORDS_APP_ANISETTE_URL to a running instance."
            )
            raise AnisetteError(msg) from e

        out = {k: str(data[k]) for k in self._KEYS if k in data} if is_dict(data) else {}
        if "X-Apple-I-MD" not in out or "X-Apple-I-MD-M" not in out:
            msg = (
                f"Anisette server at {self.url} did not return machine data "
                "(X-Apple-I-MD / X-Apple-I-MD-M). Is it a real anisette server?"
            )
            raise AnisetteError(msg)
        return out
