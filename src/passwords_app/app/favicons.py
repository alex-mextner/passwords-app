# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Optional website icons (off by default: fetching one tells a site you have an account).

Icons are fetched once per site over HTTPS, kept in the user cache, and failures are
remembered for a week so a dead site is not asked on every start. Nothing here runs unless
the user turns on "Show Website Icons".
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

import requests

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

MAX_BYTES: Final = 256 * 1024
RETRY_FAILED_AFTER: Final = 7 * 24 * 3600
_TIMEOUT = 5.0
# Formats GdkPixbuf/GdkTexture decode; anything else (HTML error pages) is refused.
_MAGIC: Final = (
    b"\x00\x00\x01\x00",
    b"\x89PNG",
    b"GIF8",
    b"\xff\xd8\xff",
    b"RIFF",
    b"<svg",
    b"<?xml",
)


def looks_like_image(data: bytes) -> bool:
    head = data[:16].lstrip()
    return any(head.startswith(m) for m in _MAGIC)


def default_url(host: str) -> str:
    return f"https://{host}/favicon.ico"


@dataclass(slots=True)
class FaviconCache:
    """Blocking cache; call `load` from a worker thread."""

    directory: Path
    url_for: Callable[[str], str] = default_url
    session: requests.Session = field(default_factory=requests.Session)
    clock: Callable[[], float] = time.time

    def _path(self, host: str) -> Path:
        return self.directory / hashlib.sha256(host.encode()).hexdigest()

    def cached(self, host: str) -> bytes | None:
        """Return the cached icon bytes; None when unknown or a recent failure."""
        path = self._path(host)
        try:
            data = path.read_bytes()
        except OSError:
            return None
        return data or None

    def _failed_recently(self, host: str) -> bool:
        path = self._path(host)
        try:
            stat = path.stat()
        except OSError:
            return False
        return stat.st_size == 0 and self.clock() - stat.st_mtime < RETRY_FAILED_AFTER

    def load(self, host: str) -> bytes | None:
        """Icon for `host` from the cache or the network; None if the site has none."""
        if not host:
            return None
        hit = self.cached(host)
        if hit is not None or self._failed_recently(host):
            return hit
        data = self._fetch(host)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._path(host).write_bytes(data or b"")
        return data

    def _fetch(self, host: str) -> bytes | None:
        try:
            with self.session.get(self.url_for(host), timeout=_TIMEOUT, stream=True) as response:
                if response.status_code != 200:  # noqa: PLR2004 - HTTP OK
                    return None
                data = response.raw.read(MAX_BYTES + 1, decode_content=True)
        except (requests.RequestException, OSError):
            return None
        if not data or len(data) > MAX_BYTES or not looks_like_image(data):
            return None
        return bytes(data)
