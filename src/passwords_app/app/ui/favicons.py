# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Loads website icons off the main thread and hands textures to tiles (opt-in setting)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from gi.repository import Gdk, GLib

if TYPE_CHECKING:
    from collections.abc import Callable

    from passwords_app.app.favicons import FaviconCache

type Done = Callable[[Gdk.Texture | None], None]


class FaviconLoader:
    def __init__(self, cache: FaviconCache, enabled: Callable[[], bool]) -> None:
        self.cache = cache
        self.enabled = enabled
        self._textures: dict[str, Gdk.Texture | None] = {}
        self._waiting: dict[str, list[Done]] = {}
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="favicon")

    def request(self, host: str, done: Done) -> None:
        """Call `done` on the main loop with the icon (or None); never when disabled."""
        if not host or not self.enabled():
            return
        if host in self._textures:
            done(self._textures[host])
            return
        waiting = self._waiting.setdefault(host, [])
        waiting.append(done)
        if len(waiting) == 1:
            self._pool.submit(self._load, host)

    def _load(self, host: str) -> None:
        data = self.cache.load(host)
        GLib.idle_add(self._loaded, host, data)

    def _loaded(self, host: str, data: bytes | None) -> bool:
        texture: Gdk.Texture | None = None
        if data:
            try:
                texture = Gdk.Texture.new_from_bytes(GLib.Bytes.new(data))
            except GLib.Error:
                texture = None
        self._textures[host] = texture
        for done in self._waiting.pop(host, []):
            done(texture)
        return GLib.SOURCE_REMOVE

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
