# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Copy with auto-clear: a copied password leaves the clipboard after N seconds (default 45).

Clearing only happens while the clipboard still holds exactly what we put there, so text the
user copied elsewhere in the meantime is never wiped. Secrets also carry KDE's
`x-kde-passwordManagerHint` so clipboard managers that honor it do not keep a history copy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gi.repository import Gdk, GLib

if TYPE_CHECKING:
    from collections.abc import Callable

SECRET_HINT_MIME = "x-kde-passwordManagerHint"  # noqa: S105 - a MIME type name, not a secret


class ClipboardGuard:
    def __init__(self, clipboard: Gdk.Clipboard, seconds: Callable[[], int]) -> None:
        self.clipboard = clipboard
        self._seconds = seconds
        self._provider: Gdk.ContentProvider | None = None
        self._timer = 0

    def copy(self, text: str, *, sensitive: bool) -> int:
        """Put `text` on the clipboard; returns the auto-clear delay (0 = never)."""
        providers = [
            Gdk.ContentProvider.new_for_bytes("text/plain;charset=utf-8", GLib.Bytes(text.encode()))
        ]
        providers.append(Gdk.ContentProvider.new_for_value(text))
        if sensitive:
            providers.append(
                Gdk.ContentProvider.new_for_bytes(SECRET_HINT_MIME, GLib.Bytes(b"secret"))
            )
        provider = Gdk.ContentProvider.new_union(providers)
        self.clipboard.set_content(provider)
        self._provider = provider
        self._cancel_timer()
        delay = max(0, self._seconds()) if sensitive else 0
        if delay:
            self._timer = GLib.timeout_add_seconds(delay, self._expire)
        return delay

    def _cancel_timer(self) -> None:
        if self._timer:
            GLib.source_remove(self._timer)
            self._timer = 0

    def _expire(self) -> bool:
        self._timer = 0
        self.clear_if_ours()
        return GLib.SOURCE_REMOVE

    def clear_if_ours(self) -> bool:
        """Clear the clipboard if it still holds our last copy; True when it did."""
        ours = (
            self._provider is not None
            and self.clipboard.is_local()
            and self.clipboard.get_content() is self._provider
        )
        if ours:
            self.clipboard.set_content(None)
        self._provider = None
        return ours

    @property
    def pending(self) -> bool:
        return bool(self._timer)
