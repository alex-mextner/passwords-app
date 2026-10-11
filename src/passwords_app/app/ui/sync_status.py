# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Header button showing the sync state, with a details popover and *Sync Now*."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gi.repository import Adw, Gtk

from passwords_app.app import formatting
from passwords_app.app.i18n import _, ngettext
from passwords_app.app.records import Status, SyncState

if TYPE_CHECKING:
    from collections.abc import Callable

_CAN_SYNC = frozenset({SyncState.IDLE, SyncState.OFFLINE, SyncState.ERROR})
_NEEDS_SIGNIN = frozenset({SyncState.SIGNED_OUT, SyncState.SIGNIN_REQUIRED})


class SyncStatusButton(Gtk.MenuButton):
    def __init__(
        self,
        *,
        on_sync: Callable[[], None],
        on_sign_in: Callable[[], None],
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        super().__init__()
        self._now = now
        self.content = Adw.ButtonContent(can_shrink=True)
        self.set_child(self.content)
        self.add_css_class("flat")

        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=6,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12,
            width_request=260,
        )
        self.heading = Gtk.Label(xalign=0)
        self.heading.add_css_class("heading")
        self.detail = Gtk.Label(xalign=0, wrap=True, max_width_chars=34)
        self.account = Gtk.Label(xalign=0, wrap=True, max_width_chars=34)
        self.account.add_css_class("dim-label")
        self.account.add_css_class("caption")
        self.counts = Gtk.Label(xalign=0)
        self.counts.add_css_class("dim-label")
        self.counts.add_css_class("caption")
        self.sync_button = Gtk.Button(label=_("Sync Now"), margin_top=6)
        self.sync_button.add_css_class("suggested-action")
        self.sync_button.add_css_class("pill")
        self._on_sync = on_sync
        self._on_sign_in = on_sign_in
        self.sync_button.connect("clicked", self._sync_clicked)
        self.sign_in_button = Gtk.Button(label=_("Sign In…"), margin_top=6)
        self.sign_in_button.add_css_class("suggested-action")
        self.sign_in_button.add_css_class("pill")
        self.sign_in_button.connect("clicked", self._sign_in_clicked)
        for child in (
            self.heading,
            self.detail,
            self.account,
            self.counts,
            self.sync_button,
            self.sign_in_button,
        ):
            box.append(child)
        popover = Gtk.Popover(child=box)
        popover.connect("show", lambda *_a: self.show_status(self.status))
        self.set_popover(popover)
        self.status = Status(state=SyncState.SYNCING)
        self.show_status(self.status)

    def _sync_clicked(self, _button: Gtk.Button) -> None:
        self.popdown()
        self._on_sync()

    def _sign_in_clicked(self, _button: Gtk.Button) -> None:
        self.popdown()
        self._on_sign_in()

    def show_status(self, status: Status) -> None:
        self.status = status
        title = formatting.status_title(status)
        self.content.set_label(title)
        self.content.set_icon_name(formatting.status_icon(status))
        detail = formatting.status_detail(status, self._now())
        self.set_tooltip_text(detail)
        self.update_property(
            [Gtk.AccessibleProperty.LABEL],
            [_("Sync status: {status}").format(status=title)],
        )
        for css, wanted in (
            ("warning", status.state in {SyncState.PAUSED, SyncState.OFFLINE}),
            ("error", status.state in {SyncState.ERROR, SyncState.UNREACHABLE, *_NEEDS_SIGNIN}),
        ):
            if wanted:
                self.add_css_class(css)
            else:
                self.remove_css_class(css)
        self.heading.set_text(title)
        self.detail.set_text(detail)
        self.account.set_visible(bool(status.apple_id))
        self.account.set_text(_("Apple Account: {apple_id}").format(apple_id=status.apple_id))
        known = status.state not in {SyncState.UNREACHABLE, SyncState.SIGNED_OUT}
        self.counts.set_visible(known)
        self.counts.set_text(
            ngettext(
                "{passwords} · {n} deleted", "{passwords} · {n} deleted", status.trash_count
            ).format(passwords=formatting.passwords_count(status.item_count), n=status.trash_count)
        )
        self.sync_button.set_visible(status.state not in _NEEDS_SIGNIN)
        self.sync_button.set_sensitive(status.state in _CAN_SYNC)
        self.sign_in_button.set_visible(status.state in _NEEDS_SIGNIN)
