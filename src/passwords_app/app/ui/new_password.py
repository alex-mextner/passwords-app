# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""New Password dialog: prefilled with a generated Apple-style strong password."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gi.repository import Adw, Gtk

from passwords_app.app.client import DaemonError
from passwords_app.app.generator_options import make_password
from passwords_app.app.i18n import _
from passwords_app.app.records import Draft
from passwords_app.app.ui.editor import EditForm, load_options
from passwords_app.app.validation import validate

if TYPE_CHECKING:
    from collections.abc import Callable

    from gi.repository import Gio

    from passwords_app.app.client import DaemonClient


class NewPasswordDialog(Adw.Dialog):
    def __init__(
        self,
        client: DaemonClient,
        settings: Gio.Settings | None,
        on_saved: Callable[[str], None],
        *,
        group: str = "",
    ) -> None:
        super().__init__(title=_("New Password"), content_width=520, content_height=640)
        self.client = client
        self.on_saved = on_saved
        header = Adw.HeaderBar(show_end_title_buttons=False, show_start_title_buttons=False)
        cancel = Gtk.Button(label=_("Cancel"))
        cancel.connect("clicked", lambda *_a: self.close())
        self.save_button = Gtk.Button(label=_("Save"))
        self.save_button.add_css_class("suggested-action")
        self.save_button.connect("clicked", lambda *_a: self.save())
        header.pack_start(cancel)
        header.pack_end(self.save_button)

        self.form = EditForm(settings, reveal_password=True)
        self.form.load(Draft(url="", password=make_password(load_options(settings)), group=group))
        self.form.url.connect("entry-activated", lambda *_a: self.form.username.grab_focus())
        self.form.username.connect("entry-activated", lambda *_a: self.save())
        hint = Gtk.Label(
            label=_("A strong password was created for you. It will sync to all your devices."),
            wrap=True,
            xalign=0,
        )
        hint.add_css_class("dim-label")
        hint.add_css_class("caption")
        self.form.insert_child_after(hint, self.form.main_group)

        clamp = Adw.Clamp(
            maximum_size=520,
            child=self.form,
            margin_top=12,
            margin_bottom=24,
            margin_start=12,
            margin_end=12,
        )
        view = Adw.ToolbarView(
            content=Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, child=clamp)
        )
        view.add_top_bar(header)
        self.set_child(view)
        self.set_default_widget(self.save_button)
        self.saving = False
        self.dismissed = False  # locking force-closes the dialog; a late Enter must not save
        self.connect("closed", lambda *_a: setattr(self, "dismissed", True))
        self.set_focus(self.form.url)

    def save(self) -> None:
        if self.saving or self.dismissed:  # Enter reaches here even with the button insensitive
            return
        result = validate(self.form.draft())
        self.form.show_errors(result.errors)
        if not result.ok:
            return
        self.saving = True
        self.save_button.set_sensitive(False)

        def done(reply: str | DaemonError) -> None:
            self.saving = False
            self.save_button.set_sensitive(True)
            if isinstance(reply, DaemonError):
                self.form.error_label.set_text(reply.message)
                self.form.error_label.set_visible(True)
                return
            self.close()
            self.on_saved(reply)

        self.client.save(result.draft, done)
