# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The edit form (used in place in the detail pane and in the New Password dialog)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gi.repository import Adw, Gio, Gtk, Pango

from passwords_app.app.generator_options import (
    MAX_CUSTOM_LENGTH,
    MIN_CUSTOM_LENGTH,
    GeneratorOptions,
    Mode,
    make_password,
)
from passwords_app.app.i18n import _
from passwords_app.app.records import Draft
from passwords_app.app.validation import Field

if TYPE_CHECKING:
    from collections.abc import Callable


def load_options(settings: Gio.Settings | None) -> GeneratorOptions:
    if settings is None:
        return GeneratorOptions()
    try:
        mode = Mode(settings.get_string("generator-mode"))
    except ValueError:
        mode = Mode.APPLE
    return GeneratorOptions(
        mode=mode,
        length=settings.get_uint("generator-length"),
        uppercase=settings.get_boolean("generator-uppercase"),
        digits=settings.get_boolean("generator-digits"),
        symbols=settings.get_boolean("generator-symbols"),
    ).clamped()


def store_options(settings: Gio.Settings | None, options: GeneratorOptions) -> None:
    if settings is None:
        return
    settings.set_string("generator-mode", options.mode.value)
    settings.set_uint("generator-length", options.length)
    settings.set_boolean("generator-uppercase", options.uppercase)
    settings.set_boolean("generator-digits", options.digits)
    settings.set_boolean("generator-symbols", options.symbols)


class GeneratorPopover(Gtk.Popover):
    """Generator with Apple-style default and custom options; *Use* fills the password."""

    def __init__(self, settings: Gio.Settings | None, on_use: Callable[[str], None]) -> None:
        super().__init__()
        self._settings = settings
        self._on_use = on_use
        options = load_options(settings)
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12,
            width_request=320,
        )
        self.modes = Adw.ToggleGroup()
        self.modes.add(Adw.Toggle(name=Mode.APPLE.value, label=_("Strong")))
        self.modes.add(Adw.Toggle(name=Mode.CUSTOM.value, label=_("Custom")))
        self.modes.set_active_name(options.mode.value)
        self.modes.update_property([Gtk.AccessibleProperty.LABEL], [_("Password style")])
        self.modes.connect("notify::active-name", lambda *_a: self._changed())
        self.preview = Gtk.Label(wrap=True, selectable=True, xalign=0.5)
        self.preview.set_wrap_mode(Pango.WrapMode.CHAR)  # generated passwords have no spaces
        self.preview.add_css_class("generated-password")
        self.hint = Gtk.Label(wrap=True, xalign=0)
        self.hint.add_css_class("caption")
        self.hint.add_css_class("dim-label")

        self.options_group = Adw.PreferencesGroup()
        self.length = Adw.SpinRow.new_with_range(MIN_CUSTOM_LENGTH, MAX_CUSTOM_LENGTH, 1)
        self.length.set_title(_("Length"))
        self.length.set_value(options.length)
        self.length.connect("notify::value", lambda *_a: self._changed())
        self.uppercase = Adw.SwitchRow(title=_("Uppercase Letters"), active=options.uppercase)
        self.digits = Adw.SwitchRow(title=_("Digits"), active=options.digits)
        self.symbols = Adw.SwitchRow(title=_("Symbols"), active=options.symbols)
        for switch in (self.uppercase, self.digits, self.symbols):
            switch.connect("notify::active", lambda *_a: self._changed())
        for row in (self.length, self.uppercase, self.digits, self.symbols):
            self.options_group.add(row)

        buttons = Gtk.Box(spacing=6, homogeneous=True)
        self.regenerate = Gtk.Button(label=_("Regenerate"))
        self.regenerate.connect("clicked", lambda *_a: self._refresh())
        self.use = Gtk.Button(label=_("Use Password"))
        self.use.add_css_class("suggested-action")
        self.use.connect("clicked", lambda *_a: self._use())
        buttons.append(self.regenerate)
        buttons.append(self.use)
        for child in (self.modes, self.preview, self.hint, self.options_group, buttons):
            box.append(child)
        self.set_child(box)
        self._changed()

    @property
    def options(self) -> GeneratorOptions:
        return GeneratorOptions(
            mode=Mode(self.modes.get_active_name() or Mode.APPLE.value),
            length=int(self.length.get_value()),
            uppercase=self.uppercase.get_active(),
            digits=self.digits.get_active(),
            symbols=self.symbols.get_active(),
        )

    def _changed(self) -> None:
        options = self.options
        self.options_group.set_visible(options.mode is Mode.CUSTOM)
        self.hint.set_text(
            _("Easy to type on a phone and accepted by almost every website.")
            if options.mode is Mode.APPLE
            else _("Lowercase letters are always included.")
        )
        store_options(self._settings, options)
        self._refresh()

    def _refresh(self) -> None:
        self.preview.set_text(make_password(self.options))

    def _use(self) -> None:
        self._on_use(self.preview.get_text())
        self.popdown()


def _entry_row(title: str) -> Adw.EntryRow:
    row = Adw.EntryRow(title=title)
    row.update_property([Gtk.AccessibleProperty.LABEL], [title])
    return row


class EditForm(Gtk.Box):
    """All editable fields with per-field error display."""

    def __init__(self, settings: Gio.Settings | None, *, reveal_password: bool = False) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self._id = ""
        self._group = ""
        self.error_label = Gtk.Label(wrap=True, xalign=0, visible=False)
        self.error_label.add_css_class("error")
        self.append(self.error_label)

        self.main_group = Adw.PreferencesGroup()
        self.title = _entry_row(_("Title"))
        self.url = _entry_row(_("Website"))
        self.url.set_input_purpose(Gtk.InputPurpose.URL)
        self.username = _entry_row(_("User Name"))
        self.username.set_input_purpose(Gtk.InputPurpose.EMAIL)
        if reveal_password:
            self.password: Adw.EntryRow = _entry_row(_("Password"))
            self.password.add_css_class("secret-value")
        else:
            self.password = Adw.PasswordEntryRow(title=_("Password"))
            self.password.update_property([Gtk.AccessibleProperty.LABEL], [_("Password")])
        self.generator = GeneratorPopover(settings, self.set_password)
        self.generate_button = Gtk.MenuButton(
            icon_name="pa-generate-symbolic",
            popover=self.generator,
            valign=Gtk.Align.CENTER,
            tooltip_text=_("Generate Password"),
        )
        self.generate_button.add_css_class("flat")
        self.generate_button.update_property(
            [Gtk.AccessibleProperty.LABEL], [_("Generate Password")]
        )
        self.password.add_suffix(self.generate_button)
        for row in (self.title, self.url, self.username, self.password):
            self.main_group.add(row)
        self.append(self.main_group)

        self.code_group = Adw.PreferencesGroup(
            title=_("Verification Code"),
            description=_("Paste the setup key or otpauth:// link the website shows."),
        )
        self.otpauth = Adw.PasswordEntryRow(title=_("Setup Key"))
        self.otpauth.update_property([Gtk.AccessibleProperty.LABEL], [_("Setup Key")])
        self.code_group.add(self.otpauth)
        self.append(self.code_group)

        self.alt_group = Adw.PreferencesGroup(title=_("Additional Websites"))
        add_alt = Gtk.Button(
            icon_name="list-add-symbolic",
            tooltip_text=_("Add Website"),
            valign=Gtk.Align.CENTER,
        )
        add_alt.add_css_class("flat")
        add_alt.update_property([Gtk.AccessibleProperty.LABEL], [_("Add Website")])
        add_alt.connect("clicked", lambda *_a: self.add_alt_url("").grab_focus())
        self.alt_group.set_header_suffix(add_alt)
        self.alt_rows: list[Adw.EntryRow] = []
        self.append(self.alt_group)

        self.notes_group = Adw.PreferencesGroup(title=_("Notes"))
        self.notes = Gtk.TextView(
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
            top_margin=10,
            bottom_margin=10,
            left_margin=12,
            right_margin=12,
            height_request=96,
        )
        self.notes.add_css_class("card")
        self.notes.update_property([Gtk.AccessibleProperty.LABEL], [_("Notes")])
        self.notes_group.add(self.notes)
        self.append(self.notes_group)
        self._field_rows: dict[Field, list[Gtk.Widget]] = {
            Field.TITLE: [self.title],
            Field.URL: [self.url],
            Field.USERNAME: [self.username],
            Field.PASSWORD: [self.password],
            Field.OTPAUTH: [self.otpauth],
            Field.NOTES: [self.notes],
        }

    # ---------------------------------------------------------------- data
    def load(self, draft: Draft) -> None:
        self._id = draft.id
        self._group = draft.group
        self.title.set_text(draft.title)
        self.url.set_text(draft.url)
        self.username.set_text(draft.username)
        self.password.set_text(draft.password)
        self.otpauth.set_text(draft.otpauth)
        for row in self.alt_rows:
            self.alt_group.remove(row)
        self.alt_rows.clear()
        for url in draft.alt_urls:
            self.add_alt_url(url)
        self.notes.get_buffer().set_text(draft.notes)
        self.show_errors({})

    def draft(self) -> Draft:
        buffer = self.notes.get_buffer()
        notes = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)  # noqa: FBT003
        return Draft(
            id=self._id,
            url=self.url.get_text(),
            username=self.username.get_text(),
            password=self.password.get_text(),
            title=self.title.get_text(),
            notes=notes,
            otpauth=self.otpauth.get_text(),
            alt_urls=tuple(r.get_text() for r in self.alt_rows),
            group=self._group,
        )

    def set_password(self, password: str) -> None:
        self.password.set_text(password)

    def add_alt_url(self, url: str) -> Adw.EntryRow:
        row = _entry_row(_("Website"))
        row.set_text(url)
        row.set_input_purpose(Gtk.InputPurpose.URL)
        remove = Gtk.Button(
            icon_name="edit-delete-symbolic",
            valign=Gtk.Align.CENTER,
            tooltip_text=_("Remove Website"),
        )
        remove.add_css_class("flat")
        remove.update_property([Gtk.AccessibleProperty.LABEL], [_("Remove Website")])
        remove.connect("clicked", lambda *_a: self._remove_alt(row))
        row.add_suffix(remove)
        self.alt_rows.append(row)
        self.alt_group.add(row)
        return row

    def _remove_alt(self, row: Adw.EntryRow) -> None:
        self.alt_rows.remove(row)
        self.alt_group.remove(row)

    # ---------------------------------------------------------------- errors
    def show_errors(self, errors: dict[Field, str]) -> None:
        rows: dict[Field, list[Gtk.Widget]] = {**self._field_rows, Field.ALT_URLS: [*self.alt_rows]}
        for field, widgets in rows.items():
            for widget in widgets:
                if field in errors:
                    widget.add_css_class("error")
                else:
                    widget.remove_css_class("error")
        self.error_label.set_visible(bool(errors))
        self.error_label.set_text("\n".join(errors.values()))
        if errors:
            first = next(f for f in rows if f in errors)
            if rows[first]:
                rows[first][0].grab_focus()

    @property
    def has_errors(self) -> bool:
        return self.error_label.get_visible()

    def focus_first(self) -> None:
        self.url.grab_focus() if not self.url.get_text() else self.password.grab_focus()
