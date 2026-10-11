# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Right pane: one login (view and in-place edit) or one deleted login (restore/purge).

The password is fetched with Get() only when a login is shown and is dropped as soon as
another one is selected, so at most one password sits in the app's memory at a time.
"""

from __future__ import annotations

from datetime import UTC, datetime
from functools import partial
from typing import TYPE_CHECKING, ClassVar, Protocol

from gi.repository import Adw, Gdk, GLib, GObject, Gtk

from passwords_app.app import codes, formatting
from passwords_app.app.client import DaemonError, ErrorKind
from passwords_app.app.formatting import MASK, Copied
from passwords_app.app.i18n import _, pgettext
from passwords_app.app.records import Draft, Item, TrashEntry
from passwords_app.app.security import Issue, Level, issue_text, level, level_text
from passwords_app.app.ui.editor import EditForm
from passwords_app.app.ui.widgets import (
    CountdownRing,
    MonogramTile,
    StrengthMeter,
    copy_button,
    icon_button,
)
from passwords_app.app.validation import validate

if TYPE_CHECKING:
    from collections.abc import Callable

    from gi.repository import Gio

    from passwords_app.app.ui.favicons import FaviconLoader
    from passwords_app.app.vault import Vault


class Host(Protocol):
    """What the detail pane needs from the window."""

    def copy_text(self, text: str, what: Copied, *, sensitive: bool) -> None: ...
    def toast(self, message: str) -> object: ...
    def open_uri(self, uri: str) -> None: ...
    def delete_item(self, item_id: str) -> None: ...
    def saved(self, item_id: str) -> None: ...
    def restore_entry(self, trash_id: str) -> None: ...
    def purge_entry(self, trash_id: str) -> None: ...


def _property_row(title: str) -> Adw.ActionRow:
    row = Adw.ActionRow(title=title, subtitle_selectable=True)
    row.add_css_class("property")
    return row


class DetailPage(Adw.NavigationPage):
    __gtype_name__ = "PasswordsDetailPage"
    __gsignals__: ClassVar[dict[str, tuple[GObject.SignalFlags, None, tuple[type, ...]]]] = {
        # Edit mode or the shown item changed; the window updates which actions apply.
        "mode-changed": (GObject.SignalFlags.RUN_FIRST, None, ()),
    }

    def __init__(  # noqa: PLR0915 - builds the whole detail tree; splitting scatters one layout
        self,
        vault: Vault,
        host: Host,
        settings: Gio.Settings | None,
        *,
        favicons: FaviconLoader | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        super().__init__(title=_("Password"), tag="detail")
        self.vault = vault
        self.favicons = favicons
        self.host = host
        self._now = now
        self.item: Item | None = None  # with password once Get() returned
        self.entry: TrashEntry | None = None
        self.editing = False
        # Bumped on entering and leaving edit mode; a save reply from an earlier session must
        # not end the edit the user has started since (on this or another item).
        self._edit_session = 0
        self.revealed = False
        self._serial = 0
        self._code_refresh = 0
        self.code = ""  # the code currently shown, for copy and tests

        # ---- header (the big title below already names the item)
        header = Adw.HeaderBar(show_title=False)
        self.cancel_button = Gtk.Button(label=_("Cancel"), visible=False)
        self.cancel_button.set_action_name("win.cancel-edit")
        header.pack_start(self.cancel_button)
        self.edit_button = Gtk.Button(label=_("Edit"), visible=False)
        self.edit_button.set_action_name("win.edit")
        self.save_button = Gtk.Button(label=_("Save"), visible=False)
        self.save_button.add_css_class("suggested-action")
        self.save_button.set_action_name("win.save-edit")
        header.pack_end(self.edit_button)
        header.pack_end(self.save_button)

        # ---- view mode
        self.tile = MonogramTile(72)
        self.title_label = Gtk.Label(wrap=True, xalign=0, selectable=True)
        # Leaving edit mode hands focus to the first focusable widget, this label; GTK would
        # select its whole text, which reads as a stray highlight on the title.
        self.title_label.connect(
            "notify::has-focus", lambda *_a: self.title_label.select_region(0, 0)
        )
        self.title_label.add_css_class("detail-title")
        self.modified_label = Gtk.Label(xalign=0)
        self.modified_label.add_css_class("dim-label")
        heading = Gtk.Box(spacing=18)
        heading.add_css_class("detail-header")
        titles = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, spacing=2)
        titles.append(self.title_label)
        titles.append(self.modified_label)
        heading.append(self.tile)
        heading.append(titles)

        self.account_group = Adw.PreferencesGroup()
        self.username_row = _property_row(_("User Name"))
        self.username_row.add_suffix(
            copy_button(_("Copy User Name"), lambda: self._run("win.copy-username"))
        )
        self.password_row = _property_row(_("Password"))
        self.password_row.set_subtitle_selectable(False)
        self.reveal_button = Gtk.ToggleButton(
            icon_name="view-reveal-symbolic",
            valign=Gtk.Align.CENTER,
            tooltip_text=_("Show Password"),
        )
        self.reveal_button.add_css_class("flat")
        self.reveal_button.update_property([Gtk.AccessibleProperty.LABEL], [_("Show Password")])
        self.reveal_button.connect("toggled", self._on_reveal)
        self.password_row.add_suffix(self.reveal_button)
        self.password_row.add_suffix(
            copy_button(_("Copy Password"), lambda: self._run("win.copy-password"))
        )
        self.strength_row = Adw.ActionRow(title=_("Password Strength"))
        self.strength = StrengthMeter()
        self.strength.set_valign(Gtk.Align.CENTER)
        self.strength.set_size_request(140, -1)
        self.strength.label.set_visible(False)
        self.strength_label = Gtk.Label()
        self.strength_label.add_css_class("dim-label")
        self.strength_row.add_suffix(self.strength_label)
        self.strength_row.add_suffix(self.strength)
        self.code_row = Adw.ActionRow(title=_("Verification Code"))
        self.code_label = Gtk.Label(selectable=True)
        self.code_label.add_css_class("code-value")
        self.ring = CountdownRing(22)
        self.code_row.add_suffix(self.code_label)
        self.code_row.add_suffix(self.ring)
        self.code_row.add_suffix(
            copy_button(_("Copy Verification Code"), lambda: self._run("win.copy-code"))
        )
        for row in (self.username_row, self.password_row, self.strength_row, self.code_row):
            self.account_group.add(row)

        self.warnings_group = Adw.PreferencesGroup(title=_("Security Recommendations"))
        self.warning_rows: list[Adw.ActionRow] = []

        self.sites_group = Adw.PreferencesGroup(title=_("Websites"))
        self.site_rows: list[Adw.ActionRow] = []

        self.notes_group = Adw.PreferencesGroup(title=_("Notes"))
        self.notes_label = Gtk.Label(
            wrap=True,
            xalign=0,
            selectable=True,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12,
        )
        notes_card = Gtk.Box()
        notes_card.add_css_class("card")
        notes_card.append(self.notes_label)
        self.notes_group.add(notes_card)

        self.info_group = Adw.PreferencesGroup()
        self.group_row = _property_row(_("Shared Group"))
        self.created_row = _property_row(_("Created"))
        self.modified_row = _property_row(_("Modified"))
        for row in (self.group_row, self.created_row, self.modified_row):
            self.info_group.add(row)

        self.delete_button = Gtk.Button(label=_("Delete Password"), halign=Gtk.Align.CENTER)
        self.delete_button.add_css_class("destructive-action")
        self.delete_button.add_css_class("pill")
        self.delete_button.set_action_name("win.delete")

        self.view_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        for child in (
            heading,
            self.account_group,
            self.warnings_group,
            self.sites_group,
            self.notes_group,
            self.info_group,
            self.delete_button,
        ):
            self.view_box.append(child)

        # ---- edit mode
        self.form = EditForm(settings)

        # ---- deleted item
        self.trash_box = self._build_trash_box()

        # ---- empty
        self.empty = Adw.StatusPage(
            icon_name="pa-key-symbolic",
            title=_("No Password Selected"),
            description=_("Choose a password from the list."),
        )
        # Compact keeps the glyph at a size its 16 px grid renders cleanly at.
        self.empty.add_css_class("compact")
        self.loading = Adw.Spinner(halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)

        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        for name, content in (
            ("view", self.view_box),
            ("edit", self.form),
            ("trash", self.trash_box),
        ):
            clamp = Adw.Clamp(
                maximum_size=640,
                child=content,
                margin_top=12,
                margin_bottom=24,
                margin_start=12,
                margin_end=12,
            )
            self.stack.add_named(
                Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, child=clamp), name
            )
        self.stack.add_named(self.empty, "empty")
        self.stack.add_named(self.loading, "loading")
        self.stack.set_visible_child_name("empty")
        # A password iCloud refuses to store: why, while it stays on this computer only.
        self.local_banner = Adw.Banner(revealed=False)
        view = Adw.ToolbarView(content=self.stack)
        view.add_top_bar(header)
        view.add_top_bar(self.local_banner)
        self.set_child(view)

    def _run(self, action: str) -> None:
        self.activate_action(action, None)

    # ---------------------------------------------------------------- trash
    def _build_trash_box(self) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        heading = Gtk.Box(spacing=18)
        heading.add_css_class("detail-header")
        self.trash_tile = MonogramTile(72)
        titles = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, spacing=2)
        self.trash_title = Gtk.Label(wrap=True, xalign=0)
        self.trash_title.add_css_class("detail-title")
        self.trash_left = Gtk.Label(xalign=0)
        self.trash_left.add_css_class("dim-label")
        titles.append(self.trash_title)
        titles.append(self.trash_left)
        heading.append(self.trash_tile)
        heading.append(titles)
        group = Adw.PreferencesGroup()
        self.trash_user = _property_row(_("User Name"))
        self.trash_site = _property_row(_("Website"))
        self.trash_reason = _property_row(_("Why It Is Here"))
        self.trash_deleted = _property_row(pgettext("date an item was deleted", "Deleted"))
        for row in (self.trash_user, self.trash_site, self.trash_reason, self.trash_deleted):
            group.add(row)
        buttons = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
        self.restore_button = Gtk.Button(label=_("Restore"))
        self.restore_button.add_css_class("suggested-action")
        self.restore_button.add_css_class("pill")
        self.restore_button.connect("clicked", lambda *_a: self._restore())
        self.purge_button = Gtk.Button(label=_("Delete Now"))
        self.purge_button.add_css_class("destructive-action")
        self.purge_button.add_css_class("pill")
        self.purge_button.connect("clicked", lambda *_a: self._purge())
        buttons.append(self.restore_button)
        buttons.append(self.purge_button)
        hint = Gtk.Label(
            label=_("Restoring puts the password back on this computer and in iCloud."),
            wrap=True,
            justify=Gtk.Justification.CENTER,
        )
        hint.add_css_class("dim-label")
        hint.add_css_class("caption")
        for child in (heading, group, buttons, hint):
            box.append(child)
        return box

    def show_trash(self, entry: TrashEntry | None) -> None:
        self.leave_edit()
        self._forget()
        self.entry = entry
        if entry is None:
            self._show_empty()
            return
        item = entry.item
        self.set_title(item.display_title)
        self.trash_tile.show_item(item)
        self.trash_title.set_text(item.display_title)
        now = self._now()
        self.trash_left.set_text(
            formatting.days_left_text(formatting.days_left(entry.expires_at, now))
        )
        self.trash_user.set_subtitle(GLib.markup_escape_text(item.username or _("None")))
        self.trash_site.set_subtitle(GLib.markup_escape_text(item.host))
        self.trash_reason.set_subtitle(formatting.reason_text(entry.reason))
        self.trash_deleted.set_subtitle(formatting.date_time(entry.deleted_at, now))
        self.edit_button.set_visible(False)
        self.local_banner.set_revealed(False)
        self.stack.set_visible_child_name("trash")

    def _restore(self) -> None:
        if self.entry is not None:
            self.host.restore_entry(self.entry.trash_id)

    def _purge(self) -> None:
        if self.entry is not None:
            self.host.purge_entry(self.entry.trash_id)

    # ---------------------------------------------------------------- item
    def _forget(self) -> None:
        """Drop the shown password and stop code refreshes."""
        self._serial += 1
        self.item = None
        self.entry = None
        self.revealed = False
        self.reveal_button.set_active(False)
        self.password_row.set_subtitle(MASK)
        self.code = ""
        self.ring.stop()
        if self._code_refresh:
            GLib.source_remove(self._code_refresh)
            self._code_refresh = 0
        self.emit("mode-changed")

    def _show_empty(self) -> None:
        self.set_title(_("Password"))
        self.edit_button.set_visible(False)
        self.local_banner.set_revealed(False)
        self.stack.set_visible_child_name("empty")

    def show_item(self, item_id: str | None) -> None:
        """Fetch and show `item_id` (None clears the pane)."""
        if self.editing:
            self.leave_edit()
        self._forget()
        if item_id is None:
            self._show_empty()
            return
        serial = self._serial
        if self.stack.get_visible_child_name() in {"empty", "trash"}:
            self.stack.set_visible_child_name("loading")

        def got(result: Item | DaemonError) -> None:
            if serial != self._serial:
                return
            if isinstance(result, DaemonError):
                if result.kind is not ErrorKind.NOT_FOUND:
                    self.host.toast(result.message)
                self._show_empty()
                return
            self._render(result)

        self.vault.client.get(item_id, got)

    def _render(self, item: Item) -> None:
        self.item = item
        now = self._now()
        self.set_title(item.display_title)
        self.tile.show_item(item)
        self.load_icon()
        self.title_label.set_text(item.display_title)
        self.modified_label.set_text(
            _("Last modified {when}").format(
                when=formatting.date_time(item.modified, now, in_sentence=True)
            )
        )
        self.username_row.set_subtitle(GLib.markup_escape_text(item.username or _("None")))
        self.password_row.set_subtitle(MASK)
        password = item.password or ""
        self.strength.show_level(level(password, user_inputs=(item.username, item.host)))
        self.strength_label.set_text(level_text(self.strength.level or Level.WEAK))
        self.code_row.set_visible(item.has_code)
        if item.has_code:
            self.code_label.set_text("··· ···")
            self._fetch_code()
        self._render_warnings(item)
        self._render_sites(item)
        self.notes_group.set_visible(bool(item.notes))
        self.notes_label.set_text(item.notes)
        self.group_row.set_visible(bool(item.group))
        self.group_row.set_subtitle(GLib.markup_escape_text(item.group))
        self.created_row.set_subtitle(formatting.date_time(item.created, now))
        self.modified_row.set_subtitle(formatting.date_time(item.modified, now))
        self.edit_button.set_visible(True)
        self._render_sync_problem(item)
        self.stack.set_visible_child_name("view")
        self.emit("mode-changed")

    def _render_sync_problem(self, item: Item) -> None:
        if item.sync_problem:
            self.local_banner.set_title(
                _("On this computer only: iCloud did not accept this password. {reason}").format(
                    reason=formatting.sync_problem_text(item.sync_problem)
                )
            )
        self.local_banner.set_revealed(bool(item.sync_problem))

    def _show_icon(self, serial: int, texture: Gdk.Texture | None) -> None:
        if serial == self._serial:
            self.tile.set_icon(texture)

    def load_icon(self) -> None:
        item = self.item
        if item is None or self.favicons is None:
            return
        serial = self._serial
        self.favicons.request(item.host, lambda texture: self._show_icon(serial, texture))

    def refresh_warnings(self) -> None:
        if self.item is not None and not self.editing:
            self._render_warnings(self.item)

    def _render_warnings(self, item: Item) -> None:
        for row in self.warning_rows:
            self.warnings_group.remove(row)
        self.warning_rows.clear()
        issues = self.vault.report.of(item.id)
        for issue in sorted(issues, key=lambda i: list(Issue).index(i)):
            others = len(self.vault.report.reused_with.get(item.id, ()))
            row = Adw.ActionRow(title=issue_text(issue, others), subtitle_lines=3)
            row.set_subtitle(
                _("Change this password on the website, then update it here.")
                if issue is not Issue.REUSED
                else _("Use a different password for every website.")
            )
            icon = Gtk.Image(icon_name="dialog-warning-symbolic")
            icon.add_css_class("warning-icon")
            row.add_prefix(icon)
            row.add_css_class("error-row" if issue is Issue.COMPROMISED else "warning-row")
            self.warning_rows.append(row)
            self.warnings_group.add(row)
        self.warnings_group.set_visible(bool(issues))

    def _render_sites(self, item: Item) -> None:
        for row in self.site_rows:
            self.sites_group.remove(row)
        self.site_rows.clear()
        for url in (item.url, *item.alt_urls):
            shown = url.split("://", 1)[-1]
            row = Adw.ActionRow(title=GLib.markup_escape_text(shown), title_lines=1)
            row.set_tooltip_text(url)
            uri = url if "://" in url else f"https://{url}"
            row.add_suffix(
                icon_button(
                    "pa-external-link-symbolic",
                    _("Open {site}").format(site=url),
                    partial(self._open, uri),
                )
            )
            self.site_rows.append(row)
            self.sites_group.add(row)

    def _open(self, uri: str) -> None:
        self.host.open_uri(uri)

    def _fetch_code(self) -> None:
        item = self.item
        if item is None:
            return
        serial = self._serial
        period = codes.period_of(item.otpauth)

        def done(result: tuple[str, int] | DaemonError) -> None:
            if serial != self._serial or isinstance(result, DaemonError):
                return
            code, seconds = result
            self.code_label.set_text(codes.grouped(code))
            self.code = code
            self.ring.start(seconds, period)
            if self._code_refresh:
                GLib.source_remove(self._code_refresh)
            self._code_refresh = GLib.timeout_add(max(1, seconds) * 1000, self._code_expired)

        self.vault.client.get_code(item.id, done)

    def _code_expired(self) -> bool:
        self._code_refresh = 0
        self._fetch_code()
        return GLib.SOURCE_REMOVE

    def _on_reveal(self, button: Gtk.ToggleButton) -> None:
        self.revealed = button.get_active()
        shown = self.revealed and self.item is not None
        self.password_row.set_subtitle(
            GLib.markup_escape_text(self.item.password or "") if shown and self.item else MASK
        )
        tip = _("Hide Password") if self.revealed else _("Show Password")
        button.set_icon_name("view-conceal-symbolic" if self.revealed else "view-reveal-symbolic")
        button.set_tooltip_text(tip)
        button.update_property([Gtk.AccessibleProperty.LABEL], [tip])
        if shown:
            self.password_row.add_css_class("secret-value")
        else:
            self.password_row.remove_css_class("secret-value")

    def toggle_reveal(self) -> None:
        self.reveal_button.set_active(not self.reveal_button.get_active())

    # ---------------------------------------------------------------- edit
    def enter_edit(self) -> None:
        if self.item is None or self.editing:
            return
        self.editing = True
        self._edit_session += 1
        self.save_button.set_sensitive(True)
        self.form.load(Draft.from_item(self.item))
        self.stack.set_visible_child_name("edit")
        self.edit_button.set_visible(False)
        self.save_button.set_visible(True)
        self.cancel_button.set_visible(True)
        self.form.title.grab_focus()
        self.emit("mode-changed")

    def leave_edit(self) -> None:
        if not self.editing:
            return
        self.editing = False
        self._edit_session += 1
        self.form.load(Draft(url=""))  # do not keep the password in the form
        self.save_button.set_visible(False)
        self.cancel_button.set_visible(False)
        self.edit_button.set_visible(self.item is not None)
        self.stack.set_visible_child_name("view" if self.item is not None else "empty")
        self.emit("mode-changed")

    def save_edit(self) -> None:
        if not self.editing:
            return
        result = validate(self.form.draft())
        self.form.show_errors(result.errors)
        if not result.ok:
            return
        self.save_button.set_sensitive(False)
        session = self._edit_session

        def saved(reply: str | DaemonError) -> None:
            if session != self._edit_session:  # the user has moved on; report, touch nothing
                if isinstance(reply, DaemonError):
                    self.host.toast(reply.message)
                else:
                    self.host.toast(_("Saved"))
                    self.vault.schedule_reload()
                return
            self.save_button.set_sensitive(True)
            if isinstance(reply, DaemonError):
                self.form.error_label.set_text(reply.message)
                self.form.error_label.set_visible(True)
                return
            self.leave_edit()
            self.host.saved(reply)
            self.show_item(reply)

        self.vault.client.save(result.draft, saved)
