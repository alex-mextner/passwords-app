# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Sidebar: All, Codes, Security (badge), Deleted (count), then shared groups."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from gi.repository import Adw, GObject, Gtk, Pango

from passwords_app.app import sections
from passwords_app.app.i18n import _, ngettext
from passwords_app.app.sections import Kind, Section

if TYPE_CHECKING:
    from passwords_app.app.ui.sync_status import SyncStatusButton


class SidebarRow(Gtk.ListBoxRow):
    def __init__(self, section: Section) -> None:
        super().__init__()
        self.section = section
        box = Gtk.Box(spacing=12, margin_top=2, margin_bottom=2)
        self.icon = Gtk.Image(
            icon_name=section.icon, accessible_role=Gtk.AccessibleRole.PRESENTATION
        )
        self.label = Gtk.Label(
            label=section.title, xalign=0, hexpand=True, ellipsize=Pango.EllipsizeMode.END
        )
        self.count = Gtk.Label(xalign=1)
        self.count.add_css_class("sidebar-count")
        self.badge = Gtk.Label(visible=False, valign=Gtk.Align.CENTER)
        self.badge.add_css_class("sidebar-badge")
        for child in (self.icon, self.label, self.count, self.badge):
            box.append(child)
        self.set_child(box)
        self._n = 0
        self._update_name()

    def set_count(self, n: int, *, badge: bool = False) -> None:
        self._n = n
        text = str(n) if n else ""
        self.badge.set_visible(badge and n > 0)
        self.count.set_visible(not (badge and n > 0))
        (self.badge if badge else self.count).set_text(text)
        self._update_name()

    @property
    def shown_count(self) -> str:
        return self.badge.get_text() if self.badge.get_visible() else self.count.get_text()

    def _update_name(self) -> None:
        if self.section.kind is Kind.SECURITY and self._n:
            name = ngettext(
                "{title}, {n} recommendation", "{title}, {n} recommendations", self._n
            ).format(title=self.section.title, n=self._n)
        elif self._n:
            name = ngettext("{title}, {n} item", "{title}, {n} items", self._n).format(
                title=self.section.title, n=self._n
            )
        else:
            name = self.section.title
        self.update_property([Gtk.AccessibleProperty.LABEL], [name])


class Sidebar(Adw.NavigationPage):
    __gtype_name__ = "PasswordsSidebar"
    __gsignals__: ClassVar[dict[str, tuple[GObject.SignalFlags, None, tuple[type, ...]]]] = {
        "section-selected": (GObject.SignalFlags.RUN_FIRST, None, ()),
    }

    def __init__(self, status_button: SyncStatusButton, menu: Gtk.MenuButton) -> None:
        super().__init__(title=_("Passwords"), tag="sidebar")
        header = Adw.HeaderBar(show_title=False)
        header.pack_start(status_button)
        header.pack_end(menu)
        self.list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.list.add_css_class("navigation-sidebar")
        self.list.update_property([Gtk.AccessibleProperty.LABEL], [_("Sections")])
        self.list.set_header_func(self._header)
        self.rows: dict[Section, SidebarRow] = {}
        for section in sections.FIXED:
            self._add(section)
        self.list.connect("row-selected", self._on_row_selected)
        scrolled = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        scrolled.set_child(self.list)
        view = Adw.ToolbarView(content=scrolled)
        view.add_top_bar(header)
        self.set_child(view)
        self.selected: Section = sections.ALL
        self.list.select_row(self.rows[sections.ALL])

    def _add(self, section: Section) -> SidebarRow:
        row = SidebarRow(section)
        self.rows[section] = row
        self.list.append(row)
        return row

    def _header(self, row: Gtk.ListBoxRow, before: Gtk.ListBoxRow | None) -> None:
        if not isinstance(row, SidebarRow) or row.section.kind is not Kind.GROUP:
            row.set_header(None)
            return
        if isinstance(before, SidebarRow) and before.section.kind is Kind.GROUP:
            row.set_header(None)
            return
        label = Gtk.Label(label=_("Shared Groups"), xalign=0, margin_start=12, margin_top=18)
        label.add_css_class("heading")
        label.add_css_class("dim-label")
        row.set_header(label)

    def set_groups(self, groups: list[str]) -> None:
        wanted = [Section(Kind.GROUP, g) for g in groups]
        for section, row in list(self.rows.items()):
            if section.kind is Kind.GROUP and section not in wanted:
                if self.selected == section:
                    self.select(sections.ALL)
                self.list.remove(row)
                del self.rows[section]
        for section in wanted:
            if section not in self.rows:
                self._add(section)
        self.list.invalidate_headers()

    def set_counts(self, counts: dict[Section, int]) -> None:
        for section, row in self.rows.items():
            row.set_count(counts.get(section, 0), badge=section.kind is Kind.SECURITY)

    def select(self, section: Section) -> None:
        row = self.rows.get(section)
        if row is not None:
            self.list.select_row(row)

    def _on_row_selected(self, _list: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if isinstance(row, SidebarRow):
            self.selected = row.section
            self.emit("section-selected")
