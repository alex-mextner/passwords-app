# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Middle pane: search field, sort menu, banners, and the item (or deleted-item) list.

Filtering runs in a `Gtk.CustomFilter` over precomputed haystacks and tells GTK whether a
new query is stricter or looser than the last, so typing one more letter only re-checks the
items still visible.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar, cast

from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango

from passwords_app.app import codes, formatting, sections
from passwords_app.app.client import DaemonError
from passwords_app.app.constants import TRASH_RETENTION_DAYS
from passwords_app.app.i18n import _, ngettext
from passwords_app.app.search import Change, Query, change_between
from passwords_app.app.sections import Kind, Section
from passwords_app.app.security import Issue, issue_text
from passwords_app.app.sorting import SortOrder
from passwords_app.app.ui.widgets import CountdownRing, MonogramTile
from passwords_app.app.vault import ItemObject, TrashObject, Vault

if TYPE_CHECKING:
    from collections.abc import Callable

    from passwords_app.app.ui.favicons import FaviconLoader


class ItemRow(Gtk.Box):
    """One list row; in the Codes section it also shows the live code and its ring."""

    def __init__(self, vault: Vault, favicons: FaviconLoader) -> None:
        super().__init__(spacing=12)
        self.add_css_class("item-row")
        self.vault = vault
        self.favicons = favicons
        self.tile = MonogramTile(32)
        texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, hexpand=True)
        self.title = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self.title.add_css_class("title")
        self.subtitle = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self.subtitle.add_css_class("dim-label")
        self.subtitle.add_css_class("caption")
        texts.append(self.title)
        texts.append(self.subtitle)
        self.local_badge = Gtk.Label(
            label=_("On this computer only"), visible=False, valign=Gtk.Align.CENTER
        )
        self.local_badge.add_css_class("local-only-badge")
        self.warning = Gtk.Image(icon_name="dialog-warning-symbolic", visible=False)
        self.warning.add_css_class("warning")
        self.code = Gtk.Label(visible=False)
        self.code.add_css_class("list-code")
        for child in (self.tile, texts, self.local_badge, self.warning, self.code):
            self.append(child)
        self._ring: CountdownRing | None = None  # only Codes rows need one
        self.obj: ItemObject | None = None
        self._refresh = 0
        self._serial = 0

    def bind(self, obj: ItemObject, section: Section) -> str:
        """Show `obj`; returns the row's accessible label."""
        self.obj = obj
        item = obj.item
        self.tile.show_item(item, obj.letter, obj.tint)
        self._serial += 1
        serial = self._serial
        self.favicons.request(obj.host, lambda texture: self._show_icon(serial, texture))
        self.title.set_text(item.display_title)
        subtitle = item.username or _("No user name")
        if section.kind is Kind.SECURITY and obj.issues:
            worst = min(obj.issues, key=lambda i: list(Issue).index(i))
            subtitle = issue_text(worst, len(self.vault.report.reused_with.get(item.id, ())))
        self.subtitle.set_text(subtitle)
        self.warning.set_visible(section.kind is Kind.SECURITY and bool(obj.issues))
        show_code = section.kind is Kind.CODES and item.has_code
        self.code.set_visible(show_code)
        if show_code or self._ring is not None:
            self.ring.set_visible(show_code)
        if show_code:
            self._fetch_code()
        return self._show_local_only(item.sync_problem, f"{item.display_title}, {subtitle}")

    def _show_local_only(self, sync_problem: str, label: str) -> str:
        """Badge a password iCloud refuses to store; returns `label` naming the badge too."""
        self.local_badge.set_visible(bool(sync_problem))
        self.local_badge.set_tooltip_text(
            formatting.sync_problem_text(sync_problem) if sync_problem else None
        )
        return f"{label}, {self.local_badge.get_label()}" if sync_problem else label

    @property
    def ring(self) -> CountdownRing:
        if self._ring is None:
            self._ring = CountdownRing(18)
            self.append(self._ring)
        return self._ring

    def _show_icon(self, serial: int, texture: Gdk.Texture | None) -> None:
        if serial == self._serial:
            self.tile.set_icon(texture)

    def unbind(self) -> None:
        self.obj = None
        self._serial += 1
        if self._refresh:
            GLib.source_remove(self._refresh)
            self._refresh = 0
        if self._ring is not None:
            self._ring.stop()

    def _fetch_code(self) -> None:
        if self.obj is None:
            return
        self._serial += 1
        serial = self._serial
        item = self.obj.item

        def done(result: tuple[str, int] | DaemonError) -> None:
            if serial != self._serial or isinstance(result, DaemonError):
                return
            code, seconds = result
            self.code.set_text(codes.grouped(code))
            self.ring.start(seconds, codes.DEFAULT_PERIOD)
            if self._refresh:
                GLib.source_remove(self._refresh)
            self._refresh = GLib.timeout_add(max(1, seconds) * 1000, self._on_expired)

        self.vault.client.get_code(item.id, done)

    def _on_expired(self) -> bool:
        self._refresh = 0
        self._fetch_code()
        return GLib.SOURCE_REMOVE


class TrashRow(Gtk.Box):
    def __init__(self, now: Callable[[], datetime]) -> None:
        super().__init__(spacing=12)
        self.add_css_class("item-row")
        self._now = now
        self.tile = MonogramTile(32)
        texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, hexpand=True)
        self.title = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self.title.add_css_class("title")
        self.subtitle = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self.subtitle.add_css_class("dim-label")
        self.subtitle.add_css_class("caption")
        texts.append(self.title)
        texts.append(self.subtitle)
        self.append(self.tile)
        self.append(texts)

    def bind(self, obj: TrashObject) -> str:
        entry = obj.entry
        self.tile.show_item(entry.item)
        self.title.set_text(entry.item.display_title)
        left = formatting.days_left_text(formatting.days_left(entry.expires_at, self._now()))
        self.subtitle.set_text(left)
        return f"{entry.item.display_title}, {left}"


class ItemListPage(Adw.NavigationPage):
    __gtype_name__ = "PasswordsItemListPage"
    __gsignals__: ClassVar[dict[str, tuple[GObject.SignalFlags, None, tuple[type, ...]]]] = {
        "item-selected": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "trash-selected": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "sort-changed": (GObject.SignalFlags.RUN_FIRST, None, ()),
    }

    def __init__(  # noqa: PLR0915 - builds both list views; splitting scatters one layout
        self,
        vault: Vault,
        *,
        sort_order: SortOrder,
        hibp_switch: Adw.SwitchRow,
        favicons: FaviconLoader,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        super().__init__(title=_("All"), tag="list")
        self.vault = vault
        self.favicons = favicons
        self.section: Section = sections.ALL
        self.query = Query(())
        self.sort_order = sort_order
        self._splicing = False
        self._now = now

        # ---- header
        header = Adw.HeaderBar()
        self.add_button = Gtk.Button(icon_name="list-add-symbolic", tooltip_text=_("New Password"))
        self.add_button.update_property([Gtk.AccessibleProperty.LABEL], [_("New Password")])
        self.add_button.set_action_name("win.new-password")
        header.pack_end(self.add_button)
        sort_menu = Gio.Menu()
        for order, label in (
            (SortOrder.TITLE, _("Title")),
            (SortOrder.WEBSITE, _("Website")),
            (SortOrder.MODIFIED, _("Date Modified")),
        ):
            sort_menu.append(label, f"win.sort-order::{order.value}")
        section_menu = Gio.Menu()
        section_menu.append_section(_("Sort By"), sort_menu)
        self.sort_button = Gtk.MenuButton(
            icon_name="view-sort-ascending-symbolic",
            menu_model=section_menu,
            tooltip_text=_("Sort"),
        )
        self.sort_button.update_property([Gtk.AccessibleProperty.LABEL], [_("Sort")])
        header.pack_end(self.sort_button)

        # ---- banners (the window places them across list and detail)
        self.pause_banner = Adw.Banner(button_label=_("Review…"))
        self.pause_banner.set_action_name("win.review-pause")
        self.signin_banner = Adw.Banner(
            title=_("Sign in to iCloud to keep your passwords in sync"),
            button_label=_("Sign In…"),
        )
        self.signin_banner.set_action_name("win.sign-in")
        self.unreachable_banner = Adw.Banner(
            title=_("The Passwords background service is not running"),
            button_label=_("Retry"),
        )
        self.unreachable_banner.set_action_name("win.retry")

        # ---- search
        self.search = Gtk.SearchEntry(
            placeholder_text=_("Search"),
            hexpand=True,
            margin_start=12,
            margin_end=12,
            margin_top=6,
            margin_bottom=6,
        )
        self.search.update_property([Gtk.AccessibleProperty.LABEL], [_("Search passwords")])
        self.search.connect("search-changed", self._on_search_changed)
        self.search.connect("activate", self._on_search_activate)
        self.search.connect("stop-search", lambda *_a: self.search.set_text(""))

        # ---- security header (HIBP opt-in lives where its results show)
        self.security_header = Adw.PreferencesGroup(
            margin_start=12, margin_end=12, margin_bottom=6, visible=False
        )
        self.security_header.add(hibp_switch)

        # ---- item list
        # Filtering and sorting run in Python over the whole list at once and the result is
        # spliced into one store: a GtkFilter would call back into Python per item, which
        # costs far more than a 16 ms frame at 5 000 items.
        self._base: list[ItemObject] = []  # current section, sorted
        self.filtered: Gio.ListStore[ItemObject] = Gio.ListStore(item_type=ItemObject)
        self.selection = Gtk.SingleSelection(
            model=self.filtered, autoselect=False, can_unselect=True
        )
        self.selection.connect("selection-changed", self._on_item_selection)
        factory = Gtk.SignalListItemFactory()
        factory.connect("setup", self._setup_item)
        factory.connect("bind", self._bind_item)
        factory.connect("unbind", self._unbind_item)
        self.list_view = Gtk.ListView(model=self.selection, factory=factory)
        self.list_view.add_css_class("navigation-sidebar")
        self.list_view.update_property([Gtk.AccessibleProperty.LABEL], [_("Passwords")])
        self.list_view.connect("activate", self._on_activate)

        # ---- trash list
        self.trash_filtered: Gio.ListStore[TrashObject] = Gio.ListStore(item_type=TrashObject)
        self.trash_selection = Gtk.SingleSelection(
            model=self.trash_filtered, autoselect=False, can_unselect=True
        )
        self.trash_selection.connect("selection-changed", self._on_trash_selection)
        trash_factory = Gtk.SignalListItemFactory()
        trash_factory.connect("setup", self._setup_trash)
        trash_factory.connect("bind", self._bind_trash)
        self.trash_view = Gtk.ListView(model=self.trash_selection, factory=trash_factory)
        self.trash_view.add_css_class("navigation-sidebar")
        self.trash_view.update_property([Gtk.AccessibleProperty.LABEL], [_("Deleted passwords")])
        self.trash_view.connect("activate", self._on_activate)

        # ---- empty states
        self.empty = Adw.StatusPage(vexpand=True)
        self.empty.add_css_class("compact")
        self.loading = Adw.Spinner(halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)

        self.stack = Gtk.Stack(vexpand=True)
        for name, child in (
            ("items", self.list_view),
            ("trash", self.trash_view),
        ):
            scrolled = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, child=child)
            self.stack.add_named(scrolled, name)
        self.stack.add_named(self.empty, "empty")
        self.stack.add_named(self.loading, "loading")

        view = Adw.ToolbarView(content=self.stack)
        view.add_top_bar(header)
        view.add_top_bar(self.search)
        view.add_top_bar(self.security_header)
        self.set_child(view)

        vault.items.connect("items-changed", lambda *_a: self.refilter())
        vault.trash.connect("items-changed", lambda *_a: self._refresh_trash())
        self.refilter()
        self._refresh_trash()  # a window opened after the first load starts from the snapshot

    # ---------------------------------------------------------------- factory
    def _setup_item(self, _factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem) -> None:
        list_item.set_child(ItemRow(self.vault, self.favicons))

    def _bind_item(self, _factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem) -> None:
        row = cast("ItemRow", list_item.get_child())
        list_item.set_accessible_label(
            row.bind(cast("ItemObject", list_item.get_item()), self.section)
        )

    def _setup_trash(self, _factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem) -> None:
        list_item.set_child(TrashRow(self._now))

    def _bind_trash(self, _factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem) -> None:
        row = cast("TrashRow", list_item.get_child())
        list_item.set_accessible_label(row.bind(cast("TrashObject", list_item.get_item())))

    def _unbind_item(self, _factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem) -> None:
        cast("ItemRow", list_item.get_child()).unbind()

    # ---------------------------------------------------------------- filtering / sorting
    def _matches(self, objs: list[ItemObject], query: Query) -> list[ItemObject]:
        if query.empty:
            return objs
        tokens = query.tokens
        return [o for o in objs if all(t in o.hay for t in tokens)]

    def _show(self, objs: list[ItemObject]) -> None:
        """Replace the visible items, keeping the selected item selected when it stays."""
        selected = self.selected_item()
        selected_id = selected.item.id if selected is not None else None
        self._splicing = True
        try:
            self.filtered.splice(0, self.filtered.get_n_items(), objs)
            position = Gtk.INVALID_LIST_POSITION
            if selected_id is not None:
                position = next(
                    (i for i, o in enumerate(objs) if o.item.id == selected_id), position
                )
            self.selection.set_selected(position)
        finally:
            self._splicing = False
        if selected_id is not None and position == Gtk.INVALID_LIST_POSITION:
            self.emit("item-selected")  # the selected item left the list
        self._update_stack()

    def _refresh_trash(self) -> None:
        """Replace the visible entries, keeping the selected entry selected when it stays."""
        query = self.query
        entries = [
            cast("TrashObject", self.vault.trash.get_item(i))
            for i in range(self.vault.trash.get_n_items())
        ]
        shown = entries if query.empty else [e for e in entries if query.matches(e.hay)]
        selected = self.selected_trash()
        selected_id = selected.entry.trash_id if selected is not None else None
        self._splicing = True
        try:
            self.trash_filtered.splice(0, self.trash_filtered.get_n_items(), shown)
            position = _trash_position(shown, selected_id)
            self.trash_selection.set_selected(position)
        finally:
            self._splicing = False
        if selected_id is not None and position == Gtk.INVALID_LIST_POSITION:
            # Purged, restored or filtered out: its detail must not offer a dead Restore.
            self.emit("trash-selected")
        self._update_stack()

    def set_query(self, text: str) -> None:
        new = Query.parse(text)
        change = change_between(self.query, new)
        self.query = new
        if change is Change.SAME:
            return
        if change is Change.MORE_STRICT:
            # Every match of the new query is among the items shown now.
            current = [
                cast("ItemObject", self.filtered.get_item(i))
                for i in range(self.filtered.get_n_items())
            ]
            self._show(self._matches(current, new))
        else:
            self._show(self._matches(self._base, new))
        self._refresh_trash()

    def set_section(self, section: Section) -> None:
        self.section = section
        self.set_title(section.title)
        self.security_header.set_visible(section.kind is Kind.SECURITY)
        self.selection.set_selected(Gtk.INVALID_LIST_POSITION)
        self.trash_selection.set_selected(Gtk.INVALID_LIST_POSITION)
        self.refilter()
        self._rebind()

    def refilter(self) -> None:
        """Rebuild the section's sorted base list (items, verdicts or sort order changed)."""
        section, order = self.section, self.sort_order
        objs = [
            cast("ItemObject", self.vault.items.get_item(i))
            for i in range(self.vault.items.get_n_items())
        ]
        base = [o for o in objs if section.includes(o.item, o.issues)]
        base.sort(key=lambda o: o.key(order))
        self._base = base
        self._show(self._matches(base, self.query))

    def rebind(self) -> None:
        """Re-render visible rows (a display setting such as website icons changed)."""
        self._rebind()

    def _rebind(self) -> None:
        # Rows show section-specific details (codes, warnings); rebinding refreshes them.
        model = self.list_view.get_model()
        self.list_view.set_model(None)
        self.list_view.set_model(model)

    def set_sort(self, order: SortOrder) -> None:
        if order is self.sort_order:
            return
        self.sort_order = order
        self.refilter()
        self.emit("sort-changed")

    # ---------------------------------------------------------------- state
    def _update_stack(self) -> None:
        deleted = self.section.kind is Kind.DELETED
        count = self.trash_filtered.get_n_items() if deleted else self.filtered.get_n_items()
        if not self.vault.loaded:
            self.stack.set_visible_child_name("loading")
            return
        if count:
            self.stack.set_visible_child_name("trash" if deleted else "items")
            return
        if not self.query.empty:
            self.empty.set_icon_name("system-search-symbolic")
            self.empty.set_title(_("No Results"))
            self.empty.set_description(_("Try a different search"))
        elif deleted:
            self.empty.set_icon_name("user-trash-symbolic")
            self.empty.set_title(_("No Deleted Passwords"))
            self.empty.set_description(
                ngettext(
                    "Passwords you delete stay here for {n} day.",
                    "Passwords you delete stay here for {n} days.",
                    TRASH_RETENTION_DAYS,
                ).format(n=TRASH_RETENTION_DAYS)
            )
        elif self.section.kind is Kind.SECURITY:
            self.empty.set_icon_name("security-high-symbolic")
            self.empty.set_title(_("No Security Recommendations"))
            self.empty.set_description(_("None of your passwords are weak or reused."))
        elif self.section.kind is Kind.CODES:
            self.empty.set_icon_name("pa-codes-symbolic")
            self.empty.set_title(_("No Verification Codes"))
            self.empty.set_description(
                _("Add a setup key to a password to generate codes for that website.")
            )
        else:
            self.empty.set_icon_name("dialog-password-symbolic")
            self.empty.set_title(_("No Passwords"))
            self.empty.set_description(_("Passwords you save will appear here."))
        self.stack.set_visible_child_name("empty")

    def selected_item(self) -> ItemObject | None:
        obj = self.selection.get_selected_item()
        return cast("ItemObject", obj) if obj is not None else None

    def selected_trash(self) -> TrashObject | None:
        obj = self.trash_selection.get_selected_item()
        return cast("TrashObject", obj) if obj is not None else None

    def select_id(self, item_id: str) -> bool:
        for position in range(self.filtered.get_n_items()):
            obj = cast("ItemObject", self.filtered.get_item(position))
            if obj.item.id == item_id:
                self.selection.set_selected(position)
                self.list_view.scroll_to(position, Gtk.ListScrollFlags.FOCUS, None)
                return True
        return False

    def select_position(self, position: int) -> None:
        deleted = self.section.kind is Kind.DELETED
        model = self.trash_selection if deleted else self.selection
        view = self.trash_view if deleted else self.list_view
        n = model.get_n_items()
        if not n:
            return
        position = max(0, min(position, n - 1))
        model.set_selected(position)
        view.scroll_to(position, Gtk.ListScrollFlags.FOCUS | Gtk.ListScrollFlags.SELECT, None)

    def focus_list(self) -> None:
        deleted = self.section.kind is Kind.DELETED
        model = self.trash_selection if deleted else self.selection
        view = self.trash_view if deleted else self.list_view
        position = model.get_selected()
        if position == Gtk.INVALID_LIST_POSITION:
            position = 0
        if model.get_n_items():
            view.scroll_to(position, Gtk.ListScrollFlags.FOCUS, None)
            view.grab_focus()

    # ---------------------------------------------------------------- signals
    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        self.set_query(entry.get_text())
        self._update_stack()

    def _on_search_activate(self, _entry: Gtk.SearchEntry) -> None:
        self.select_position(0)
        self.focus_list()

    def _on_item_selection(self, *_args: object) -> None:
        if not self._splicing:
            self.emit("item-selected")

    def _on_trash_selection(self, *_args: object) -> None:
        if not self._splicing:
            self.emit("trash-selected")

    def _on_activate(self, view: Gtk.ListView, position: int) -> None:
        model = cast("Gtk.SingleSelection", view.get_model())
        model.set_selected(position)
        self.activate_action("win.show-detail", None)


def _trash_position(shown: list[TrashObject], trash_id: str | None) -> int:
    """Where the entry `trash_id` is among `shown`, else `Gtk.INVALID_LIST_POSITION`."""
    return next(
        (i for i, o in enumerate(shown) if o.entry.trash_id == trash_id),
        Gtk.INVALID_LIST_POSITION,
    )
