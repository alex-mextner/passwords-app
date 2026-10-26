# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Main window: sidebar → list → detail in two nested `Adw.NavigationSplitView`s.

Below 860 sp the sidebar collapses behind a back button; below 560 sp the list and detail
collapse too, so the window works from phone width to a full desktop.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from passwords_app.app import formatting, sections
from passwords_app.app.client import DaemonError, ErrorKind
from passwords_app.app.favicons import FaviconCache
from passwords_app.app.formatting import Copied, copied_text
from passwords_app.app.i18n import _
from passwords_app.app.records import SyncState
from passwords_app.app.sections import Kind, Section
from passwords_app.app.sorting import SortOrder
from passwords_app.app.ui.clipboard import ClipboardGuard
from passwords_app.app.ui.detail import DetailPage
from passwords_app.app.ui.favicons import FaviconLoader
from passwords_app.app.ui.item_list import ItemListPage
from passwords_app.app.ui.lock import IdleTimer, unlock_hint
from passwords_app.app.ui.new_password import NewPasswordDialog
from passwords_app.app.ui.shortcuts import shortcuts
from passwords_app.app.ui.sidebar import Sidebar
from passwords_app.app.ui.signin import SignInDialog
from passwords_app.app.ui.sync_status import SyncStatusButton
from passwords_app.app.ui.widgets import on_activate

if TYPE_CHECKING:
    from collections.abc import Callable

    from passwords_app.app.records import Item, TrashEntry
    from passwords_app.app.ui.lock import Authorizer
    from passwords_app.app.vault import Vault

_SECTION_NAMES = {
    "all": sections.ALL,
    "codes": sections.CODES,
    "security": sections.SECURITY,
    "deleted": sections.DELETED,
}


def _is_editable(widget: object) -> bool:
    # Text widgets implement the Gtk.Editable interface. The stubs declare it a Protocol that
    # is not runtime_checkable, but at runtime it is a real GObject interface class that
    # isinstance accepts, so the stub's claim is bypassed here and nowhere else.
    return isinstance(widget, cast("type[object]", Gtk.Editable))


class MainWindow(Adw.ApplicationWindow):
    __gtype_name__ = "PasswordsMainWindow"

    def __init__(  # noqa: PLR0915 - builds the whole window tree; splitting scatters one layout
        self,
        application: Adw.Application,
        vault: Vault,
        settings: Gio.Settings,
        *,
        authorizer: Authorizer | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        super().__init__(application=application, title=_("Passwords"))
        self.vault = vault
        self.settings = settings
        self._now = now
        self._authorizer = authorizer
        # False until the fprintd probe answers: never promise a fingerprint before it is known.
        self.fingerprint_available = False
        self.last_deleted: Item | None = None
        self.pending_select: str | None = None
        self.last_toast: Adw.Toast | None = None
        self.sign_in_dialog: SignInDialog | None = None
        self.pause_dialog: Adw.AlertDialog | None = None
        self.clipboard = ClipboardGuard(
            self.get_clipboard(), lambda: settings.get_uint("clipboard-clear-seconds")
        )
        self.set_size_request(360, 294)
        self.set_default_size(settings.get_int("window-width"), settings.get_int("window-height"))
        if settings.get_boolean("window-maximized"):
            self.maximize()

        # ---- panes
        self.status_button = SyncStatusButton(
            on_sync=self.sync_now, on_sign_in=self.show_sign_in, now=now
        )
        menu = Gio.Menu()
        menu.append(_("Preferences"), "app.preferences")
        menu.append(_("Keyboard Shortcuts"), "app.shortcuts")
        menu.append(_("About Passwords"), "app.about")
        self.menu_button = Gtk.MenuButton(
            icon_name="open-menu-symbolic",
            menu_model=menu,
            primary=True,
            tooltip_text=_("Main Menu"),
        )
        self.menu_button.update_property([Gtk.AccessibleProperty.LABEL], [_("Main Menu")])
        self.sidebar = Sidebar(self.status_button, self.menu_button)
        self.hibp_switch = Adw.SwitchRow(
            title=_("Detect Compromised Passwords"),
            subtitle=_("Only the first 5 characters of a password’s fingerprint are sent."),  # noqa: RUF001 - typographic punctuation in UI text
        )
        settings.bind("hibp-enabled", self.hibp_switch, "active", Gio.SettingsBindFlags.DEFAULT)
        try:
            order = SortOrder(settings.get_string("sort-order"))
        except ValueError:
            order = SortOrder.TITLE
        self.favicons = FaviconLoader(
            FaviconCache(Path(GLib.get_user_cache_dir()) / "passwords-app" / "favicons"),
            lambda: settings.get_boolean("favicons-enabled"),
        )
        self.list_page = ItemListPage(
            vault,
            sort_order=order,
            hibp_switch=self.hibp_switch,
            favicons=self.favicons,
            now=now,
        )
        self.detail = DetailPage(vault, self, settings, favicons=self.favicons, now=now)

        self.inner = Adw.NavigationSplitView(
            sidebar=self.list_page,
            content=self.detail,
            min_sidebar_width=300,
            max_sidebar_width=420,
            sidebar_width_fraction=0.4,
        )
        # Banners concern the whole vault, so they span list and detail below the panes
        # instead of squeezing their sentence into the list column.
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.inner.set_vexpand(True)
        content.append(self.inner)
        for banner in (
            self.list_page.unreachable_banner,
            self.list_page.signin_banner,
            self.list_page.pause_banner,
        ):
            content.append(banner)
        self.outer = Adw.NavigationSplitView(
            sidebar=self.sidebar,
            content=Adw.NavigationPage(title=_("Passwords"), child=content, tag="content"),
            # Wide enough for the longest header status («Сбой синхронизации») untruncated,
            # also in DejaVu Sans, the widest common fallback UI font.
            min_sidebar_width=288,
            max_sidebar_width=310,
            sidebar_width_fraction=0.24,
        )
        self.toasts = Adw.ToastOverlay(child=self.outer)

        # ---- lock screen
        unlock = Gtk.Button(label=_("Unlock"), halign=Gtk.Align.CENTER)
        unlock.add_css_class("suggested-action")
        unlock.add_css_class("pill")
        unlock.connect("clicked", lambda *_a: self.unlock())
        self.lock_page = Adw.StatusPage(
            icon_name="system-lock-screen-symbolic",
            title=_("Passwords Is Locked"),
            description=unlock_hint(fingerprint=False),
            child=unlock,
        )
        self.lock_page.add_css_class("lock-screen")
        lock_view = Adw.ToolbarView(content=self.lock_page)
        lock_view.add_top_bar(Adw.HeaderBar(show_title=False))
        self.root_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.root_stack.add_named(self.toasts, "main")
        self.root_stack.add_named(lock_view, "locked")
        self.set_content(self.root_stack)
        self.idle = IdleTimer(lambda: settings.get_uint("lock-idle-minutes"), self.lock)
        self.lock_available = authorizer is not None

        # ---- adaptive breakpoints
        wide = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 860sp"))
        # add_setter takes the property value positionally; there is no keyword form.
        wide.add_setter(self.outer, "collapsed", True)  # noqa: FBT003
        narrow = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 560sp"))
        narrow.add_setter(self.outer, "collapsed", True)  # noqa: FBT003
        narrow.add_setter(self.inner, "collapsed", True)  # noqa: FBT003
        self.add_breakpoint(wide)
        self.add_breakpoint(narrow)

        self._install_actions(order)
        self._install_bubble_shortcuts()
        self._track_activity()

        # ---- wiring
        self.sidebar.connect("section-selected", lambda *_a: self._on_section())
        self.list_page.connect("item-selected", lambda *_a: self._on_item_selected())
        self.detail.connect("mode-changed", lambda *_a: self._update_action_state())
        self.list_page.connect("trash-selected", lambda *_a: self._on_trash_selected())
        self.list_page.connect(
            "sort-changed",
            lambda *_a: settings.set_string("sort-order", self.list_page.sort_order.value),
        )
        type_anywhere = Gtk.EventControllerKey(propagation_phase=Gtk.PropagationPhase.BUBBLE)
        type_anywhere.connect("key-pressed", self._on_type_anywhere)
        self.add_controller(type_anywhere)
        search_keys = Gtk.EventControllerKey()
        search_keys.connect("key-pressed", self._on_search_key)
        self.list_page.search.add_controller(search_keys)
        vault.connect("status-changed", lambda *_a: self._on_status())
        vault.connect("items-changed", lambda *_a: self._on_items_changed())
        vault.connect("trash-changed", lambda *_a: self._update_counts())
        vault.connect("report-changed", lambda *_a: self._on_report())
        vault.connect("failed", self._on_failed)
        settings.connect("changed::hibp-enabled", lambda *_a: self._on_hibp_changed())
        settings.connect("changed::lock-enabled", lambda *_a: self._apply_lock_setting())
        settings.connect("changed::favicons-enabled", lambda *_a: self._on_favicons_changed())
        vault.hibp_enabled = settings.get_boolean("hibp-enabled")
        self.connect("close-request", self._on_close)
        self._apply_lock_setting()
        self._on_status()
        # A window opened after the first load starts from the vault's snapshot.
        self.sidebar.set_groups(vault.groups())
        self._update_counts()

    # ---------------------------------------------------------------- actions
    def _install_actions(self, order: SortOrder) -> None:
        simple: dict[str, Callable[[], None]] = {
            "new-password": self.new_password,
            "search": self.focus_search,
            "sync-now": self.sync_now,
            "copy-password": self.copy_password,
            "copy-username": self.copy_username,
            "copy-code": self.copy_code,
            "reveal": self.detail.toggle_reveal,
            "edit": self.edit,
            "save-edit": self.detail.save_edit,
            "cancel-edit": self.cancel_edit,
            "delete": self.delete_selected,
            "undo": self.undo_delete,
            "review-pause": self.review_pause,
            "sign-in": self.show_sign_in,
            "retry": self.retry,
            "show-detail": self.show_detail,
        }
        for name, callback in simple.items():
            action = Gio.SimpleAction.new(name, None)
            on_activate(action, callback)
            self.add_action(action)
        section = Gio.SimpleAction.new("section", GLib.VariantType.new("s"))
        section.connect("activate", self._on_section_action)
        self.add_action(section)
        sort = Gio.SimpleAction.new_stateful(
            "sort-order", GLib.VariantType.new("s"), GLib.Variant("s", order.value)
        )
        sort.connect("activate", self._on_sort_action)
        self.add_action(sort)
        self._sort_action = sort
        self._update_action_state()

    def _on_sort_action(self, action: Gio.SimpleAction, param: GLib.Variant) -> None:
        action.set_state(param)
        self.list_page.set_sort(SortOrder(param.get_string()))

    def _install_bubble_shortcuts(self) -> None:
        """Ctrl+C, Delete, Ctrl+Z, Escape: only when the focused widget did not use them."""
        controller = Gtk.ShortcutController(propagation_phase=Gtk.PropagationPhase.BUBBLE)
        for entry in shortcuts():
            if not entry.bubble:
                continue
            for accel in entry.accels:
                controller.add_shortcut(
                    Gtk.Shortcut.new(
                        Gtk.ShortcutTrigger.parse_string(accel),
                        Gtk.NamedAction.new(entry.action),
                    )
                )
        self.add_controller(controller)

    def _action(self, name: str) -> Gio.SimpleAction:
        return cast("Gio.SimpleAction", self.lookup_action(name))

    def _update_action_state(self) -> None:
        item = self.selected_item()
        has_item = (
            item is not None and self.list_page.section.kind is not Kind.DELETED and not self.locked
        )
        editing = self.detail.editing
        for name in ("copy-password", "copy-username", "delete", "reveal"):
            self._action(name).set_enabled(has_item and not editing)
        self._action("copy-code").set_enabled(has_item and bool(item and item.has_code))
        self._action("edit").set_enabled(has_item and not editing)
        self._action("save-edit").set_enabled(editing)
        self._action("cancel-edit").set_enabled(editing)
        self._action("undo").set_enabled(self.last_deleted is not None)

    # ---------------------------------------------------------------- activity / lock
    def _track_activity(self) -> None:
        for controller in (
            Gtk.EventControllerKey(),
            Gtk.EventControllerMotion(),
            Gtk.GestureClick(),
        ):
            controller.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
            if isinstance(controller, Gtk.EventControllerKey):
                controller.connect("key-pressed", self._poke_key)
            elif isinstance(controller, Gtk.EventControllerMotion):
                controller.connect("motion", lambda *_a: self.idle.poke())
            else:
                controller.connect("pressed", lambda *_a: self.idle.poke())
            self.add_controller(controller)

    def _poke_key(self, *_args: object) -> bool:
        self.idle.poke()
        return False  # observe only; the key still reaches its widget

    def set_authorizer(self, authorizer: Authorizer | None) -> None:
        """Late-bind the unlock authorizer once polkit has answered the availability probe."""
        self._authorizer = authorizer
        self.lock_available = authorizer is not None
        self._apply_lock_setting()

    def set_fingerprint_available(self, *, available: bool) -> None:
        """Late-bind whether the unlock dialog can offer a fingerprint (reader, enrolled finger)."""
        if available == self.fingerprint_available:
            return  # keeps "Not unlocked. Try again." on screen when the answer changes nothing
        self.fingerprint_available = available
        self.lock_page.set_description(unlock_hint(fingerprint=available))

    def _apply_lock_setting(self) -> None:
        if self.lock_available and self.settings.get_boolean("lock-enabled"):
            self.idle.arm()
        else:
            self.idle.disarm()

    @property
    def locked(self) -> bool:
        return self.root_stack.get_visible_child_name() == "locked"

    def lock(self) -> None:
        """Hide everything and forget the shown password until polkit says otherwise."""
        if not self.lock_available:
            return
        self.cancel_edit()
        # Dialogs float above the content stack; a New Password form shows its password.
        while (dialog := self.get_visible_dialog()) is not None:
            dialog.force_close()
        self.detail.show_item(None)
        self.root_stack.set_visible_child_name("locked")
        self.idle.disarm()
        self._update_action_state()

    def unlock(self) -> None:
        if self._authorizer is None:
            return

        def done(authorized: bool) -> None:  # noqa: FBT001
            if not authorized:
                self.lock_page.set_description(_("Not unlocked. Try again."))
                return
            self.lock_page.set_description(unlock_hint(fingerprint=self.fingerprint_available))
            self.root_stack.set_visible_child_name("main")
            self._on_item_selected()
            self._apply_lock_setting()

        self._authorizer(done)

    # ---------------------------------------------------------------- host API (detail pane)
    def copy_text(self, text: str, what: Copied, *, sensitive: bool) -> None:
        if self.locked:  # also covers replies that arrive after the window locked
            return
        self.toast(copied_text(what, self.clipboard.copy(text, sensitive=sensitive)))

    def toast(self, message: str, *, undo: bool = False) -> Adw.Toast:
        toast = Adw.Toast(title=GLib.markup_escape_text(message), timeout=5)
        if undo:
            toast.set_button_label(_("Undo"))
            toast.set_action_name("win.undo")
            toast.set_priority(Adw.ToastPriority.HIGH)
        self.toasts.add_toast(toast)
        self.last_toast = toast
        return toast

    def open_uri(self, uri: str) -> None:
        def launched(launcher: Gtk.UriLauncher, result: Gio.AsyncResult) -> None:
            try:
                launcher.launch_finish(result)
            except GLib.Error as err:
                self.toast(err.message or _("Could not open the website"))

        Gtk.UriLauncher.new(uri).launch(self, None, launched)

    def delete_item(self, item_id: str) -> None:
        obj = self.vault.find(item_id)
        if obj is None:
            return
        item = obj.item

        def done(result: DaemonError | None) -> None:
            if isinstance(result, DaemonError):
                self.toast(result.message)
                return
            self.last_deleted = item
            self._update_action_state()
            self.toast(_("Deleted “{title}”").format(title=item.display_title), undo=True)
            self.vault.schedule_reload()

        self.vault.client.delete(item_id, done)

    def saved(self, item_id: str) -> None:
        self.pending_select = item_id
        self.toast(_("Saved"))
        self.vault.schedule_reload()

    def restore_entry(self, trash_id: str) -> None:
        def done(result: str | DaemonError) -> None:
            if isinstance(result, DaemonError):
                self.toast(result.message)
                return
            self.toast(_("Restored"))
            self.vault.schedule_reload()
            self.detail.show_trash(None)

        self.vault.client.restore(trash_id, done)

    def purge_entry(self, trash_id: str) -> None:
        dialog = Adw.AlertDialog(
            heading=_("Delete Permanently?"),
            body=_("This password will be deleted from this computer and cannot be restored."),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("purge", _("Delete Now"))
        dialog.set_response_appearance("purge", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def chosen(_d: Adw.AlertDialog, response: str) -> None:
            if response != "purge":
                return

            def done(result: DaemonError | None) -> None:
                if isinstance(result, DaemonError):
                    self.toast(result.message)
                    return
                self.toast(_("Deleted permanently"))
                self.detail.show_trash(None)
                self.vault.schedule_reload()

            self.vault.client.purge(trash_id, done)

        dialog.connect("response", chosen)
        self.purge_dialog = dialog
        dialog.present(self)

    # ---------------------------------------------------------------- commands
    def selected_item(self) -> Item | None:
        obj = self.list_page.selected_item()
        return obj.item if obj is not None else None

    def _with_full_item(self, use: Callable[[Item], None]) -> None:
        item = self.selected_item()
        if item is None or self.locked:  # a locked window fetches no secrets
            return
        shown = self.detail.item
        if shown is not None and shown.id == item.id and shown.password is not None:
            use(shown)
            return

        def got(result: Item | DaemonError) -> None:
            if isinstance(result, DaemonError):
                self.toast(result.message)
                return
            use(result)

        self.vault.client.get(item.id, got)

    def copy_password(self) -> None:
        self._with_full_item(
            lambda item: self.copy_text(item.password or "", Copied.PASSWORD, sensitive=True)
        )

    def copy_username(self) -> None:
        item = self.selected_item()
        if item is not None:
            self.copy_text(item.username, Copied.USERNAME, sensitive=False)

    def copy_code(self) -> None:
        item = self.selected_item()
        if item is None or not item.has_code or self.locked:
            return

        def done(result: tuple[str, int] | DaemonError) -> None:
            if isinstance(result, DaemonError):
                self.toast(result.message)
                return
            self.copy_text(result[0], Copied.CODE, sensitive=True)

        self.vault.client.get_code(item.id, done)

    def reveal_and_copy(self, item_id: str, notify: Callable[[str, int], None]) -> None:
        """Show `item_id` and copy its password (GNOME Shell search result activated).

        While locked nothing is fetched or copied; the user sees the lock screen.
        """
        if self.locked:
            return
        self.sidebar.select(sections.ALL)
        self.list_page.search.set_text("")
        if not self.list_page.select_id(item_id):
            self.pending_select = item_id

        def copy(item: Item) -> None:
            if self.locked:  # locked while the reply or the focus was pending
                return
            delay = self.clipboard.copy(item.password or "", sensitive=True)
            self.toast(copied_text(Copied.PASSWORD, delay))
            notify(item.display_title, delay)

        def got(result: Item | DaemonError) -> None:
            if isinstance(result, DaemonError):
                self.toast(result.message)
                return
            self.when_active(lambda: copy(result))

        self.vault.client.get(item_id, got)

    def when_active(self, run: Callable[[], None], timeout_ms: int = 2000) -> None:
        """Run once the window has keyboard focus (or after `timeout_ms`).

        Wayland compositors only accept clipboard changes from the focused client, and a
        Shell search result activates us while the overview is still closing.
        """
        if self.is_active():
            run()
            return
        state = {"done": False}

        def fire(*_args: object) -> bool:
            if not state["done"]:
                state["done"] = True
                self.disconnect(handler)
                run()
            return GLib.SOURCE_REMOVE

        handler = self.connect("notify::is-active", lambda *_a: self.is_active() and fire())
        GLib.timeout_add(timeout_ms, fire)

    def edit(self) -> None:
        if self.selected_item() is None:
            return
        self.show_detail()
        self.detail.enter_edit()
        self._update_action_state()

    def cancel_edit(self) -> None:
        if self.detail.editing:
            self.detail.leave_edit()
            self._update_action_state()

    def delete_selected(self) -> None:
        item = self.selected_item()
        if item is not None and not self.detail.editing and not self.locked:
            self.delete_item(item.id)

    def undo_delete(self) -> None:
        item = self.last_deleted
        if item is None:
            return
        self.last_deleted = None
        self._update_action_state()

        def listed(result: list[TrashEntry] | DaemonError) -> None:
            if isinstance(result, DaemonError):
                self.toast(result.message)
                return
            entries = [e for e in result if e.item.id == item.id]
            if not entries:
                return
            newest = max(entries, key=lambda e: e.deleted_at)

            def restored(reply: str | DaemonError) -> None:
                if isinstance(reply, DaemonError):
                    self.toast(reply.message)
                    return
                self.pending_select = reply
                self.vault.schedule_reload()

            self.vault.client.restore(newest.trash_id, restored)

        self.vault.client.list_trash(listed)

    def new_password(self) -> None:
        if self.locked:
            return
        group = self.list_page.section.group if self.list_page.section.kind is Kind.GROUP else ""
        dialog = NewPasswordDialog(self.vault.client, self.settings, self._created, group=group)
        self.new_dialog = dialog
        dialog.present(self)

    def _created(self, item_id: str) -> None:
        self.toast(_("Password saved"))
        if self.list_page.section.kind in {Kind.DELETED, Kind.SECURITY, Kind.CODES}:
            self.sidebar.select(sections.ALL)
        self.pending_select = item_id
        self.vault.schedule_reload()

    def focus_search(self) -> None:
        if self.outer.get_collapsed():
            self.outer.set_show_content(True)
        if self.inner.get_collapsed():
            self.inner.set_show_content(False)
        self.list_page.search.grab_focus()
        self.list_page.search.select_region(0, -1)

    def sync_now(self) -> None:
        def done(result: DaemonError | None) -> None:
            if isinstance(result, DaemonError):
                if result.kind is ErrorKind.AUTH_REQUIRED:
                    self.show_sign_in()
                else:
                    self.toast(result.message)

        self.vault.client.sync_now(done)

    def retry(self) -> None:
        self.vault.refresh_status()
        self.vault.reload()

    def show_detail(self) -> None:
        if self.inner.get_collapsed():
            self.inner.set_show_content(True)

    def select_section_name(self, name: str) -> None:
        section = _SECTION_NAMES.get(name)
        if section is not None:
            self.sidebar.select(section)

    def _on_section_action(self, _action: Gio.SimpleAction, param: GLib.Variant) -> None:
        self.select_section_name(param.get_string())

    # ---------------------------------------------------------------- pause / sign-in
    def review_pause(self) -> None:
        status = self.vault.status
        dialog = Adw.AlertDialog(
            heading=formatting.pause_title(status),
            body=_(
                "So many deletions at once may be a mistake, so nothing was deleted yet. "
                "Apply the deletions everywhere, or restore these passwords on both sides."
            ),
        )
        dialog.add_response("cancel", _("Decide Later"))
        dialog.add_response("restore", _("Restore Them"))
        dialog.add_response("apply", _("Apply Deletions"))
        dialog.set_response_appearance("restore", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_response_appearance("apply", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("restore")
        dialog.set_close_response("cancel")
        dialog.connect("response", self._on_pause_response)
        self.pause_dialog = dialog
        dialog.present(self)

    def _on_pause_response(self, _dialog: Adw.AlertDialog, response: str) -> None:
        if response not in {"apply", "restore"}:
            return
        apply = response == "apply"

        def done(result: DaemonError | None) -> None:
            if isinstance(result, DaemonError):
                self.toast(result.message)
                return
            self.toast(_("Deletions applied") if apply else _("Passwords restored"))
            self.vault.schedule_reload()

        self.vault.client.resolve_pause(apply=apply, done=done)

    def show_sign_in(self) -> None:
        if self.sign_in_dialog is not None:
            self.sign_in_dialog.present(self)
            return
        dialog = SignInDialog(
            self.vault.client,
            apple_id=self.vault.status.apple_id,
            join_pending=self.vault.status.join_pending,
            on_done=self._signed_in,
        )
        dialog.connect("closed", lambda *_a: setattr(self, "sign_in_dialog", None))
        self.sign_in_dialog = dialog
        dialog.present(self)

    def _signed_in(self) -> None:
        self.toast(_("Signed in. Syncing…"))
        self.vault.refresh_status()
        self.sync_now()

    # ---------------------------------------------------------------- vault events
    def _on_status(self) -> None:
        status = self.vault.status
        self.status_button.show_status(status, self.vault.count_refused())
        paused = status.state is SyncState.PAUSED
        self.list_page.pause_banner.set_title(formatting.pause_title(status))
        self.list_page.pause_banner.set_revealed(paused)
        self.list_page.signin_banner.set_revealed(
            status.state in {SyncState.SIGNIN_REQUIRED, SyncState.SIGNED_OUT}
        )
        self.list_page.unreachable_banner.set_revealed(status.state is SyncState.UNREACHABLE)
        self._action("sync-now").set_enabled(
            status.state in {SyncState.IDLE, SyncState.OFFLINE, SyncState.ERROR}
        )

    def _on_items_changed(self) -> None:
        # The list page already re-filtered itself from the store's items-changed.
        self.sidebar.set_groups(self.vault.groups())
        self._update_counts()
        # Refusals arrive as ItemsChanged: the header's "Synced" depends on them too.
        self.status_button.show_status(self.vault.status, self.vault.count_refused())
        shown = self.detail.item
        target = self.pending_select or (shown.id if shown is not None else None)
        self.pending_select = None
        if target and self.list_page.select_id(target):
            self._refresh_if_stale(target, shown)
            return
        if self.selected_item() is None and self.list_page.section.kind is not Kind.DELETED:
            self.detail.show_item(None)

    def _refresh_if_stale(self, target: str, shown: Item | None) -> None:
        """Reload the detail when the selected item changed elsewhere or iCloud's verdict did."""
        obj = self.vault.find(target)
        stale = (
            shown is not None
            and obj is not None
            and (obj.item.modified, obj.item.sync_problem) != (shown.modified, shown.sync_problem)
        )
        if stale and not self.detail.editing:
            self.detail.show_item(target)

    def _on_failed(self, _vault: Vault, message: str) -> None:
        if message:
            self.toast(message)

    def _on_report(self) -> None:
        self._update_counts()
        if self.list_page.section.kind is Kind.SECURITY:
            self.list_page.refilter()
        self.detail.refresh_warnings()

    def _update_counts(self) -> None:
        vault = self.vault
        counts: dict[Section, int] = {
            sections.ALL: vault.items.get_n_items(),
            sections.CODES: vault.count_codes(),
            sections.SECURITY: len(vault.report.flagged),
            sections.DELETED: vault.trash.get_n_items(),
        }
        for group in vault.groups():
            counts[Section(Kind.GROUP, group)] = vault.count_group(group)
        self.sidebar.set_counts(counts)

    def _on_favicons_changed(self) -> None:
        self.list_page.rebind()
        if self.detail.item is not None:
            if self.settings.get_boolean("favicons-enabled"):
                self.detail.load_icon()
            else:
                self.detail.tile.set_icon(None)

    def _on_hibp_changed(self) -> None:
        self.vault.hibp_enabled = self.settings.get_boolean("hibp-enabled")
        self.vault.schedule_scan()

    # ---------------------------------------------------------------- selection
    def _on_section(self) -> None:
        section = self.sidebar.selected
        self.cancel_edit()
        self.list_page.set_section(section)
        if self.outer.get_collapsed():
            self.outer.set_show_content(True)
        if section.kind is Kind.DELETED:
            self.detail.show_trash(None)
        else:
            self.detail.show_item(None)
        self._update_action_state()

    def _on_item_selected(self) -> None:
        obj = self.list_page.selected_item()
        self.detail.show_item(obj.item.id if obj is not None else None)
        self._update_action_state()

    def _on_trash_selected(self) -> None:
        obj = self.list_page.selected_trash()
        self.detail.show_trash(obj.entry if obj is not None else None)
        self._update_action_state()

    def _on_type_anywhere(
        self,
        _controller: Gtk.EventControllerKey,
        keyval: int,
        _code: int,
        state: Gdk.ModifierType,
    ) -> bool:
        """Printable keys nobody handled start a search, like Apple's type-to-find.

        Only plain characters are taken: Escape, Delete and shortcuts keep their meaning, and
        nothing is taken while a text field or a dialog has the focus.
        """
        if state & (Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.ALT_MASK):
            return False
        char = chr(Gdk.keyval_to_unicode(keyval) or 0)
        if not char.isprintable() or char.isspace():
            return False
        if _is_editable(self.get_focus()) or self.get_visible_dialog() is not None:
            return False
        if self.locked or self.detail.editing:
            return False
        self.focus_search()
        search = self.list_page.search
        search.set_text(search.get_text() + char)
        search.set_position(-1)
        return True

    def _on_search_key(
        self,
        _controller: Gtk.EventControllerKey,
        keyval: int,
        _code: int,
        _state: Gdk.ModifierType,
    ) -> bool:
        if keyval == Gdk.KEY_Down:
            self.list_page.select_position(0)
            self.list_page.focus_list()
            return True
        return False

    def _on_close(self, _window: Gtk.Window) -> bool:
        width, height = self.get_default_size()
        self.settings.set_int("window-width", width)
        self.settings.set_int("window-height", height)
        self.settings.set_boolean("window-maximized", self.is_maximized())
        self.detail.show_item(None)
        self.favicons.close()
        return False
