# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The app's live view of the daemon: items, deleted items, sync status, security report.

It owns the `Gio.ListStore`s the list views render, reloads them when the daemon signals a
change (coalescing bursts into one reload), and keeps no passwords around: the security scan
fetches each password, scores it in a worker thread, and keeps only the verdicts.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, ClassVar

from gi.repository import Gio, GLib, GObject

from passwords_app.app import monogram
from passwords_app.app.client import DaemonClient, DaemonError, ErrorKind
from passwords_app.app.i18n import _
from passwords_app.app.records import Item, Status, SyncState, TrashEntry
from passwords_app.app.search import haystack
from passwords_app.app.security import HibpClient, Issue, Report, analyze
from passwords_app.app.sorting import SortKey, SortOrder, sort_key

if TYPE_CHECKING:
    from collections.abc import Callable

_RELOAD_DELAY_MS = 50
_SCAN_DELAY_MS = 400
_SCAN_CONCURRENCY = 8


class ItemObject(GObject.Object):
    """List-model wrapper; caches what filtering and sorting need per keystroke."""

    __gtype_name__ = "PasswordsItemObject"

    def __init__(self, item: Item) -> None:
        super().__init__()
        self.item = item
        self.hay = haystack(item)
        # Rows re-bind on every keystroke that changes the visible set; parse URLs once here.
        self.host = item.host
        self.letter = monogram.letter(item)
        self.tint = f"tint-{monogram.color_index(monogram.site_key(item))}"
        self._keys: dict[SortOrder, SortKey] = {}
        self.issues: frozenset[Issue] = frozenset()

    def key(self, order: SortOrder) -> SortKey:
        cached = self._keys.get(order)
        if cached is None:
            cached = self._keys[order] = sort_key(self.item, order)
        return cached


class TrashObject(GObject.Object):
    __gtype_name__ = "PasswordsTrashObject"

    def __init__(self, entry: TrashEntry) -> None:
        super().__init__()
        self.entry = entry
        self.hay = haystack(entry.item)


class Vault(GObject.Object):
    __gtype_name__ = "PasswordsVault"
    __gsignals__: ClassVar[dict[str, tuple[GObject.SignalFlags, None, tuple[type, ...]]]] = {
        "status-changed": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "items-changed": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "trash-changed": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "report-changed": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "failed": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
    }

    def __init__(
        self,
        client: DaemonClient,
        *,
        hibp: Callable[[], HibpClient] | None = None,
    ) -> None:
        super().__init__()
        self.client = client
        self.items: Gio.ListStore[ItemObject] = Gio.ListStore(item_type=ItemObject)
        self.trash: Gio.ListStore[TrashObject] = Gio.ListStore(item_type=TrashObject)
        self.status = Status(state=SyncState.SYNCING)
        self.report = Report()
        self.loaded = False
        self.hibp_enabled = False
        self._hibp_factory = hibp or HibpClient
        self._by_id: dict[str, ItemObject] = {}
        # Items the reload that last emitted items-changed found changed: named by the
        # daemon, or listed differently. A password edit changes nothing the list shows,
        # and iCloud stamps whole seconds, so the daemon's names are the only sure sign.
        self.changed_ids: frozenset[str] = frozenset()
        self._announced: set[str] = set()
        self._reload_source = 0
        self._reload_items = False
        self._trash_loaded = False
        self._scan_source = 0
        self._scan_generation = 0
        self.scanning = False
        self._seen_daemon = False

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        self.client.subscribe(self._on_status_signal, self._on_items_signal)
        self.client.watch(self._on_daemon_appeared, self._on_daemon_vanished)
        self.refresh_status()
        self.reload()

    def stop(self) -> None:
        for source in (self._reload_source, self._scan_source):
            if source:
                GLib.source_remove(source)
        self._reload_source = self._scan_source = 0
        self._scan_generation += 1
        self.client.close()

    # ---------------------------------------------------------------- lookups
    def find(self, item_id: str) -> ItemObject | None:
        return self._by_id.get(item_id)

    def position_of(self, item_id: str) -> int | None:
        obj = self._by_id.get(item_id)
        if obj is None:
            return None
        found, position = self.items.find(obj)
        return position if found else None

    def groups(self) -> list[str]:
        return sorted(
            {o.item.group for o in self._by_id.values() if o.item.group}, key=str.casefold
        )

    def count_codes(self) -> int:
        return sum(1 for o in self._by_id.values() if o.item.has_code)

    def count_group(self, group: str) -> int:
        return sum(1 for o in self._by_id.values() if o.item.group == group)

    def count_refused(self) -> int:
        """Passwords iCloud refuses to store, which stay on this computer only."""
        return sum(1 for o in self._by_id.values() if o.item.sync_problem)

    # ---------------------------------------------------------------- loading
    def schedule_reload(self, *, items: bool = True) -> None:
        """Coalesce bursts of ItemsChanged (a sync cycle may emit many) into one reload.

        The trash is always reloaded; `items=False` leaves the live list alone.
        """
        self._reload_items = self._reload_items or items
        if not self._reload_source:
            self._reload_source = GLib.timeout_add(_RELOAD_DELAY_MS, self._reload_now)

    def _reload_now(self) -> bool:
        self._reload_source = 0
        if self._reload_items:
            self._list_items()
        self._reload_items = False
        self.client.list_trash(self._on_trash)
        return GLib.SOURCE_REMOVE

    def reload(self) -> None:
        self._list_items()
        self.client.list_trash(self._on_trash)

    def _list_items(self) -> None:
        # A name announced after this request left may be missing from its reply; it stays
        # for the reload that announcement scheduled.
        announced, self._announced = frozenset(self._announced), set()

        def listed(result: list[Item] | DaemonError) -> None:
            self._on_items(result, announced)

        self.client.list_items(listed)

    def refresh_status(self) -> None:
        self.client.get_status(self._on_status)

    def _on_items(self, result: list[Item] | DaemonError, announced: frozenset[str]) -> None:
        if isinstance(result, DaemonError):
            self._announced |= announced
            self._fail(result)
            return
        previous = self._by_id
        objects: list[ItemObject] = []
        changed = set(announced)
        for item in result:
            old = previous.get(item.id)
            if old is not None and old.item == item:
                objects.append(old)  # unchanged: keep the object, its caches and verdicts
            else:
                changed.add(item.id)
                obj = ItemObject(item)
                if old is not None:
                    obj.issues = old.issues
                objects.append(obj)
        self._by_id = {o.item.id: o for o in objects}
        self.changed_ids = frozenset(changed)
        # Before the splice: the store's items-changed is what the list page redraws from,
        # and it must already see the vault loaded or it stays on the spinner.
        self.loaded = True
        self.items.splice(0, self.items.get_n_items(), objects)
        self.emit("items-changed")
        self.schedule_scan()

    def _on_trash(self, result: list[TrashEntry] | DaemonError) -> None:
        if isinstance(result, DaemonError):
            self._fail(result)
            return
        ordered = sorted(result, key=lambda e: e.deleted_at, reverse=True)
        self._trash_loaded = True
        self.trash.splice(0, self.trash.get_n_items(), [TrashObject(e) for e in ordered])
        self.emit("trash-changed")

    def _on_status(self, result: Status | DaemonError) -> None:
        if isinstance(result, DaemonError):
            if result.kind is ErrorKind.UNREACHABLE:
                self._set_status(Status(state=SyncState.UNREACHABLE))
            return
        self._set_status(result)

    def _set_status(self, status: Status) -> None:
        self.status = status
        self.emit("status-changed")

    def _on_status_signal(self, status: Status) -> None:
        self._set_status(status)
        # Retention purges in a sync cycle change no live item, so no ItemsChanged names
        # them: the lower trash count is their only announcement.
        if self._trash_loaded and status.trash_count != self.trash.get_n_items():
            self.schedule_reload(items=False)

    def _on_items_signal(self, ids: list[str]) -> None:
        self._announced.update(ids)
        self.schedule_reload()

    def _on_daemon_appeared(self) -> None:
        if not self._seen_daemon:
            # The watch reports an already running daemon right away; start() loaded it.
            self._seen_daemon = True
            return
        self.refresh_status()
        self.schedule_reload()

    def _on_daemon_vanished(self) -> None:
        self._seen_daemon = True
        # D-Bus activation restarts the daemon on the next call; until then say so plainly.
        self._set_status(Status(state=SyncState.UNREACHABLE))

    def _fail(self, error: DaemonError) -> None:
        if error.kind is ErrorKind.UNREACHABLE:
            self._set_status(Status(state=SyncState.UNREACHABLE))
            return
        self.emit("failed", error.message)

    # ---------------------------------------------------------------- security scan
    def schedule_scan(self) -> None:
        self.scanning = True
        if self._scan_source:
            GLib.source_remove(self._scan_source)
        self._scan_source = GLib.timeout_add(_SCAN_DELAY_MS, self._scan_now)

    def _scan_now(self) -> bool:
        self._scan_source = 0
        self.scan()
        return GLib.SOURCE_REMOVE

    def scan(self) -> None:
        """Fetch every password, analyze off the main thread, publish verdicts only."""
        self._scan_generation += 1
        generation = self._scan_generation
        ids = list(self._by_id)
        fetched: list[Item] = []
        pending = list(reversed(ids))
        in_flight = 0
        self.scanning = True

        def fetch_next() -> None:
            nonlocal in_flight
            while pending and in_flight < _SCAN_CONCURRENCY:
                in_flight += 1
                self.client.get(pending.pop(), got)
            if not pending and in_flight == 0:
                self._analyze(generation, fetched)

        def got(result: Item | DaemonError) -> None:
            nonlocal in_flight
            in_flight -= 1
            if generation != self._scan_generation:
                return
            if not isinstance(result, DaemonError):
                fetched.append(result)
            fetch_next()

        fetch_next()

    def _analyze(self, generation: int, fetched: list[Item]) -> None:
        use_hibp = self.hibp_enabled
        factory = self._hibp_factory

        def work() -> None:
            compromised: set[str] = set()
            hibp_failed = False
            if use_hibp:
                try:
                    compromised = factory().compromised({i.id: i.password or "" for i in fetched})
                except Exception:  # noqa: BLE001 - any network failure only skips this check
                    hibp_failed = True
            report = analyze(fetched, compromised)
            fetched.clear()  # drop the passwords as soon as they are scored
            GLib.idle_add(self._publish, generation, report, hibp_failed)

        threading.Thread(target=work, name="security-scan", daemon=True).start()

    def _publish(self, generation: int, report: Report, hibp_failed: bool) -> bool:  # noqa: FBT001
        if generation != self._scan_generation:
            return GLib.SOURCE_REMOVE
        self.report = report
        for item_id, obj in self._by_id.items():
            obj.issues = report.of(item_id)
        self.scanning = False
        self.emit("report-changed")
        if hibp_failed:
            self.emit("failed", _("Could not check passwords against known data leaks"))
        return GLib.SOURCE_REMOVE
