# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`LocalStore` backed by the Secret Service collection "iCloud Passwords" (gnome-keyring).

Safety rule from `sync.ports`: the engine reads "missing" as "deleted", so this store
either returns the complete collection or raises `LocalUnavailable` — locked, gone,
service down, a secret that did not come back, an item that vanished mid-read, or an
adopted item whose new id could not be written back (reporting it anyway would hand out a
different id on every fetch and duplicate it in iCloud). Items that are readable but cannot
become a `Credential` are reported in `LocalSnapshot.rejected`, never dropped silently.
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, Self, cast

from dbus_fast import Message, MessageType

from passwords_app.keyring.client import (
    BUS_NAME,
    COLLECTION,
    ITEM,
    SecretServiceClient,
    SecretServiceError,
    object_id,
)
from passwords_app.keyring.collection import (
    CollectionUnavailableError,
    ensure_collection,
    ensure_unlocked,
)
from passwords_app.keyring.mapping import (
    ID_ATTRIBUTE,
    ItemRejectedError,
    ReadItem,
    StoredItem,
    item_content,
    needs_created,
    read_item,
)
from passwords_app.store.state import StateCorruptedError
from passwords_app.sync.ports import (
    ConflictError,
    LocalSnapshot,
    LocalUnavailable,
    RejectedLocalItem,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Iterable

    from dbus_fast.aio import MessageBus

    from passwords_app.core.model import Credential

DEFAULT_LABEL = "iCloud Passwords"
_CHANGE_SIGNALS = frozenset({"ItemCreated", "ItemChanged", "ItemDeleted"})
_DUPLICATE_ID = "another item in the collection already has this id"
_HASHED_ATTRIBUTE = "gkr:compat:hashed:"
# Matches the spec's "2 s after any local change".
FILE_POLL_SECONDS = 2.0
# Pipelined property reads make a large fetch fast, but buses cap pending replies per
# connection (dbus-daemon's built-in default is 128), so keep well under that.
MAX_IN_FLIGHT = 64
_ADOPTION_NAMESPACE = uuid.UUID("6f1d2c4e-8b3a-5e7f-9a01-3c5d7e9f1b24")
# Where the properties a fetch read are kept across restarts (see `SealedKeyValue`).
SAVED_PROPERTIES_KEY = "keyring-properties"
_SAVED_VERSION = 1

type _ReadProperty = Callable[[str, str], Awaitable[Any]]


@dataclass(frozen=True, slots=True)
class _Properties:
    """An item's properties as one fetch read them (unix seconds, see `StoredItem`)."""

    label: str
    attributes: dict[str, str]
    created: int | None
    modified: int


class SealedKeyValue(Protocol):
    """Encrypted key-value storage, i.e. state.db's `kv` table (`StateStore.get`/`set`).

    The saved properties are not secret, but attributes carry usernames and URLs, so they
    must only ever be stored sealed.
    """

    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str) -> None: ...


def _adoption_id(item: StoredItem) -> str:
    # Derived, not random: two fetches racing to adopt the same item (e.g. daemon and app)
    # must agree on its id, or one snapshot's id is overwritten by the other's write-back.
    return str(uuid.uuid5(_ADOPTION_NAMESPACE, f"{item.ref}\n{item.created}")).upper()


class SecretServiceStore:
    __slots__ = ("_client", "_collection", "_io", "_known", "_known_since", "_label", "_saved")

    def __init__(
        self,
        client: SecretServiceClient,
        collection: str,
        label: str,
        *,
        saved: SealedKeyValue | None = None,
    ) -> None:
        self._client = client
        self._collection = collection
        self._label = label
        # An item update is several D-Bus calls (secret, attributes, label); a fetch
        # interleaved with one could pair a new password with the old account. Writers
        # in other processes (Seahorse) cannot be excluded: their torn edit converges on
        # the next fetch, which `changes()` triggers.
        self._io = asyncio.Lock()
        # Properties earlier fetches read, by item path, reused while the item's Modified
        # stands still (see `_read_all`); `_known_since` is when the last fetch began.
        # With `saved`, they outlive the process: a restarted daemon's first fetch is then
        # as cheap as a repeat fetch, and only a never-seen collection is read in full.
        self._saved = saved
        self._known, self._known_since = _load_saved(saved)

    @classmethod
    async def open(
        cls, bus: MessageBus, *, label: str = DEFAULT_LABEL, saved: SealedKeyValue | None = None
    ) -> Self:
        """Find or create the collection and unlock it, all without prompting.

        `saved` keeps what fetches read across restarts (see `SealedKeyValue`).
        """
        try:
            client = await SecretServiceClient.open(bus)
            collection = await ensure_collection(client, label)
            await ensure_unlocked(client, collection, label)
        except (SecretServiceError, CollectionUnavailableError) as exc:
            raise LocalUnavailable(str(exc)) from exc
        return cls(client, collection, label, saved=saved)

    @property
    def collection(self) -> str:
        """D-Bus object path of the synced collection."""
        return self._collection

    async def _ready(self) -> None:
        try:
            await ensure_unlocked(self._client, self._collection, self._label)
        except CollectionUnavailableError as exc:
            raise LocalUnavailable(str(exc)) from exc

    # --- fetch ------------------------------------------------------------------------

    async def fetch(self) -> LocalSnapshot:
        try:
            async with self._io:
                await self._ready()
                stored = await self._read_all()
                return await self._snapshot(stored)
        except SecretServiceError as exc:
            raise LocalUnavailable(str(exc)) from exc

    async def _read_all(self) -> list[StoredItem]:
        # gnome-keyring finds an item by scanning all of them, so every property read costs
        # O(items) and a full read of 2 000 items takes seconds. Every change to an item
        # (label, attributes, secret) sets its Modified to the current second, so an item
        # whose Modified has not moved since an earlier fetch still has the label,
        # attributes and creation time that fetch read. Modified has one-second
        # resolution: an edit in the very second a fetch began could leave it unchanged,
        # so only properties with Modified before that second are kept for reuse — any
        # later edit then moves Modified past them. Secrets are always read afresh.
        # The same holds across a restart: the cache is saved with the second its fetch
        # began whenever its content changes, so a restart under a clock set back since
        # drops it.
        began = int(time.time())
        if began < self._known_since:
            # The clock went back: Modified no longer orders edits. Forget what was read,
            # the saved copy too and before any read below can fail, or a restart once the
            # clock caught up again would trust it.
            self._remember({}, began)
        paths: list[str] = list(
            await self._client.get_property(self._collection, COLLECTION, "Items")
        )
        secrets, fresh = await asyncio.gather(
            self._client.get_secrets(paths), self._read_changed(paths)
        )
        await self._check_still_unlocked(paths, secrets, fresh.values())
        properties = {path: fresh[path] if path in fresh else self._known[path] for path in paths}
        known = {path: p for path, p in properties.items() if p.modified < began}
        if known != self._known:
            self._remember(known, began)
        self._known_since = began
        return [
            StoredItem(
                ref=path,
                label=p.label,
                attributes=p.attributes,
                secret=secrets[path],
                created=p.created,
                modified=p.modified,
            )
            for path, p in properties.items()
        ]

    def _remember(self, known: dict[str, _Properties], since: int) -> None:
        """Keep `known`, read by the fetch that began at `since`, in `saved` too if given."""
        if self._saved is not None:
            self._saved.set(SAVED_PROPERTIES_KEY, _encode_saved(known, since))
        self._known = known
        self._known_since = since

    async def _read_changed(self, paths: list[str]) -> dict[str, _Properties]:
        """Read the properties of every item that is new or whose Modified has moved."""
        client = self._client
        in_flight = asyncio.Semaphore(MAX_IN_FLIGHT)

        async def read(path: str, name: str) -> Any:  # noqa: ANN401 - D-Bus property value
            async with in_flight:
                return await client.get_property(path, ITEM, name)

        known = [path for path in paths if path in self._known]
        fresh: dict[str, _Properties]
        modified, fresh = await asyncio.gather(
            asyncio.gather(*(read(path, "Modified") for path in known)),
            _read_properties([path for path in paths if path not in self._known], read),
        )
        moved = [
            path
            for path, mtime in zip(known, modified, strict=True)
            if int(mtime) != self._known[path].modified
        ]
        fresh.update(await _read_properties(moved, read))
        return fresh

    async def _check_still_unlocked(
        self, paths: list[str], secrets: dict[str, bytes], fresh: Iterable[_Properties]
    ) -> None:
        missing = len(paths) - len(secrets)
        if missing:
            msg = f"{missing} secret(s) could not be read (collection locked meanwhile?)"
            raise LocalUnavailable(msg)
        # A locked item shows an empty label and only hashed attributes; read as-is it
        # would look like a different, unparsable item and its credential would vanish.
        hashed = any(name.startswith(_HASHED_ATTRIBUTE) for p in fresh for name in p.attributes)
        if hashed or await self._client.is_locked(self._collection):
            msg = "the collection was locked while it was being read"
            raise LocalUnavailable(msg)

    async def _snapshot(self, stored: list[StoredItem]) -> LocalSnapshot:
        items: dict[str, Credential] = {}
        rejected: list[RejectedLocalItem] = []
        unreadable: dict[str, RejectedLocalItem] = {}
        # Oldest first, so when an id is duplicated the original keeps it.
        for item in sorted(stored, key=lambda s: _creation_order(s.ref)):
            try:
                read = read_item(item, new_id=functools.partial(_adoption_id, item))
            except ItemRejectedError as exc:
                problem = RejectedLocalItem(ref=item.ref, label=item.label, reason=str(exc))
                rejected.append(problem)
                if synced_id := item.attributes.get(ID_ATTRIBUTE):
                    unreadable.setdefault(synced_id, problem)
                continue
            credential = read.credential
            if credential.id in items:
                rejected.append(
                    RejectedLocalItem(ref=item.ref, label=item.label, reason=_DUPLICATE_ID)
                )
                continue
            if read.adopted:
                await self._write_back(item.ref, read)
            items[credential.id] = credential
        # A synced item that became unreadable would be missing from `items`, which the
        # engine takes as a local delete; pause instead until the item is fixed.
        for synced_id, problem in unreadable.items():
            if synced_id not in items:
                msg = f"synced item {problem.label!r} cannot be read: {problem.reason}"
                raise LocalUnavailable(msg)
        return LocalSnapshot(items=items, rejected=tuple(rejected))

    async def _write_back(self, ref: str, read: ReadItem) -> None:
        content = item_content(read.credential, written_at=int(time.time()))
        await self._client.update_item(ref, content.label, content.attributes, None)

    # --- writes -----------------------------------------------------------------------

    async def _find(self, item_id: str) -> list[str]:
        return await self._client.search(self._collection, {ID_ATTRIBUTE: item_id})

    async def _check_unchanged(
        self, item_id: str, found: list[str], expected: str | None, *, missing_ok: bool
    ) -> None:
        """Raise `ConflictError` unless the item still has the content hash `expected`."""
        if expected is None or (not found and missing_ok):
            return
        # The item a fetch would report for this id: the oldest of any duplicates.
        current = await self._read_item(min(found, key=_creation_order)) if found else None
        if current is None or current.content_hash() != expected:
            msg = f"keyring item {item_id} changed since it was read"
            raise ConflictError(msg)

    async def _read_item(self, path: str) -> Credential | None:
        """Read one item afresh; None when it can no longer become a Credential."""
        client = self._client

        async def read(item: str, name: str) -> Any:  # noqa: ANN401 - D-Bus property value
            return await client.get_property(item, ITEM, name)

        properties, secrets = await asyncio.gather(
            _read_properties([path], read), client.get_secrets([path])
        )
        if path not in secrets:
            msg = "a secret could not be read (collection locked meanwhile?)"
            raise LocalUnavailable(msg)
        p = properties[path]
        stored = StoredItem(
            ref=path,
            label=p.label,
            attributes=p.attributes,
            secret=secrets[path],
            created=p.created,
            modified=p.modified,
        )
        try:
            return read_item(stored, new_id=functools.partial(_adoption_id, stored)).credential
        except ItemRejectedError:
            return None

    async def upsert(self, credential: Credential, *, expected: str | None = None) -> None:
        """Create or overwrite the item with this id (raises ValueError if unstorable).

        With `expected`, raises `ConflictError` instead when the item is gone or its content
        hash differs (see `LocalStore.upsert`); the check and the write share the store's
        lock, so only a writer in another process (Seahorse) can still slip in between.
        """
        item_content(credential, written_at=0)  # refuse unstorable input before any I/O
        try:
            async with self._io:
                await self._ready()
                found = await self._find(credential.id)
                await self._check_unchanged(credential.id, found, expected, missing_ok=False)
                # Stamped right before the write: waiting for the lock or an unlock must
                # not make our own write look like a later edit by someone else.
                content = item_content(credential, written_at=int(time.time()))
                if not found:
                    await self._client.create_item(
                        self._collection,
                        content.label,
                        content.attributes,
                        content.secret,
                        replace=False,
                    )
                    return
                first, *duplicates = sorted(found)
                await self._client.update_item(
                    first, content.label, content.attributes, content.secret
                )
                for extra in duplicates:
                    await self._client.delete_item(extra)
        except SecretServiceError as exc:
            raise LocalUnavailable(str(exc)) from exc

    async def delete(self, item_id: str, *, expected: str | None = None) -> None:
        """Delete every item carrying this id; deleting a missing id is a no-op.

        With `expected`, raises `ConflictError` instead when the item's content hash differs.
        """
        try:
            async with self._io:
                await self._ready()
                found = await self._find(item_id)
                await self._check_unchanged(item_id, found, expected, missing_ok=True)
                for path in found:
                    await self._client.delete_item(path)
        except SecretServiceError as exc:
            raise LocalUnavailable(str(exc)) from exc

    # --- change notifications ---------------------------------------------------------

    async def changes(self) -> AsyncIterator[None]:
        """Yield once per change to the collection's items (our own writes included).

        gnome-keyring signals ItemCreated/ItemChanged/ItemDeleted, but *not* a new secret
        (``SetSecret``, which is how Seahorse saves an edited password). That one is caught
        by watching the keyring file, which gnome-keyring rewrites on every change.
        """
        bus = self._client.bus
        queue: asyncio.Queue[None] = asyncio.Queue()
        collection = self._collection

        def on_message(message: Message) -> None:
            if (
                message.message_type == MessageType.SIGNAL
                and message.path == collection
                and message.interface == COLLECTION
                and message.member in _CHANGE_SIGNALS
            ):
                queue.put_nowait(None)

        rule = f"type='signal',sender='{BUS_NAME}',interface='{COLLECTION}',path='{collection}'"
        bus.add_message_handler(on_message)
        watcher = asyncio.create_task(_watch_file(keyring_file(collection), queue))
        try:
            await _bus_match(bus, "AddMatch", rule)
            while True:
                await queue.get()
                yield None
        finally:
            watcher.cancel()
            bus.remove_message_handler(on_message)
            if bus.connected:
                await _bus_match(bus, "RemoveMatch", rule)


def keyring_file(collection: str) -> Path:
    """Where gnome-keyring keeps a collection on disk."""
    data_home = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data_home) / "keyrings" / f"{object_id(collection)}.keyring"


def _file_state(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


async def _watch_file(path: Path, queue: asyncio.Queue[None]) -> None:
    last = _file_state(path)
    while True:
        await asyncio.sleep(FILE_POLL_SECONDS)
        current = _file_state(path)
        if current != last:
            last = current
            queue.put_nowait(None)


async def _read_properties(paths: list[str], read: _ReadProperty) -> dict[str, _Properties]:
    attributes, modified, labels = await asyncio.gather(
        asyncio.gather(*(read(path, "Attributes") for path in paths)),
        asyncio.gather(*(read(path, "Modified") for path in paths)),
        asyncio.gather(*(read(path, "Label") for path in paths)),
    )
    detailed = [
        path
        for path, attrs, mtime in zip(paths, attributes, modified, strict=True)
        if needs_created(attrs, int(mtime))
    ]
    created = await asyncio.gather(*(read(path, "Created") for path in detailed))
    created_at = {path: int(when) for path, when in zip(detailed, created, strict=True)}
    return {
        path: _Properties(
            label=str(label),
            attributes=dict(attrs),
            created=created_at.get(path),
            modified=int(mtime),
        )
        for path, attrs, mtime, label in zip(paths, attributes, modified, labels, strict=True)
    }


def _encode_saved(known: dict[str, _Properties], since: int) -> str:
    items = {path: [p.label, p.attributes, p.created, p.modified] for path, p in known.items()}
    saved = {"version": _SAVED_VERSION, "since": since, "items": items}
    return json.dumps(saved, ensure_ascii=False, separators=(",", ":"))


def _load_saved(saved: SealedKeyValue | None) -> tuple[dict[str, _Properties], int]:
    if saved is None:
        return {}, 0
    try:
        raw = saved.get(SAVED_PROPERTIES_KEY)
    except StateCorruptedError:
        # Unlike a sync base, this row only saves reads: a damaged one must not keep the
        # daemon from starting. The next fetch reads every item and seals a new row.
        raw = None
    return _decode_saved(raw)


def _decode_saved(raw: str | None) -> tuple[dict[str, _Properties], int]:
    """Read back the saved properties and the second their fetch began.

    The cache only saves reads, so one that is missing, from another version or damaged is
    dropped and the next fetch reads every item in full.
    """
    fields = _json_object(raw)
    since, items = fields.get("since"), fields.get("items")
    if fields.get("version") != _SAVED_VERSION or not isinstance(since, int):
        return {}, 0
    entries = cast("dict[str, object]", items) if isinstance(items, dict) else {}
    known = {
        path: properties
        for path, entry in entries.items()
        if (properties := _saved_properties(entry)) is not None
    }
    # One damaged entry means the whole row is not what this code wrote.
    return (known, since) if isinstance(items, dict) and len(known) == len(entries) else ({}, 0)


def _json_object(raw: str | None) -> dict[str, object]:
    """`raw` parsed as a JSON object; empty when it is missing or anything else."""
    try:
        value: object = json.loads(raw or "{}")
    except ValueError:
        return {}
    return cast("dict[str, object]", value) if isinstance(value, dict) else {}


def _saved_properties(entry: object) -> _Properties | None:
    match cast("list[object]", entry) if isinstance(entry, list) else []:
        case [str(label), attributes, None | int() as created, int(modified)] if _is_text_map(
            attributes
        ):
            return _Properties(label, cast("dict[str, str]", attributes), created, modified)
        case _:
            return None


def _is_text_map(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    pairs = cast("dict[object, object]", value)
    return all(isinstance(name, str) and isinstance(text, str) for name, text in pairs.items())


def _creation_order(ref: str) -> tuple[int, str]:
    # gnome-keyring numbers a collection's items in creation order (".../collection/x/7").
    number = ref.rsplit("/", 1)[-1]
    return (int(number), ref) if number.isdigit() else (sys.maxsize, ref)


async def _bus_match(bus: MessageBus, member: str, rule: str) -> None:
    reply = await bus.call(
        Message(
            destination="org.freedesktop.DBus",
            path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus",
            member=member,
            signature="s",
            body=[rule],
        )
    )
    if reply.message_type == MessageType.ERROR:
        msg = f"{member} failed: {reply.error_name}"
        raise LocalUnavailable(msg)
