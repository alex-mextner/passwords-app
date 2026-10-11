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
import os
import sys
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

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
from passwords_app.sync.ports import LocalSnapshot, LocalUnavailable, RejectedLocalItem

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

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


def _adoption_id(item: StoredItem) -> str:
    # Derived, not random: two fetches racing to adopt the same item (e.g. daemon and app)
    # must agree on its id, or one snapshot's id is overwritten by the other's write-back.
    return str(uuid.uuid5(_ADOPTION_NAMESPACE, f"{item.ref}\n{item.created}")).upper()


class SecretServiceStore:
    __slots__ = ("_client", "_collection", "_io", "_label")

    def __init__(self, client: SecretServiceClient, collection: str, label: str) -> None:
        self._client = client
        self._collection = collection
        self._label = label
        # An item update is several D-Bus calls (secret, attributes, label); a fetch
        # interleaved with one could pair a new password with the old account. Writers
        # in other processes (Seahorse) cannot be excluded: their torn edit converges on
        # the next fetch, which `changes()` triggers.
        self._io = asyncio.Lock()

    @classmethod
    async def open(cls, bus: MessageBus, *, label: str = DEFAULT_LABEL) -> Self:
        """Find or create the collection and unlock it, all without prompting."""
        try:
            client = await SecretServiceClient.open(bus)
            collection = await ensure_collection(client, label)
            await ensure_unlocked(client, collection, label)
        except (SecretServiceError, CollectionUnavailableError) as exc:
            raise LocalUnavailable(str(exc)) from exc
        return cls(client, collection, label)

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
        client = self._client
        paths: list[str] = list(await client.get_property(self._collection, COLLECTION, "Items"))
        in_flight = asyncio.Semaphore(MAX_IN_FLIGHT)

        async def read(path: str, name: str) -> Any:  # noqa: ANN401 - D-Bus property value
            async with in_flight:
                return await client.get_property(path, ITEM, name)

        secrets, attributes, modified, labels = await asyncio.gather(
            client.get_secrets(paths),
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
        await self._check_still_unlocked(paths, secrets, attributes)
        created_at = {path: int(when) for path, when in zip(detailed, created, strict=True)}
        return [
            StoredItem(
                ref=path,
                label=str(label),
                attributes=dict(attrs),
                secret=secrets[path],
                created=created_at.get(path),
                modified=int(mtime),
            )
            for path, attrs, mtime, label in zip(paths, attributes, modified, labels, strict=True)
        ]

    async def _check_still_unlocked(
        self, paths: list[str], secrets: dict[str, bytes], attributes: list[dict[str, str]]
    ) -> None:
        missing = len(paths) - len(secrets)
        if missing:
            msg = f"{missing} secret(s) could not be read (collection locked meanwhile?)"
            raise LocalUnavailable(msg)
        # A locked item shows an empty label and only hashed attributes; read as-is it
        # would look like a different, unparsable item and its credential would vanish.
        hashed = any(name.startswith(_HASHED_ATTRIBUTE) for attrs in attributes for name in attrs)
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

    async def upsert(self, credential: Credential) -> None:
        """Create or overwrite the item with this id (raises ValueError if unstorable)."""
        item_content(credential, written_at=0)  # refuse unstorable input before any I/O
        try:
            async with self._io:
                await self._ready()
                found = await self._find(credential.id)
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

    async def delete(self, item_id: str) -> None:
        """Delete every item carrying this id; deleting a missing id is a no-op."""
        try:
            async with self._io:
                await self._ready()
                for path in await self._find(item_id):
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
