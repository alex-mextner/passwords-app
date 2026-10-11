# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""In-memory `RemoteStore` / `LocalStore` with failure injection, shared by every test suite.

API summary (keep it small; daemon, app, browser, and e2e suites depend on it):

`MemoryRemote` (iCloud stand-in)
- `put(c) -> etag` / `remove(id)`: simulate edits made on an Apple device (no etag check).
- `items` (read-only view `id -> RemoteItem`), `etag_of(id)`.
- `offline = True`: every call raises `RemoteUnavailable`.
- `fail_next(op, exc, times=1)`: the next `times` calls of `op` ("fetch" | "upsert" |
  "delete") raise `exc` (e.g. `ConflictError()`, `AuthRequired()`).
- `on_write`: optional async hook run inside `upsert`/`delete` before the etag check, to
  model a concurrent device edit racing the engine.
- `calls`: list of `(op, item_id | None)` in call order.

`MemoryLocal` (GNOME Keyring collection stand-in)
- `put(c)` / `remove(id)`: simulate edits made in Seahorse or another libsecret app.
- `items` (read-only view `id -> Credential`), `rejected` (list of `RejectedLocalItem`).
- `lock()` / `unlock()` / `locked`: a locked collection raises `LocalUnavailable` on every
  call, exactly like the real adapter.
- `fail_next(op, exc, times=1)` as above.
- `changes()`: async iterator yielding once per mutation, including the engine's own writes
  (the real Secret Service signals those too; debouncing is the consumer's job).
- `calls` as above.

`make_credential(item_id, **fields)` builds a valid `Credential` with fixed timestamps.
"""

from __future__ import annotations

import asyncio
import itertools
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal

from passwords_app.core.model import Credential
from passwords_app.sync.ports import (
    ConflictError,
    LocalSnapshot,
    LocalUnavailable,
    RejectedLocalItem,
    RemoteItem,
    RemoteSnapshot,
    RemoteUnavailable,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping

type Op = Literal["fetch", "upsert", "delete"]

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def make_credential(item_id: str = "ID-1", **fields: Any) -> Credential:
    """A valid credential; `modified` may be given as seconds after `EPOCH` (int)."""
    values: dict[str, Any] = {
        "url": f"https://{item_id.lower()}.example.com",
        "username": "user",
        "password": "pw-" + item_id,
        "created": EPOCH,
        "modified": EPOCH,
    }
    values.update(fields)
    if isinstance(values["modified"], int):
        values["modified"] = EPOCH + timedelta(seconds=values["modified"])
    return Credential(id=item_id, **values)


class _Faults:
    def __init__(self) -> None:
        self._queued: dict[Op, list[Exception]] = defaultdict(list)

    def add(self, op: Op, exc: Exception, times: int) -> None:
        self._queued[op].extend([exc] * times)

    def check(self, op: Op) -> None:
        queue = self._queued[op]
        if queue:
            raise queue.pop(0)


class MemoryRemote:
    def __init__(self, items: Mapping[str, Credential] | None = None) -> None:
        self._items: dict[str, RemoteItem] = {}
        self._etags = itertools.count(1)
        self._faults = _Faults()
        self.offline = False
        self.on_write: Callable[[str], Awaitable[None]] | None = None
        self.calls: list[tuple[Op, str | None]] = []
        for c in (items or {}).values():
            self.put(c)

    @property
    def items(self) -> Mapping[str, RemoteItem]:
        return MappingProxyType(self._items)

    def etag_of(self, item_id: str) -> str | None:
        item = self._items.get(item_id)
        return None if item is None else item.etag

    def _next_etag(self) -> str:
        return f"etag-{next(self._etags)}"

    def put(self, credential: Credential) -> str:
        etag = self._next_etag()
        self._items[credential.id] = RemoteItem(credential, etag)
        return etag

    def remove(self, item_id: str) -> None:
        del self._items[item_id]

    def fail_next(self, op: Op, exc: Exception, times: int = 1) -> None:
        self._faults.add(op, exc, times)

    def _enter(self, op: Op, item_id: str | None) -> None:
        self.calls.append((op, item_id))
        if self.offline:
            msg = "iCloud unreachable (simulated)"
            raise RemoteUnavailable(msg)
        self._faults.check(op)

    async def fetch(self) -> RemoteSnapshot:
        self._enter("fetch", None)
        return RemoteSnapshot(dict(self._items))

    async def upsert(self, credential: Credential, etag: str | None) -> str:
        self._enter("upsert", credential.id)
        if self.on_write is not None:
            await self.on_write(credential.id)
        current = self._items.get(credential.id)
        if etag is None and current is not None:
            msg = f"record {credential.id} already exists"
            raise ConflictError(msg)
        if etag is not None and (current is None or current.etag != etag):
            msg = f"record {credential.id} changed since fetch"
            raise ConflictError(msg)
        return self.put(credential)

    async def delete(self, item_id: str, etag: str | None) -> None:
        self._enter("delete", item_id)
        if self.on_write is not None:
            await self.on_write(item_id)
        current = self._items.get(item_id)
        if current is None or (etag is not None and current.etag != etag):
            msg = f"record {item_id} changed since fetch"
            raise ConflictError(msg)
        del self._items[item_id]


class MemoryLocal:
    def __init__(self, items: Mapping[str, Credential] | None = None) -> None:
        self._items: dict[str, Credential] = dict(items or {})
        self._faults = _Faults()
        self._listeners: list[asyncio.Queue[None]] = []
        self.locked = False
        self.rejected: list[RejectedLocalItem] = []
        self.calls: list[tuple[Op, str | None]] = []

    @property
    def items(self) -> Mapping[str, Credential]:
        return MappingProxyType(self._items)

    def lock(self) -> None:
        self.locked = True

    def unlock(self) -> None:
        self.locked = False

    def fail_next(self, op: Op, exc: Exception, times: int = 1) -> None:
        self._faults.add(op, exc, times)

    def _notify(self) -> None:
        for queue in self._listeners:
            queue.put_nowait(None)

    def put(self, credential: Credential) -> None:
        self._items[credential.id] = credential
        self._notify()

    def remove(self, item_id: str) -> None:
        del self._items[item_id]
        self._notify()

    def _enter(self, op: Op, item_id: str | None) -> None:
        self.calls.append((op, item_id))
        if self.locked:
            msg = "collection is locked (simulated)"
            raise LocalUnavailable(msg)
        self._faults.check(op)

    async def fetch(self) -> LocalSnapshot:
        self._enter("fetch", None)
        return LocalSnapshot(dict(self._items), tuple(self.rejected))

    async def upsert(self, credential: Credential) -> None:
        self._enter("upsert", credential.id)
        self.put(credential)

    async def delete(self, item_id: str) -> None:
        self._enter("delete", item_id)
        # Deleting an already-missing item is a no-op, as with the Secret Service API.
        if item_id in self._items:
            self.remove(item_id)

    async def changes(self) -> AsyncGenerator[None]:
        queue: asyncio.Queue[None] = asyncio.Queue()
        self._listeners.append(queue)
        try:
            while True:
                await queue.get()
                yield
        finally:
            self._listeners.remove(queue)
