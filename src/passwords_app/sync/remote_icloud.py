# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""iCloud Keychain as the sync engine's `RemoteStore`.

The keychain client is blocking (HTTP and crypto), so every call runs in a worker thread and
calls are serialized: they share the zone cache. The connection is opened lazily and reopened
once when Apple rejects the token, which refreshes it; every failure surfaces as one of the
engine's errors, never as a smaller snapshot.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import TYPE_CHECKING, Protocol

import requests

from passwords_app.icloud.account import SignInRequired
from passwords_app.icloud.errors import AppleError
from passwords_app.icloud.keychain.client import RecordConflictError
from passwords_app.icloud.passwords import UnsupportedCredentialError
from passwords_app.icloud.transport.cloudkit import CloudKitError
from passwords_app.sync.ports import (
    AuthRequired,
    ConflictError,
    RemoteItem,
    RemoteSnapshot,
    RemoteUnavailable,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from passwords_app.core.model import Credential
    from passwords_app.icloud.keychain.client import StoredLogin

logger = logging.getLogger(__name__)


class Keychain(Protocol):
    def fetch(self) -> Mapping[str, StoredLogin]: ...

    def save(self, cred: Credential, etag: str | None) -> str: ...

    def delete(self, item_id: str, etag: str | None) -> None: ...


class ICloudRemoteStore:
    """`RemoteStore` over a keychain opened by `connect` (e.g. `Account.open_keychain`).

    `generation` names the account state the open keychain belongs to; when it changes (a
    sign-out, another sign-in, a join) the keychain is reopened rather than reused, so a store
    never keeps talking to an account that is gone.
    """

    def __init__(
        self, connect: Callable[[], Keychain], generation: Callable[[], object] = lambda: None
    ) -> None:
        self._connect = connect
        self._generation = generation
        self._keychain: Keychain | None = None
        self._opened_for: object = None
        self._lock = threading.Lock()

    def _call[T](self, op: Callable[[Keychain], T]) -> T:
        with self._lock:
            for attempt in range(2):
                try:
                    current = self._generation()
                    if self._keychain is None or current != self._opened_for:
                        self._keychain = None
                        self._keychain = self._connect()
                        self._opened_for = current
                    return op(self._keychain)
                except CloudKitError as e:
                    if not e.unauthorized:
                        raise _translate(e) from e
                    self._keychain = None
                    if attempt:
                        msg = "iCloud keeps rejecting the sign-in; sign in again"
                        raise AuthRequired(msg) from e
                    logger.info("iCloud token rejected; reconnecting")
                except (AppleError, requests.RequestException, OSError, ValueError) as e:
                    raise _translate(e) from e
        msg = "unreachable"  # pragma: no cover - the loop always returns or raises
        raise AssertionError(msg)  # pragma: no cover

    async def fetch(self) -> RemoteSnapshot:
        logins = await asyncio.to_thread(self._call, lambda k: k.fetch())
        return RemoteSnapshot(
            {item_id: RemoteItem(s.credential, s.etag) for item_id, s in logins.items()}
        )

    async def upsert(self, credential: Credential, etag: str | None) -> str:
        return await asyncio.to_thread(self._call, lambda k: k.save(credential, etag))

    async def delete(self, item_id: str, etag: str | None) -> None:
        await asyncio.to_thread(self._call, lambda k: k.delete(item_id, etag))


def _translate(error: Exception) -> Exception:
    if isinstance(error, RecordConflictError):
        return ConflictError(str(error))
    if isinstance(error, SignInRequired):
        return AuthRequired(str(error))
    if isinstance(error, UnsupportedCredentialError):
        return RemoteUnavailable(f"iCloud Keychain cannot store this login: {error}")
    return RemoteUnavailable(str(error) or type(error).__name__)
