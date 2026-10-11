# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Encrypted session store: the auth tokens and keychain peer identity of the signed-in account.

`session.enc` is a libsodium secret box (XSalsa20-Poly1305) over the session JSON. Its 32-byte
master key lives in the login keyring (Secret Service, attributes application=passwords-app
type=master-key, stored base64) or, without a keyring, in a 0600 `master.key` file. Keys
written before the base64 change (raw 32 bytes) still load. The key is looked up once per
process: every keyring round-trip is a D-Bus call and may prompt.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import threading
from typing import TYPE_CHECKING, Protocol, cast

import nacl.exceptions
import nacl.secret
import nacl.utils

from passwords_app.icloud.errors import AppleError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path

    from passwords_app.icloud.paths import ConfigPaths
    from passwords_app.icloud.values import Record

logger = logging.getLogger(__name__)

ATTRIBUTES = {"application": "passwords-app", "type": "master-key"}
_LABEL = "Passwords app (iCloud Keychain sync) master key"
KEY_SIZE: int = nacl.secret.SecretBox.KEY_SIZE


class SessionError(AppleError):
    """The stored session exists but cannot be read with the current master key."""


class _SecretItem(Protocol):
    def get_secret(self) -> bytes: ...


class _Collection(Protocol):
    # Positional-only, as this app calls them; the `_` names mark the stubs' parameters as never
    # read (vulture would otherwise report them as unused variables).
    def is_locked(self) -> bool: ...
    def unlock(self) -> bool: ...
    def search_items(self, _attributes: dict[str, str], /) -> Iterable[_SecretItem]: ...
    def create_item(
        self, _label: str, _attributes: dict[str, str], _secret: bytes, /, *, replace: bool
    ) -> object: ...


def decode_key(stored: bytes | str | None) -> bytes | None:
    """Decode a stored master key in either form (base64 or legacy raw); None if unusable."""
    if stored is None:
        return None
    raw = stored.encode() if isinstance(stored, str) else bytes(stored)
    if len(raw) == KEY_SIZE:
        return raw
    try:
        key = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    return key if len(key) == KEY_SIZE else None


def _default_collection() -> _Collection | None:
    try:
        import secretstorage  # noqa: PLC0415 - optional, and slow to import (D-Bus)

        conn = secretstorage.dbus_init()
        return cast("_Collection", secretstorage.get_default_collection(conn))
    except Exception as e:  # noqa: BLE001 - no bus, no keyring daemon, no collection: fall back
        logger.warning("D-Bus keyring unavailable (%s); using the key file", type(e).__name__)
        return None


def key_from_collection(coll: _Collection) -> bytes | None:
    """Return the keyring's master key, creating it if missing; None if the keyring refuses."""
    try:
        if coll.is_locked() and coll.unlock():  # True means the prompt was dismissed
            logger.warning("keyring unlock dismissed; using the key file")
            return None
        unusable = 0
        for item in coll.search_items(ATTRIBUTES):
            key = decode_key(item.get_secret())
            if key is not None:
                return key
            unusable += 1
        if unusable:
            logger.warning("keyring holds %d unusable master-key item(s); replacing", unusable)
        key = nacl.utils.random(KEY_SIZE)
        coll.create_item(_LABEL, ATTRIBUTES, base64.b64encode(key), replace=True)
    except Exception as e:  # noqa: BLE001 - any keyring failure means "use the key file"
        logger.warning("keyring access failed (%s); using the key file", type(e).__name__)
        return None
    return key


def write_private(path: Path, data: bytes) -> None:
    """Write a file that is 0600 from creation: secrets must never exist world-readable."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    path.chmod(0o600)


def key_from_file(path: Path) -> bytes:
    if path.exists():
        key = decode_key(path.read_bytes())
        if key is not None:
            return key
        logger.warning("master key file %s is unusable; writing a fresh key", path)
    key = nacl.utils.random(KEY_SIZE)
    write_private(path, base64.b64encode(key))
    logger.warning("stored the master key in %s (0600); a keyring is safer", path)
    return key


_cache_lock = threading.Lock()
_cached_keys: dict[str, bytes] = {}


class SessionStore:
    """Load and save the session record under one config directory."""

    def __init__(
        self,
        paths: ConfigPaths,
        *,
        collection: Callable[[], _Collection | None] | None = None,
    ) -> None:
        self.paths = paths
        self._collection = collection or (_default_collection)

    def master_key(self) -> bytes:
        """Return the master key from the per-process cache, the keyring, or the key file."""
        cache_key = str(self.paths.root)
        with _cache_lock:
            key = _cached_keys.get(cache_key)
            if key is None:
                coll = self._collection()
                key = key_from_collection(coll) if coll is not None else None
                if key is None:
                    self.paths.ensure()
                    key = key_from_file(self.paths.fallback_key)
                _cached_keys[cache_key] = key
            return key

    def save(self, data: Record) -> None:
        box = nacl.secret.SecretBox(self.master_key())
        self.paths.ensure()
        write_private(self.paths.session, box.encrypt(json.dumps(data).encode()))

    def load(self) -> Record | None:
        f = self.paths.session
        if not f.exists():
            return None
        box = nacl.secret.SecretBox(self.master_key())
        try:
            data = json.loads(box.decrypt(f.read_bytes()).decode())
        except nacl.exceptions.CryptoError as e:
            msg = (
                f"cannot decrypt {f}: the master key no longer matches it (the keyring entry "
                "was lost or replaced). Sign out and sign in again."
            )
            raise SessionError(msg) from e
        if not isinstance(data, dict):
            msg = f"{f} does not hold a session"
            raise SessionError(msg)
        return cast("Record", data)

    def clear(self) -> None:
        self.paths.session.unlink(missing_ok=True)


def forget_cached_keys() -> None:
    """Drop the per-process key cache (after the keyring entry is replaced, and in tests)."""
    with _cache_lock:
        _cached_keys.clear()
