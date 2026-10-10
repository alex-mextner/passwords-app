# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""state.db: sync bases, trash, held deletions, and small settings, encrypted per row.

Every row that can contain a secret is sealed with AES-256-GCM under a key the caller fetches
from the Secret Service. The associated data binds each ciphertext to its table, row id, and
plaintext metadata columns, so a blob copied into another row, or a reason/date edited in
place, fails authentication with `StateCorruptedError` instead of decrypting to someone else's
data.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Self, cast, get_args

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from passwords_app.core.model import Credential, TrashEntry, TrashReason
from passwords_app.sync.plan import BaseEntry
from passwords_app.sync.ports import PendingDeletions

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

KEY_SIZE = 32
_NONCE_SIZE = 12
_REASONS: frozenset[str] = frozenset(get_args(TrashReason))

SCHEMA_VERSION = 1

# Index = version reached after running the script; each runs in one transaction.
_MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE bases (
        item_id TEXT PRIMARY KEY,
        etag TEXT,
        blob BLOB NOT NULL
    );
    CREATE TABLE trash (
        trash_id TEXT PRIMARY KEY,
        deleted_at TEXT NOT NULL,
        reason TEXT NOT NULL,
        blob BLOB NOT NULL
    );
    CREATE INDEX trash_deleted_at ON trash (deleted_at);
    CREATE TABLE pending (
        side TEXT NOT NULL CHECK (side IN ('local', 'remote')),
        item_id TEXT NOT NULL,
        PRIMARY KEY (side, item_id)
    );
    CREATE TABLE kv (
        key TEXT PRIMARY KEY,
        blob BLOB NOT NULL
    );
    """,
)


class StateError(Exception):
    """state.db cannot be used."""


class StateCorruptedError(StateError):
    """A row failed authentication or decoding: tampered, truncated, or wrong key."""


class StateSchemaError(StateError):
    """state.db was written by a newer version of the app."""


def _ts(value: datetime) -> str:
    # Fixed-width UTC text sorts chronologically, which `purge_older_than` relies on.
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_ts(text: str) -> datetime:
    # fromisoformat is C and reads this fixed format exactly; strptime would cost a large
    # share of every cycle, since all bases are decoded each time.
    parsed = datetime.fromisoformat(text)
    if parsed.utcoffset() != timedelta(0):
        msg = "stored timestamp is not UTC"
        raise ValueError(msg)
    return parsed


def _encode_credential(c: Credential) -> bytes:
    return json.dumps(
        {
            "id": c.id,
            "url": c.url,
            "username": c.username,
            "password": c.password,
            "created": _ts(c.created),
            "modified": _ts(c.modified),
            "title": c.title,
            "notes": c.notes,
            "otpauth": c.otpauth,
            "alt_urls": list(c.alt_urls),
            "group": c.group,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


def _decode_credential(raw: bytes) -> Credential:
    try:
        d = json.loads(raw)
        return Credential(
            id=d["id"],
            url=d["url"],
            username=d["username"],
            password=d["password"],
            created=_parse_ts(d["created"]),
            modified=_parse_ts(d["modified"]),
            title=d["title"],
            notes=d["notes"],
            otpauth=d["otpauth"],
            alt_urls=tuple(d["alt_urls"]),
            group=d["group"],
        )
    except (ValueError, KeyError, TypeError) as exc:
        msg = "stored credential is malformed"
        raise StateCorruptedError(msg) from exc


class StateStore:
    """Single-connection store; use from one thread (the daemon's event loop)."""

    def __init__(self, path: Path, key: bytes) -> None:
        if len(key) != KEY_SIZE:
            msg = f"key must be {KEY_SIZE} bytes"
            raise ValueError(msg)
        self._aead = AESGCM(key)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Create the file 0600 before SQLite opens it so no window exists with wider rights.
        os.close(os.open(path, os.O_RDWR | os.O_CREAT, 0o600))
        self._db = sqlite3.connect(path, isolation_level=None)
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._migrate()
        except BaseException:
            self._db.close()
            raise

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def schema_version(self) -> int:
        return cast("int", self._db.execute("PRAGMA user_version").fetchone()[0])

    def _migrate(self) -> None:
        current = self.schema_version
        if current > SCHEMA_VERSION:
            msg = f"state.db schema {current} is newer than supported {SCHEMA_VERSION}"
            raise StateSchemaError(msg)
        for version in range(current + 1, SCHEMA_VERSION + 1):
            script = _MIGRATIONS[version - 1]
            # executescript() commits implicitly, so the version bump lives in the same
            # explicit transaction to keep a crash from leaving a half-migrated file.
            self._db.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {version};\nCOMMIT;")

    # ------------------------------------------------------------------ crypto

    def _seal(self, plaintext: bytes, aad: bytes) -> bytes:
        nonce = os.urandom(_NONCE_SIZE)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def _open(self, blob: bytes, aad: bytes) -> bytes:
        if len(blob) < _NONCE_SIZE + 16:
            msg = "encrypted row is truncated"
            raise StateCorruptedError(msg)
        try:
            return self._aead.decrypt(blob[:_NONCE_SIZE], blob[_NONCE_SIZE:], aad)
        except InvalidTag as exc:
            msg = "encrypted row failed authentication"
            raise StateCorruptedError(msg) from exc

    @staticmethod
    def _base_aad(item_id: str, etag: str | None) -> bytes:
        return json.dumps(["base", item_id, etag]).encode()

    @staticmethod
    def _trash_aad(trash_id: str, deleted_at: str, reason: str) -> bytes:
        return json.dumps(["trash", trash_id, deleted_at, reason]).encode()

    @staticmethod
    def _kv_aad(key: str) -> bytes:
        return json.dumps(["kv", key]).encode()

    # ------------------------------------------------------------------ bases

    def bases(self) -> dict[str, BaseEntry]:
        out: dict[str, BaseEntry] = {}
        for item_id, etag, blob in self._db.execute("SELECT item_id, etag, blob FROM bases"):
            c = _decode_credential(self._open(blob, self._base_aad(item_id, etag)))
            if c.id != item_id:
                msg = "base row id does not match its credential"
                raise StateCorruptedError(msg)
            out[item_id] = BaseEntry(c, etag)
        return out

    def set_base(self, entry: BaseEntry) -> None:
        item_id = entry.credential.id
        blob = self._seal(_encode_credential(entry.credential), self._base_aad(item_id, entry.etag))
        self._db.execute(
            "INSERT OR REPLACE INTO bases (item_id, etag, blob) VALUES (?, ?, ?)",
            (item_id, entry.etag, blob),
        )

    def drop_base(self, item_id: str) -> None:
        self._db.execute("DELETE FROM bases WHERE item_id = ?", (item_id,))

    # ------------------------------------------------------------------ trash

    def add_trash(self, entry: TrashEntry) -> bool:
        """Store `entry`; returns False when that trash id is already stored (idempotent)."""
        deleted_at = _ts(entry.deleted_at)
        blob = self._seal(
            _encode_credential(entry.credential),
            self._trash_aad(entry.trash_id, deleted_at, entry.reason),
        )
        cur = self._db.execute(
            "INSERT OR IGNORE INTO trash (trash_id, deleted_at, reason, blob) VALUES (?, ?, ?, ?)",
            (entry.trash_id, deleted_at, entry.reason, blob),
        )
        return cur.rowcount == 1

    def _trash_row(self, trash_id: str, deleted_at: str, reason: str, blob: bytes) -> TrashEntry:
        plaintext = self._open(blob, self._trash_aad(trash_id, deleted_at, reason))
        if reason not in _REASONS:
            msg = "trash row has an unknown reason"
            raise StateCorruptedError(msg)
        return TrashEntry(
            trash_id=trash_id,
            credential=_decode_credential(plaintext),
            deleted_at=_parse_ts(deleted_at),
            reason=cast("TrashReason", reason),
        )

    def trash(self, *, since: datetime | None = None) -> list[TrashEntry]:
        """Trash entries deleted at or after `since` (default: all), most recent first."""
        rows = self._db.execute(
            "SELECT trash_id, deleted_at, reason, blob FROM trash WHERE deleted_at >= ?"
            " ORDER BY deleted_at DESC, trash_id",
            ("" if since is None else _ts(since),),
        )
        return [self._trash_row(*row) for row in rows]

    def get_trash(self, trash_id: str) -> TrashEntry | None:
        row = self._db.execute(
            "SELECT trash_id, deleted_at, reason, blob FROM trash WHERE trash_id = ?",
            (trash_id,),
        ).fetchone()
        return None if row is None else self._trash_row(*row)

    def remove_trash(self, trash_id: str) -> bool:
        cur = self._db.execute("DELETE FROM trash WHERE trash_id = ?", (trash_id,))
        return cur.rowcount == 1

    def purge_older_than(self, cutoff: datetime) -> int:
        """Delete entries deleted strictly before `cutoff`; returns how many were removed."""
        cur = self._db.execute("DELETE FROM trash WHERE deleted_at < ?", (_ts(cutoff),))
        return cur.rowcount

    # ------------------------------------------------------------------ pending deletions

    def pending(self) -> PendingDeletions | None:
        local: list[str] = []
        remote: list[str] = []
        for side, item_id in self._db.execute(
            "SELECT side, item_id FROM pending ORDER BY side, item_id"
        ):
            (local if side == "local" else remote).append(item_id)
        if not local and not remote:
            return None
        return PendingDeletions(tuple(local), tuple(remote))

    def set_pending(self, pending: PendingDeletions | None) -> None:
        rows: Iterable[tuple[str, str]] = ()
        if pending is not None:
            rows = [("local", i) for i in pending.local_ids] + [
                ("remote", i) for i in pending.remote_ids
            ]
        with self.transaction():
            self._db.execute("DELETE FROM pending")
            self._db.executemany("INSERT INTO pending (side, item_id) VALUES (?, ?)", rows)

    # ------------------------------------------------------------------ key-value

    def get(self, key: str) -> str | None:
        row = self._db.execute("SELECT blob FROM kv WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        try:
            return self._open(row[0], self._kv_aad(key)).decode()
        except UnicodeDecodeError as exc:
            msg = "stored value is not text"
            raise StateCorruptedError(msg) from exc

    def set(self, key: str, value: str) -> None:
        blob = self._seal(value.encode(), self._kv_aad(key))
        self._db.execute("INSERT OR REPLACE INTO kv (key, blob) VALUES (?, ?)", (key, blob))

    def delete(self, key: str) -> None:
        self._db.execute("DELETE FROM kv WHERE key = ?", (key,))

    # ------------------------------------------------------------------ transactions

    def transaction(self) -> _Transaction:
        """Group writes so they land together or not at all (`with store.transaction(): ...`)."""
        return _Transaction(self._db)


class _Transaction:
    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db
        self._outer = False

    def __enter__(self) -> None:
        # Nested use joins the enclosing transaction instead of failing on a second BEGIN.
        self._outer = not self._db.in_transaction
        if self._outer:
            self._db.execute("BEGIN IMMEDIATE")

    def __exit__(self, exc_type: type[BaseException] | None, *_: object) -> None:
        if not self._outer:
            return
        if exc_type is None:
            self._db.execute("COMMIT")
        else:
            self._db.execute("ROLLBACK")
